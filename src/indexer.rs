//! Deterministic replay of accepted envelopes into shielded state
//! (paper sections 8, 15, A.6, A.7).

use crate::{
    Fr, K_MIN, N_OUT, WINDOW_W,
    chain::{self, Electrum, op_return_payload},
    envelope::{self, Envelope, MintEnvelope, TransferEnvelope},
    keys, note,
    prover::Params,
    tree::MerkleTree,
};
use bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

/// Rejections kept in the state file: the most recent ones.
pub const MAX_REJECTIONS: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("opening {}: {source}", path.display())]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Chain(#[from] chain::Error),
    #[error("block {0} changed while it was being fetched")]
    BlockChanged(u32),
}

/// Deployment profile: fixed once, shared by every wallet and indexer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deployment {
    pub activation: u32,
    pub vault_script_pubkey: ScriptBuf,
    pub operator_address: String,
    pub vk_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptedTransfer {
    pub txid: Txid,
    pub height: u32,
    #[serde(with = "crate::serde_hex::bytes")]
    pub bytes: Vec<u8>,
    pub positions: [u64; N_OUT],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptedMint {
    pub txid: Txid,
    pub height: u32,
    #[serde(with = "crate::serde_hex::bytes")]
    pub bytes: Vec<u8>,
    pub value: u64,
    pub pos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Transfer(AcceptedTransfer),
    Mint(AcceptedMint),
}

impl AcceptedTransfer {
    pub fn envelope(&self) -> TransferEnvelope {
        match Envelope::parse(&self.bytes).expect("stored envelope parses") {
            Some(Envelope::Transfer(t)) => t,
            _ => unreachable!("stored transfer event holds a transfer"),
        }
    }
}

impl AcceptedMint {
    pub fn envelope(&self) -> MintEnvelope {
        match Envelope::parse(&self.bytes).expect("stored envelope parses") {
            Some(Envelope::Mint(m)) => m,
            _ => unreachable!("stored mint event holds a mint"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rejection {
    pub txid: Txid,
    pub height: u32,
    pub reason: String,
}

/// Why a carrier transaction was not accepted. Display is the stored text.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RejectReason {
    #[error("carrier: {0}")]
    Carrier(&'static str),
    #[error("parse: {0}")]
    Parse(#[from] envelope::Error),
    #[error("anchor {anchor} outside window for block {height}")]
    AnchorOutsideWindow { anchor: u32, height: u32 },
    #[error("no retained root for anchor {0}")]
    NoRetainedRoot(u32),
    #[error("duplicate nullifier inside envelope")]
    DuplicateNullifier,
    #[error("nullifier {} already spent", hex::encode(keys::fr_to_bytes(.0)))]
    NullifierSpent(Fr),
    #[error("proof does not verify")]
    ProofInvalid,
    #[error("mint carrier pays nothing to the vault")]
    MintUnfunded,
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct HexFr(#[serde(with = "crate::serde_hex::fr")] Fr);

#[derive(Serialize, Deserialize)]
struct StateFile {
    deployment: Deployment,
    replayed_height: u32,
    leaves: Vec<HexFr>,
    nullifiers: Vec<HexFr>,
    roots: Vec<(u32, HexFr)>,
    block_hashes: Vec<(u32, BlockHash)>,
    events: Vec<Event>,
    rejections: Vec<Rejection>,
}

pub struct State {
    pub deployment: Deployment,
    pub replayed_height: u32,
    pub tree: MerkleTree,
    pub nullifiers: BTreeSet<Fr>,
    pub roots: BTreeMap<u32, Fr>,
    pub block_hashes: BTreeMap<u32, BlockHash>,
    pub events: Vec<Event>,
    pub rejections: Vec<Rejection>,
}

impl State {
    pub fn fresh(deployment: Deployment) -> Self {
        let tree = MerkleTree::new();
        let mut roots = BTreeMap::new();
        // R[activation - 1] is the empty tree: the initial state.
        roots.insert(deployment.activation - 1, tree.root());
        Self {
            replayed_height: deployment.activation - 1,
            deployment,
            tree,
            nullifiers: BTreeSet::new(),
            roots,
            block_hashes: BTreeMap::new(),
            events: Vec::new(),
            rejections: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let file = std::fs::File::open(path).map_err(|source| Error::Open {
            path: path.to_path_buf(),
            source,
        })?;
        let f: StateFile = serde_json::from_reader(file)?;
        let mut tree = MerkleTree::new();
        for HexFr(l) in f.leaves {
            tree.append(l);
        }
        Ok(Self {
            deployment: f.deployment,
            replayed_height: f.replayed_height,
            tree,
            nullifiers: f.nullifiers.into_iter().map(|HexFr(n)| n).collect(),
            roots: f.roots.into_iter().map(|(h, HexFr(r))| (h, r)).collect(),
            block_hashes: f.block_hashes.into_iter().collect(),
            events: f.events,
            rejections: f.rejections,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let f = StateFile {
            deployment: self.deployment.clone(),
            replayed_height: self.replayed_height,
            leaves: self.tree.leaves().into_iter().map(HexFr).collect(),
            nullifiers: self.nullifiers.iter().copied().map(HexFr).collect(),
            roots: self.roots.iter().map(|(h, r)| (*h, HexFr(*r))).collect(),
            block_hashes: self.block_hashes.iter().map(|(h, b)| (*h, *b)).collect(),
            events: self.events.clone(),
            rejections: self.rejections.clone(),
        };
        let tmp = path.with_extension("json.tmp");
        serde_json::to_writer(std::fs::File::create(&tmp)?, &f)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    /// Replays every block from replayed_height + 1 to the tip. Returns the
    /// number of blocks processed. On a reorganisation the whole state is
    /// rebuilt from activation, which is cheap on a probe.
    pub fn sync(&mut self, e: &mut Electrum, params: &Params) -> Result<u32, Error> {
        let tip = e.tip_height()?;
        if let Some(h) = self.block_hashes.get(&self.replayed_height).copied() {
            if e.block_hash(self.replayed_height)? != h {
                eprintln!(
                    "reorganisation at or below {}: replaying from activation",
                    self.replayed_height
                );
                *self = Self::fresh(self.deployment.clone());
            }
        }
        let mut n = 0;
        while self.replayed_height < tip {
            let h = self.replayed_height + 1;
            self.replay_block(e, params, h)?;
            n += 1;
        }
        Ok(n)
    }

    /// Fetches the whole block before touching state, and bails if the
    /// block hash moved meanwhile: nothing is mutated and the next sync
    /// rebuilds from its stored tip.
    fn replay_block(&mut self, e: &mut Electrum, params: &Params, h: u32) -> Result<(), Error> {
        let hash = e.block_hash(h)?;
        let mut txs = Vec::new();
        for txid in e.block_txids(h)? {
            txs.push((txid, e.transaction(&txid)?));
        }
        if e.block_hash(h)? != hash {
            return Err(Error::BlockChanged(h));
        }
        let vault = self.deployment.vault_script_pubkey.clone();
        for (txid, tx) in &txs {
            if let Err(reason) = self.replay_tx(params, h, *txid, tx, &vault) {
                self.rejections.push(Rejection {
                    txid: *txid,
                    height: h,
                    reason: reason.to_string(),
                });
            }
        }
        self.roots.insert(h, self.tree.root());
        self.block_hashes.insert(h, hash);
        self.replayed_height = h;
        // Keep a little more root history than the window needs.
        let keep_from = h.saturating_sub(WINDOW_W + 10);
        self.roots
            .retain(|k, _| *k >= keep_from || *k == self.deployment.activation - 1);
        self.block_hashes.retain(|k, _| *k >= keep_from);
        let excess = self.rejections.len().saturating_sub(MAX_REJECTIONS);
        self.rejections.drain(..excess);
        Ok(())
    }

    /// One transaction of block `h`. Ok when it carries no envelope or the
    /// envelope was accepted; Err with the reason to record otherwise.
    pub fn replay_tx(
        &mut self,
        params: &Params,
        h: u32,
        txid: Txid,
        tx: &Transaction,
        vault: &ScriptBuf,
    ) -> std::result::Result<(), RejectReason> {
        let Some(payload) = op_return_payload(tx).map_err(RejectReason::Carrier)? else {
            return Ok(());
        };
        match Envelope::parse(&payload)? {
            None => Ok(()),
            Some(Envelope::Transfer(t)) => self.accept_transfer(params, h, txid, &t, &payload),
            Some(Envelope::Mint(m)) => {
                let value = tx
                    .output
                    .iter()
                    .filter(|o| o.script_pubkey == *vault)
                    .map(|o| o.value.to_sat())
                    .sum();
                self.accept_mint(h, txid, &m, &payload, value)
            }
        }
    }

    /// Paper A.7 order: parse (done), binding, anchor window, nullifiers,
    /// proof, then mutate.
    fn accept_transfer(
        &mut self,
        params: &Params,
        h: u32,
        txid: Txid,
        t: &TransferEnvelope,
        payload: &[u8],
    ) -> std::result::Result<(), RejectReason> {
        let (anchor, height) = (u64::from(t.h_anchor), u64::from(h));
        if anchor + u64::from(WINDOW_W) < height || anchor + u64::from(K_MIN) > height {
            return Err(RejectReason::AnchorOutsideWindow {
                anchor: t.h_anchor,
                height: h,
            });
        }
        let r_anchor = *self
            .roots
            .get(&t.h_anchor)
            .ok_or(RejectReason::NoRetainedRoot(t.h_anchor))?;
        if t.nf[0] == t.nf[1] {
            return Err(RejectReason::DuplicateNullifier);
        }
        for nf in &t.nf {
            if self.nullifiers.contains(nf) {
                return Err(RejectReason::NullifierSpent(*nf));
            }
        }
        let public = crate::circuit::PublicInputs {
            r_anchor,
            digest: t.statement_digest(),
        };
        if !params.verify(&public, &t.proof) {
            return Err(RejectReason::ProofInvalid);
        }
        let h_body = t.h_body();
        let mut positions = [0u64; N_OUT];
        for j in 0..N_OUT {
            positions[j] = self
                .tree
                .append(note::leaf(&h_body, j as u8, &t.pk_eph[j], &t.ct[j]));
        }
        for nf in &t.nf {
            self.nullifiers.insert(*nf);
        }
        self.events.push(Event::Transfer(AcceptedTransfer {
            txid,
            height: h,
            bytes: payload.to_vec(),
            positions,
        }));
        Ok(())
    }

    fn accept_mint(
        &mut self,
        h: u32,
        txid: Txid,
        m: &MintEnvelope,
        payload: &[u8],
        value: u64,
    ) -> std::result::Result<(), RejectReason> {
        if value == 0 {
            return Err(RejectReason::MintUnfunded);
        }
        let pos = self
            .tree
            .append(note::mint_leaf(value, &m.d, &m.pk_d, &m.r_seed));
        self.events.push(Event::Mint(AcceptedMint {
            txid,
            height: h,
            bytes: payload.to_vec(),
            value,
            pos,
        }));
        Ok(())
    }
}

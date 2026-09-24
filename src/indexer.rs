//! Deterministic replay of accepted envelopes into shielded state
//! (paper sections 8, 15, A.6, A.7).

use crate::chain::{op_return_payload, Electrum};
use crate::envelope::{Envelope, MintEnvelope, TransferEnvelope};
use crate::keys;
use crate::note;
use crate::prover::Params;
use crate::tree::MerkleTree;
use crate::{Fr, K_MIN, N_OUT, WINDOW_W};
use anyhow::{ensure, Context, Result};
use bitcoin::{BlockHash, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

/// Deployment profile: fixed once, shared by every wallet and indexer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deployment {
    pub activation: u32,
    pub vault_script_pubkey: String,
    pub operator_address: String,
    pub vk_fingerprint: String,
}

impl Deployment {
    pub fn vault_spk(&self) -> Result<ScriptBuf> {
        Ok(ScriptBuf::from_bytes(hex::decode(&self.vault_script_pubkey)?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptedTransfer {
    pub txid: Txid,
    pub height: u32,
    pub bytes: String,
    pub positions: [u64; N_OUT],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptedMint {
    pub txid: Txid,
    pub height: u32,
    pub bytes: String,
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
        match Envelope::parse(&hex::decode(&self.bytes).expect("stored hex")).expect("stored envelope parses") {
            Some(Envelope::Transfer(t)) => t,
            _ => unreachable!("stored transfer event holds a transfer"),
        }
    }
}

impl AcceptedMint {
    pub fn envelope(&self) -> MintEnvelope {
        match Envelope::parse(&hex::decode(&self.bytes).expect("stored hex")).expect("stored envelope parses") {
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
    Parse(String),
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
struct StateFile {
    deployment: Deployment,
    replayed_height: u32,
    leaves: Vec<String>,
    nullifiers: Vec<String>,
    roots: Vec<(u32, String)>,
    block_hashes: Vec<(u32, BlockHash)>,
    events: Vec<Event>,
    rejections: Vec<Rejection>,
}

pub struct State {
    pub deployment: Deployment,
    pub replayed_height: u32,
    pub tree: MerkleTree,
    pub nullifiers: HashSet<Fr>,
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
            nullifiers: HashSet::new(),
            roots,
            block_hashes: BTreeMap::new(),
            events: Vec::new(),
            rejections: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let f: StateFile = serde_json::from_reader(std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?)?;
        let mut tree = MerkleTree::new();
        for l in &f.leaves {
            tree.append(keys::fr_from_bytes(&hex::decode(l)?).context("bad leaf")?);
        }
        Ok(Self {
            deployment: f.deployment,
            replayed_height: f.replayed_height,
            tree,
            nullifiers: f.nullifiers.iter().map(|h| keys::fr_from_bytes(&hex::decode(h).unwrap_or_default()).context("bad nullifier")).collect::<Result<_>>()?,
            roots: f.roots.iter().map(|(h, r)| Ok((*h, keys::fr_from_bytes(&hex::decode(r)?).context("bad root")?))).collect::<Result<_>>()?,
            block_hashes: f.block_hashes.into_iter().collect(),
            events: f.events,
            rejections: f.rejections,
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let f = StateFile {
            deployment: self.deployment.clone(),
            replayed_height: self.replayed_height,
            leaves: self.tree.leaves().iter().map(|l| hex::encode(keys::fr_to_bytes(l))).collect(),
            nullifiers: self.nullifiers.iter().map(|n| hex::encode(keys::fr_to_bytes(n))).collect(),
            roots: self.roots.iter().map(|(h, r)| (*h, hex::encode(keys::fr_to_bytes(r)))).collect(),
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
    pub fn sync(&mut self, e: &mut Electrum, params: &Params) -> Result<u32> {
        let tip = e.tip_height()?;
        if let Some(h) = self.block_hashes.get(&self.replayed_height).copied() {
            if e.block_hash(self.replayed_height)? != h {
                eprintln!("reorganisation at or below {}: replaying from activation", self.replayed_height);
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
    fn replay_block(&mut self, e: &mut Electrum, params: &Params, h: u32) -> Result<()> {
        let hash = e.block_hash(h)?;
        let mut txs = Vec::new();
        for txid in e.block_txids(h)? {
            txs.push((txid, e.transaction(&txid)?));
        }
        ensure!(e.block_hash(h)? == hash, "block {h} changed while it was being fetched");
        let vault = self.deployment.vault_spk()?;
        for (txid, tx) in &txs {
            if let Err(reason) = self.replay_tx(params, h, *txid, tx, &vault) {
                self.rejections.push(Rejection { txid: *txid, height: h, reason: reason.to_string() });
            }
        }
        self.roots.insert(h, self.tree.root());
        self.block_hashes.insert(h, hash);
        self.replayed_height = h;
        // Keep a little more root history than the window needs.
        let keep_from = h.saturating_sub(WINDOW_W + 10);
        self.roots.retain(|k, _| *k >= keep_from || *k == self.deployment.activation - 1);
        self.block_hashes.retain(|k, _| *k >= keep_from);
        Ok(())
    }

    /// One transaction of block `h`. Ok when it carries no envelope or the
    /// envelope was accepted; Err with the reason to record otherwise.
    pub fn replay_tx(&mut self, params: &Params, h: u32, txid: Txid, tx: &Transaction, vault: &ScriptBuf) -> std::result::Result<(), RejectReason> {
        let Some(payload) = op_return_payload(tx).map_err(RejectReason::Carrier)? else { return Ok(()) };
        match Envelope::parse(&payload).map_err(|e| RejectReason::Parse(e.to_string()))? {
            None => Ok(()),
            Some(Envelope::Transfer(t)) => self.accept_transfer(params, h, txid, &t, &payload),
            Some(Envelope::Mint(m)) => {
                let value = tx.output.iter().filter(|o| o.script_pubkey == *vault).map(|o| o.value.to_sat()).sum();
                self.accept_mint(h, txid, &m, &payload, value)
            }
        }
    }

    /// Paper A.7 order: parse (done), binding, anchor window, nullifiers,
    /// proof, then mutate.
    fn accept_transfer(&mut self, params: &Params, h: u32, txid: Txid, t: &TransferEnvelope, payload: &[u8]) -> std::result::Result<(), RejectReason> {
        let (anchor, height) = (u64::from(t.h_anchor), u64::from(h));
        if anchor + u64::from(WINDOW_W) < height || anchor + u64::from(K_MIN) > height {
            return Err(RejectReason::AnchorOutsideWindow { anchor: t.h_anchor, height: h });
        }
        let r_anchor = *self.roots.get(&t.h_anchor).ok_or(RejectReason::NoRetainedRoot(t.h_anchor))?;
        if t.nf[0] == t.nf[1] {
            return Err(RejectReason::DuplicateNullifier);
        }
        for nf in &t.nf {
            if self.nullifiers.contains(nf) {
                return Err(RejectReason::NullifierSpent(*nf));
            }
        }
        let public = crate::circuit::PublicInputs { r_anchor, digest: t.statement_digest() };
        if !params.verify(&public, &t.proof) {
            return Err(RejectReason::ProofInvalid);
        }
        let h_body = t.h_body();
        let mut positions = [0u64; N_OUT];
        for j in 0..N_OUT {
            positions[j] = self.tree.append(note::leaf(&h_body, j as u8, &t.pk_eph[j], &t.ct[j]));
        }
        for nf in &t.nf {
            self.nullifiers.insert(*nf);
        }
        self.events.push(Event::Transfer(AcceptedTransfer { txid, height: h, bytes: hex::encode(payload), positions }));
        Ok(())
    }

    fn accept_mint(&mut self, h: u32, txid: Txid, m: &MintEnvelope, payload: &[u8], value: u64) -> std::result::Result<(), RejectReason> {
        if value == 0 {
            return Err(RejectReason::MintUnfunded);
        }
        let pos = self.tree.append(note::mint_leaf(value, &m.d, &m.pk_d, &m.r_seed));
        self.events.push(Event::Mint(AcceptedMint { txid, height: h, bytes: hex::encode(payload), value, pos }));
        Ok(())
    }
}

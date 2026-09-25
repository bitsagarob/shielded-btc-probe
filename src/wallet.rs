//! Wallet: owned notes, scanning against replayed state, minting (peg-in),
//! building and publishing transfers, and the operator's peg-out handler.

use crate::{
    Fr, Fs, K_WALLET, N_IN, N_OUT, TREE_DEPTH, WINDOW_W,
    chain::{self, ChainSource, FundingKey, Utxo, op_return_payload},
    circuit::{self, InputWitness, OutputWitness, PublicInputs, TransferWitness},
    envelope::{CT_OUT_LEN, Envelope, MintEnvelope, Payout, TransferEnvelope},
    indexer::{self, Deployment, Event, State},
    keys::{self, Address, DIVERSIFIER_LEN, SpendingKeys, ViewingKeys, WalletKeys},
    note::{self, NotePlaintext},
    prover::{self, Params},
    tree::MerklePath,
};
use ark_ff::UniformRand;
use bitcoin::{
    Amount, Network, ScriptBuf, Transaction, TxOut, Txid, address::FromScriptError, secp256k1,
};
use fs2::FileExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{} already exists", .0.display())]
    Exists(PathBuf),
    #[error("opening {}: {source}", path.display())]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("funding key: {0}")]
    FundingKey(secp256k1::Error),
    #[error("vault key: {0}")]
    VaultKey(secp256k1::Error),
    #[error(transparent)]
    Chain(#[from] chain::Error),
    #[error(transparent)]
    Prover(#[from] prover::Error),
    #[error(transparent)]
    Indexer(#[from] indexer::Error),
    #[error("replay leaf mismatch at {0}")]
    LeafMismatch(u64),
    #[error("amount must be positive")]
    ZeroAmount,
    #[error(
        "insufficient shielded balance: {available} sat available under the anchor, {needed} needed (two inputs max, notes younger than {K_WALLET} blocks wait)"
    )]
    InsufficientBalance { available: u64, needed: u64 },
    #[error("note position {0} not in tree")]
    NotInTree(u64),
    #[error("local note {0} does not match the replayed leaf")]
    StaleNote(u64),
    #[error("no retained root for anchor {0}")]
    NoRoot(u32),
    #[error("replayed leaves do not rebuild the root at {0}")]
    AnchorMismatch(u32),
    #[error("arity")]
    Arity,
    #[error("nullifier already in the replayed set")]
    NullifierReplayed,
    #[error("the inputs share a nullifier")]
    DuplicateNullifier,
    #[error("ct_out length")]
    CtOutLength,
    #[error("own proof failed to verify")]
    OwnProofInvalid,
    #[error("asks {amount} sat but burned {burned} sat")]
    PayoutExceedsBurn { amount: u64, burned: u64 },
    #[error("{0} sat is below dust")]
    PayoutBelowDust(u64),
    #[error("non-standard payout script")]
    NonStandardPayout,
    #[error("payout script: {0}")]
    PayoutScript(#[from] FromScriptError),
    #[error("{amount} sat does not cover the {fee} sat fee plus dust")]
    PayoutBelowFee { amount: u64, fee: u64 },
    #[error("carrier {0} is still in the mempool or chain, pass --force to unlock anyway")]
    CarrierPresent(Txid),
    #[error("on mainnet, pass --only <txid> for each request you have verified")]
    PayoutsUnsupervised,
    #[error("no accepted payout request in {0}")]
    NoSuchRequest(Txid),
    #[error("{0} sat is over the {DEPOSIT_CAP} sat deposit cap, pass --i-know to mint anyway")]
    DepositCapped(u64),
    #[error("wallet file is locked by another process")]
    Locked,
    #[error("this wallet has no funding key")]
    NoFundingKey,
    #[error("this wallet has no vault key")]
    NoVaultKey,
    #[error("note values overflow u64")]
    Overflow,
}

/// Deposits above this on bitcoin need an explicit override.
pub const DEPOSIT_CAP: u64 = 100_000;

pub fn check_deposit(network: Network, amount: u64, overridden: bool) -> Result<(), Error> {
    if network == Network::Bitcoin && amount > DEPOSIT_CAP && !overridden {
        return Err(Error::DepositCapped(amount));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedNote {
    pub v: u64,
    #[serde(with = "crate::serde_hex::bytes")]
    pub d: [u8; DIVERSIFIER_LEN],
    #[serde(with = "crate::serde_hex::fr")]
    pub r_seed: Fr,
    pub is_mint: bool,
    #[serde(with = "crate::serde_hex::fr")]
    pub h_body_create: Fr,
    pub j: u8,
    pub pos: u64,
    pub source_txid: Txid,
    pub spent: bool,
    /// Set while a spend is published but not yet replayed.
    pub locked_by: Option<Txid>,
    /// Anchor of that spend; the lock lapses once the anchor window has passed.
    #[serde(default)]
    pub lock_anchor: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SentRecord {
    pub txid: Txid,
    pub v: u64,
    pub to: String,
    pub j: u8,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WalletFile {
    #[serde(with = "crate::serde_hex::bytes")]
    pub seed: [u8; 32],
    /// Pays for carriers. Absent in a viewing-only file.
    #[serde(default, with = "opt_hex")]
    pub funding_sk: Option<[u8; 32]>,
    /// Operator only: the key holding the vault, separate from the fee key.
    #[serde(default, with = "opt_hex")]
    pub vault_sk: Option<[u8; 32]>,
    #[zeroize(skip)]
    pub notes: Vec<OwnedNote>,
    #[zeroize(skip)]
    pub sent: Vec<SentRecord>,
    #[zeroize(skip)]
    pub scanned_events: usize,
    /// Txid of the last scanned event; a mismatch means replay history changed.
    #[serde(default)]
    #[zeroize(skip)]
    pub scanned_txid: Option<Txid>,
    /// Peg-out requests paid, keyed by hex of nf[0] (older files hold carrier txids).
    #[zeroize(skip)]
    pub paid_payouts: Vec<String>,
    /// Peg-out requests refused, hex of nf[0] to the reason.
    #[serde(default)]
    #[zeroize(skip)]
    pub failed_payouts: BTreeMap<String, String>,
    /// Payout transactions this wallet broadcast.
    #[serde(default)]
    #[zeroize(skip)]
    pub payout_txids: Vec<Txid>,
}

mod opt_hex {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        use serde::de::Error;
        Option::<String>::deserialize(d)?
            .map(|h| {
                <[u8; 32]>::try_from(hex::decode(h).map_err(D::Error::custom)?)
                    .map_err(|_| D::Error::custom("expected 32 bytes"))
            })
            .transpose()
    }
}

/// The viewing side of a wallet, written by `export-viewing`.
#[derive(Serialize)]
struct ViewingExport {
    addresses: Vec<String>,
    vk_in: String,
    vk_out: String,
    sk_view: String,
}

/// A proved transfer that has not been published.
pub struct BuiltTransfer {
    pub envelope: TransferEnvelope,
    /// Indices into the wallet's notes that it spends.
    pub inputs: Vec<usize>,
    pub prove_s: f64,
}

pub struct Wallet {
    pub path: PathBuf,
    pub file: WalletFile,
    pub keys: WalletKeys,
    funding: Option<FundingKey>,
    vault: Option<FundingKey>,
    /// Exclusive flock on `<path>.lock` for the wallet's lifetime; the wallet
    /// file itself is replaced by rename on every save, so it cannot carry
    /// the lock.
    _lock: File,
}

fn random_key() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}
fn event_txid(ev: &Event) -> Txid {
    match ev {
        Event::Mint(m) => m.txid,
        Event::Transfer(t) => t.txid,
    }
}
fn input_witness(n: &OwnedNote, path: MerklePath) -> InputWitness {
    InputWitness {
        enabled: true,
        is_mint: n.is_mint,
        v: n.v,
        d: n.d,
        r_seed: n.r_seed,
        h_body_create: n.h_body_create,
        j: n.j,
        path,
    }
}
fn own_nullifier(der: &SpendingKeys, n: &OwnedNote) -> Fr {
    note::nullifier(&der.sk_nf, &note::rho(&n.r_seed), n.pos)
}
fn lock(path: &Path) -> Result<File, Error> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path.with_extension("json.lock"))?;
    f.try_lock_exclusive().map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            Error::Locked
        } else {
            e.into()
        }
    })?;
    Ok(f)
}

impl Wallet {
    pub fn create(path: &Path) -> Result<Self, Error> {
        if path.exists() {
            return Err(Error::Exists(path.to_path_buf()));
        }
        let lock = lock(path)?;
        let file = WalletFile {
            seed: random_key(),
            funding_sk: Some(random_key()),
            vault_sk: Some(random_key()),
            notes: vec![],
            sent: vec![],
            scanned_events: 0,
            scanned_txid: None,
            paid_payouts: vec![],
            failed_payouts: BTreeMap::new(),
            payout_txids: vec![],
        };
        let w = Self::from_file(path.to_path_buf(), file, lock)?;
        w.save()?;
        Ok(w)
    }

    pub fn open(path: &Path) -> Result<Self, Error> {
        let lock = lock(path)?;
        let file = File::open(path).map_err(|source| Error::Open {
            path: path.to_path_buf(),
            source,
        })?;
        let file: WalletFile = serde_json::from_reader(file)?;
        Self::from_file(path.to_path_buf(), file, lock)
    }

    /// Gives an older file its vault key. Returns whether anything changed.
    pub fn migrate(&mut self) -> Result<bool, Error> {
        if self.vault.is_some() {
            return Ok(false);
        }
        let k = random_key();
        self.vault = Some(FundingKey::from_bytes(&k).map_err(Error::VaultKey)?);
        self.file.vault_sk = Some(k);
        self.save()?;
        Ok(true)
    }

    fn from_file(path: PathBuf, file: WalletFile, lock: File) -> Result<Self, Error> {
        let key = |k: &Option<[u8; 32]>| k.as_ref().map(FundingKey::from_bytes).transpose();
        let funding = key(&file.funding_sk).map_err(Error::FundingKey)?;
        let vault = key(&file.vault_sk).map_err(Error::VaultKey)?;
        Ok(Self {
            path,
            keys: WalletKeys::from_seed(file.seed),
            funding,
            vault,
            file,
            _lock: lock,
        })
    }

    /// Writes a 0600 tmp file, syncs it, renames it over the wallet and
    /// syncs the directory. Any failure before the rename removes the tmp
    /// file, so no half-written copy of the seed stays behind.
    pub fn save(&self) -> Result<(), Error> {
        let bytes = serde_json::to_vec_pretty(&self.file)?;
        let tmp = self.path.with_extension("json.tmp");
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        let dir = self.path.parent().filter(|d| !d.as_os_str().is_empty());
        File::open(dir.unwrap_or(Path::new(".")))?.sync_all()?;
        Ok(())
    }

    /// Viewing keys and addresses only, as a new 0600 JSON file.
    pub fn export_viewing(&self, out: &Path) -> Result<(), Error> {
        let vk = self.keys.viewing();
        let export = ViewingExport {
            addresses: vec![self.address().to_string()],
            vk_in: hex::encode(keys::fr_to_bytes(&vk.vk_in)),
            vk_out: hex::encode(vk.vk_out),
            sk_view: hex::encode(keys::scalar_to_bytes(&vk.sk_view)),
        };
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out)?;
        f.write_all(&serde_json::to_vec_pretty(&export)?)?;
        f.sync_all()?;
        Ok(())
    }

    pub fn address(&self) -> Address {
        self.keys.address(0)
    }

    pub fn funding_key(&self) -> Result<&FundingKey, Error> {
        self.funding.as_ref().ok_or(Error::NoFundingKey)
    }

    pub fn vault_key(&self) -> Result<&FundingKey, Error> {
        self.vault.as_ref().ok_or(Error::NoVaultKey)
    }

    /// The vault key of a wallet known to be an operator's. Panics on a
    /// viewing-only or unmigrated file; commands use `vault_key`.
    pub fn vault(&self) -> FundingKey {
        self.vault.clone().expect("this wallet has no vault key")
    }

    pub fn balance(&self) -> Result<u64, Error> {
        self.file
            .notes
            .iter()
            .filter(|n| !n.spent && n.locked_by.is_none())
            .try_fold(0u64, |acc, n| acc.checked_add(n.v).ok_or(Error::Overflow))
    }

    /// Paper 16.1 and 16.2 against the indexer's accepted history.
    pub fn scan(&mut self, state: &State) -> Result<usize, Error> {
        let der = self.keys.derive();
        let cursor = self.file.scanned_events;
        let anchored = self.file.scanned_txid.is_some_and(|t| {
            state
                .events
                .get(cursor.wrapping_sub(1))
                .is_some_and(|ev| event_txid(ev) == t)
        });
        if cursor > 0 && !anchored {
            log::warn!("replayed history changed under the wallet, rescanning from activation");
            self.file.notes.clear();
            self.file.sent.clear();
            self.file.scanned_events = 0;
        }
        // Paper C.4: every local record must still describe the accepted leaf.
        let mut kept = Vec::with_capacity(self.file.notes.len());
        for n in self.file.notes.drain(..) {
            let leaf = circuit::input_leaf(
                &der.sk_spend,
                &input_witness(
                    &n,
                    MerklePath {
                        pos: n.pos,
                        siblings: vec![],
                    },
                ),
            );
            if leaf.is_some() && state.tree.leaf(n.pos) == leaf {
                kept.push(n);
            } else {
                log::warn!(
                    "dropping note at position {}: no longer matches the replayed leaf",
                    n.pos
                );
                self.file.scanned_events = 0;
            }
        }
        self.file.notes = kept;
        let mut nfs: HashSet<Fr> = self
            .file
            .notes
            .iter()
            .map(|n| own_nullifier(&der, n))
            .collect();
        let operator = self.address().to_string() == state.deployment.operator_address;
        let mut found = 0;
        for ev in &state.events[self.file.scanned_events..] {
            match ev {
                Event::Mint(m) => {
                    let env = m.envelope()?;
                    if keys::address_for(&der.viewing, env.d).is_some_and(|a| a.pk_d == env.pk_d) {
                        let n = OwnedNote {
                            v: m.value,
                            d: env.d,
                            r_seed: env.r_seed,
                            is_mint: true,
                            h_body_create: Fr::from(0u64),
                            j: 0,
                            pos: m.pos,
                            source_txid: m.txid,
                            spent: false,
                            locked_by: None,
                            lock_anchor: None,
                        };
                        found += self.record(&der, &mut nfs, n) as usize;
                    }
                }
                Event::Transfer(t) => {
                    let env = t.envelope()?;
                    let h_body = env.h_body();
                    for j in 0..N_OUT {
                        let leaf = note::leaf(&h_body, j as u8, &env.pk_eph[j], &env.ct[j]);
                        if state.tree.leaf(t.positions[j]) != Some(leaf) {
                            return Err(Error::LeafMismatch(t.positions[j]));
                        }
                    }
                    for j in 0..N_OUT {
                        let Some(n) = note::decrypt_as_recipient(
                            &env.ct[j],
                            &env.pk_eph[j],
                            &der.viewing.sk_view,
                        ) else {
                            continue;
                        };
                        // Output 0 of a transfer carrying a payout is the peg-out
                        // burn, but only in the operator's hands.
                        let burned = operator && j == 0 && env.payout.is_some();
                        let n = OwnedNote {
                            v: n.v,
                            d: n.d,
                            r_seed: n.r_seed,
                            is_mint: false,
                            h_body_create: h_body,
                            j: j as u8,
                            pos: t.positions[j],
                            source_txid: t.txid,
                            spent: burned,
                            locked_by: None,
                            lock_anchor: None,
                        };
                        found += self.record(&der, &mut nfs, n) as usize;
                    }
                    // Sender-side recovery, only for transfers that spend a note of ours.
                    if !env.nf.iter().any(|nf| nfs.contains(nf)) {
                        continue;
                    }
                    if let Some(records) = note::decrypt_recovery(
                        &env.ct_out,
                        &env.recovery_binding(),
                        &der.viewing.vk_out,
                    ) {
                        for (j, (pk_d, sk_eph)) in records.iter().take(N_OUT).enumerate() {
                            if let Some(n) =
                                note::decrypt_as_sender(&env.ct[j], &env.pk_eph[j], pk_d, sk_eph)
                            {
                                if self
                                    .file
                                    .sent
                                    .iter()
                                    .all(|s| !(s.txid == t.txid && s.j == j as u8))
                                {
                                    let to = Address {
                                        d: n.d,
                                        pk_d: *pk_d,
                                    }
                                    .to_string();
                                    self.file.sent.push(SentRecord {
                                        txid: t.txid,
                                        v: n.v,
                                        to,
                                        j: j as u8,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        self.file.scanned_events = state.events.len();
        self.file.scanned_txid = state.events.last().map(event_txid);
        // Spent status from the nullifier set; a lock whose anchor window has
        // passed without the nullifier appearing can never be replayed.
        for n in &mut self.file.notes {
            if state.nullifiers.contains(&own_nullifier(&der, n)) {
                n.spent = true;
                n.locked_by = None;
                n.lock_anchor = None;
            } else if n
                .lock_anchor
                .is_some_and(|a| state.replayed_height > a.saturating_add(WINDOW_W))
            {
                n.locked_by = None;
                n.lock_anchor = None;
            }
        }
        self.save()?;
        Ok(found)
    }

    /// Adds a scanned note unless it is empty or already recorded.
    fn record(&mut self, der: &SpendingKeys, nfs: &mut HashSet<Fr>, n: OwnedNote) -> bool {
        if n.v == 0
            || self
                .file
                .notes
                .iter()
                .any(|o| o.source_txid == n.source_txid && o.j == n.j)
        {
            return false;
        }
        nfs.insert(own_nullifier(der, &n));
        self.file.notes.push(n);
        true
    }

    /// Releases notes locked by a carrier that will never be replayed. Refuses
    /// while the carrier is still known to the chain unless forced.
    pub fn unlock(
        &mut self,
        client: &mut impl ChainSource,
        txid: &Txid,
        force: bool,
    ) -> Result<usize, Error> {
        if !force {
            match client.transaction(txid) {
                Ok(_) => return Err(Error::CarrierPresent(*txid)),
                Err(chain::Error::Rpc { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut n = 0;
        for note in self
            .file
            .notes
            .iter_mut()
            .filter(|n| n.locked_by == Some(*txid))
        {
            note.locked_by = None;
            note.lock_anchor = None;
            n += 1;
        }
        self.save()?;
        Ok(n)
    }

    pub fn funding_utxos(&self, client: &mut impl ChainSource) -> Result<Vec<Utxo>, Error> {
        let mut u = client.listunspent(&self.funding_key()?.script_pubkey())?;
        u.sort_by_key(|u| Reverse(u.value));
        Ok(u)
    }

    /// Peg-in: pay `amount` to the vault and publish a plaintext mint note
    /// to our own address in the same carrier. Returns (txid, envelope
    /// bytes, vsize, fee sat).
    pub fn mint(
        &mut self,
        client: &mut impl ChainSource,
        dep: &Deployment,
        amount: u64,
    ) -> Result<(Txid, usize, usize, u64), Error> {
        let addr = self.address();
        let r_seed = Fr::rand(&mut rand::thread_rng());
        let env = Envelope::Mint(MintEnvelope {
            d: addr.d,
            pk_d: addr.pk_d,
            r_seed,
        });
        let payload = env.to_bytes();
        let utxos = self.funding_utxos(client)?;
        let (tx, fee) = self.funding_key()?.build_carrier(
            &utxos,
            &payload,
            vec![TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: dep.vault_script_pubkey.clone(),
            }],
            dep.fee_rate_sat_vb,
        )?;
        let vsize = tx.vsize();
        let txid = client.broadcast(&tx)?;
        Ok((txid, payload.len(), vsize, fee))
    }

    /// Section 13.1: selects inputs under the anchor R[H + 1 - K_WALLET],
    /// builds the outputs and ct_out, binds the body and proves. Touches no
    /// wallet state and no network.
    pub fn build_transfer(
        &self,
        state: &State,
        params: &Params,
        to: &Address,
        amount: u64,
        payout: Option<Payout>,
    ) -> Result<BuiltTransfer, Error> {
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }
        let der = self.keys.derive();
        let h_anchor = (state.replayed_height + 1).saturating_sub(K_WALLET);
        let r_anchor = *state.roots.get(&h_anchor).ok_or(Error::NoRoot(h_anchor))?;
        let len = *state
            .leaf_counts
            .get(&h_anchor)
            .ok_or(Error::NoRoot(h_anchor))?;
        let anchored = state.tree.prefix(len);
        if anchored.root() != r_anchor {
            return Err(Error::AnchorMismatch(h_anchor));
        }
        // Input selection: up to two unspent, unlocked notes under the anchor.
        let mut candidates: Vec<usize> = (0..self.file.notes.len())
            .filter(|&i| {
                let n = &self.file.notes[i];
                !n.spent && n.locked_by.is_none() && n.pos < len
            })
            .collect();
        candidates.sort_by(|a, b| self.file.notes[*b].v.cmp(&self.file.notes[*a].v));
        let mut chosen = Vec::new();
        let mut total = 0u64;
        for i in candidates {
            chosen.push(i);
            total = total
                .checked_add(self.file.notes[i].v)
                .ok_or(Error::Overflow)?;
            if total >= amount || chosen.len() == N_IN {
                break;
            }
        }
        if total < amount {
            return Err(Error::InsufficientBalance {
                available: total,
                needed: amount,
            });
        }
        let mut rng = rand::thread_rng();
        let own = self.address();
        let mut inputs: Vec<InputWitness> = Vec::with_capacity(N_IN);
        for &i in &chosen {
            let n = &self.file.notes[i];
            let path = anchored.path(n.pos).ok_or(Error::NotInTree(n.pos))?;
            let inp = input_witness(n, path);
            // Paper C.4: the local record must still describe the accepted leaf.
            if !circuit::input_leaf(&der.sk_spend, &inp)
                .is_some_and(|leaf| state.tree.leaf(n.pos) == Some(leaf))
            {
                return Err(Error::StaleNote(n.pos));
            }
            inputs.push(inp);
        }
        while inputs.len() < N_IN {
            // Dummy input: zero value, fresh randomness, no membership check.
            inputs.push(InputWitness {
                enabled: false,
                is_mint: false,
                v: 0,
                d: own.d,
                r_seed: Fr::rand(&mut rng),
                h_body_create: Fr::from(0u64),
                j: 0,
                path: MerklePath {
                    pos: 0,
                    siblings: vec![Fr::from(0u64); TREE_DEPTH],
                },
            });
        }
        let outputs = [
            OutputWitness {
                v: amount,
                d: to.d,
                r_seed: Fr::rand(&mut rng),
                pk_d: to.pk_d,
            },
            OutputWitness {
                v: total - amount,
                d: own.d,
                r_seed: Fr::rand(&mut rng),
                pk_d: own.pk_d,
            },
        ];

        let mut w = TransferWitness {
            sk_spend: der.sk_spend,
            h_body: Fr::from(0u64),
            inputs: inputs.clone().try_into().map_err(|_| Error::Arity)?,
            outputs: outputs.clone(),
        };
        let st = circuit::evaluate(&w);
        if st.nf[0] == st.nf[1] {
            return Err(Error::DuplicateNullifier);
        }
        if st.nf.iter().any(|nf| state.nullifiers.contains(nf)) {
            return Err(Error::NullifierReplayed);
        }
        let records: [(crate::EdwardsAffine, Fs); N_OUT] =
            std::array::from_fn(|j| (outputs[j].pk_d, note::sk_eph(&outputs[j].r_seed)));
        let mut envelope = TransferEnvelope {
            h_anchor,
            nf: st.nf,
            pk_eph: st.pk_eph,
            ct: st.ct,
            ct_out: vec![],
            payout,
            proof: vec![],
        };
        envelope.ct_out =
            note::encrypt_recovery(&records, &envelope.recovery_binding(), &der.viewing.vk_out);
        if envelope.ct_out.len() != CT_OUT_LEN {
            return Err(Error::CtOutLength);
        }
        w.h_body = envelope.h_body();
        let public = PublicInputs {
            r_anchor,
            digest: envelope.statement_digest(),
        };
        let t = Instant::now();
        envelope.proof = params.prove(&public, &w)?;
        let prove_s = t.elapsed().as_secs_f64();
        if !params.verify(&public, &envelope.proof) {
            return Err(Error::OwnProofInvalid);
        }
        Ok(BuiltTransfer {
            envelope,
            inputs: chosen,
            prove_s,
        })
    }

    /// Builds, proves and publishes a transfer of `amount` to `to`, with an
    /// optional peg-out request, then locks its inputs. Returns (txid, the
    /// built transfer, vsize, fee sat).
    pub fn send(
        &mut self,
        client: &mut impl ChainSource,
        state: &State,
        params: &Params,
        to: &Address,
        amount: u64,
        payout: Option<Payout>,
    ) -> Result<(Txid, BuiltTransfer, usize, u64), Error> {
        let built = self.build_transfer(state, params, to, amount, payout)?;
        let payload = built.envelope.to_bytes();
        let utxos = self.funding_utxos(client)?;
        let (tx, fee) = self.funding_key()?.build_carrier(
            &utxos,
            &payload,
            vec![],
            state.deployment.fee_rate_sat_vb,
        )?;
        let vsize = tx.vsize();
        let txid = client.broadcast(&tx)?;
        for &i in &built.inputs {
            self.file.notes[i].locked_by = Some(txid);
            self.file.notes[i].lock_anchor = Some(built.envelope.h_anchor);
        }
        self.save()?;
        Ok((txid, built, vsize, fee))
    }

    /// Operator only: pay every accepted peg-out request addressed to us
    /// that has not been paid yet, or with `only` exactly that request. On
    /// bitcoin `only` is required. The fee comes out of the request. Returns
    /// (request txid, sat paid, fee sat, payout txid) per payout made.
    pub fn process_payouts(
        &mut self,
        client: &mut impl ChainSource,
        state: &State,
        only: Option<Txid>,
    ) -> Result<Vec<(Txid, u64, u64, Txid)>, Error> {
        if only.is_none() && state.deployment.network == Network::Bitcoin {
            return Err(Error::PayoutsUnsupervised);
        }
        let vk: ViewingKeys = self.keys.viewing();
        let vault_spk = self.vault_key()?.script_pubkey();
        // Payout carriers spend the vault and publish nf[0] in their OP_RETURN,
        // so the chain itself says what was already paid. Mempool entries only
        // count when this wallet broadcast them.
        let mut on_chain: HashSet<Vec<u8>> = HashSet::new();
        let mut fetched: HashMap<Txid, Transaction> = HashMap::new();
        let history = client.history(&vault_spk)?;
        let mut fetch = |id: &Txid| -> Result<Transaction, Error> {
            if let Some(tx) = fetched.get(id) {
                return Ok(tx.clone());
            }
            let tx = client.transaction(id)?;
            fetched.insert(*id, tx.clone());
            Ok(tx)
        };
        for (txid, height) in history {
            if height <= 0 && !self.file.payout_txids.contains(&txid) {
                continue;
            }
            let tx = fetch(&txid)?;
            if let Ok(Some(p)) = op_return_payload(&tx) {
                if spends_vault(&tx, &vault_spk, &mut fetch)? {
                    on_chain.insert(p);
                }
            }
        }
        let mut done = Vec::new();
        let mut seen = false;
        for ev in &state.events {
            let Event::Transfer(t) = ev else { continue };
            if only.is_some_and(|o| o != t.txid) {
                continue;
            }
            let env = t.envelope()?;
            let Some(p) = &env.payout else { continue };
            seen = true;
            let nf = keys::fr_to_bytes(&env.nf[0]);
            let key = hex::encode(nf);
            if self.file.paid_payouts.contains(&key)
                || self.file.paid_payouts.contains(&t.txid.to_string())
                || self.file.failed_payouts.contains_key(&key)
            {
                continue;
            }
            // Convention: the burned value is output 0, sent to the operator.
            let Some(n) = note::decrypt_as_recipient(&env.ct[0], &env.pk_eph[0], &vk.sk_view)
            else {
                continue;
            };
            if on_chain.contains(&nf[..]) {
                self.file.paid_payouts.push(key);
                self.save()?;
                continue;
            }
            // Chain trouble leaves the request pending; only the request itself
            // can be refused.
            let (tx, fee) = match validate_payout(p, n.v, state.deployment.network)
                .and_then(|_| self.build_payout(client, p, &nf, state.deployment.fee_rate_sat_vb))
            {
                Ok(built) => built,
                Err(Error::Chain(err)) => {
                    log::warn!("payout in {} deferred: {err}", t.txid);
                    continue;
                }
                Err(err) => {
                    self.fail_payout(&t.txid, key, err)?;
                    continue;
                }
            };
            // Intent and txid on disk before the network sees the transaction.
            // A broadcast error is ambiguous (the server may have relayed it),
            // so both stay; the next run's history check tells.
            let paid = tx.compute_txid();
            self.file.paid_payouts.push(key);
            self.file.payout_txids.push(paid);
            self.save()?;
            match client.broadcast(&tx) {
                Ok(_) => done.push((t.txid, tx.output[0].value.to_sat(), fee, paid)),
                Err(err) => log::warn!(
                    "payout in {} broadcast as {paid} returned an error, kept as paid: {err}",
                    t.txid
                ),
            }
        }
        if let Some(o) = only.filter(|_| !seen) {
            return Err(Error::NoSuchRequest(o));
        }
        Ok(done)
    }

    fn build_payout(
        &self,
        client: &mut impl ChainSource,
        p: &Payout,
        nf: &[u8],
        fee_rate_sat_vb: u64,
    ) -> Result<(Transaction, u64), Error> {
        let vault = self.vault_key()?;
        let mut utxos = client.listunspent(&vault.script_pubkey())?;
        utxos.sort_by_key(|u| Reverse(u.value));
        let out = |v: u64| {
            vec![TxOut {
                value: Amount::from_sat(v),
                script_pubkey: ScriptBuf::from_bytes(p.script_pubkey.clone()),
            }]
        };
        let fee = vault
            .build_carrier(&utxos, nf, out(p.amount), fee_rate_sat_vb)?
            .0
            .vsize() as u64
            * fee_rate_sat_vb;
        if p.amount < fee + 546 {
            return Err(Error::PayoutBelowFee {
                amount: p.amount,
                fee,
            });
        }
        Ok(vault.build_carrier(&utxos, nf, out(p.amount - fee), fee_rate_sat_vb)?)
    }

    fn fail_payout(&mut self, txid: &Txid, key: String, err: Error) -> Result<(), Error> {
        log::warn!("payout in {txid} not paid: {err}");
        self.file.failed_payouts.insert(key, err.to_string());
        self.save()
    }
}

/// A peg-out request must not exceed the burn, must clear dust, and must
/// pay a standard single-key or script-hash output.
pub fn validate_payout(p: &Payout, burned: u64, network: Network) -> Result<(), Error> {
    if p.amount > burned {
        return Err(Error::PayoutExceedsBurn {
            amount: p.amount,
            burned,
        });
    }
    if p.amount < 546 {
        return Err(Error::PayoutBelowDust(p.amount));
    }
    let s = bitcoin::Script::from_bytes(&p.script_pubkey);
    if !(s.is_p2wpkh() || s.is_p2tr() || s.is_p2sh() || s.is_p2pkh()) {
        return Err(Error::NonStandardPayout);
    }
    bitcoin::Address::from_script(s, network)?;

    Ok(())
}

/// Whether `tx` spends an output paying `vault`; `prev` fetches the
/// transaction an input references.
pub fn spends_vault(
    tx: &Transaction,
    vault: &ScriptBuf,
    prev: &mut impl FnMut(&Txid) -> Result<Transaction, Error>,
) -> Result<bool, Error> {
    if tx.is_coinbase() {
        return Ok(false);
    }
    for i in &tx.input {
        let p = prev(&i.previous_output.txid)?;
        if p.output
            .get(i.previous_output.vout as usize)
            .is_some_and(|o| o.script_pubkey == *vault)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn note_plaintext(n: &OwnedNote) -> NotePlaintext {
    NotePlaintext {
        v: n.v,
        d: n.d,
        r_seed: n.r_seed,
    }
}

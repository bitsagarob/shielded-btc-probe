//! Wallet: owned notes, scanning against replayed state, minting (peg-in),
//! building and publishing transfers, and the operator's peg-out handler.

use crate::{
    Fr, Fs, N_IN, N_OUT, TREE_DEPTH, WINDOW_W,
    chain::{self, Electrum, FEE_RATE_SAT_VB, FundingKey, NETWORK, Utxo, op_return_payload},
    circuit::{self, InputWitness, OutputWitness, PublicInputs, TransferWitness},
    envelope::{CT_OUT_LEN, Envelope, MintEnvelope, Payout, TransferEnvelope},
    indexer::{Event, State},
    keys::{self, Address, DIVERSIFIER_LEN, SpendingKeys, WalletKeys},
    note::{self, NotePlaintext},
    prover::{self, Params},
    tree::MerklePath,
};
use ark_ff::UniformRand;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Txid, address::FromScriptError, secp256k1};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashSet},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Instant,
};

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
    #[error("replay leaf mismatch at {0}")]
    LeafMismatch(u64),
    #[error("amount must be positive")]
    ZeroAmount,
    #[error(
        "insufficient shielded balance: {available} sat available, {needed} needed (two inputs max)"
    )]
    InsufficientBalance { available: u64, needed: u64 },
    #[error("note position {0} not in tree")]
    NotInTree(u64),
    #[error("local note {0} does not match the replayed leaf")]
    StaleNote(u64),
    #[error("no root for {0}")]
    NoRoot(u32),
    #[error("indexer state is not at its own tip")]
    StateNotAtTip,
    #[error("arity")]
    Arity,
    #[error("nullifier already in the replayed set")]
    NullifierReplayed,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletFile {
    #[serde(with = "crate::serde_hex::bytes")]
    pub seed: [u8; 32],
    #[serde(with = "crate::serde_hex::bytes")]
    pub funding_sk: [u8; 32],
    /// Operator only: the key holding the vault, separate from the fee key.
    #[serde(default, with = "crate::serde_hex::bytes")]
    pub vault_sk: [u8; 32],
    pub notes: Vec<OwnedNote>,
    pub sent: Vec<SentRecord>,
    pub scanned_events: usize,
    /// Txid of the last scanned event; a mismatch means replay history changed.
    #[serde(default)]
    pub scanned_txid: Option<Txid>,
    /// Peg-out requests paid, keyed by hex of nf[0] (older files hold carrier txids).
    pub paid_payouts: Vec<String>,
    /// Peg-out requests refused or failed, hex of nf[0] to the reason.
    #[serde(default)]
    pub failed_payouts: BTreeMap<String, String>,
}

pub struct Wallet {
    pub path: PathBuf,
    pub file: WalletFile,
    pub keys: WalletKeys,
    pub funding: FundingKey,
    vault: FundingKey,
}

fn random_key() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
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

impl Wallet {
    pub fn create(path: &Path) -> Result<Self, Error> {
        if path.exists() {
            return Err(Error::Exists(path.to_path_buf()));
        }
        let file = WalletFile {
            seed: random_key(),
            funding_sk: random_key(),
            vault_sk: random_key(),
            notes: vec![],
            sent: vec![],
            scanned_events: 0,
            scanned_txid: None,
            paid_payouts: vec![],
            failed_payouts: BTreeMap::new(),
        };
        let w = Self::from_file(path.to_path_buf(), file)?;
        w.save()?;
        Ok(w)
    }

    pub fn open(path: &Path) -> Result<Self, Error> {
        let file = std::fs::File::open(path).map_err(|source| Error::Open {
            path: path.to_path_buf(),
            source,
        })?;
        let mut file: WalletFile = serde_json::from_reader(file)?;
        let fill = file.vault_sk == [0u8; 32];
        if fill {
            file.vault_sk = random_key();
        }
        let w = Self::from_file(path.to_path_buf(), file)?;
        if fill {
            w.save()?;
        }
        Ok(w)
    }

    fn from_file(path: PathBuf, file: WalletFile) -> Result<Self, Error> {
        let funding = FundingKey::from_bytes(&file.funding_sk).map_err(Error::FundingKey)?;
        let vault = FundingKey::from_bytes(&file.vault_sk).map_err(Error::VaultKey)?;
        Ok(Self {
            path,
            keys: WalletKeys::from_seed(file.seed),
            funding,
            vault,
            file,
        })
    }

    pub fn save(&self) -> Result<(), Error> {
        let tmp = self.path.with_extension("json.tmp");
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        serde_json::to_writer_pretty(&f, &self.file)?;
        f.sync_all()?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }

    pub fn address(&self) -> Address {
        self.keys.address(0)
    }

    pub fn vault(&self) -> FundingKey {
        self.vault.clone()
    }

    pub fn balance(&self) -> u64 {
        self.file
            .notes
            .iter()
            .filter(|n| !n.spent && n.locked_by.is_none())
            .map(|n| n.v)
            .sum()
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
        let mut found = 0;
        for ev in &state.events[self.file.scanned_events..] {
            match ev {
                Event::Mint(m) => {
                    let env = m.envelope();
                    if keys::address_for(&der, env.d).is_some_and(|a| a.pk_d == env.pk_d) {
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
                    let env = t.envelope();
                    let h_body = env.h_body();
                    for j in 0..N_OUT {
                        let leaf = note::leaf(&h_body, j as u8, &env.pk_eph[j], &env.ct[j]);
                        if state.tree.leaf(t.positions[j]) != Some(leaf) {
                            return Err(Error::LeafMismatch(t.positions[j]));
                        }
                    }
                    for j in 0..N_OUT {
                        let Some(n) =
                            note::decrypt_as_recipient(&env.ct[j], &env.pk_eph[j], &der.sk_view)
                        else {
                            continue;
                        };
                        // Output 0 of a transfer carrying a payout is the peg-out burn.
                        let burned = j == 0 && env.payout.is_some();
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
                    if let Some(records) =
                        note::decrypt_recovery(&env.ct_out, &env.recovery_binding(), &der.vk_out)
                    {
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
                .is_some_and(|a| state.replayed_height > a + WINDOW_W)
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

    /// Releases notes locked by a carrier that will never be replayed.
    pub fn unlock(&mut self, txid: &Txid) -> Result<usize, Error> {
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

    pub fn funding_utxos(&self, client: &mut Electrum) -> Result<Vec<Utxo>, Error> {
        let mut u = client.listunspent(&self.funding.script_pubkey())?;
        u.sort_by_key(|u| Reverse(u.value));
        Ok(u)
    }

    /// Peg-in: pay `amount` to the vault and publish a plaintext mint note
    /// to our own address in the same carrier.
    pub fn mint(
        &mut self,
        client: &mut Electrum,
        vault_spk: &ScriptBuf,
        amount: u64,
    ) -> Result<(Txid, usize, usize), Error> {
        let addr = self.address();
        let r_seed = Fr::rand(&mut rand::thread_rng());
        let env = Envelope::Mint(MintEnvelope {
            d: addr.d,
            pk_d: addr.pk_d,
            r_seed,
        });
        let payload = env.to_bytes();
        let utxos = self.funding_utxos(client)?;
        let tx = self.funding.build_carrier(
            &utxos,
            &payload,
            vec![TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: vault_spk.clone(),
            }],
        )?;
        let vsize = tx.vsize();
        let txid = client.broadcast(&tx)?;
        Ok((txid, payload.len(), vsize))
    }

    /// Builds, proves and publishes a transfer of `amount` to `to`, with an
    /// optional peg-out request. Returns (txid, envelope bytes, vsize, prove seconds).
    pub fn send(
        &mut self,
        client: &mut Electrum,
        state: &State,
        params: &Params,
        to: &Address,
        amount: u64,
        payout: Option<Payout>,
    ) -> Result<(Txid, usize, usize, f64), Error> {
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }
        let der = self.keys.derive();
        // Input selection: up to two unspent, unlocked notes.
        let mut candidates: Vec<usize> = (0..self.file.notes.len())
            .filter(|&i| !self.file.notes[i].spent && self.file.notes[i].locked_by.is_none())
            .collect();
        candidates.sort_by(|a, b| self.file.notes[*b].v.cmp(&self.file.notes[*a].v));
        let mut chosen = Vec::new();
        let mut total = 0u64;
        for i in candidates {
            chosen.push(i);
            total += self.file.notes[i].v;
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
        let mut inputs: Vec<InputWitness> = Vec::with_capacity(N_IN);
        for &i in &chosen {
            let n = &self.file.notes[i];
            let path = state.tree.path(n.pos).ok_or(Error::NotInTree(n.pos))?;
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
                d: self.address().d,
                r_seed: Fr::rand(&mut rng),
                h_body_create: Fr::from(0u64),
                j: 0,
                path: MerklePath {
                    pos: 0,
                    siblings: vec![Fr::from(0u64); TREE_DEPTH],
                },
            });
        }
        let change_addr = self.address();
        let outputs = [
            OutputWitness {
                v: amount,
                d: to.d,
                r_seed: Fr::rand(&mut rng),
                pk_d: to.pk_d,
            },
            OutputWitness {
                v: total - amount,
                d: change_addr.d,
                r_seed: Fr::rand(&mut rng),
                pk_d: change_addr.pk_d,
            },
        ];
        let h_anchor = state.replayed_height;
        let r_anchor = *state.roots.get(&h_anchor).ok_or(Error::NoRoot(h_anchor))?;
        if r_anchor != state.tree.root() {
            return Err(Error::StateNotAtTip);
        }

        let mut w = TransferWitness {
            sk_spend: der.sk_spend,
            h_body: Fr::from(0u64),
            inputs: inputs.clone().try_into().map_err(|_| Error::Arity)?,
            outputs: outputs.clone(),
        };
        for nf in circuit::evaluate(&w).nf {
            if state.nullifiers.contains(&nf) {
                return Err(Error::NullifierReplayed);
            }
        }
        let st = circuit::evaluate(&w);
        let records: [(crate::EdwardsAffine, Fs); N_OUT] =
            std::array::from_fn(|j| (outputs[j].pk_d, note::sk_eph(&outputs[j].r_seed)));
        let mut env = TransferEnvelope {
            h_anchor,
            nf: st.nf,
            pk_eph: st.pk_eph,
            ct: st.ct,
            ct_out: vec![],
            payout,
            proof: vec![],
        };
        env.ct_out = note::encrypt_recovery(&records, &env.recovery_binding(), &der.vk_out);
        if env.ct_out.len() != CT_OUT_LEN {
            return Err(Error::CtOutLength);
        }
        w.h_body = env.h_body();
        let public = PublicInputs {
            r_anchor,
            digest: env.statement_digest(),
        };
        let t = Instant::now();
        env.proof = params.prove(&public, &w)?;
        let prove_s = t.elapsed().as_secs_f64();
        if !params.verify(&public, &env.proof) {
            return Err(Error::OwnProofInvalid);
        }

        let payload = env.to_bytes();
        let utxos = self.funding_utxos(client)?;
        let tx = self.funding.build_carrier(&utxos, &payload, vec![])?;
        let vsize = tx.vsize();
        let txid = client.broadcast(&tx)?;
        for &i in &chosen {
            self.file.notes[i].locked_by = Some(txid);
            self.file.notes[i].lock_anchor = Some(h_anchor);
        }
        self.save()?;
        Ok((txid, payload.len(), vsize, prove_s))
    }

    /// Operator only: pay every accepted peg-out request addressed to us
    /// that has not been paid yet. The fee comes out of the request. Returns
    /// (request txid, sat paid, payout txid) per payout made.
    pub fn process_payouts(
        &mut self,
        client: &mut Electrum,
        state: &State,
    ) -> Result<Vec<(Txid, u64, Txid)>, Error> {
        let der = self.keys.derive();
        // Payout carriers publish nf[0] in their OP_RETURN, so the chain itself
        // says what was already paid.
        let mut on_chain: HashSet<Vec<u8>> = HashSet::new();
        for txid in client.history(&self.vault.script_pubkey())? {
            if let Ok(Some(p)) = op_return_payload(&client.transaction(&txid)?) {
                on_chain.insert(p);
            }
        }
        let mut done = Vec::new();
        for ev in &state.events {
            let Event::Transfer(t) = ev else { continue };
            let env = t.envelope();
            let Some(p) = &env.payout else { continue };
            let nf = keys::fr_to_bytes(&env.nf[0]);
            let key = hex::encode(nf);
            if self.file.paid_payouts.contains(&key)
                || self.file.paid_payouts.contains(&t.txid.to_string())
                || self.file.failed_payouts.contains_key(&key)
            {
                continue;
            }
            // Convention: the burned value is output 0, sent to the operator.
            let Some(n) = note::decrypt_as_recipient(&env.ct[0], &env.pk_eph[0], &der.sk_view)
            else {
                continue;
            };
            if on_chain.contains(&nf[..]) {
                self.file.paid_payouts.push(key);
                self.save()?;
                continue;
            }
            let tx = match validate_payout(p, n.v).and_then(|_| self.build_payout(client, p, &nf)) {
                Ok(tx) => tx,
                Err(err) => {
                    self.fail_payout(&t.txid, key, err)?;
                    continue;
                }
            };
            // Intent on disk before the network sees the transaction.
            self.file.paid_payouts.push(key.clone());
            self.save()?;
            match client.broadcast(&tx) {
                Ok(paid) => done.push((t.txid, tx.output[0].value.to_sat(), paid)),
                Err(err) => {
                    self.file.paid_payouts.retain(|k| k != &key);
                    self.fail_payout(&t.txid, key, err.into())?;
                }
            }
        }
        Ok(done)
    }

    fn build_payout(
        &self,
        client: &mut Electrum,
        p: &Payout,
        nf: &[u8],
    ) -> Result<Transaction, Error> {
        let mut utxos = client.listunspent(&self.vault.script_pubkey())?;
        utxos.sort_by_key(|u| Reverse(u.value));
        let out = |v: u64| {
            vec![TxOut {
                value: Amount::from_sat(v),
                script_pubkey: ScriptBuf::from_bytes(p.script_pubkey.clone()),
            }]
        };
        let fee =
            self.vault.build_carrier(&utxos, nf, out(p.amount))?.vsize() as u64 * FEE_RATE_SAT_VB;
        if p.amount < fee + 546 {
            return Err(Error::PayoutBelowFee {
                amount: p.amount,
                fee,
            });
        }
        Ok(self.vault.build_carrier(&utxos, nf, out(p.amount - fee))?)
    }

    fn fail_payout(&mut self, txid: &Txid, key: String, err: Error) -> Result<(), Error> {
        log::warn!("payout in {txid} not paid: {err}");
        self.file.failed_payouts.insert(key, err.to_string());
        self.save()
    }
}

/// A peg-out request must not exceed the burn, must clear dust, and must
/// pay a standard single-key or script-hash output.
pub fn validate_payout(p: &Payout, burned: u64) -> Result<(), Error> {
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
    bitcoin::Address::from_script(s, NETWORK)?;
    Ok(())
}

pub fn note_plaintext(n: &OwnedNote) -> NotePlaintext {
    NotePlaintext {
        v: n.v,
        d: n.d,
        r_seed: n.r_seed,
    }
}

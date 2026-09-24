//! Wallet: owned notes, scanning against replayed state, minting (peg-in),
//! building and publishing transfers, and the operator's peg-out handler.

use crate::chain::{op_return_payload, Electrum, FundingKey, Utxo, FEE_RATE_SAT_VB, NETWORK};
use crate::circuit::{self, InputWitness, OutputWitness, PublicInputs, TransferWitness};
use crate::envelope::{Envelope, MintEnvelope, Payout, TransferEnvelope, CT_OUT_LEN};
use crate::indexer::{Event, State};
use crate::keys::{self, Address, Derived, WalletKeys, DIVERSIFIER_LEN};
use crate::note::{self, NotePlaintext};
use crate::prover::Params;
use crate::tree::MerklePath;
use crate::{Fr, Fs, N_IN, N_OUT, TREE_DEPTH, WINDOW_W};
use anyhow::{anyhow, ensure, Context, Result};
use ark_ff::UniformRand;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Txid};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedNote {
    pub v: u64,
    pub d: String,
    pub r_seed: String,
    pub is_mint: bool,
    pub h_body_create: String,
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
    pub seed: String,
    pub funding_sk: String,
    /// Operator only: the key holding the vault, separate from the fee key.
    #[serde(default)]
    pub vault_sk: String,
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
    pub path: std::path::PathBuf,
    pub file: WalletFile,
    pub keys: WalletKeys,
    pub funding: FundingKey,
    vault: FundingKey,
}

fn fr_hex(x: &Fr) -> String {
    hex::encode(keys::fr_to_bytes(x))
}
fn fr_from_hex(s: &str) -> Result<Fr> {
    keys::fr_from_bytes(&hex::decode(s)?).ok_or_else(|| anyhow!("bad field element"))
}
fn d_from_hex(s: &str) -> Result<[u8; DIVERSIFIER_LEN]> {
    let v = hex::decode(s)?;
    v.as_slice().try_into().map_err(|_| anyhow!("bad diversifier"))
}
fn key_from_hex(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)?.as_slice().try_into().map_err(|_| anyhow!("bad key"))
}
fn random_hex() -> String {
    let mut b = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    hex::encode(b)
}
fn event_txid(ev: &Event) -> Txid {
    match ev {
        Event::Mint(m) => m.txid,
        Event::Transfer(t) => t.txid,
    }
}
fn input_witness(n: &OwnedNote, path: MerklePath) -> Result<InputWitness> {
    Ok(InputWitness {
        enabled: true,
        is_mint: n.is_mint,
        v: n.v,
        d: d_from_hex(&n.d)?,
        r_seed: fr_from_hex(&n.r_seed)?,
        h_body_create: fr_from_hex(&n.h_body_create)?,
        j: n.j,
        path,
    })
}
fn own_nullifier(der: &Derived, n: &OwnedNote) -> Result<Fr> {
    Ok(note::nullifier(&der.sk_nf, &note::rho(&fr_from_hex(&n.r_seed)?), n.pos))
}

impl Wallet {
    pub fn create(path: &Path) -> Result<Self> {
        ensure!(!path.exists(), "{} already exists", path.display());
        let file = WalletFile {
            seed: random_hex(),
            funding_sk: random_hex(),
            vault_sk: random_hex(),
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

    pub fn open(path: &Path) -> Result<Self> {
        let mut file: WalletFile = serde_json::from_reader(std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?)?;
        let fill = file.vault_sk.is_empty();
        if fill {
            file.vault_sk = random_hex();
        }
        let w = Self::from_file(path.to_path_buf(), file)?;
        if fill {
            w.save()?;
        }
        Ok(w)
    }

    fn from_file(path: std::path::PathBuf, file: WalletFile) -> Result<Self> {
        let seed: [u8; 32] = hex::decode(&file.seed)?.as_slice().try_into().map_err(|_| anyhow!("bad seed"))?;
        let funding = FundingKey::from_bytes(&key_from_hex(&file.funding_sk).context("funding key")?)?;
        let vault = FundingKey::from_bytes(&key_from_hex(&file.vault_sk).context("vault key")?)?;
        Ok(Self { path, keys: WalletKeys::from_seed(seed), funding, vault, file })
    }

    pub fn save(&self) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = self.path.with_extension("json.tmp");
        let f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
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
        self.file.notes.iter().filter(|n| !n.spent && n.locked_by.is_none()).map(|n| n.v).sum()
    }

    /// Paper 16.1 and 16.2 against the indexer's accepted history.
    pub fn scan(&mut self, state: &State) -> Result<usize> {
        let der = self.keys.derive();
        let cursor = self.file.scanned_events;
        if cursor > 0 && state.events.get(cursor - 1).map(event_txid) != self.file.scanned_txid {
            eprintln!("replayed history changed under the wallet, rescanning from activation");
            self.file.notes.clear();
            self.file.sent.clear();
            self.file.scanned_events = 0;
        }
        // Paper C.4: every local record must still describe the accepted leaf.
        let mut kept = Vec::with_capacity(self.file.notes.len());
        for n in self.file.notes.drain(..) {
            let leaf = circuit::input_leaf(&der.sk_spend, &input_witness(&n, MerklePath { pos: n.pos, siblings: vec![] })?);
            if state.tree.leaf(n.pos) == Some(leaf) {
                kept.push(n);
            } else {
                eprintln!("dropping note at position {}: no longer matches the replayed leaf", n.pos);
            }
        }
        self.file.notes = kept;
        let mut nfs: HashSet<Fr> = self.file.notes.iter().map(|n| own_nullifier(&der, n)).collect::<Result<_>>()?;
        let mut found = 0;
        for ev in &state.events[self.file.scanned_events..] {
            match ev {
                Event::Mint(m) => {
                    let env = m.envelope();
                    if keys::address_for(&der, env.d).pk_d == env.pk_d {
                        let n = OwnedNote {
                            v: m.value,
                            d: hex::encode(env.d),
                            r_seed: fr_hex(&env.r_seed),
                            is_mint: true,
                            h_body_create: fr_hex(&Fr::from(0u64)),
                            j: 0,
                            pos: m.pos,
                            source_txid: m.txid,
                            spent: false,
                            locked_by: None,
                            lock_anchor: None,
                        };
                        found += self.record(&der, &mut nfs, n)? as usize;
                    }
                }
                Event::Transfer(t) => {
                    let env = t.envelope();
                    let h_body = env.h_body();
                    for j in 0..N_OUT {
                        let leaf = note::leaf(&h_body, j as u8, &env.pk_eph[j], &env.ct[j]);
                        ensure!(state.tree.leaf(t.positions[j]) == Some(leaf), "replay leaf mismatch at {}", t.positions[j]);
                    }
                    for j in 0..N_OUT {
                        let Some(n) = note::decrypt_as_recipient(&env.ct[j], &env.pk_eph[j], &der.sk_view) else { continue };
                        // Output 0 of a transfer carrying a payout is the peg-out burn.
                        let burned = j == 0 && env.payout.is_some();
                        let n = OwnedNote {
                            v: n.v,
                            d: hex::encode(n.d),
                            r_seed: fr_hex(&n.r_seed),
                            is_mint: false,
                            h_body_create: fr_hex(&h_body),
                            j: j as u8,
                            pos: t.positions[j],
                            source_txid: t.txid,
                            spent: burned,
                            locked_by: None,
                            lock_anchor: None,
                        };
                        found += self.record(&der, &mut nfs, n)? as usize;
                    }
                    // Sender-side recovery, only for transfers that spend a note of ours.
                    if !env.nf.iter().any(|nf| nfs.contains(nf)) {
                        continue;
                    }
                    if let Some(records) = note::decrypt_recovery(&env.ct_out, &env.recovery_binding(), &der.vk_out) {
                        for (j, (pk_d, sk_eph)) in records.iter().take(N_OUT).enumerate() {
                            if let Some(n) = note::decrypt_as_sender(&env.ct[j], &env.pk_eph[j], pk_d, sk_eph) {
                                if self.file.sent.iter().all(|s| !(s.txid == t.txid && s.j == j as u8)) {
                                    let to = Address { d: n.d, pk_d: *pk_d }.encode();
                                    self.file.sent.push(SentRecord { txid: t.txid, v: n.v, to, j: j as u8 });
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
            if state.nullifiers.contains(&own_nullifier(&der, n)?) {
                n.spent = true;
                n.locked_by = None;
                n.lock_anchor = None;
            } else if n.lock_anchor.is_some_and(|a| state.replayed_height > a + WINDOW_W) {
                n.locked_by = None;
                n.lock_anchor = None;
            }
        }
        self.save()?;
        Ok(found)
    }

    /// Adds a scanned note unless it is empty or already recorded.
    fn record(&mut self, der: &Derived, nfs: &mut HashSet<Fr>, n: OwnedNote) -> Result<bool> {
        if n.v == 0 || self.file.notes.iter().any(|o| o.source_txid == n.source_txid && o.j == n.j) {
            return Ok(false);
        }
        nfs.insert(own_nullifier(der, &n)?);
        self.file.notes.push(n);
        Ok(true)
    }

    /// Releases notes locked by a carrier that will never be replayed.
    pub fn unlock(&mut self, txid: &Txid) -> Result<usize> {
        let mut n = 0;
        for note in self.file.notes.iter_mut().filter(|n| n.locked_by == Some(*txid)) {
            note.locked_by = None;
            note.lock_anchor = None;
            n += 1;
        }
        self.save()?;
        Ok(n)
    }

    pub fn funding_utxos(&self, e: &mut Electrum) -> Result<Vec<Utxo>> {
        let mut u = e.listunspent(&self.funding.script_pubkey())?;
        u.sort_by(|a, b| b.value.cmp(&a.value));
        Ok(u)
    }

    /// Peg-in: pay `amount` to the vault and publish a plaintext mint note
    /// to our own address in the same carrier.
    pub fn mint(&mut self, e: &mut Electrum, vault_spk: &ScriptBuf, amount: u64) -> Result<(Txid, usize, usize)> {
        let addr = self.address();
        let r_seed = Fr::rand(&mut rand::thread_rng());
        let env = Envelope::Mint(MintEnvelope { d: addr.d, pk_d: addr.pk_d, r_seed });
        let payload = env.to_bytes();
        let utxos = self.funding_utxos(e)?;
        let tx = self.funding.build_carrier(
            &utxos,
            &payload,
            vec![TxOut { value: Amount::from_sat(amount), script_pubkey: vault_spk.clone() }],
        )?;
        let vsize = tx.vsize();
        let txid = e.broadcast(&tx)?;
        Ok((txid, payload.len(), vsize))
    }

    /// Builds, proves and publishes a transfer of `amount` to `to`, with an
    /// optional peg-out request. Returns (txid, envelope bytes, vsize, prove seconds).
    pub fn send(
        &mut self,
        e: &mut Electrum,
        state: &State,
        params: &Params,
        to: &Address,
        amount: u64,
        payout: Option<Payout>,
    ) -> Result<(Txid, usize, usize, f64)> {
        ensure!(amount > 0, "amount must be positive");
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
        ensure!(total >= amount, "insufficient shielded balance: {total} sat available, {amount} needed (two inputs max)");
        let mut rng = rand::thread_rng();
        let mut inputs: Vec<InputWitness> = Vec::with_capacity(N_IN);
        for &i in &chosen {
            let n = &self.file.notes[i];
            let path = state.tree.path(n.pos).ok_or_else(|| anyhow!("note position {} not in tree", n.pos))?;
            let inp = input_witness(n, path)?;
            // Paper C.4: the local record must still describe the accepted leaf.
            ensure!(
                state.tree.leaf(n.pos) == Some(circuit::input_leaf(&der.sk_spend, &inp)),
                "local note {} does not match the replayed leaf",
                n.pos
            );
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
                path: MerklePath { pos: 0, siblings: vec![Fr::from(0u64); TREE_DEPTH] },
            });
        }
        let change_addr = self.address();
        let outputs = [
            OutputWitness { v: amount, d: to.d, r_seed: Fr::rand(&mut rng), pk_d: to.pk_d },
            OutputWitness { v: total - amount, d: change_addr.d, r_seed: Fr::rand(&mut rng), pk_d: change_addr.pk_d },
        ];
        let h_anchor = state.replayed_height;
        let r_anchor = *state.roots.get(&h_anchor).ok_or_else(|| anyhow!("no root for {h_anchor}"))?;
        ensure!(r_anchor == state.tree.root(), "indexer state is not at its own tip");

        let mut w = TransferWitness { sk_spend: der.sk_spend, h_body: Fr::from(0u64), inputs: inputs.clone().try_into().map_err(|_| anyhow!("arity"))?, outputs: outputs.clone() };
        for nf in circuit::evaluate(&w).nf {
            ensure!(!state.nullifiers.contains(&nf), "nullifier already in the replayed set");
        }
        let st = circuit::evaluate(&w);
        let records: [(crate::EdwardsAffine, Fs); N_OUT] = std::array::from_fn(|j| (outputs[j].pk_d, note::sk_eph(&outputs[j].r_seed)));
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
        ensure!(env.ct_out.len() == CT_OUT_LEN, "ct_out length");
        w.h_body = env.h_body();
        let public = PublicInputs { r_anchor, digest: env.statement_digest() };
        let t = Instant::now();
        env.proof = params.prove(&public, &w)?;
        let prove_s = t.elapsed().as_secs_f64();
        ensure!(params.verify(&public, &env.proof), "own proof failed to verify");

        let payload = env.to_bytes();
        let utxos = self.funding_utxos(e)?;
        let tx = self.funding.build_carrier(&utxos, &payload, vec![])?;
        let vsize = tx.vsize();
        let txid = e.broadcast(&tx)?;
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
    pub fn process_payouts(&mut self, e: &mut Electrum, state: &State) -> Result<Vec<(Txid, u64, Txid)>> {
        let der = self.keys.derive();
        // Payout carriers publish nf[0] in their OP_RETURN, so the chain itself
        // says what was already paid.
        let mut on_chain: HashSet<Vec<u8>> = HashSet::new();
        for txid in e.history(&self.vault.script_pubkey())? {
            if let Some(p) = op_return_payload(&e.transaction(&txid)?) {
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
            if self.file.paid_payouts.contains(&key) || self.file.paid_payouts.contains(&t.txid.to_string()) || self.file.failed_payouts.contains_key(&key) {
                continue;
            }
            // Convention: the burned value is output 0, sent to the operator.
            let Some(n) = note::decrypt_as_recipient(&env.ct[0], &env.pk_eph[0], &der.sk_view) else { continue };
            if on_chain.contains(&nf[..]) {
                self.file.paid_payouts.push(key);
                self.save()?;
                continue;
            }
            let tx = match validate_payout(p, n.v).and_then(|_| self.build_payout(e, p, &nf)) {
                Ok(tx) => tx,
                Err(err) => {
                    self.fail_payout(&t.txid, key, err)?;
                    continue;
                }
            };
            // Intent on disk before the network sees the transaction.
            self.file.paid_payouts.push(key.clone());
            self.save()?;
            match e.broadcast(&tx) {
                Ok(paid) => done.push((t.txid, tx.output[0].value.to_sat(), paid)),
                Err(err) => {
                    self.file.paid_payouts.retain(|k| k != &key);
                    self.fail_payout(&t.txid, key, err)?;
                }
            }
        }
        Ok(done)
    }

    fn build_payout(&self, e: &mut Electrum, p: &Payout, nf: &[u8]) -> Result<Transaction> {
        let mut utxos = e.listunspent(&self.vault.script_pubkey())?;
        utxos.sort_by(|a, b| b.value.cmp(&a.value));
        let out = |v: u64| vec![TxOut { value: Amount::from_sat(v), script_pubkey: ScriptBuf::from_bytes(p.script_pubkey.clone()) }];
        let fee = self.vault.build_carrier(&utxos, nf, out(p.amount))?.vsize() as u64 * FEE_RATE_SAT_VB;
        ensure!(p.amount >= fee + 546, "{} sat does not cover the {fee} sat fee plus dust", p.amount);
        self.vault.build_carrier(&utxos, nf, out(p.amount - fee))
    }

    fn fail_payout(&mut self, txid: &Txid, key: String, err: anyhow::Error) -> Result<()> {
        eprintln!("payout in {txid} not paid: {err:#}");
        self.file.failed_payouts.insert(key, format!("{err:#}"));
        self.save()
    }
}

/// A peg-out request must not exceed the burn, must clear dust, and must
/// pay a standard single-key or script-hash output.
pub fn validate_payout(p: &Payout, burned: u64) -> Result<()> {
    ensure!(p.amount <= burned, "asks {} sat but burned {burned} sat", p.amount);
    ensure!(p.amount >= 546, "{} sat is below dust", p.amount);
    let s = bitcoin::Script::from_bytes(&p.script_pubkey);
    ensure!(s.is_p2wpkh() || s.is_p2tr() || s.is_p2sh() || s.is_p2pkh(), "non-standard payout script");
    bitcoin::Address::from_script(s, NETWORK).context("payout script")?;
    Ok(())
}

pub fn parse_address(s: &str) -> Result<Address> {
    Address::decode(s).ok_or_else(|| anyhow!("not a shielded address: {s}"))
}

pub fn note_plaintext(n: &OwnedNote) -> Result<NotePlaintext> {
    Ok(NotePlaintext { v: n.v, d: d_from_hex(&n.d)?, r_seed: fr_from_hex(&n.r_seed)? })
}


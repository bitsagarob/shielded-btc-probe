//! Wallet: owned notes, scanning against replayed state, minting (peg-in),
//! building and publishing transfers, and the operator's peg-out handler.

use crate::chain::{Electrum, FundingKey, Utxo};
use crate::circuit::{self, InputWitness, OutputWitness, PublicInputs, TransferWitness};
use crate::envelope::{Envelope, MintEnvelope, Payout, TransferEnvelope, CT_OUT_LEN};
use crate::indexer::{Event, State};
use crate::keys::{self, Address, WalletKeys, DIVERSIFIER_LEN};
use crate::note::{self, NotePlaintext};
use crate::prover::Params;
use crate::tree::MerklePath;
use crate::{Fr, Fs, N_IN, N_OUT, TREE_DEPTH};
use anyhow::{anyhow, ensure, Context, Result};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use bitcoin::{Amount, ScriptBuf, TxOut, Txid};
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
    pub notes: Vec<OwnedNote>,
    pub sent: Vec<SentRecord>,
    pub scanned_events: usize,
    pub paid_payouts: Vec<Txid>,
}

pub struct Wallet {
    pub path: std::path::PathBuf,
    pub file: WalletFile,
    pub keys: WalletKeys,
    pub funding: FundingKey,
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

impl Wallet {
    pub fn create(path: &Path) -> Result<Self> {
        ensure!(!path.exists(), "{} already exists", path.display());
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        let mut fsk = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut seed);
        rand::RngCore::fill_bytes(&mut rng, &mut fsk);
        let file = WalletFile {
            seed: hex::encode(seed),
            funding_sk: hex::encode(fsk),
            notes: vec![],
            sent: vec![],
            scanned_events: 0,
            paid_payouts: vec![],
        };
        let w = Self::from_file(path.to_path_buf(), file)?;
        w.save()?;
        Ok(w)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let file: WalletFile = serde_json::from_reader(std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?)?;
        Self::from_file(path.to_path_buf(), file)
    }

    fn from_file(path: std::path::PathBuf, file: WalletFile) -> Result<Self> {
        let seed: [u8; 32] = hex::decode(&file.seed)?.as_slice().try_into().map_err(|_| anyhow!("bad seed"))?;
        let fsk: [u8; 32] = hex::decode(&file.funding_sk)?.as_slice().try_into().map_err(|_| anyhow!("bad funding key"))?;
        Ok(Self { path, keys: WalletKeys::from_seed(seed), funding: FundingKey::from_bytes(&fsk)?, file })
    }

    pub fn save(&self) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        serde_json::to_writer_pretty(std::fs::File::create(&tmp)?, &self.file)?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }

    pub fn address(&self) -> Address {
        self.keys.address(0)
    }

    pub fn balance(&self) -> u64 {
        self.file.notes.iter().filter(|n| !n.spent && n.locked_by.is_none()).map(|n| n.v).sum()
    }

    /// Paper 16.1 and 16.2 against the indexer's accepted history.
    pub fn scan(&mut self, state: &State) -> Result<usize> {
        let der = self.keys.derive();
        let mut found = 0;
        for ev in &state.events[self.file.scanned_events..] {
            match ev {
                Event::Mint(m) => {
                    let env = m.envelope();
                    if keys::address_for(&der, env.d).pk_d == env.pk_d {
                        self.file.notes.push(OwnedNote {
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
                        });
                        found += 1;
                    }
                }
                Event::Transfer(t) => {
                    let env = t.envelope();
                    let h_body = env.h_body();
                    for j in 0..N_OUT {
                        let Some(n) = note::decrypt_as_recipient(&env.ct[j], &env.pk_eph[j], &der.sk_view) else { continue };
                        let leaf = note::leaf(&h_body, j as u8, &env.pk_eph[j], &env.ct[j]);
                        ensure!(state.tree.leaf(t.positions[j]) == Some(leaf), "replay leaf mismatch at {}", t.positions[j]);
                        self.file.notes.push(OwnedNote {
                            v: n.v,
                            d: hex::encode(n.d),
                            r_seed: fr_hex(&n.r_seed),
                            is_mint: false,
                            h_body_create: fr_hex(&h_body),
                            j: j as u8,
                            pos: t.positions[j],
                            source_txid: t.txid,
                            spent: false,
                            locked_by: None,
                        });
                        found += 1;
                    }
                    // Sender-side recovery of our own transfers.
                    if let Some(records) = self.decrypt_ct_out(&env, &der.vk_out) {
                        for (j, (pk_d, sk_eph)) in records.iter().enumerate() {
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
        // Spent status and lock release come from the nullifier set.
        for n in &mut self.file.notes {
            let nf = note::nullifier(&der.sk_nf, &note::rho(&fr_from_hex(&n.r_seed)?), n.pos);
            if state.nullifiers.contains(&nf) {
                n.spent = true;
                n.locked_by = None;
            }
        }
        self.save()?;
        Ok(found)
    }

    fn ct_out_key(vk_out: &[u8; 32], binding: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
        let hk = Hkdf::<Sha256>::new(Some(binding), vk_out);
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        hk.expand(b"sbp/ctout/key", &mut key).expect("valid length");
        hk.expand(b"sbp/ctout/nonce", &mut nonce).expect("valid length");
        (key, nonce)
    }

    fn encrypt_ct_out(&self, binding: &[u8; 32], records: &[(crate::EdwardsAffine, Fs); N_OUT]) -> Vec<u8> {
        let (key, nonce) = Self::ct_out_key(&self.keys.derive().vk_out, binding);
        let mut pt = Vec::with_capacity(N_OUT * 64);
        for (pk_d, s) in records {
            pt.extend_from_slice(&keys::point_to_bytes(pk_d));
            pt.extend_from_slice(&s.into_bigint().to_bytes_le());
        }
        let cipher = ChaCha20Poly1305::new((&key).into());
        cipher.encrypt((&nonce).into(), AeadPayload { msg: &pt, aad: binding }).expect("aead")
    }

    fn decrypt_ct_out(&self, env: &TransferEnvelope, vk_out: &[u8; 32]) -> Option<Vec<(crate::EdwardsAffine, Fs)>> {
        let binding = env.recovery_binding();
        let (key, nonce) = Self::ct_out_key(vk_out, &binding);
        let cipher = ChaCha20Poly1305::new((&key).into());
        let pt = cipher.decrypt((&nonce).into(), AeadPayload { msg: &env.ct_out, aad: &binding }).ok()?;
        let mut out = Vec::with_capacity(N_OUT);
        for chunk in pt.chunks(64) {
            let pk_d = keys::point_from_bytes(&chunk[..32])?;
            let s = Fs::from_le_bytes_mod_order(&chunk[32..]);
            out.push((pk_d, s));
        }
        Some(out)
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
            let inp = InputWitness {
                enabled: true,
                is_mint: n.is_mint,
                v: n.v,
                d: d_from_hex(&n.d)?,
                r_seed: fr_from_hex(&n.r_seed)?,
                h_body_create: fr_from_hex(&n.h_body_create)?,
                j: n.j,
                path,
            };
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
        env.ct_out = self.encrypt_ct_out(&env.recovery_binding(), &records);
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
        }
        self.save()?;
        Ok((txid, payload.len(), vsize, prove_s))
    }

    /// Operator only: pay every accepted peg-out request addressed to us
    /// that has not been paid yet. Returns the payouts made.
    pub fn process_payouts(&mut self, e: &mut Electrum, state: &State) -> Result<Vec<(Txid, u64, Txid)>> {
        let der = self.keys.derive();
        let mut done = Vec::new();
        for ev in &state.events {
            let Event::Transfer(t) = ev else { continue };
            if self.file.paid_payouts.contains(&t.txid) {
                continue;
            }
            let env = t.envelope();
            let Some(p) = &env.payout else { continue };
            // Convention: the burned value is output 0, sent to the operator.
            let Some(n) = note::decrypt_as_recipient(&env.ct[0], &env.pk_eph[0], &der.sk_view) else { continue };
            if p.amount > n.v {
                eprintln!("payout in {} asks {} sat but burned {} sat, skipping", t.txid, p.amount, n.v);
                continue;
            }
            let utxos = self.funding_utxos(e)?;
            let tx = self.funding.build_carrier(
                &utxos,
                b"",
                vec![TxOut { value: Amount::from_sat(p.amount), script_pubkey: ScriptBuf::from_bytes(p.script_pubkey.clone()) }],
            )?;
            let paid = e.broadcast(&tx)?;
            self.file.paid_payouts.push(t.txid);
            self.save()?;
            done.push((t.txid, p.amount, paid));
        }
        Ok(done)
    }
}

pub fn parse_address(s: &str) -> Result<Address> {
    Address::decode(s).ok_or_else(|| anyhow!("not a shielded address: {s}"))
}

pub fn note_plaintext(n: &OwnedNote) -> Result<NotePlaintext> {
    Ok(NotePlaintext { v: n.v, d: d_from_hex(&n.d)?, r_seed: fr_from_hex(&n.r_seed)? })
}


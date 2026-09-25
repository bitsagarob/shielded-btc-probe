//! Wallet behaviour against hand-built replay state. Nothing here touches
//! a network; every chain is a MockChain.

use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute, hashes::Hash, script::PushBytesBuf, transaction,
};
use serde_json::{Value, json};
use shielded_probe::{
    Fr, K_WALLET, WINDOW_W,
    chain::{ChainSource, FundingKey, MockChain, op_return_payload},
    envelope::{CT_OUT_LEN, Envelope, PROOF_LEN, Payout, TransferEnvelope, recovery_binding},
    indexer::{AcceptedMint, AcceptedTransfer, Deployment, Event, RejectReason, State},
    keys::Address,
    note::{self, NotePlaintext},
    prover::Params,
    wallet::{DEPOSIT_CAP, Wallet, check_deposit, spends_vault, validate_payout},
};
use std::{os::unix::fs::PermissionsExt, sync::OnceLock};
use zeroize::Zeroize;

fn params() -> &'static Params {
    static P: OnceLock<Params> = OnceLock::new();
    P.get_or_init(|| Params::setup_insecure().unwrap())
}

fn tmp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("sbp-wallet-{name}-{}.json", std::process::id()))
}

fn tmp(name: &str) -> std::path::PathBuf {
    let p = tmp_path(name);
    let _ = std::fs::remove_file(&p);
    p
}

fn fresh_state(op: &Wallet) -> State {
    State::fresh(Deployment {
        network: Network::Signet,
        fee_rate_sat_vb: 2,
        activation: 10,
        activation_hash: None,
        vault_script_pubkey: op.vault_key().unwrap().script_pubkey(),
        operator_address: op.address().to_string(),
        vk_fingerprint: "test".into(),
    })
}

fn mint_to(st: &mut State, w: &Wallet, v: u64, seed: u64, txid_byte: u8) -> u64 {
    let a = w.address();
    let r_seed = Fr::from(seed);
    let env = shielded_probe::envelope::MintEnvelope {
        d: a.d,
        pk_d: a.pk_d,
        r_seed,
    };
    let pos = st.tree.append(note::mint_leaf(v, &a.d, &a.pk_d, &r_seed));
    st.events.push(Event::Mint(AcceptedMint {
        txid: Txid::from_byte_array([txid_byte; 32]),
        height: 11,
        bytes: env.to_bytes(),
        value: v,
        pos,
    }));
    pos
}

/// Appends an accepted transfer. `sender` is the vk_out ct_out is written
/// under; None leaves ct_out as junk.
fn transfer(
    st: &mut State,
    outs: [(&Address, u64, u64); 2],
    sender: Option<&[u8; 32]>,
    nf: [Fr; 2],
    payout: Option<Payout>,
    txid_byte: u8,
) -> Txid {
    let notes: Vec<NotePlaintext> = outs
        .iter()
        .map(|(a, v, seed)| NotePlaintext {
            v: *v,
            d: a.d,
            r_seed: Fr::from(*seed),
        })
        .collect();
    let encs: Vec<_> = notes
        .iter()
        .zip(&outs)
        .map(|(n, (a, _, _))| note::encrypt(n, &a.pk_d).unwrap())
        .collect();
    let pk_eph = [encs[0].0, encs[1].0];
    let ct = [encs[0].1, encs[1].1];
    let records: Vec<_> = notes
        .iter()
        .zip(&outs)
        .map(|(n, (a, _, _))| (a.pk_d, note::sk_eph(&n.r_seed)))
        .collect();
    let ct_out = match sender {
        Some(vk) => note::encrypt_recovery(&records, &recovery_binding(&pk_eph, &ct), vk),
        None => vec![9u8; CT_OUT_LEN],
    };
    let env = TransferEnvelope {
        h_anchor: 10,
        nf,
        pk_eph,
        ct,
        ct_out,
        payout,
        proof: vec![0u8; PROOF_LEN],
    };
    let h_body = env.h_body();
    let positions = std::array::from_fn(|j| {
        st.tree
            .append(note::leaf(&h_body, j as u8, &env.pk_eph[j], &env.ct[j]))
    });
    let txid = Txid::from_byte_array([txid_byte; 32]);
    st.events.push(Event::Transfer(AcceptedTransfer {
        txid,
        height: 12,
        bytes: env.to_bytes(),
        positions,
    }));
    for n in nf {
        st.nullifiers.insert(n);
    }
    txid
}

fn own_nf(w: &Wallet, seed: u64, pos: u64) -> Fr {
    note::nullifier(&w.keys.derive().sk_nf, &note::rho(&Fr::from(seed)), pos)
}

#[test]
fn scan_dedups_when_cursor_rewinds() {
    let op = Wallet::create(&tmp("op1")).unwrap();
    let mut alice = Wallet::create(&tmp("alice1")).unwrap();
    let mut st = fresh_state(&op);
    mint_to(&mut st, &alice, 1000, 5, 1);
    alice.scan(&st).unwrap();
    assert_eq!(alice.balance().unwrap(), 1000);
    alice.file.scanned_events = 0;
    alice.scan(&st).unwrap();
    assert_eq!(alice.file.notes.len(), 1);
    assert_eq!(alice.balance().unwrap(), 1000);
}

#[test]
fn scan_rescans_when_history_changed() {
    let op = Wallet::create(&tmp("op2")).unwrap();
    let mut alice = Wallet::create(&tmp("alice2")).unwrap();
    let mut st = fresh_state(&op);
    mint_to(&mut st, &alice, 1000, 5, 1);
    mint_to(&mut st, &alice, 1000, 6, 2);
    alice.scan(&st).unwrap();
    assert_eq!(alice.file.scanned_events, 2);
    assert_eq!(alice.balance().unwrap(), 2000);
    // Reorg: the indexer rebuilt and the second mint is gone.
    let mut st2 = fresh_state(&op);
    mint_to(&mut st2, &alice, 1000, 5, 1);
    alice.scan(&st2).unwrap();
    assert_eq!(alice.file.notes.len(), 1);
    assert_eq!(alice.balance().unwrap(), 1000);
    assert_eq!(alice.file.scanned_events, 1);
    // Same length, different history.
    let mut st3 = fresh_state(&op);
    mint_to(&mut st3, &alice, 700, 8, 3);
    alice.scan(&st3).unwrap();
    assert_eq!(alice.file.notes.len(), 1);
    assert_eq!(alice.balance().unwrap(), 700);
    // Wallet that scanned four events meets an empty rebuild.
    let mut w = Wallet::create(&tmp("w2")).unwrap();
    w.file.scanned_events = 4;
    w.scan(&fresh_state(&op)).unwrap();
    assert_eq!(w.file.scanned_events, 0);
}

#[test]
fn scan_drops_and_rediscovers_a_stale_note() {
    let op = Wallet::create(&tmp("op9")).unwrap();
    let mut alice = Wallet::create(&tmp("alice9")).unwrap();
    let mut st = fresh_state(&op);
    mint_to(&mut st, &alice, 1000, 5, 1);
    alice.scan(&st).unwrap();
    alice.file.notes[0].v = 999;
    alice.scan(&st).unwrap();
    assert_eq!(alice.file.notes.len(), 1);
    assert_eq!(alice.balance().unwrap(), 1000);
}

#[test]
fn scan_releases_a_lock_after_the_anchor_window() {
    let op = Wallet::create(&tmp("op3")).unwrap();
    let mut alice = Wallet::create(&tmp("alice3")).unwrap();
    let mut st = fresh_state(&op);
    mint_to(&mut st, &alice, 1000, 5, 1);
    alice.scan(&st).unwrap();
    alice.file.notes[0].locked_by = Some(Txid::from_byte_array([9; 32]));
    alice.file.notes[0].lock_anchor = Some(st.replayed_height);
    st.replayed_height += WINDOW_W;
    alice.scan(&st).unwrap();
    assert_eq!(alice.balance().unwrap(), 0, "still inside the window");
    st.replayed_height += 1;
    alice.scan(&st).unwrap();
    assert!(alice.file.notes[0].locked_by.is_none());
    assert_eq!(alice.balance().unwrap(), 1000);
}

#[test]
fn unlock_releases_a_lock_without_anchor() {
    let op = Wallet::create(&tmp("op4")).unwrap();
    let mut alice = Wallet::create(&tmp("alice4")).unwrap();
    let mut st = fresh_state(&op);
    mint_to(&mut st, &alice, 1000, 5, 1);
    alice.scan(&st).unwrap();
    let carrier = Txid::from_byte_array([9; 32]);
    alice.file.notes[0].locked_by = Some(carrier);
    st.replayed_height += 500;
    alice.scan(&st).unwrap();
    assert_eq!(alice.balance().unwrap(), 0);
    let mut e = MockChain::new(100);
    assert_eq!(
        alice
            .unlock(&mut e, &Txid::from_byte_array([8; 32]), false)
            .unwrap(),
        0
    );
    assert_eq!(alice.unlock(&mut e, &carrier, false).unwrap(), 1);
    assert_eq!(alice.balance().unwrap(), 1000);
}

#[test]
fn unlock_refuses_while_the_carrier_is_known_to_the_chain() {
    let op = Wallet::create(&tmp("op15")).unwrap();
    let mut alice = Wallet::create(&tmp("alice15")).unwrap();
    let mut st = fresh_state(&op);
    mint_to(&mut st, &alice, 1000, 5, 1);
    alice.scan(&st).unwrap();
    let mut e = MockChain::new(99);
    e.mine(vec![carrier(b"mined")]);
    let mined = e.block_txids(100).unwrap()[0];
    alice.file.notes[0].locked_by = Some(mined);
    assert_eq!(alice.balance().unwrap(), 0);
    assert!(alice.unlock(&mut e, &mined, false).is_err());
    assert_eq!(alice.balance().unwrap(), 0);
    assert_eq!(alice.unlock(&mut e, &mined, true).unwrap(), 1);
    assert_eq!(alice.balance().unwrap(), 1000);
}

#[test]
fn scan_ignores_sent_records_forged_with_vk_out() {
    let op = Wallet::create(&tmp("op5")).unwrap();
    let mut alice = Wallet::create(&tmp("alice5")).unwrap();
    let carol = Wallet::create(&tmp("carol5")).unwrap();
    let mut st = fresh_state(&op);
    let vk_out = alice.keys.derive().vk_out;
    let to = carol.address();
    transfer(
        &mut st,
        [(&to, 1_000_000, 77), (&to, 5, 78)],
        Some(&vk_out),
        [Fr::from(1u64), Fr::from(2u64)],
        None,
        3,
    );
    alice.scan(&st).unwrap();
    assert!(alice.file.notes.is_empty());
    assert!(
        alice.file.sent.is_empty(),
        "sent history forged without spending a note of alice's"
    );
}

#[test]
fn scan_records_own_spend_as_sent() {
    let op = Wallet::create(&tmp("op6")).unwrap();
    let mut alice = Wallet::create(&tmp("alice6")).unwrap();
    let carol = Wallet::create(&tmp("carol6")).unwrap();
    let mut st = fresh_state(&op);
    let pos = mint_to(&mut st, &alice, 1000, 5, 1);
    let vk_out = alice.keys.derive().vk_out;
    let (to, change) = (carol.address(), alice.address());
    let txid = transfer(
        &mut st,
        [(&to, 600, 77), (&change, 400, 78)],
        Some(&vk_out),
        [own_nf(&alice, 5, pos), Fr::from(2u64)],
        None,
        3,
    );
    alice.scan(&st).unwrap();
    assert!(alice.file.notes[0].spent);
    assert_eq!(alice.balance().unwrap(), 400);
    assert_eq!(alice.file.sent.len(), 2);
    assert_eq!(
        (
            alice.file.sent[0].txid,
            alice.file.sent[0].v,
            alice.file.sent[0].to.as_str()
        ),
        (txid, 600, to.to_string().as_str())
    );
    alice.scan(&st).unwrap();
    assert_eq!(alice.file.sent.len(), 2);
}

#[test]
fn scan_records_burned_output_as_spent() {
    let mut op = Wallet::create(&tmp("op7")).unwrap();
    let alice = Wallet::create(&tmp("alice7")).unwrap();
    let mut st = fresh_state(&op);
    let payout = Payout {
        amount: 1000,
        script_pubkey: alice.funding_key().unwrap().script_pubkey().to_bytes(),
    };
    transfer(
        &mut st,
        [(&op.address(), 1000, 77), (&alice.address(), 0, 78)],
        None,
        [Fr::from(1u64), Fr::from(2u64)],
        Some(payout),
        3,
    );
    assert_eq!(op.scan(&st).unwrap(), 1);
    assert!(op.file.notes[0].spent);
    assert_eq!(op.balance().unwrap(), 0);
    // Without a payout the same output is ordinary income.
    transfer(
        &mut st,
        [(&op.address(), 1000, 79), (&alice.address(), 1, 80)],
        None,
        [Fr::from(3u64), Fr::from(4u64)],
        None,
        4,
    );
    op.scan(&st).unwrap();
    assert_eq!(op.balance().unwrap(), 1000);
}

#[test]
fn scan_skips_zero_value_outputs() {
    let op = Wallet::create(&tmp("op8")).unwrap();
    let mut alice = Wallet::create(&tmp("alice8")).unwrap();
    let mut st = fresh_state(&op);
    transfer(
        &mut st,
        [(&alice.address(), 0, 77), (&alice.address(), 0, 78)],
        None,
        [Fr::from(1u64), Fr::from(2u64)],
        None,
        3,
    );
    assert_eq!(alice.scan(&st).unwrap(), 0);
    assert!(alice.file.notes.is_empty());
}

#[test]
fn create_writes_a_private_wallet_file() {
    let p = tmp("perm");
    let _ = Wallet::create(&p).unwrap();
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn open_never_writes_and_migrate_fills_a_missing_vault_key() {
    let p = tmp("old");
    let w = Wallet::create(&p).unwrap();
    let old = format!(
        r#"{{"seed":"{}","funding_sk":"{}","notes":[],"sent":[],"scanned_events":0,"paid_payouts":["{}"]}}"#,
        hex::encode(w.file.seed),
        hex::encode(w.file.funding_sk.unwrap()),
        Txid::from_byte_array([4; 32])
    );
    drop(w);
    std::fs::write(&p, &old).unwrap();
    let mut a = Wallet::open(&p).unwrap();
    assert!(a.file.vault_sk.is_none());
    assert_eq!(
        a.vault_key().err().map(|e| e.to_string()),
        Some("this wallet has no vault key".into())
    );
    assert_eq!(std::fs::read_to_string(&p).unwrap(), old, "open wrote");
    assert!(a.migrate().unwrap());
    assert!(!a.migrate().unwrap());
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let vault = a.vault_key().unwrap().script_pubkey();
    assert_ne!(vault, a.funding_key().unwrap().script_pubkey());
    drop(a);
    let b = Wallet::open(&p).unwrap();
    assert_eq!(
        vault,
        b.vault_key().unwrap().script_pubkey(),
        "vault key persisted by migrate"
    );
}

#[test]
fn a_viewing_only_file_scans_but_cannot_fund_and_exports_its_viewing_keys() {
    let op = Wallet::create(&tmp("op18")).unwrap();
    let p = tmp("view18");
    let full = Wallet::create(&p).unwrap();
    let (seed, addr) = (full.file.seed, full.address());
    let vk = full.keys.viewing();
    drop(full);
    std::fs::write(
        &p,
        format!(
            r#"{{"seed":"{}","notes":[],"sent":[],"scanned_events":0,"paid_payouts":[]}}"#,
            hex::encode(seed)
        ),
    )
    .unwrap();
    let mut v = Wallet::open(&p).unwrap();
    assert_eq!(v.address(), addr);
    assert_eq!(
        v.funding_key().err().map(|e| e.to_string()),
        Some("this wallet has no funding key".into())
    );
    let mut st = fresh_state(&op);
    mint_to(&mut st, &v, 1000, 5, 1);
    assert_eq!(v.scan(&st).unwrap(), 1);
    assert_eq!(v.balance().unwrap(), 1000);
    let mut e = MockChain::new(100);
    assert_eq!(
        v.mint(&mut e, &st.deployment, 1)
            .err()
            .map(|e| e.to_string()),
        Some("this wallet has no funding key".into())
    );
    let out = tmp("view18-export");
    v.export_viewing(&out).unwrap();
    assert!(v.export_viewing(&out).is_err(), "never overwrites");
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = std::fs::read_to_string(&out).unwrap();
    let j: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(j["addresses"], json!([addr.to_string()]));
    assert_eq!(
        j["vk_in"],
        json!(hex::encode(shielded_probe::keys::fr_to_bytes(&vk.vk_in)))
    );
    assert_eq!(j["vk_out"], json!(hex::encode(vk.vk_out)));
    assert_eq!(
        j["sk_view"],
        json!(hex::encode(shielded_probe::keys::scalar_to_bytes(
            &vk.sk_view
        )))
    );
    assert!(!text.contains(&hex::encode(seed)));
    assert_eq!(j.as_object().unwrap().len(), 4);
}

#[test]
fn a_second_open_of_the_same_wallet_is_refused_while_the_first_lives() {
    let p = tmp("lock");
    let w = Wallet::create(&p).unwrap();
    assert_eq!(
        Wallet::open(&p).err().map(|e| e.to_string()),
        Some("wallet file is locked by another process".into())
    );
    assert!(
        Wallet::create(&p)
            .err()
            .is_some_and(|e| matches!(e, shielded_probe::wallet::Error::Exists(_)))
    );
    w.save().unwrap();
    assert!(Wallet::open(&p).is_err(), "the lock survives a save");
    drop(w);
    let again = Wallet::open(&p).unwrap();
    assert_eq!(
        std::fs::metadata(p.with_extension("json.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(again);
}

#[test]
fn encrypt_recovery_decrypt_recovery_roundtrip() {
    let a = Wallet::create(&tmp("rec")).unwrap();
    let vk = a.keys.derive().vk_out;
    let records = vec![
        (a.address().pk_d, note::sk_eph(&Fr::from(1u64))),
        (a.address().pk_d, note::sk_eph(&Fr::from(2u64))),
    ];
    let binding = [7u8; 32];
    let ct = note::encrypt_recovery(&records, &binding, &vk);
    assert_eq!(ct.len(), CT_OUT_LEN);
    assert_eq!(note::decrypt_recovery(&ct, &binding, &vk), Some(records));
    assert_eq!(note::decrypt_recovery(&ct, &[8u8; 32], &vk), None);
    assert_eq!(note::decrypt_recovery(&ct, &binding, &[0u8; 32]), None);
}

#[test]
fn validate_payout_cases() {
    let p2wpkh = FundingKey::from_bytes(&[8u8; 32])
        .unwrap()
        .script_pubkey()
        .to_bytes();
    assert!(
        validate_payout(
            &Payout {
                amount: 1000,
                script_pubkey: p2wpkh.clone()
            },
            1000,
            Network::Signet
        )
        .is_ok()
    );
    assert!(
        validate_payout(
            &Payout {
                amount: 1001,
                script_pubkey: p2wpkh.clone()
            },
            1000,
            Network::Signet
        )
        .is_err()
    );
    assert!(
        validate_payout(
            &Payout {
                amount: 545,
                script_pubkey: p2wpkh.clone()
            },
            1000,
            Network::Signet
        )
        .is_err()
    );
    assert!(
        validate_payout(
            &Payout {
                amount: 1000,
                script_pubkey: vec![]
            },
            1000,
            Network::Signet
        )
        .is_err()
    );
    assert!(
        validate_payout(
            &Payout {
                amount: 1000,
                script_pubkey: vec![0x51]
            },
            1000,
            Network::Signet
        )
        .is_err()
    );
    let mut p2wsh = vec![0x00, 0x20];
    p2wsh.extend_from_slice(&[1u8; 32]);
    assert!(
        validate_payout(
            &Payout {
                amount: 1000,
                script_pubkey: p2wsh
            },
            1000,
            Network::Signet
        )
        .is_err()
    );
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&[1u8; 32]);
    assert!(
        validate_payout(
            &Payout {
                amount: 1000,
                script_pubkey: p2tr
            },
            1000,
            Network::Signet
        )
        .is_ok()
    );
}

#[test]
fn process_payouts_refuses_bad_requests_and_keeps_going() {
    let mut op = Wallet::create(&tmp("op10")).unwrap();
    let alice = Wallet::create(&tmp("alice10")).unwrap();
    let mut st = fresh_state(&op);
    let spk = alice.funding_key().unwrap().script_pubkey().to_bytes();
    let (o, a) = (op.address(), alice.address());
    transfer(
        &mut st,
        [(&o, 1000, 1), (&a, 1, 2)],
        None,
        [Fr::from(1u64), Fr::from(2u64)],
        Some(Payout {
            amount: 100,
            script_pubkey: spk.clone(),
        }),
        1,
    );
    transfer(
        &mut st,
        [(&o, 1000, 3), (&a, 1, 4)],
        None,
        [Fr::from(3u64), Fr::from(4u64)],
        Some(Payout {
            amount: 1000,
            script_pubkey: vec![0x51],
        }),
        2,
    );
    transfer(
        &mut st,
        [(&o, 10_000, 5), (&a, 1, 6)],
        None,
        [Fr::from(5u64), Fr::from(6u64)],
        Some(Payout {
            amount: 10_000,
            script_pubkey: spk.clone(),
        }),
        3,
    );
    // Paid under the old scheme, recorded by carrier txid.
    let old = transfer(
        &mut st,
        [(&o, 10_000, 7), (&a, 1, 8)],
        None,
        [Fr::from(7u64), Fr::from(8u64)],
        Some(Payout {
            amount: 10_000,
            script_pubkey: spk,
        }),
        4,
    );
    op.file.paid_payouts.push(old.to_string());
    op.scan(&st).unwrap();
    assert_eq!(op.balance().unwrap(), 0);
    let mut e = MockChain::new(100);
    let done = op.process_payouts(&mut e, &st, None).unwrap();
    assert!(done.is_empty());
    let key = |nf: u64| hex::encode(shielded_probe::keys::fr_to_bytes(&Fr::from(nf)));
    assert!(op.file.failed_payouts[&key(1)].contains("below dust"));
    assert!(op.file.failed_payouts[&key(3)].contains("non-standard"));
    // The vault owns nothing: insufficient funds is transient, so the request
    // stays pending rather than refused.
    assert!(!op.file.failed_payouts.contains_key(&key(5)));
    assert_eq!(op.file.failed_payouts.len(), 2);
    assert_eq!(op.file.paid_payouts, vec![old.to_string()]);
    let path = op.path.clone();
    drop(op);
    let mut again = Wallet::open(&path).unwrap();
    assert_eq!(again.file.failed_payouts.len(), 2);
    assert!(again.process_payouts(&mut e, &st, None).unwrap().is_empty());
    assert_eq!(again.file.failed_payouts.len(), 2);
}

#[test]
fn a_stranger_paying_the_vault_with_nf_in_op_return_is_not_a_payout() {
    let op = Wallet::create(&tmp("op11")).unwrap();
    let vault = op.vault_key().unwrap().script_pubkey();
    let nf = shielded_probe::keys::fr_to_bytes(&Fr::from(42u64));
    let funded = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: FundingKey::from_bytes(&[8u8; 32]).unwrap().script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: vault.clone(),
            },
        ],
    };
    let spend = |vout: u32| Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funded.compute_txid(), vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(294),
                script_pubkey: vault.clone(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(
                    PushBytesBuf::try_from(nf.to_vec()).unwrap(),
                ),
            },
        ],
    };
    let mut prev = |id: &Txid| {
        assert_eq!(*id, funded.compute_txid());
        Ok(funded.clone())
    };
    // The stranger's transaction carries the same OP_RETURN as a real payout.
    let forged = spend(0);
    assert_eq!(op_return_payload(&forged), Ok(Some(nf.to_vec())));
    assert!(!spends_vault(&forged, &vault, &mut prev).unwrap());
    assert!(spends_vault(&spend(1), &vault, &mut prev).unwrap());
}

#[test]
fn burn_marking_spares_non_operator_recipients() {
    let op = Wallet::create(&tmp("op12")).unwrap();
    let mut alice = Wallet::create(&tmp("alice12")).unwrap();
    let mut st = fresh_state(&op);
    let a = alice.address();
    transfer(
        &mut st,
        [(&a, 1000, 77), (&a, 1000, 78)],
        None,
        [Fr::from(1u64), Fr::from(2u64)],
        Some(Payout {
            amount: 1000,
            script_pubkey: vec![0x51],
        }),
        3,
    );
    assert_eq!(alice.scan(&st).unwrap(), 2);
    assert!(!alice.file.notes[0].spent);
    assert_eq!(alice.balance().unwrap(), 2000);
}

#[test]
fn hostile_state_event_bytes_are_an_error_not_a_panic() {
    let op = Wallet::create(&tmp("op13")).unwrap();
    let mut alice = Wallet::create(&tmp("alice13")).unwrap();
    let mut st = fresh_state(&op);
    st.events.push(Event::Transfer(AcceptedTransfer {
        txid: Txid::all_zeros(),
        height: 11,
        bytes: vec![1, 2, 3],
        positions: [0, 1],
    }));
    let p = tmp("state13");
    st.save(&p).unwrap();
    let st = State::load(&p).unwrap();
    assert!(alice.scan(&st).is_err());
    let mut e = MockChain::new(100);
    assert!(alice.process_payouts(&mut e, &st, None).is_err());
    let mut mint = fresh_state(&op);
    mint.events.push(Event::Mint(AcceptedMint {
        txid: Txid::all_zeros(),
        height: 11,
        bytes: vec![1, 2, 3],
        value: 1,
        pos: 0,
    }));
    assert!(alice.scan(&mint).is_err());
}

#[test]
fn payouts_only_pays_the_named_request_and_bitcoin_requires_it() {
    let mut op = Wallet::create(&tmp("op14")).unwrap();
    let alice = Wallet::create(&tmp("alice14")).unwrap();
    let mut st = fresh_state(&op);
    let (o, a) = (op.address(), alice.address());
    let below_dust = || {
        Some(Payout {
            amount: 100,
            script_pubkey: alice.funding_key().unwrap().script_pubkey().to_bytes(),
        })
    };
    let first = transfer(
        &mut st,
        [(&o, 1000, 1), (&a, 1, 2)],
        None,
        [Fr::from(1u64), Fr::from(2u64)],
        below_dust(),
        1,
    );
    let second = transfer(
        &mut st,
        [(&o, 1000, 3), (&a, 1, 4)],
        None,
        [Fr::from(3u64), Fr::from(4u64)],
        below_dust(),
        2,
    );
    op.scan(&st).unwrap();
    let mut e = MockChain::new(100);
    let key = |nf: u64| hex::encode(shielded_probe::keys::fr_to_bytes(&Fr::from(nf)));
    // Both requests are refused when reached; only the named one is reached.
    assert!(
        op.process_payouts(&mut e, &st, Some(second))
            .unwrap()
            .is_empty()
    );
    assert!(op.file.failed_payouts.contains_key(&key(3)));
    assert!(!op.file.failed_payouts.contains_key(&key(1)));
    assert!(
        op.process_payouts(&mut e, &st, Some(Txid::all_zeros()))
            .unwrap_err()
            .to_string()
            .starts_with("no accepted payout request")
    );
    st.deployment.network = Network::Bitcoin;
    assert_eq!(
        op.process_payouts(&mut e, &st, None)
            .unwrap_err()
            .to_string(),
        "on mainnet, pass --only <txid> for each request you have verified"
    );
    assert!(!op.file.failed_payouts.contains_key(&key(1)));
    assert!(
        op.process_payouts(&mut e, &st, Some(first))
            .unwrap()
            .is_empty()
    );
    assert!(op.file.failed_payouts.contains_key(&key(1)));
}

#[test]
fn deposit_cap_applies_on_bitcoin_only() {
    assert!(check_deposit(Network::Signet, DEPOSIT_CAP + 1, false).is_ok());
    assert!(check_deposit(Network::Bitcoin, DEPOSIT_CAP, false).is_ok());
    assert!(
        check_deposit(Network::Bitcoin, DEPOSIT_CAP + 1, false)
            .unwrap_err()
            .to_string()
            .contains("--i-know")
    );
    assert!(check_deposit(Network::Bitcoin, DEPOSIT_CAP + 1, true).is_ok());
}

/// Records the current tree as the root of block `h`, as replay_block does.
fn close_block(st: &mut State, h: u32) {
    st.roots.insert(h, st.tree.root());
    st.leaf_counts.insert(h, st.tree.len());
    st.replayed_height = h;
}

fn carrier(envelope: &[u8]) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(
                PushBytesBuf::try_from(envelope.to_vec()).unwrap(),
            ),
        }],
    }
}

/// Section 13.1 end to end: a wallet-built transfer anchored K_WALLET deep
/// is accepted by replay, seen by both wallets, and refused when republished.
#[test]
fn built_transfer_is_accepted_by_replay_and_scanned_by_both_wallets() {
    let op = Wallet::create(&tmp("op16")).unwrap();
    let mut alice = Wallet::create(&tmp("alice16")).unwrap();
    let mut bob = Wallet::create(&tmp("bob16")).unwrap();
    let mut st = fresh_state(&op);
    let vault = st.deployment.vault_script_pubkey.clone();
    close_block(&mut st, 10);
    mint_to(&mut st, &alice, 1000, 5, 1);
    close_block(&mut st, 11);
    alice.scan(&st).unwrap();
    // The mint is in the newest block: not yet under an anchor K_WALLET deep.
    let young = alice.build_transfer(&st, params(), &bob.address(), 600, None);
    assert!(matches!(
        young,
        Err(shielded_probe::wallet::Error::InsufficientBalance { available: 0, .. })
    ));
    close_block(&mut st, 12);
    let built = alice
        .build_transfer(&st, params(), &bob.address(), 600, None)
        .unwrap();
    assert_eq!(built.envelope.h_anchor, 12 + 1 - K_WALLET);
    assert_eq!(built.inputs, vec![0]);
    let bytes = built.envelope.to_bytes();
    assert_eq!(bytes.len(), 669);
    assert_eq!(
        Envelope::parse(&bytes).unwrap(),
        Some(Envelope::Transfer(Box::new(built.envelope.clone())))
    );
    let txid = Txid::from_byte_array([3; 32]);
    st.replay_tx(params(), 13, txid, &carrier(&bytes), &vault)
        .unwrap();
    assert_eq!(st.tree.len(), 3);
    assert_eq!(st.nullifiers.len(), 2);
    close_block(&mut st, 13);
    assert_eq!(
        st.replay_tx(
            params(),
            14,
            Txid::from_byte_array([4; 32]),
            &carrier(&bytes),
            &vault
        ),
        Err(RejectReason::NullifierSpent(built.envelope.nf[0]))
    );
    assert_eq!(bob.scan(&st).unwrap(), 1);
    assert_eq!(bob.balance().unwrap(), 600);
    assert_eq!(alice.scan(&st).unwrap(), 1);
    assert!(alice.file.notes[0].spent);
    assert_eq!(alice.balance().unwrap(), 400);
    assert_eq!(alice.file.sent.len(), 2);
    assert_eq!(alice.file.sent[0].to, bob.address().to_string());
    // Bob spends the received note two blocks later, with a payout request.
    close_block(&mut st, 14);
    let payout = Payout {
        amount: 600,
        script_pubkey: alice.funding_key().unwrap().script_pubkey().to_bytes(),
    };
    let redeem = bob
        .build_transfer(&st, params(), &op.address(), 600, Some(payout))
        .unwrap();
    assert_eq!(redeem.envelope.to_bytes().len(), 699);
    st.replay_tx(
        params(),
        15,
        Txid::from_byte_array([5; 32]),
        &carrier(&redeem.envelope.to_bytes()),
        &vault,
    )
    .unwrap();
    assert_eq!(st.tree.len(), 5);
}

#[test]
fn a_lost_broadcast_reply_does_not_pay_the_same_request_twice() {
    let mut op = Wallet::create(&tmp("op17")).unwrap();
    let alice = Wallet::create(&tmp("alice17")).unwrap();
    let mut st = fresh_state(&op);
    let vault = op.vault_key().unwrap().script_pubkey();
    let spk = alice.funding_key().unwrap().script_pubkey();
    let req = transfer(
        &mut st,
        [(&op.address(), 10_000, 1), (&alice.address(), 1, 2)],
        None,
        [Fr::from(1u64), Fr::from(2u64)],
        Some(Payout {
            amount: 10_000,
            script_pubkey: spk.to_bytes(),
        }),
        7,
    );
    op.scan(&st).unwrap();
    let funded = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: vault.clone(),
        }],
    };
    let mut e = MockChain::new(99);
    e.mine(vec![funded]);
    e.drop_next_broadcast_reply = true;
    let key = hex::encode(shielded_probe::keys::fr_to_bytes(&Fr::from(1u64)));

    // Run 1: the server relays the payout but the reply is lost.
    let done = op.process_payouts(&mut e, &st, Some(req)).unwrap();
    assert!(done.is_empty());
    let first = e.mempool[0].compute_txid();
    assert_eq!(op.file.paid_payouts, vec![key.clone()]);
    assert_eq!(op.file.payout_txids, vec![first]);
    assert_eq!(e.mempool[0].output[0].script_pubkey, spk);

    // Run 2: the payout sits in the mempool with its change back to the vault.
    let done = op.process_payouts(&mut e, &st, Some(req)).unwrap();
    assert!(done.is_empty());
    assert_eq!(e.mempool.len(), 1);
    drop(op);
    let mut again = Wallet::open(&tmp_path("op17")).unwrap();
    assert_eq!(again.file.paid_payouts, vec![key]);
    assert!(
        again
            .process_payouts(&mut e, &st, Some(req))
            .unwrap()
            .is_empty()
    );
    assert_eq!(e.mempool.len(), 1);
}

#[test]
fn zeroize_clears_the_key_bytes_and_keeps_the_records() {
    let op = Wallet::create(&tmp("op19")).unwrap();
    let mut alice = Wallet::create(&tmp("alice19")).unwrap();
    let mut st = fresh_state(&op);
    mint_to(&mut st, &alice, 1000, 5, 1);
    alice.scan(&st).unwrap();
    let mut f = alice.file.clone();
    f.zeroize();
    assert_eq!(f.seed, [0u8; 32]);
    assert!(f.funding_sk.is_none() && f.vault_sk.is_none());
    assert_eq!(f.notes.len(), 1);
    assert_eq!(f.scanned_events, 1);
    let mut der = alice.keys.derive();
    let vk_out = der.viewing.vk_out;
    der.zeroize();
    assert_eq!(der.viewing.vk_out, [0u8; 32]);
    assert_ne!(vk_out, [0u8; 32]);
    assert_eq!(der.sk_spend, shielded_probe::Fs::from(0u64));
}

#[test]
fn a_failed_save_leaves_no_tmp_file_behind() {
    let dir = std::env::temp_dir().join(format!("sbp-wallet-save-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let w = Wallet::create(&dir.join("w.json")).unwrap();
    let tmp = w.path.with_extension("json.tmp");
    // A non-empty directory in the wallet's place makes the rename fail.
    std::fs::remove_file(&w.path).unwrap();
    std::fs::create_dir_all(w.path.join("x")).unwrap();
    assert!(w.save().is_err());
    assert!(!tmp.exists(), "tmp file with the seed left behind");
    std::fs::remove_dir_all(&w.path).unwrap();
    w.save().unwrap();
    assert!(!tmp.exists());
    assert_eq!(
        std::fs::metadata(&w.path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn balance_and_note_selection_refuse_to_overflow() {
    let op = Wallet::create(&tmp("op20")).unwrap();
    let mut alice = Wallet::create(&tmp("alice20")).unwrap();
    let mut st = fresh_state(&op);
    close_block(&mut st, 10);
    mint_to(&mut st, &alice, u64::MAX - 1, 5, 1);
    mint_to(&mut st, &alice, 5, 6, 2);
    close_block(&mut st, 11);
    close_block(&mut st, 12);
    alice.scan(&st).unwrap();
    assert_eq!(
        alice.balance().err().map(|e| e.to_string()),
        Some("note values overflow u64".into())
    );
    assert!(matches!(
        alice
            .build_transfer(&st, params(), &op.address(), u64::MAX, None)
            .err(),
        Some(shielded_probe::wallet::Error::Overflow)
    ));
    alice.file.notes[1].spent = true;
    assert_eq!(alice.balance().unwrap(), u64::MAX - 1);
}

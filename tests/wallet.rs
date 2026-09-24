//! Wallet behaviour against hand-built replay state. Nothing here
//! broadcasts; the payout test reads Fulcrum with a vault that owns nothing.

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    hashes::Hash, script::PushBytesBuf, transaction,
};
use shielded_probe::{
    Fr, WINDOW_W,
    chain::{DEFAULT_ELECTRUM, Electrum, FundingKey, op_return_payload},
    envelope::{CT_OUT_LEN, PROOF_LEN, Payout, TransferEnvelope, recovery_binding},
    indexer::{AcceptedMint, AcceptedTransfer, Deployment, Event, State},
    keys::Address,
    note::{self, NotePlaintext},
    wallet::{Wallet, spends_vault, validate_payout},
};
use std::os::unix::fs::PermissionsExt;

fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("sbp-wallet-{name}-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn fresh_state(op: &Wallet) -> State {
    State::fresh(Deployment {
        activation: 10,
        vault_script_pubkey: op.vault().script_pubkey(),
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
    assert_eq!(alice.balance(), 1000);
    alice.file.scanned_events = 0;
    alice.scan(&st).unwrap();
    assert_eq!(alice.file.notes.len(), 1);
    assert_eq!(alice.balance(), 1000);
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
    assert_eq!(alice.balance(), 2000);
    // Reorg: the indexer rebuilt and the second mint is gone.
    let mut st2 = fresh_state(&op);
    mint_to(&mut st2, &alice, 1000, 5, 1);
    alice.scan(&st2).unwrap();
    assert_eq!(alice.file.notes.len(), 1);
    assert_eq!(alice.balance(), 1000);
    assert_eq!(alice.file.scanned_events, 1);
    // Same length, different history.
    let mut st3 = fresh_state(&op);
    mint_to(&mut st3, &alice, 700, 8, 3);
    alice.scan(&st3).unwrap();
    assert_eq!(alice.file.notes.len(), 1);
    assert_eq!(alice.balance(), 700);
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
    assert_eq!(alice.balance(), 1000);
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
    assert_eq!(alice.balance(), 0, "still inside the window");
    st.replayed_height += 1;
    alice.scan(&st).unwrap();
    assert!(alice.file.notes[0].locked_by.is_none());
    assert_eq!(alice.balance(), 1000);
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
    assert_eq!(alice.balance(), 0);
    assert_eq!(alice.unlock(&Txid::from_byte_array([8; 32])).unwrap(), 0);
    assert_eq!(alice.unlock(&carrier).unwrap(), 1);
    assert_eq!(alice.balance(), 1000);
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
    assert_eq!(alice.balance(), 400);
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
        script_pubkey: alice.funding.script_pubkey().to_bytes(),
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
    assert_eq!(op.balance(), 0);
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
    assert_eq!(op.balance(), 1000);
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
fn open_fills_a_missing_vault_key() {
    let p = tmp("old");
    let w = Wallet::create(&p).unwrap();
    let old = format!(
        r#"{{"seed":"{}","funding_sk":"{}","notes":[],"sent":[],"scanned_events":0,"paid_payouts":["{}"]}}"#,
        hex::encode(w.file.seed),
        hex::encode(w.file.funding_sk),
        Txid::from_byte_array([4; 32])
    );
    std::fs::write(&p, old).unwrap();
    let a = Wallet::open(&p).unwrap();
    assert_ne!(a.file.vault_sk, [0u8; 32]);
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let b = Wallet::open(&p).unwrap();
    assert_eq!(
        a.vault().script_pubkey(),
        b.vault().script_pubkey(),
        "vault key persisted on first open"
    );
    assert_ne!(a.vault().script_pubkey(), a.funding.script_pubkey());
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
            1000
        )
        .is_ok()
    );
    assert!(
        validate_payout(
            &Payout {
                amount: 1001,
                script_pubkey: p2wpkh.clone()
            },
            1000
        )
        .is_err()
    );
    assert!(
        validate_payout(
            &Payout {
                amount: 545,
                script_pubkey: p2wpkh.clone()
            },
            1000
        )
        .is_err()
    );
    assert!(
        validate_payout(
            &Payout {
                amount: 1000,
                script_pubkey: vec![]
            },
            1000
        )
        .is_err()
    );
    assert!(
        validate_payout(
            &Payout {
                amount: 1000,
                script_pubkey: vec![0x51]
            },
            1000
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
            1000
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
            1000
        )
        .is_ok()
    );
}

#[test]
fn process_payouts_refuses_bad_requests_and_keeps_going() {
    let mut op = Wallet::create(&tmp("op10")).unwrap();
    let alice = Wallet::create(&tmp("alice10")).unwrap();
    let mut st = fresh_state(&op);
    let spk = alice.funding.script_pubkey().to_bytes();
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
    assert_eq!(op.balance(), 0);
    let mut e = Electrum::connect(DEFAULT_ELECTRUM).unwrap();
    let done = op.process_payouts(&mut e, &st).unwrap();
    assert!(done.is_empty());
    let key = |nf: u64| hex::encode(shielded_probe::keys::fr_to_bytes(&Fr::from(nf)));
    assert!(op.file.failed_payouts[&key(1)].contains("below dust"));
    assert!(op.file.failed_payouts[&key(3)].contains("non-standard"));
    // The vault owns nothing: insufficient funds is transient, so the request
    // stays pending rather than refused.
    assert!(!op.file.failed_payouts.contains_key(&key(5)));
    assert_eq!(op.file.failed_payouts.len(), 2);
    assert_eq!(op.file.paid_payouts, vec![old.to_string()]);
    let mut again = Wallet::open(&op.path).unwrap();
    assert_eq!(again.file.failed_payouts.len(), 2);
    assert!(again.process_payouts(&mut e, &st).unwrap().is_empty());
    assert_eq!(again.file.failed_payouts.len(), 2);
}

#[test]
fn a_stranger_paying_the_vault_with_nf_in_op_return_is_not_a_payout() {
    let op = Wallet::create(&tmp("op11")).unwrap();
    let vault = op.vault().script_pubkey();
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

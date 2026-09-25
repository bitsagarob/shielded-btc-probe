//! Replay behaviour the reviewer reproduced: anchor window arithmetic,
//! canonical envelope bytes, carrier strictness, stable state files.

use bitcoin::{
    Amount, Network, ScriptBuf, Transaction, TxOut, Txid, absolute, hashes::Hash,
    script::PushBytesBuf, transaction,
};
use shielded_probe::{
    EdwardsAffine, Fr,
    chain::{ChainSource, DEFAULT_ELECTRUM, Electrum, MockChain, op_return_payload},
    envelope::{CT_OUT_LEN, Envelope, MAGIC, MintEnvelope, PROOF_LEN, Payout, TransferEnvelope},
    indexer::{Deployment, Event, MAX_REJECTIONS, RejectReason, Rejection, State},
    keys::{self, WalletKeys},
    note::{NotePlaintext, encrypt},
    prover::Params,
    wallet::Wallet,
};
use std::sync::OnceLock;

const VAULT: &str = "00140000000000000000000000000000000000000000";

fn dep() -> Deployment {
    Deployment {
        network: Network::Signet,
        fee_rate_sat_vb: 2,
        activation: 1000,
        vault_script_pubkey: ScriptBuf::from_hex(VAULT).unwrap(),
        operator_address: String::new(),
        vk_fingerprint: String::new(),
    }
}

fn vault() -> ScriptBuf {
    dep().vault_script_pubkey
}

#[test]
fn a_profile_without_network_or_fee_rate_is_signet_at_two_sat_vb() {
    let d: Deployment = serde_json::from_str(&format!(
        r#"{{"activation":1,"vault_script_pubkey":"{VAULT}","operator_address":"","vk_fingerprint":""}}"#
    ))
    .unwrap();
    assert_eq!(d.network, Network::Signet);
    assert_eq!(d.fee_rate_sat_vb, 2);
    let d: Deployment = serde_json::from_str(
        &serde_json::to_string(&Deployment {
            network: Network::Bitcoin,
            fee_rate_sat_vb: 7,
            ..dep()
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(d.network, Network::Bitcoin);
    assert_eq!(d.fee_rate_sat_vb, 7);
}

fn params() -> &'static Params {
    static P: OnceLock<Params> = OnceLock::new();
    P.get_or_init(|| Params::setup_insecure().unwrap())
}

fn transfer(h_anchor: u32) -> TransferEnvelope {
    let w = WalletKeys::from_seed([3u8; 32]);
    let a = w.address(0);
    let n = NotePlaintext {
        v: 5,
        d: a.d,
        r_seed: Fr::from(8u64),
    };
    let (pk, ct) = encrypt(&n, &a.pk_d).unwrap();
    TransferEnvelope {
        h_anchor,
        nf: [Fr::from(1u64), Fr::from(2u64)],
        pk_eph: [pk, pk],
        ct: [ct, ct],
        ct_out: vec![9u8; CT_OUT_LEN],
        payout: None,
        proof: vec![0u8; PROOF_LEN],
    }
}

fn mint() -> MintEnvelope {
    MintEnvelope {
        d: [7u8; 11],
        pk_d: EdwardsAffine::default(),
        r_seed: Fr::from(5u64),
    }
}

fn tx(output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output,
    }
}

fn push(payload: &[u8]) -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(PushBytesBuf::try_from(payload.to_vec()).unwrap()),
    }
}

fn raw(script: Vec<u8>) -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn pay_vault(sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: vault(),
    }
}

fn replay(st: &mut State, h: u32, output: Vec<TxOut>) -> Result<(), RejectReason> {
    st.replay_tx(params(), h, Txid::all_zeros(), &tx(output), &vault())
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sbp-replay-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn replay_tx_anchor_window_bounds_hold_and_never_overflow() {
    let mut st = State::fresh(dep());
    let h = 1200u32;
    for k in (h - 110)..h {
        st.roots.insert(k, st.tree.root());
    }
    for a in [h - 100, h - 1] {
        assert_eq!(
            replay(&mut st, h, vec![push(&transfer(a).to_bytes())]),
            Err(RejectReason::ProofInvalid),
            "anchor {a}"
        );
    }
    for a in [h - 101, h, u32::MAX] {
        assert_eq!(
            replay(&mut st, h, vec![push(&transfer(a).to_bytes())]),
            Err(RejectReason::AnchorOutsideWindow {
                anchor: a,
                height: h
            }),
            "anchor {a}"
        );
    }
    assert_eq!(st.tree.len(), 0);
}

#[test]
fn parse_rejects_noncanonical_point_encoding() {
    let m = mint();
    let canon = m.to_bytes();
    let mut wire = canon.clone();
    // pk_d occupies bytes 17..49; the identity has x = 0, so the sign flag is free.
    wire[48] ^= 0x80;
    assert_eq!(
        keys::point_from_bytes(&wire[17..49]),
        Some(EdwardsAffine::default())
    );
    assert!(Envelope::parse(&wire).is_err());
    assert_eq!(Envelope::parse(&canon).unwrap(), Some(Envelope::Mint(m)));
    let mut st = State::fresh(dep());
    assert!(matches!(
        replay(&mut st, 1000, vec![pay_vault(1), push(&wire)]),
        Err(RejectReason::Parse(_))
    ));
    assert_eq!(st.tree.len(), 0);
}

#[test]
fn parse_rejects_empty_payout_script() {
    let mut t = transfer(1);
    t.payout = Some(Payout {
        amount: 0,
        script_pubkey: vec![],
    });
    assert!(Envelope::parse(&t.to_bytes()).is_err());
    t.payout = Some(Payout {
        amount: 0,
        script_pubkey: vec![0x51],
    });
    assert_eq!(
        Envelope::parse(&t.to_bytes()).unwrap(),
        Some(Envelope::Transfer(Box::new(t)))
    );
}

#[test]
fn op_return_payload_rejects_nonminimal_push() {
    let nonminimal = |payload: &[u8]| {
        let mut s = vec![0x6a, 0x4e];
        s.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        s.extend_from_slice(payload);
        raw(s)
    };
    assert_eq!(
        op_return_payload(&tx(vec![nonminimal(&[0x11u8; 70])])),
        Ok(None)
    );
    let mut claims = MAGIC.to_vec();
    claims.resize(70, 0x11);
    assert_eq!(
        op_return_payload(&tx(vec![nonminimal(&claims)])),
        Err("non-minimal push")
    );
    assert_eq!(
        op_return_payload(&tx(vec![push(&claims)])),
        Ok(Some(claims))
    );
}

#[test]
fn replay_tx_records_malformed_magic_carriers() {
    let m = mint().to_bytes();
    let two = vec![pay_vault(1), push(&m), push(b"note")];
    assert_eq!(
        op_return_payload(&tx(two.clone())),
        Err("more than one OP_RETURN output")
    );
    let mut extra =
        ScriptBuf::new_op_return(PushBytesBuf::try_from(m.clone()).unwrap()).into_bytes();
    extra.extend_from_slice(&[0x01, 0x00]);
    assert_eq!(
        op_return_payload(&tx(vec![raw(extra)])),
        Err("extra data after the envelope push")
    );
    assert_eq!(
        op_return_payload(&tx(vec![push(b"a"), push(b"b")])),
        Ok(None)
    );
    assert_eq!(op_return_payload(&tx(vec![raw(vec![0x6a])])), Ok(None));
    let mut st = State::fresh(dep());
    let r = replay(&mut st, 1000, two).unwrap_err();
    assert_eq!(r, RejectReason::Carrier("more than one OP_RETURN output"));
    assert_eq!(r.to_string(), "carrier: more than one OP_RETURN output");
    assert_eq!(st.tree.len(), 0);
}

#[test]
fn save_writes_nullifiers_in_stable_order() {
    let dir = scratch("nf-order");
    let mut files = std::collections::HashSet::new();
    for i in 0..8 {
        let mut st = State::fresh(dep());
        for k in 0..12u64 {
            st.nullifiers.insert(Fr::from(k * 7919));
        }
        let p = dir.join(format!("{i}.json"));
        st.save(&p).unwrap();
        files.insert(std::fs::read(&p).unwrap());
    }
    assert_eq!(files.len(), 1);
}

#[test]
fn replay_tx_accepts_the_same_mint_twice() {
    let mut st = State::fresh(dep());
    let m = mint().to_bytes();
    replay(&mut st, 1000, vec![pay_vault(1), push(&m)]).unwrap();
    replay(&mut st, 1000, vec![pay_vault(1), push(&m)]).unwrap();
    assert_eq!(st.tree.len(), 2);
    assert_eq!(st.tree.leaf(0), st.tree.leaf(1));
    assert_eq!(
        replay(&mut st, 1000, vec![push(&m)]),
        Err(RejectReason::MintUnfunded)
    );
    assert_eq!(st.events.len(), 2);
}

#[test]
fn save_load_roundtrip_keeps_tree_and_state() {
    let mut st = State::fresh(dep());
    let empty = st.tree.root();
    for k in 1..=3u64 {
        st.tree.append(Fr::from(k));
    }
    st.nullifiers.insert(Fr::from(99u64));
    st.roots.insert(1005, st.tree.root());
    let p = scratch("roundtrip").join("s.json");
    st.save(&p).unwrap();
    let l = State::load(&p).unwrap();
    assert_eq!(l.tree.root(), st.tree.root());
    assert_ne!(l.tree.root(), empty);
    assert_eq!(l.roots, st.roots);
    assert_eq!(l.nullifiers, st.nullifiers);
    assert_eq!(l.tree.path(0).unwrap().root(&Fr::from(1u64)), l.tree.root());
}

/// Live: replays the signet tip through the atomic block path and trims
/// the rejection log to the last MAX_REJECTIONS entries.
#[test]
#[ignore = "reads the live Fulcrum at 127.0.0.1:50001"]
fn sync_replays_a_block_and_caps_rejections() {
    let mut e = Electrum::connect(DEFAULT_ELECTRUM).unwrap();
    let tip = e.tip_height().unwrap();
    let mut st = State::fresh(Deployment {
        activation: tip,
        ..dep()
    });
    for i in 0..(MAX_REJECTIONS + 5) as u32 {
        st.rejections.push(Rejection {
            txid: Txid::all_zeros(),
            height: i,
            reason: String::new(),
        });
    }
    let n = st.sync(&mut e, params()).unwrap();
    assert!(n >= 1);
    assert_eq!(st.rejections.len(), MAX_REJECTIONS);
    assert_eq!(st.rejections[0].height, 5);
    assert_eq!(st.block_hashes.get(&tip), Some(&e.block_hash(tip).unwrap()));
}

fn mint_to(w: &Wallet, sats: u64, seed: u64) -> Transaction {
    let a = w.address();
    let m = MintEnvelope {
        d: a.d,
        pk_d: a.pk_d,
        r_seed: Fr::from(seed),
    };
    tx(vec![pay_vault(sats), push(&m.to_bytes())])
}

/// Three blocks: a mint, a transfer spending it, an empty one. Block 2 is
/// then replaced, so the transfer is orphaned and the state must be rebuilt
/// from activation.
#[test]
fn sync_rebuilds_from_activation_when_a_replayed_block_is_replaced() {
    let dir = scratch("reorg");
    let mut alice = Wallet::create(&dir.join("alice.json")).unwrap();
    let bob = Wallet::create(&dir.join("bob.json")).unwrap();
    let mut chain = MockChain::new(999);
    let mut st = State::fresh(dep());
    chain.mine(vec![mint_to(&alice, 1000, 5)]);
    assert_eq!(st.sync(&mut chain, params()).unwrap(), 1);
    alice.scan(&st).unwrap();
    // The indexer accepts an anchor K_MIN deep; build against the next height.
    st.replayed_height = 1001;
    let built = alice
        .build_transfer(&st, params(), &bob.address(), 600, None)
        .unwrap();
    st.replayed_height = 1000;
    assert_eq!(built.envelope.h_anchor, 1000);
    chain.mine(vec![tx(vec![push(&built.envelope.to_bytes())])]);
    chain.mine(vec![]);
    assert_eq!(st.sync(&mut chain, params()).unwrap(), 2);
    assert_eq!(st.replayed_height, 1002);
    assert_eq!(st.tree.len(), 3);
    assert_eq!(st.nullifiers.len(), 2);
    assert_eq!(st.events.len(), 2);
    let old_tip = chain.block_hash(1002).unwrap();
    assert_eq!(st.block_hashes.get(&1002), Some(&old_tip));

    chain.replace(1001, vec![mint_to(&alice, 700, 6)]);
    let new_tip = chain.block_hash(1002).unwrap();
    assert_ne!(new_tip, old_tip);
    assert_eq!(st.sync(&mut chain, params()).unwrap(), 3);
    assert_eq!(st.replayed_height, 1002);
    assert_eq!(st.tree.len(), 2);
    assert!(st.nullifiers.is_empty());
    assert_eq!(st.events.len(), 2);
    assert!(st.events.iter().all(|e| matches!(e, Event::Mint(_))));
    assert_eq!(
        st.block_hashes.get(&1000),
        Some(&chain.block_hash(1000).unwrap())
    );
    assert_eq!(st.block_hashes.get(&1002), Some(&new_tip));
    alice.scan(&st).unwrap();
    assert_eq!(alice.balance().unwrap(), 1700);
}

#[test]
fn sync_leaves_state_unmutated_when_a_block_changes_while_it_is_fetched() {
    let dir = scratch("midfetch");
    let alice = Wallet::create(&dir.join("alice.json")).unwrap();
    let mut chain = MockChain::new(999);
    let mint = mint_to(&alice, 1000, 5);
    chain.mine(vec![mint.clone()]);
    // The block gains a transaction while its txids are being fetched.
    chain.after_txids = Some(Box::new(move |c| {
        c.replace(1000, vec![mint, mint_to(&alice, 700, 6)])
    }));
    let mut st = State::fresh(dep());
    assert!(matches!(
        st.sync(&mut chain, params()),
        Err(shielded_probe::indexer::Error::BlockChanged(1000))
    ));
    assert_eq!(st.replayed_height, 999);
    assert_eq!(st.tree.len(), 0);
    assert!(st.events.is_empty());
    assert!(st.block_hashes.is_empty());
    assert_eq!(st.roots.len(), 1);
    assert_eq!(st.sync(&mut chain, params()).unwrap(), 1);
    assert_eq!(st.tree.len(), 2);
    assert_eq!(
        st.block_hashes.get(&1000),
        Some(&chain.block_hash(1000).unwrap())
    );
}

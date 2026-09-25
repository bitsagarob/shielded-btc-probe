//! Hostile-input tests ported from the robustness review, adjusted to the
//! fixed behaviour. Nothing here broadcasts; every Electrum test talks to a
//! scripted mock on loopback that the test itself owns.

use ark_ff::{BigInteger, Field, PrimeField};
use bitcoin::{
    BlockHash, Network, ScriptBuf, Txid, blockdata::constants::genesis_block, hashes::Hash,
};
use serde_json::{Value, json};
use shielded_btc_probe::{
    EdwardsAffine, Fr,
    chain::{ChainSource, Electrum, Error as ChainError, FundingKey, MockChain, Utxo},
    envelope::{CT_OUT_LEN, Envelope, Error as EnvError, PROOF_LEN, Payout, TransferEnvelope},
    indexer::{Deployment, Error as IndexerError, MAX_REJECTIONS, Rejection, State},
    keys::{self, WalletKeys},
    note::{self, NotePlaintext},
    prover::Params,
    wallet::{Error as WalletError, Wallet},
};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    sync::{Arc, Mutex, OnceLock},
    thread,
};

fn params() -> &'static Params {
    static P: OnceLock<Params> = OnceLock::new();
    P.get_or_init(|| Params::setup_insecure().unwrap())
}

fn dep() -> Deployment {
    Deployment {
        network: Network::Signet,
        fee_rate_sat_vb: 2,
        activation: 1000,
        activation_hash: None,
        vault_script_pubkey: ScriptBuf::from_hex("00140000000000000000000000000000000000000000")
            .unwrap(),
        operator_address: String::new(),
        vk_fingerprint: String::new(),
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("sbp-robust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn utxo(value: u64) -> Utxo {
    Utxo {
        outpoint: bitcoin::OutPoint::new(Txid::all_zeros(), 0),
        value,
        height: 1,
    }
}

#[test]
fn build_carrier_refuses_to_overflow() {
    let k = FundingKey::from_bytes(&[9u8; 32]).unwrap();
    assert!(matches!(
        k.build_carrier(&[utxo(500), utxo(u64::MAX)], b"x", vec![], 1),
        Err(ChainError::Overflow)
    ));
    let extra = vec![bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(u64::MAX),
        script_pubkey: ScriptBuf::new(),
    }];
    assert!(matches!(
        k.build_carrier(&[utxo(100_000)], b"x", extra, 1),
        Err(ChainError::Overflow)
    ));
    assert!(matches!(
        k.build_carrier(&[utxo(100_000)], b"x", vec![], u64::MAX),
        Err(ChainError::Overflow)
    ));
}

#[test]
fn build_transfer_at_replayed_height_u32_max_is_an_error() {
    let op = Wallet::create(&tmp("op-h.json")).unwrap();
    let mut st = State::fresh(dep());
    st.replayed_height = u32::MAX;
    assert!(matches!(
        op.build_transfer(&st, params(), &op.address(), 1, None),
        Err(WalletError::HeightOverflow)
    ));
}

fn transfer() -> TransferEnvelope {
    let w = WalletKeys::from_seed([3u8; 32]);
    let a = w.address(0).unwrap();
    let n = NotePlaintext {
        v: 5,
        d: a.d,
        r_seed: Fr::from(8u64),
    };
    let (pk, ct) = note::encrypt(&n, &a.pk_d).unwrap();
    TransferEnvelope {
        h_anchor: 42,
        nf: [Fr::from(1u64), Fr::from(2u64)],
        pk_eph: [pk, pk],
        ct: [ct, ct],
        ct_out: vec![9u8; CT_OUT_LEN],
        payout: None,
        proof: vec![0u8; PROOF_LEN],
    }
}

#[test]
fn envelope_every_truncation_and_bitflip_is_an_error_not_a_panic() {
    let bytes = transfer().to_bytes();
    for n in 0..bytes.len() {
        assert!(
            !matches!(Envelope::parse(&bytes[..n]), Ok(Some(_))),
            "prefix {n} parsed"
        );
    }
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut b = bytes.clone();
            b[i] ^= 1 << bit;
            let _ = Envelope::parse(&b);
        }
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Envelope::parse(&longer), Err(EnvError::TrailingBytes));
}

#[test]
fn envelope_compact_size_edges() {
    let bytes = transfer().to_bytes();
    let splice = |enc: &[u8]| {
        let mut b = bytes[..10].to_vec();
        b.extend_from_slice(enc);
        b.extend_from_slice(&bytes[11..]);
        Envelope::parse(&b)
    };
    assert_eq!(splice(&[0]), Err(EnvError::InputCount));
    assert_eq!(splice(&[0xfd, 2, 0]), Err(EnvError::NonMinimalCount));
    assert_eq!(splice(&[0xfd, 253, 0]), Err(EnvError::InputCount));
    assert_eq!(splice(&[0xfe, 2, 0, 0, 0]), Err(EnvError::NonMinimalCount));
    assert_eq!(
        splice(&[0xfe, 0xff, 0xff, 0xff, 0xff]),
        Err(EnvError::InputCount)
    );
    assert_eq!(splice(&[0xff]), Err(EnvError::NonMinimalCount));
    assert!(splice(&[0xfd]).is_err());
    assert!(splice(&[0xfe, 1]).is_err());
    assert_eq!(Envelope::parse(&bytes[..10]), Err(EnvError::Truncated));
    assert_eq!(
        Envelope::parse(&[&bytes[..10], &[0xfe, 1][..]].concat()),
        Err(EnvError::Truncated)
    );
}

#[test]
fn envelope_payout_length_edges() {
    let body_len = transfer().body_bytes().len();
    let bytes = transfer().to_bytes();
    let with_payout = |enc: &[u8], tail: &[u8]| {
        let mut b = bytes[..body_len - 1].to_vec();
        b.extend_from_slice(enc);
        b.extend_from_slice(tail);
        b.extend_from_slice(&bytes[body_len..]);
        Envelope::parse(&b)
    };
    for plen in 1..=8u8 {
        assert_eq!(
            with_payout(&[plen], &vec![0u8; plen as usize]),
            Err(EnvError::PayoutTooShort),
            "plen {plen}"
        );
    }
    assert!(matches!(with_payout(&[9], &[0u8; 9]), Ok(Some(_))));
    let mut t = transfer();
    t.payout = Some(Payout {
        amount: 1,
        script_pubkey: vec![0x51; 255],
    });
    assert_eq!(
        Envelope::parse(&t.to_bytes()).unwrap(),
        Some(Envelope::Transfer(Box::new(t.clone())))
    );
    // A length claiming 4 GB is Truncated, without allocating.
    assert_eq!(
        with_payout(&[0xfe, 0xff, 0xff, 0xff, 0xff], &[]),
        Err(EnvError::Truncated)
    );
    assert_eq!(with_payout(&[0xff], &[]), Err(EnvError::NonMinimalCount));
    assert_eq!(
        with_payout(&[0xfd, 9, 0], &[0u8; 9]),
        Err(EnvError::NonMinimalCount)
    );
}

#[test]
fn envelope_field_elements_at_r_minus_one_r_and_r_plus_one() {
    let r = Fr::MODULUS;
    let mut minus = r;
    minus.sub_with_borrow(&ark_ff::BigInt::from(1u64));
    let mut plus = r;
    plus.add_with_carry(&ark_ff::BigInt::from(1u64));
    let enc = |b: ark_ff::BigInt<4>| {
        let mut out = [0u8; 32];
        out.copy_from_slice(&b.to_bytes_le());
        out
    };
    assert!(keys::fr_from_bytes(&enc(minus)).is_some());
    assert!(keys::fr_from_bytes(&enc(r)).is_none());
    assert!(keys::fr_from_bytes(&enc(plus)).is_none());
    assert!(keys::fr_from_bytes(&[0xff; 32]).is_none());
    let mut b = transfer().to_bytes();
    b[12..44].copy_from_slice(&enc(r));
    assert_eq!(Envelope::parse(&b), Err(EnvError::Nullifier));
}

#[test]
fn envelope_identity_is_accepted_and_small_order_points_are_rejected() {
    let id = EdwardsAffine::default();
    assert!(id.is_zero());
    assert_eq!(keys::point_from_bytes(&keys::point_to_bytes(&id)), Some(id));
    // (0, -1) has order 2 on Jubjub.
    let two = EdwardsAffine::new_unchecked(Fr::from(0u64), -Fr::from(1u64));
    assert!(two.is_on_curve());
    assert!(!two.is_in_correct_subgroup_assuming_on_curve());
    assert_eq!(keys::point_from_bytes(&keys::point_to_bytes(&two)), None);
    let bytes = transfer().to_bytes();
    let mut b = bytes.clone();
    b[76..108].copy_from_slice(&keys::point_to_bytes(&two));
    assert_eq!(Envelope::parse(&b), Err(EnvError::PkEph));
    let mut b = bytes.clone();
    b[76..108].copy_from_slice(&[0x55; 32]);
    assert!(Envelope::parse(&b).is_err());
    // The identity as pk_eph decrypts to nothing for everyone.
    let mut t = transfer();
    t.pk_eph[0] = id;
    let Ok(Some(Envelope::Transfer(t))) = Envelope::parse(&t.to_bytes()) else {
        panic!("identity pk_eph does not parse")
    };
    let sk_view = WalletKeys::from_seed([3u8; 32]).derive().sk_view;
    assert_eq!(
        note::decrypt_as_recipient(&t.ct[0], &t.pk_eph[0], &sk_view),
        None
    );
}

#[test]
fn ciphertext_decrypting_above_the_packed_range_is_rejected() {
    let w = WalletKeys::from_seed([3u8; 32]);
    let a = w.address(0).unwrap();
    let der = w.derive();
    let s = note::sk_eph(&Fr::from(8u64));
    let g_d = keys::diversify_hash(&a.d).unwrap().base;
    let pk_eph = keys::mul(&g_d, &s);
    let key = note::note_key(&keys::mul(&a.pk_d, &s), &pk_eph);
    // m0 = d * 2^64 + v is legal; add 2^152, one bit above the 19 packed bytes.
    let mut m0 = note::pack_vd(u64::MAX, &a.d);
    m0 += Fr::from(2u64).pow([152u64]);
    let ct = note::encrypt_with_key(&key, &m0, &Fr::from(8u64));
    assert_eq!(note::decrypt_as_recipient(&ct, &pk_eph, &der.sk_view), None);
    let ct = note::encrypt_with_key(&key, &(-Fr::from(1u64)), &Fr::from(8u64));
    assert_eq!(note::decrypt_as_recipient(&ct, &pk_eph, &der.sk_view), None);
}

#[test]
fn envelope_random_payloads_with_magic_never_panic() {
    use rand::{Rng, SeedableRng};
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    for _ in 0..20_000 {
        let len = rng.gen_range(0..900);
        let mut b: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
        if b.len() >= 6 {
            b[..3].copy_from_slice(b"sbp");
            b[3] = 1;
            b[4] = rng.gen_range(0..4);
            b[5] = 0;
        }
        let _ = Envelope::parse(&b);
    }
}

/// A scripted Electrum server: `reply(request)` gives the bytes to write,
/// None closes that socket. Accepts any number of connections.
fn mock<F>(reply: F) -> String
where
    F: FnMut(&Value) -> Option<Vec<u8>> + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let reply = Arc::new(Mutex::new(reply));
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            let reply = reply.clone();
            thread::spawn(move || {
                let mut w = s.try_clone().unwrap();
                let mut r = BufReader::new(s);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let Ok(req) = serde_json::from_str::<Value>(&line) else {
                        return;
                    };
                    match (reply.lock().unwrap())(&req) {
                        Some(b) if w.write_all(&b).is_ok() => {}
                        _ => return,
                    }
                }
            });
        }
    });
    addr
}

fn ok(req: &Value, result: Value) -> Vec<u8> {
    format!("{}\n", json!({"id": req["id"], "result": result})).into_bytes()
}

fn rpc_err(req: &Value, code: i64, message: &str) -> Vec<u8> {
    format!(
        "{}\n",
        json!({"id": req["id"], "error": {"code": code, "message": message}})
    )
    .into_bytes()
}

fn version_then<F>(mut f: F) -> impl FnMut(&Value) -> Option<Vec<u8>> + Send
where
    F: FnMut(&Value) -> Option<Vec<u8>> + Send,
{
    move |req| {
        if req["method"] == "server.version" {
            Some(ok(req, json!(["mock", "1.4"])))
        } else {
            f(req)
        }
    }
}

fn method(req: &Value) -> &str {
    req["method"].as_str().unwrap_or("")
}

fn genesis_hex(network: Network) -> String {
    hex::encode(bitcoin::consensus::serialize(
        &genesis_block(network).header,
    ))
}

/// A server that answers every header request with the same header and
/// serves empty blocks.
fn one_header_server(hdr: String, tip: u32) -> String {
    mock(version_then(move |req| {
        Some(match method(req) {
            "blockchain.headers.subscribe" => ok(req, json!({"height": tip})),
            "blockchain.block.header" => ok(req, json!(hdr)),
            "blockchain.transaction.id_from_pos" => rpc_err(req, 1, "No transaction at position 0"),
            _ => ok(req, Value::Null),
        })
    }))
}

#[test]
fn connect_checked_accepts_the_networks_genesis_and_refuses_another() {
    let addr = one_header_server(genesis_hex(Network::Signet), 1000);
    assert!(Electrum::connect_checked(&addr, Network::Signet).is_ok());
    match Electrum::connect_checked(&addr, Network::Bitcoin) {
        Err(ChainError::WrongGenesis { expected, got }) => {
            assert_eq!(expected, genesis_block(Network::Bitcoin).block_hash());
            assert_eq!(got, genesis_block(Network::Signet).block_hash());
        }
        r => panic!("{:?}", r.err()),
    }
    let addr = one_header_server("11".repeat(80), 1000);
    assert!(matches!(
        Electrum::connect_checked(&addr, Network::Signet),
        Err(ChainError::WrongGenesis { .. })
    ));
}

#[test]
fn sync_on_a_foreign_chain_is_an_error_not_a_rebuild() {
    let addr = one_header_server("11".repeat(80), 1000);
    let mut e = Electrum::connect(&addr).unwrap();
    let mut st = State::fresh(Deployment {
        activation_hash: Some(BlockHash::all_zeros()),
        ..dep()
    });
    st.tree.append(Fr::from(1u64));
    st.replayed_height = 1000;
    st.block_hashes.insert(1000, BlockHash::all_zeros());
    assert!(matches!(
        st.sync(&mut e, params()),
        Err(IndexerError::WrongChain { .. })
    ));
    assert_eq!(st.tree.len(), 1, "state rebuilt on a foreign chain");
    assert_eq!(st.replayed_height, 1000);
}

/// Without an activation hash (older profiles) a moved tip is still a reorg.
#[test]
fn sync_without_activation_hash_keeps_treating_a_moved_tip_as_a_reorg() {
    let addr = one_header_server("11".repeat(80), 1000);
    let mut e = Electrum::connect(&addr).unwrap();
    let mut st = State::fresh(dep());
    st.tree.append(Fr::from(1u64));
    st.replayed_height = 1000;
    st.block_hashes.insert(1000, BlockHash::all_zeros());
    st.sync(&mut e, params()).unwrap();
    assert_eq!(st.tree.len(), 0);
    assert_eq!(st.replayed_height, 1000);
}

#[test]
fn electrum_malformed_json_is_an_error() {
    let addr = mock(version_then(|_| Some(b"{not json\n".to_vec())));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(matches!(e.tip_height(), Err(ChainError::Json(_))));
}

#[test]
fn electrum_right_id_wrong_type_is_an_error() {
    let addr = mock(version_then(|req| Some(ok(req, json!("a string")))));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(e.tip_height().is_err());
    assert!(e.block_hash(1).is_err());
    assert!(e.block_txids(1).is_err());
    assert!(e.transaction(&Txid::all_zeros()).is_err());
    assert!(e.listunspent(&ScriptBuf::new()).is_err());
    assert!(e.history(&ScriptBuf::new()).is_err());
}

#[test]
fn electrum_error_without_code_or_message_is_an_error() {
    let addr = mock(version_then(|req| {
        Some(format!("{}\n", json!({"id": req["id"], "error": {}})).into_bytes())
    }));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(matches!(
        e.tip_height(),
        Err(ChainError::Rpc { code: 0, .. })
    ));
    let addr = mock(version_then(|req| {
        Some(format!("{}\n", json!({"id": req["id"], "error": "boom"})).into_bytes())
    }));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(e.tip_height().is_err());
}

#[test]
fn electrum_short_header_non_hex_tx_and_bad_txid_are_errors() {
    let addr = mock(version_then(|req| {
        Some(match method(req) {
            "blockchain.block.header" => ok(req, json!("00".repeat(40))),
            "blockchain.transaction.get" => ok(req, json!("zz")),
            "blockchain.transaction.id_from_pos" => ok(req, json!("nottxid")),
            _ => ok(req, Value::Null),
        })
    }));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(e.block_hash(1).is_err());
    assert!(e.transaction(&Txid::all_zeros()).is_err());
    assert!(e.block_txids(1).is_err());
}

#[test]
fn electrum_connection_drop_mid_block_leaves_state_untouched() {
    let hdr = "00".repeat(80);
    let addr = mock(version_then(move |req| {
        Some(match method(req) {
            "blockchain.headers.subscribe" => ok(req, json!({"height": 1001})),
            "blockchain.block.header" => ok(req, json!(hdr)),
            _ => return None,
        })
    }));
    let mut e = Electrum::connect(&addr).unwrap();
    let mut st = State::fresh(dep());
    let err = st.sync(&mut e, params()).unwrap_err();
    assert!(err.to_string().contains("closed"), "{err}");
    assert_eq!(st.replayed_height, 999);
    assert!(st.block_hashes.is_empty());
}

/// The 30 s read timeout is the only guard against a silent server.
#[test]
#[ignore = "waits out the 30 s read timeout"]
fn electrum_server_that_never_answers_times_out() {
    let addr = mock(version_then(|_| {
        thread::sleep(std::time::Duration::from_secs(40));
        None
    }));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(matches!(e.tip_height(), Err(ChainError::Io(_))));
}

/// A server that never says "No transaction at position" ends at the cap.
#[test]
#[ignore = "a million loopback round trips, about 40 s"]
fn electrum_block_txids_stops_at_the_cap() {
    let addr = mock(version_then(|req| {
        Some(ok(req, json!(Txid::all_zeros().to_string())))
    }));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(matches!(
        e.block_txids(7),
        Err(ChainError::BlockTooLarge(7))
    ));
}

#[test]
fn electrum_overlong_reply_is_an_error() {
    let addr = mock(version_then(|_| {
        let mut v = vec![b'a'; 17 << 20];
        v.push(b'\n');
        Some(v)
    }));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(matches!(e.tip_height(), Err(ChainError::ReplyTooLong)));
}

#[test]
fn electrum_height_over_u32_is_an_error() {
    let addr = mock(version_then(|req| {
        Some(match method(req) {
            "blockchain.headers.subscribe" => ok(req, json!({"height": (1u64 << 32) + 5})),
            "blockchain.scripthash.listunspent" => ok(
                req,
                json!([{"tx_hash": Txid::all_zeros().to_string(), "tx_pos": 0,
                    "value": 1, "height": 1u64 << 32}]),
            ),
            _ => ok(req, Value::Null),
        })
    }));
    let mut e = Electrum::connect(&addr).unwrap();
    assert!(e.tip_height().is_err());
    assert!(e.listunspent(&ScriptBuf::new()).is_err());
}

#[test]
fn sync_caps_the_rejection_log() {
    let mut st = State::fresh(dep());
    for i in 0..(MAX_REJECTIONS + 500) {
        st.rejections.push(Rejection {
            txid: Txid::all_zeros(),
            height: i as u32,
            reason: String::new(),
        });
    }
    let mut chain = MockChain::new(999);
    chain.mine(vec![]);
    st.sync(&mut chain, params()).unwrap();
    assert_eq!(st.rejections.len(), MAX_REJECTIONS);
    assert_eq!(st.rejections[0].height, 500);
}

fn sbp(args: &[&str], cwd: &std::path::Path) -> (i32, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sbp"))
        .args(args)
        .current_dir(cwd)
        .env("RUST_LOG", "warn")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn cli_names_the_missing_profile_checks_state_against_it_and_refuses_a_zero_mint() {
    let root = tmp("cli");
    std::fs::create_dir_all(&root).unwrap();
    let state = root.join("state");
    let wallet = root.join("w.json");
    let (w, s, params_dir) = (
        wallet.to_str().unwrap(),
        state.to_str().unwrap(),
        root.join("params").to_str().unwrap().to_owned(),
    );
    let (code, _) = sbp(&["init", "--wallet", w, "--state", s], &root);
    assert_eq!(code, 0);
    let (code, text) = sbp(&["status", "--state", s], &root);
    assert_ne!(code, 0);
    assert!(
        text.contains(&format!(
            "reading {}",
            state.join("deployment.json").display()
        )),
        "{text}"
    );
    let electrum = one_header_server(genesis_hex(Network::Signet), 1000);
    let (code, text) = sbp(
        &[
            "--params",
            &params_dir,
            "--electrum",
            &electrum,
            "deploy",
            "--state",
            s,
            "--activation",
            "1",
            "--operator-wallet",
            w,
        ],
        &root,
    );
    assert_eq!(code, 0, "{text}");
    let profile = std::fs::read(state.join("deployment.json")).unwrap();
    assert_eq!(profile.last(), Some(&b'\n'));
    assert!(text.contains(&format!(
        "activation hash {}",
        genesis_block(Network::Signet).block_hash()
    )));
    let (code, text) = sbp(
        &[
            "--electrum",
            &electrum,
            "mint",
            "--state",
            s,
            "--wallet",
            w,
            "--amount",
            "0",
        ],
        &root,
    );
    assert_ne!(code, 0);
    assert!(text.contains("amount must be positive"), "{text}");
    // A state file replayed for another deployment.
    let dep: Deployment = serde_json::from_slice(&profile).unwrap();
    State::fresh(Deployment {
        activation: 500,
        ..dep
    })
    .save(&state.join("state.json"))
    .unwrap();
    let (code, text) = sbp(&["status", "--state", s], &root);
    assert_ne!(code, 0);
    assert!(text.contains("another deployment"), "{text}");
    assert!(!text.contains("panicked"));
}

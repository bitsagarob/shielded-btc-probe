//! Hostile-input tests ported from the robustness review, adjusted to the
//! fixed behaviour. Nothing here broadcasts; every Electrum test talks to a
//! scripted mock on loopback that the test itself owns.

use bitcoin::Txid;
use bitcoin::{BlockHash, Network, ScriptBuf, blockdata::constants::genesis_block, hashes::Hash};
use serde_json::{Value, json};
use shielded_probe::{
    Fr,
    chain::{ChainSource, Electrum, Error as ChainError, MockChain},
    indexer::{Deployment, Error as IndexerError, MAX_REJECTIONS, Rejection, State},
    prover::Params,
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

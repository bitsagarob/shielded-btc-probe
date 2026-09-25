//! Two indexers fed the same carriers reach the same state, through a
//! save/load cycle in between, and write byte-identical state files.
use bitcoin::{
    Amount, Network, ScriptBuf, Transaction, TxOut, Txid, absolute, hashes::Hash,
    script::PushBytesBuf, transaction,
};
use shielded_probe::{
    Fr,
    envelope::MintEnvelope,
    indexer::{Deployment, State},
    prover::Params,
    wallet::Wallet,
};

fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("sbp-det-{name}-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
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
fn close(st: &mut State, h: u32) {
    st.roots.insert(h, st.tree.root());
    st.leaf_counts.insert(h, st.tree.len());
    st.replayed_height = h;
}

#[test]
fn two_indexers_replaying_the_same_bytes_agree_across_a_save_load_cycle() {
    let params = Params::setup_insecure().unwrap();
    let op = Wallet::create(&tmp("op")).unwrap();
    let mut alice = Wallet::create(&tmp("alice")).unwrap();
    let bob = Wallet::create(&tmp("bob")).unwrap();
    let dep = Deployment {
        network: Network::Signet,
        fee_rate_sat_vb: 2,
        activation: 10,
        vault_script_pubkey: op.vault().script_pubkey(),
        operator_address: op.address().to_string(),
        vk_fingerprint: "t".into(),
    };
    let vault = dep.vault_script_pubkey.clone();
    let a = alice.address();
    let mint = MintEnvelope {
        d: a.d,
        pk_d: a.pk_d,
        r_seed: Fr::from(5u64),
    }
    .to_bytes();
    let mint_tx = tx(vec![
        TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: vault.clone(),
        },
        push(&mint),
    ]);
    let id = |b: u8| Txid::from_byte_array([b; 32]);

    let mut x = State::fresh(dep.clone());
    let mut y = State::fresh(dep.clone());
    for st in [&mut x, &mut y] {
        close(st, 10);
        st.replay_tx(&params, 11, id(1), &mint_tx, &vault).unwrap();
        close(st, 11);
        close(st, 12);
    }
    alice.scan(&x).unwrap();
    let built = alice
        .build_transfer(&x, &params, &bob.address(), 600, None)
        .unwrap();
    let carrier = tx(vec![push(&built.envelope.to_bytes())]);

    // x goes through disk before block 13; y stays in memory.
    let px = tmp("state-x");
    x.save(&px).unwrap();
    let mut x = State::load(&px).unwrap();
    x.replay_tx(&params, 13, id(2), &carrier, &vault).unwrap();
    y.replay_tx(&params, 13, id(2), &carrier, &vault).unwrap();
    close(&mut x, 13);
    close(&mut y, 13);

    assert_eq!(x.tree.root(), y.tree.root());
    assert_eq!(x.tree.len(), 3);
    assert_eq!(x.nullifiers, y.nullifiers);
    assert_eq!(x.roots, y.roots);
    let py = tmp("state-y");
    x.save(&px).unwrap();
    y.save(&py).unwrap();
    assert_eq!(
        std::fs::read(&px).unwrap(),
        std::fs::read(&py).unwrap(),
        "state files differ"
    );
    let z = State::load(&px).unwrap();
    assert_eq!(z.tree.root(), y.tree.root());
    assert_eq!(
        z.tree.path(2).unwrap().root(&z.tree.leaf(2).unwrap()),
        z.tree.root()
    );
}

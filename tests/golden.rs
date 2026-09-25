//! Golden vectors: fixed inputs, fixed expected bytes and hashes, checked
//! into tests/golden-vectors.json and shared with js/test-golden.mjs.
//! Regenerate with SBP_WRITE_GOLDEN=1 cargo test --release --test golden.

use ark_ff::PrimeField;
use serde_json::{Value, json};
use shielded_probe::{
    Fr, Fs,
    envelope::{CT_OUT_LEN, Envelope, MintEnvelope, PROOF_LEN, Payout, TransferEnvelope},
    keys::{self, WalletKeys},
    note::{self, NotePlaintext},
    poseidon::{self, tag},
    tree::MerkleTree,
};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden-vectors.json");

fn fr(x: &Fr) -> String {
    hex::encode(keys::fr_to_bytes(x))
}
fn pt(p: &shielded_probe::EdwardsAffine) -> String {
    hex::encode(keys::point_to_bytes(p))
}
fn fs(s: &Fs) -> String {
    hex::encode(keys::scalar_to_bytes(s))
}

fn generate() -> Value {
    let alice = WalletKeys::from_seed([1u8; 32]);
    let bob = WalletKeys::from_seed([2u8; 32]);
    let (da, db) = (alice.derive(), bob.derive());
    let (a0, a1, b0) = (alice.address(0), alice.address(1), bob.address(0));
    let div = keys::diversify_hash(&a0.d).unwrap();

    // One note to bob, one change note to alice, fixed r_seeds.
    let n0 = NotePlaintext {
        v: 60_000,
        d: b0.d,
        r_seed: Fr::from(2001u64),
    };
    let n1 = NotePlaintext {
        v: 40_000,
        d: a1.d,
        r_seed: Fr::from(2002u64),
    };
    let (pk0, ct0) = note::encrypt(&n0, &b0.pk_d).unwrap();
    let (pk1, ct1) = note::encrypt(&n1, &a1.pk_d).unwrap();
    let records = [
        (b0.pk_d, note::sk_eph(&n0.r_seed)),
        (a1.pk_d, note::sk_eph(&n1.r_seed)),
    ];
    let mut env = TransferEnvelope {
        h_anchor: 0x01020304,
        nf: [Fr::from(1u64), Fr::from(2u64)],
        pk_eph: [pk0, pk1],
        ct: [ct0, ct1],
        ct_out: vec![],
        payout: Some(Payout {
            amount: 1000,
            script_pubkey: vec![0x00, 0x14].into_iter().chain([0xabu8; 20]).collect(),
        }),
        proof: vec![0x77u8; PROOF_LEN],
    };
    env.ct_out = note::encrypt_recovery(&records, &env.recovery_binding(), &da.vk_out);
    assert_eq!(env.ct_out.len(), CT_OUT_LEN);
    let mut wide = env.clone();
    wide.payout = Some(Payout {
        amount: 7,
        script_pubkey: vec![0x51; 300],
    });
    let mut plain = env.clone();
    plain.payout = None;
    let mint = MintEnvelope {
        d: a0.d,
        pk_d: a0.pk_d,
        r_seed: Fr::from(5u64),
    };

    let h_body = env.h_body();
    let mut tree = MerkleTree::new();
    let empty_root = tree.root();
    for i in 1..=5u64 {
        tree.append(Fr::from(i * 1000));
    }
    let path = tree.path(2).unwrap();
    let rho = note::rho(&n1.r_seed);

    json!({
        "seed_alice": hex::encode(alice.seed), "seed_bob": hex::encode(bob.seed),
        "keys": {
            "sk_spend": fs(&da.sk_spend), "sk_nf": fr(&da.sk_nf), "vk_in": fr(&da.vk_in),
            "sk_view": fs(&da.sk_view), "vk_out": hex::encode(da.vk_out),
            "bob_vk_in": fr(&db.vk_in),
        },
        "address": { "d": hex::encode(a0.d), "pk_d": pt(&a0.pk_d), "text": a0.to_string(),
                     "d1": hex::encode(a1.d), "pk_d1": pt(&a1.pk_d), "bob_text": b0.to_string() },
        "diversify": { "d": hex::encode(a0.d), "base": pt(&div.base), "k": div.k },
        "poseidon": {
            "leaf_1_2": fr(&poseidon::hash(tag::LEAF, &[Fr::from(1u64), Fr::from(2u64)])),
            "bytes_body_abc": fr(&poseidon::hash_bytes(tag::BODY, b"abc")),
            "bytes_body_40": fr(&poseidon::hash_bytes(tag::BODY, &[0x5au8; 40])),
        },
        "note": {
            "v": n0.v, "d": hex::encode(n0.d), "r_seed": fr(&n0.r_seed), "to_pk_d": pt(&b0.pk_d),
            "sk_eph": fs(&note::sk_eph(&n0.r_seed)), "pk_eph": pt(&pk0), "ct": hex::encode(ct0.to_bytes()),
            "rho": fr(&rho),
            "leaf_j1": fr(&note::leaf(&h_body, 1, &pk1, &ct1)),
            "mint_leaf": fr(&note::mint_leaf(1234, &a0.d, &a0.pk_d, &Fr::from(5u64))),
            "nullifier_pos7": fr(&note::nullifier(&da.sk_nf, &rho, 7)),
        },
        "envelope": {
            "bytes": hex::encode(env.to_bytes()), "len": env.to_bytes().len(),
            "h_body": fr(&h_body), "statement_digest": fr(&env.statement_digest()),
            "recovery_binding": hex::encode(env.recovery_binding()), "ct_out": hex::encode(&env.ct_out),
            "wide_payout_bytes": hex::encode(wide.to_bytes()), "wide_payout_h_body": fr(&wide.h_body()),
            "no_payout_bytes": hex::encode(plain.to_bytes()),
            "mint_bytes": hex::encode(mint.to_bytes()),
            "outputs": [
                {"j": 0, "recipient_vk_in": fr(&db.vk_in), "v": n0.v, "d": hex::encode(n0.d), "r_seed": fr(&n0.r_seed), "to": b0.to_string()},
                {"j": 1, "recipient_vk_in": fr(&da.vk_in), "v": n1.v, "d": hex::encode(n1.d), "r_seed": fr(&n1.r_seed), "to": a1.to_string()},
            ],
        },
        "merkle": {
            "empty_root": fr(&empty_root), "leaves": (1..=5u64).map(|i| fr(&Fr::from(i*1000))).collect::<Vec<_>>(),
            "root": fr(&tree.root()), "path_pos": 2, "path_siblings": path.siblings.iter().map(fr).collect::<Vec<_>>(),
        },
        "fr_modulus": Fr::MODULUS.to_string(),
    })
}

fn diff(path: &str, want: &Value, got: &Value, out: &mut Vec<String>) {
    match (want, got) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in a {
                match b.get(k) {
                    Some(g) => diff(&format!("{path}.{k}"), v, g, out),
                    None => out.push(format!("{path}.{k}: missing in generated")),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (v, g)) in a.iter().zip(b).enumerate() {
                diff(&format!("{path}[{i}]"), v, g, out);
            }
        }
        _ if want != got => out.push(format!("{path}: golden {want} != code {got}")),
        _ => {}
    }
}

#[test]
fn golden_vectors_match() {
    let got = generate();
    if std::env::var_os("SBP_WRITE_GOLDEN").is_some() {
        std::fs::write(PATH, serde_json::to_string_pretty(&got).unwrap()).unwrap();
        return;
    }
    let want: Value =
        serde_json::from_str(&std::fs::read_to_string(PATH).expect("tests/golden-vectors.json"))
            .unwrap();
    let mut out = Vec::new();
    diff("golden", &want, &got, &mut out);
    assert!(
        out.is_empty(),
        "drift from golden vectors:\n{}",
        out.join("\n")
    );
    // The golden envelope bytes must parse back to exactly themselves.
    let b = hex::decode(want["envelope"]["bytes"].as_str().unwrap()).unwrap();
    let Ok(Some(Envelope::Transfer(t))) = Envelope::parse(&b) else {
        panic!("golden envelope does not parse")
    };
    assert_eq!(t.to_bytes(), b);
    let wide = hex::decode(want["envelope"]["wide_payout_bytes"].as_str().unwrap()).unwrap();
    assert_eq!(
        wide[6 + 4 + 2 + 64 + 64 + 192 + CT_OUT_LEN],
        0xfd,
        "wide payout uses the 0xfd CompactSize form"
    );
    assert!(matches!(
        Envelope::parse(&wide),
        Ok(Some(Envelope::Transfer(_)))
    ));
}

//! Negative tests for the soundness/robustness checks no existing test pins.
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use shielded_probe::{
    Fr,
    circuit::{TransferCircuit, sample::sample_witness},
    keys::{self, WalletKeys},
    note,
    prover::Params,
};

/// A disabled input skips the Merkle check, so it must carry no value.
#[test]
fn circuit_rejects_value_on_a_disabled_input() {
    let (mut w, p) = sample_witness();
    w.inputs[1].enabled = false; // keeps v = 30_000 and its (now unchecked) path
    let cs = ConstraintSystem::<Fr>::new_ref();
    TransferCircuit {
        public: Some(p),
        witness: Some(w),
    }
    .generate_constraints(cs.clone())
    .unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "a disabled input with value was accepted"
    );
}

/// A ciphertext whose MAC verifies under the honest key but whose r_seed does
/// not derive pk_eph (paper 16.1 post-decryption check) must not decrypt.
#[test]
fn decrypt_as_recipient_rejects_a_ciphertext_whose_r_seed_does_not_derive_pk_eph() {
    let bob = WalletKeys::from_seed([1u8; 32]);
    let addr = bob.address(3);
    let der = bob.derive();
    let honest_r = Fr::from(99u64);
    let g_d = keys::diversify_hash(&addr.d).unwrap().base;
    let s = note::sk_eph(&honest_r);
    let pk_eph = keys::mul(&g_d, &s);
    let key = note::note_key(&keys::mul(&addr.pk_d, &s), &pk_eph);
    let forged = note::encrypt_with_key(&key, &note::pack_vd(5, &addr.d), &(honest_r + Fr::ONE));
    assert_eq!(
        note::decrypt_as_recipient(&forged, &pk_eph, &der.sk_view),
        None
    );
    let good = note::encrypt_with_key(&key, &note::pack_vd(5, &addr.d), &honest_r);
    assert!(note::decrypt_as_recipient(&good, &pk_eph, &der.sk_view).is_some());
}

/// A proof made for one anchor must not verify against another (the anchor
/// is a public input, and the circuit ties every enabled path to it).
#[test]
fn prove_and_verify_rejects_wrong_r_anchor() {
    let params = Params::setup_insecure().unwrap();
    let (w, p) = sample_witness();
    let proof = params.prove(&p, &w).unwrap();
    assert!(params.verify(&p, &proof));
    let wrong = shielded_probe::circuit::PublicInputs {
        r_anchor: p.r_anchor + Fr::ONE,
        ..p
    };
    assert!(
        !params.verify(&wrong, &proof),
        "proof verified under a different r_anchor"
    );
}

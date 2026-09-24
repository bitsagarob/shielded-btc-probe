//! Checks whether a Groth16 public input that no constraint touches binds
//! the proof. In arkworks it does: the libsnark-style R1CS to QAP reduction
//! adds one constraint per public input for exactly this reason. So h_body
//! being "only" a public input is safe with this backend. Other backends may
//! differ, which is why the transfer circuit hashes h_body into the digest
//! rather than relying on the reduction.

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use rand::SeedableRng;

#[derive(Clone)]
struct Naive {
    h_body: Option<Fr>,
    x: Option<Fr>,
    constrain_h_body: bool,
}

impl ConstraintSynthesizer<Fr> for Naive {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let h_body = FpVar::new_input(cs.clone(), || {
            self.h_body.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let x = FpVar::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // some unrelated statement
        (&x * &x).enforce_equal(&FpVar::constant(Fr::from(49u64)))?;
        if self.constrain_h_body {
            // any constraint that mentions h_body binds it
            (&h_body * &x).enforce_equal(&(&x * &h_body))?;
        }
        Ok(())
    }
}

fn run(constrain: bool) -> bool {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        Naive {
            h_body: None,
            x: None,
            constrain_h_body: constrain,
        },
        &mut rng,
    )
    .unwrap();
    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        Naive {
            h_body: Some(Fr::from(1u64)),
            x: Some(Fr::from(7u64)),
            constrain_h_body: constrain,
        },
        &mut rng,
    )
    .unwrap();
    // verify against a DIFFERENT h_body
    Groth16::<Bls12_381>::verify(&vk, &[Fr::from(2u64)], &proof).unwrap()
}

#[test]
fn unconstrained_h_body_is_still_bound_by_arkworks() {
    assert!(
        !run(false),
        "arkworks adds input constraints in its QAP reduction, so this must not verify"
    );
}

#[test]
fn constrained_h_body_is_bound() {
    assert!(!run(true));
}

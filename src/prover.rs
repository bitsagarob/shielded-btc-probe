//! Groth16 over BLS12-381 for the transfer circuit.
//!
//! The setup is derived from a fixed seed so that every wallet and indexer
//! on the probe network computes identical keys. That means the toxic waste
//! is public and anyone can forge proofs. Fine for a signet probe, fatal
//! anywhere else. See PROFILE.md.

use crate::circuit::{PublicInputs, TransferCircuit, TransferWitness};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey, prepare_verifying_key,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::{path::Path, time::Instant};

pub const INSECURE_SETUP_SEED: &[u8; 32] = b"sbp-probe-insecure-toxic-waste-0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("reading proving key: {0}")]
    ProvingKey(SerializationError),
    #[error("reading verifying key: {0}")]
    VerifyingKey(SerializationError),
    #[error(transparent)]
    Serialization(#[from] SerializationError),
    #[error("setup: {0:?}")]
    Setup(SynthesisError),
    #[error("stored keys are for a circuit with {found} variables, this build has {expected}")]
    StaleKeys { expected: usize, found: usize },
    #[error("stored verifying key has {found} public inputs, this circuit has {expected}")]
    VerifyingKeyShape { expected: usize, found: usize },
    #[error("stored proving and verifying keys are from different setups")]
    KeyMismatch,
    #[error("prove: {0:?}")]
    Prove(SynthesisError),
}

pub struct Params {
    pub pk: ProvingKey<Bls12_381>,
    pub vk: VerifyingKey<Bls12_381>,
    pub pvk: PreparedVerifyingKey<Bls12_381>,
}

/// (instance, witness) variable counts of the transfer circuit: the length
/// of a matching verifying key's `gamma_abc_g1` and, summed, of a matching
/// proving key's `a_query`.
pub fn circuit_shape() -> Result<(usize, usize), Error> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    TransferCircuit {
        public: None,
        witness: None,
    }
    .generate_constraints(cs.clone())
    .map_err(Error::Setup)?;
    Ok((cs.num_instance_variables(), cs.num_witness_variables()))
}

pub fn circuit_variables() -> Result<usize, Error> {
    let (instance, witness) = circuit_shape()?;
    Ok(instance + witness)
}

impl Params {
    pub fn setup_insecure() -> Result<Self, Error> {
        let mut rng = ChaCha20Rng::from_seed(*INSECURE_SETUP_SEED);
        let circuit = TransferCircuit {
            public: None,
            witness: None,
        };
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
            .map_err(Error::Setup)?;
        let pvk = prepare_verifying_key(&vk);
        Ok(Self { pk, vk, pvk })
    }

    /// Loads `dir/transfer.pk` and `dir/transfer.vk`, generating them on
    /// first use. Logs how long generation took.
    pub fn load_or_setup(dir: &Path) -> Result<Self, Error> {
        let pk_path = dir.join("transfer.pk");
        let vk_path = dir.join("transfer.vk");
        if pk_path.exists() && vk_path.exists() {
            let pk = ProvingKey::deserialize_uncompressed_unchecked(std::fs::File::open(&pk_path)?)
                .map_err(Error::ProvingKey)?;
            let vk =
                VerifyingKey::deserialize_uncompressed_unchecked(std::fs::File::open(&vk_path)?)
                    .map_err(Error::VerifyingKey)?;
            let (instance, witness) = circuit_shape()?;
            if pk.a_query.len() != instance + witness {
                return Err(Error::StaleKeys {
                    expected: instance + witness,
                    found: pk.a_query.len(),
                });
            }
            if vk.gamma_abc_g1.len() != instance {
                return Err(Error::VerifyingKeyShape {
                    expected: instance,
                    found: vk.gamma_abc_g1.len(),
                });
            }
            if pk.vk != vk {
                return Err(Error::KeyMismatch);
            }
            let pvk = prepare_verifying_key(&vk);
            return Ok(Self { pk, vk, pvk });
        }
        std::fs::create_dir_all(dir)?;
        let t = Instant::now();
        let p = Self::setup_insecure()?;
        log::info!("groth16 setup took {:.1}s", t.elapsed().as_secs_f64());
        p.pk.serialize_uncompressed(std::fs::File::create(&pk_path)?)?;
        p.vk.serialize_uncompressed(std::fs::File::create(&vk_path)?)?;
        Ok(p)
    }

    pub fn vk_fingerprint(&self) -> String {
        let mut v = Vec::new();
        self.vk.serialize_compressed(&mut v).expect("in-memory");
        hex::encode(&Sha256::digest(&v)[..8])
    }

    /// Produces the 192-byte compressed proof.
    pub fn prove(
        &self,
        public: &PublicInputs,
        witness: &TransferWitness,
    ) -> Result<Vec<u8>, Error> {
        let mut rng = rand::thread_rng();
        let circuit = TransferCircuit {
            public: Some(public.clone()),
            witness: Some(witness.clone()),
        };
        let proof =
            Groth16::<Bls12_381>::prove(&self.pk, circuit, &mut rng).map_err(Error::Prove)?;
        let mut out = Vec::with_capacity(192);
        proof.serialize_compressed(&mut out)?;
        Ok(out)
    }

    pub fn verify(&self, public: &PublicInputs, proof: &[u8]) -> bool {
        let Ok(proof) = Proof::<Bls12_381>::deserialize_compressed(proof) else {
            return false;
        };
        Groth16::<Bls12_381>::verify_with_processed_vk(&self.pvk, &public.to_vec(), &proof)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::sample::sample_witness;

    #[test]
    fn stored_keys_are_checked_against_the_circuit_shape() {
        let dir = std::env::temp_dir().join(format!("sbp-params-{}", std::process::id()));
        let fresh = Params::load_or_setup(&dir).unwrap();
        assert_eq!(fresh.pk.a_query.len(), circuit_variables().unwrap());
        let loaded = Params::load_or_setup(&dir).unwrap();
        assert_eq!(loaded.vk_fingerprint(), fresh.vk_fingerprint());
        let mut truncated = fresh.pk.clone();
        truncated.a_query.pop();
        truncated
            .serialize_uncompressed(std::fs::File::create(dir.join("transfer.pk")).unwrap())
            .unwrap();
        assert!(matches!(
            Params::load_or_setup(&dir),
            Err(Error::StaleKeys { .. })
        ));
        fresh
            .pk
            .serialize_uncompressed(std::fs::File::create(dir.join("transfer.pk")).unwrap())
            .unwrap();
        let mut wide = fresh.vk.clone();
        wide.gamma_abc_g1.push(wide.gamma_abc_g1[0]);
        wide.serialize_uncompressed(std::fs::File::create(dir.join("transfer.vk")).unwrap())
            .unwrap();
        assert!(matches!(
            Params::load_or_setup(&dir),
            Err(Error::VerifyingKeyShape {
                expected: 3,
                found: 4
            })
        ));
        let mut foreign = fresh.vk.clone();
        foreign.gamma_abc_g1.swap(0, 1);
        foreign
            .serialize_uncompressed(std::fs::File::create(dir.join("transfer.vk")).unwrap())
            .unwrap();
        assert!(matches!(
            Params::load_or_setup(&dir),
            Err(Error::KeyMismatch)
        ));
        std::fs::write(dir.join("transfer.pk"), b"").unwrap();
        assert!(matches!(
            Params::load_or_setup(&dir),
            Err(Error::ProvingKey(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn prove_and_verify_roundtrip() {
        let params = Params::setup_insecure().unwrap();
        let (w, p) = sample_witness();
        let proof = params.prove(&p, &w).unwrap();
        assert_eq!(proof.len(), 192);
        assert!(params.verify(&p, &proof));
        let mut bad = p.clone();
        bad.digest += crate::Fr::from(1u64);
        assert!(!params.verify(&bad, &proof));
        let mut tampered = proof.clone();
        tampered[5] ^= 1;
        assert!(!params.verify(&p, &tampered));
    }
}

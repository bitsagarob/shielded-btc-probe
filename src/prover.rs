//! Groth16 over BLS12-381 for the transfer circuit.
//!
//! The setup is derived from a fixed seed so that every wallet and indexer
//! on the probe network computes identical keys. That means the toxic waste
//! is public and anyone can forge proofs. Fine for a signet probe, fatal
//! anywhere else. See PROFILE.md.

use crate::circuit::{PublicInputs, TransferCircuit, TransferWitness};
use anyhow::{Context, Result};
use ark_bls12_381::Bls12_381;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::Path;
use std::time::Instant;

pub const INSECURE_SETUP_SEED: &[u8; 32] = b"sbp-probe-insecure-toxic-waste-0";

pub struct Params {
    pub pk: ProvingKey<Bls12_381>,
    pub vk: VerifyingKey<Bls12_381>,
    pub pvk: PreparedVerifyingKey<Bls12_381>,
}

impl Params {
    pub fn setup_insecure() -> Result<Self> {
        let mut rng = ChaCha20Rng::from_seed(*INSECURE_SETUP_SEED);
        let circuit = TransferCircuit { public: None, witness: None };
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| anyhow::anyhow!("setup: {e:?}"))?;
        let pvk = prepare_verifying_key(&vk);
        Ok(Self { pk, vk, pvk })
    }

    /// Loads `dir/transfer.pk` and `dir/transfer.vk`, generating them on
    /// first use. Reports how long generation took on stderr.
    pub fn load_or_setup(dir: &Path) -> Result<Self> {
        let pk_path = dir.join("transfer.pk");
        let vk_path = dir.join("transfer.vk");
        if pk_path.exists() && vk_path.exists() {
            let pk = ProvingKey::deserialize_uncompressed_unchecked(std::fs::File::open(&pk_path)?)
                .context("reading proving key")?;
            let vk = VerifyingKey::deserialize_uncompressed_unchecked(std::fs::File::open(&vk_path)?)
                .context("reading verifying key")?;
            let pvk = prepare_verifying_key(&vk);
            return Ok(Self { pk, vk, pvk });
        }
        std::fs::create_dir_all(dir)?;
        let t = Instant::now();
        let p = Self::setup_insecure()?;
        eprintln!("groth16 setup took {:.1}s", t.elapsed().as_secs_f64());
        p.pk.serialize_uncompressed(std::fs::File::create(&pk_path)?)?;
        p.vk.serialize_uncompressed(std::fs::File::create(&vk_path)?)?;
        Ok(p)
    }

    pub fn vk_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut v = Vec::new();
        self.vk.serialize_compressed(&mut v).expect("in-memory");
        hex::encode(&Sha256::digest(&v)[..8])
    }

    /// Produces the 192-byte compressed proof.
    pub fn prove(&self, public: &PublicInputs, witness: &TransferWitness) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let circuit = TransferCircuit { public: Some(public.clone()), witness: Some(witness.clone()) };
        let proof = Groth16::<Bls12_381>::prove(&self.pk, circuit, &mut rng)
            .map_err(|e| anyhow::anyhow!("prove: {e:?}"))?;
        let mut out = Vec::with_capacity(192);
        proof.serialize_compressed(&mut out)?;
        Ok(out)
    }

    pub fn verify(&self, public: &PublicInputs, proof: &[u8]) -> bool {
        let Ok(proof) = Proof::<Bls12_381>::deserialize_compressed(proof) else {
            return false;
        };
        Groth16::<Bls12_381>::verify_with_processed_vk(&self.pvk, &public.to_vec(), &proof).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::sample::sample_witness;

    #[test]
    fn prove_and_verify_roundtrip() {
        let t = Instant::now();
        let params = Params::setup_insecure().unwrap();
        eprintln!("setup {:.1}s, vk {}", t.elapsed().as_secs_f64(), params.vk_fingerprint());
        let (w, p) = sample_witness();
        let t = Instant::now();
        let proof = params.prove(&p, &w).unwrap();
        eprintln!("prove {:.2}s, proof {} bytes", t.elapsed().as_secs_f64(), proof.len());
        assert_eq!(proof.len(), 192);
        let t = Instant::now();
        assert!(params.verify(&p, &proof));
        eprintln!("verify {:.1}ms", t.elapsed().as_secs_f64() * 1000.0);
        let mut bad = p.clone();
        bad.digest += crate::Fr::from(1u64);
        assert!(!params.verify(&bad, &proof));
        let mut tampered = proof.clone();
        tampered[5] ^= 1;
        assert!(!params.verify(&p, &tampered));
    }
}

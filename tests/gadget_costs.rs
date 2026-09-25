//! Constraint counts for the byte-hash gadgets the paper's defaults would
//! need in the circuit (PROFILE.md, remaining departures). Measurement only:
//! nothing here is wired into the transfer circuit.
//!
//!   cargo test --release --test gadget_costs -- --ignored --nocapture

use ark_crypto_primitives::{
    crh::sha256::constraints::Sha256Gadget,
    sponge::{constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar},
};
use ark_r1cs_std::{
    alloc::AllocVar, convert::ToBytesGadget, fields::fp::FpVar, prelude::*, uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use shielded_btc_probe::{Fr, N_IN, N_OUT, poseidon};

type Bytes = Vec<UInt8<Fr>>;

fn count(f: impl FnOnce(&ConstraintSystemRef<Fr>) -> Result<(), SynthesisError>) -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    f(&cs).unwrap();
    assert!(cs.is_satisfied().unwrap());
    cs.num_constraints()
}

fn sha256(data: &[UInt8<Fr>]) -> Result<Bytes, SynthesisError> {
    Ok(Sha256Gadget::<Fr>::digest(data)?.0)
}

/// HMAC-SHA256 with a 32-byte key.
fn hmac(key: &[UInt8<Fr>], msg: &[UInt8<Fr>]) -> Result<Bytes, SynthesisError> {
    let pad = |x: u8| -> Bytes {
        let mut v: Bytes = key.iter().map(|k| k ^ &UInt8::constant(x)).collect();
        v.resize(64, UInt8::constant(x));
        v
    };
    let mut inner = pad(0x36);
    inner.extend_from_slice(msg);
    let mut outer = pad(0x5c);
    outer.extend(sha256(&inner)?);
    sha256(&outer)
}

/// HKDF-SHA256, no salt, one 32-byte output block.
fn hkdf(ikm: &[UInt8<Fr>], info: &[u8]) -> Result<Bytes, SynthesisError> {
    let prk = hmac(&UInt8::constant_vec(&[0u8; 32]), ikm)?;
    let mut msg = UInt8::constant_vec(info);
    msg.push(UInt8::constant(1));
    hmac(&prk, &msg)
}

fn baseline() -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    shielded_btc_probe::circuit::TransferCircuit {
        public: None,
        witness: None,
    }
    .generate_constraints_for_count(cs.clone());
    cs.num_constraints()
}

trait CountOnly {
    fn generate_constraints_for_count(self, cs: ConstraintSystemRef<Fr>);
}
impl CountOnly for shielded_btc_probe::circuit::TransferCircuit {
    fn generate_constraints_for_count(self, cs: ConstraintSystemRef<Fr>) {
        use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisMode};
        cs.set_mode(SynthesisMode::Setup);
        self.generate_constraints(cs).unwrap();
    }
}

fn report(name: &str, per_gadget: usize, per_transfer: usize) {
    let base = baseline();
    println!(
        "{name}: {per_gadget} constraints per gadget, {per_transfer} per 2-in 2-out transfer, \
         baseline {base}, total {} ({:.1}x)",
        base + per_transfer,
        (base + per_transfer) as f64 / base as f64
    );
}

#[test]
#[ignore = "measurement"]
fn sha256_one_compression() {
    let n = count(|cs| {
        let data = UInt8::new_witness_vec(cs.clone(), &[7u8; 32])?;
        sha256(&data)?;
        Ok(())
    });
    println!("sha256 over 32 witness bytes (one compression): {n} constraints");
}

/// (a) Table 1 in circuit: sk_nf = HKDF_nf(ser(sk_spend)), vk_in =
/// HKDF_in(ser(sk_spend)), sk_view = ScalarFromBytes(HKDF_view(vk_in)).
#[test]
#[ignore = "measurement"]
fn key_chain_hkdf_sha256() {
    let n = count(|cs| {
        let sk_spend = FpVar::new_witness(cs.clone(), || Ok(Fr::from(12345u64)))?;
        let ser = sk_spend.to_bytes_le()?;
        let sk_nf = hkdf(&ser, b"sbp/nf")?;
        let vk_in = hkdf(&ser, b"sbp/in")?;
        let sk_view = hkdf(&vk_in, b"sbp/view")?;
        // BytesToField(sk_nf) and ScalarFromBytes(sk_view) are linear.
        let _ = Boolean::le_bits_to_fp(&sk_nf.to_bits_le()?[..253])?;
        let _ = sk_view.to_bits_le()?[..250].to_vec();
        Ok(())
    });
    // Derived once per transfer from the single sk_spend.
    report("(a) key chain, three HKDF-SHA256", n, n);
}

/// (b) A byte-oriented committing AEAD for the 67-byte recipient
/// ciphertext: keystream SHA256(key || ctr) x2, ct = pt xor ks, tag =
/// SHA256(key || ct)[..16]. Runs per output and per re-encrypted input.
#[test]
#[ignore = "measurement"]
fn recipient_aead_67_bytes() {
    let n = count(|cs| {
        let key = UInt8::new_witness_vec(cs.clone(), &[9u8; 32])?;
        let pt = UInt8::new_witness_vec(cs.clone(), &[5u8; 51])?;
        let mut ks = Vec::new();
        for ctr in 0..2u8 {
            let mut m = key.clone();
            m.push(UInt8::constant(ctr));
            ks.extend(sha256(&m)?);
        }
        let ct: Bytes = pt.iter().zip(&ks).map(|(p, k)| p ^ k).collect();
        let mut m = key.clone();
        m.extend_from_slice(&ct);
        let _tag = &sha256(&m)?[..16];
        Ok(())
    });
    report("(b) byte AEAD, 67-byte ct", n, n * (N_IN + N_OUT));
    let kdf = count(|cs| {
        let shared = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64)))?;
        let pk_eph = FpVar::new_witness(cs.clone(), || Ok(Fr::from(4u64)))?;
        let mut m = shared.to_bytes_le()?;
        m.extend(pk_eph.to_bytes_le()?);
        sha256(&m)?;
        Ok(())
    });
    report(
        "(b) plus a SHA-256 note KDF over two compressed points",
        kdf,
        kdf * (N_IN + N_OUT),
    );
}

/// (c) DiversifyHash seeded by SHA-256(d) instead of Poseidon(d): the
/// try-and-increment search that follows is unchanged.
#[test]
#[ignore = "measurement"]
fn diversify_hash_sha256_seed() {
    let sha = count(|cs| {
        let d = FpVar::new_witness(cs.clone(), || Ok(Fr::from(77u64)))?;
        let bytes = d.to_bytes_le()?[..11].to_vec();
        let h = sha256(&bytes)?;
        let _ = Boolean::le_bits_to_fp(&h.to_bits_le()?[..253])?;
        Ok(())
    });
    let pos = count(|cs| {
        let d = FpVar::new_witness(cs.clone(), || Ok(Fr::from(77u64)))?;
        let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), poseidon::config());
        sponge.absorb(&FpVar::constant(Fr::from(4u64)))?;
        sponge.absorb(&d)?;
        sponge.squeeze_field_elements(1)?;
        Ok(())
    });
    println!("(c) Poseidon(d) today: {pos} constraints per gadget");
    report(
        "(c) SHA-256(d) seed, delta per gadget",
        sha,
        (sha - pos) * (N_IN + N_OUT),
    );
}

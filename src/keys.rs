//! Key hierarchy (paper section 6) and diversified addresses.
//!
//! Native derivations off the wallet seed use HKDF-SHA256 as in the paper.
//! Everything the circuit has to re-derive (sk_nf, vk_in, sk_view, the
//! diversified base) uses Poseidon instead, because the paper's HKDF-SHA256
//! chain would otherwise have to be arithmetised inside the proof.

use crate::{
    DIV_HASH_TRIES, EdwardsAffine, EdwardsProjective, Fr, Fs,
    poseidon::{self, tag},
};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fmt, str::FromStr};

pub const DIVERSIFIER_LEN: usize = 11;
/// Scalars derived in-circuit are truncated to this many bits so they are
/// always below the Jubjub group order (about 2^251.8).
pub const SCALAR_BITS: usize = 250;

fn hkdf(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

pub fn fr_to_bytes(x: &Fr) -> [u8; 32] {
    let v = x.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

pub fn fr_from_bytes(b: &[u8]) -> Option<Fr> {
    if b.len() != 32 {
        return None;
    }
    let candidate = Fr::from_le_bytes_mod_order(b);
    (fr_to_bytes(&candidate)[..] == b[..]).then_some(candidate)
}

/// Fr element -> Jubjub scalar by keeping the low SCALAR_BITS bits.
pub fn scalar_from_field(x: &Fr) -> Fs {
    let bits = x.into_bigint().to_bits_le();
    let mut acc = Fs::ZERO;
    let two = Fs::from(2u64);
    for &bit in bits[..SCALAR_BITS].iter().rev() {
        acc *= two;
        if bit {
            acc += Fs::ONE;
        }
    }
    acc
}

pub fn point_to_bytes(p: &EdwardsAffine) -> [u8; 32] {
    let mut v = Vec::with_capacity(32);
    p.serialize_compressed(&mut v)
        .expect("in-memory serialisation");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

pub fn point_from_bytes(b: &[u8]) -> Option<EdwardsAffine> {
    EdwardsAffine::deserialize_compressed(b).ok()
}

/// Diversifier: 11 bytes, embedded in Fr as a little-endian integer.
pub fn diversifier_to_field(d: &[u8; DIVERSIFIER_LEN]) -> Fr {
    Fr::from_le_bytes_mod_order(d)
}

pub fn diversifier_from_field(x: &Fr) -> Option<[u8; DIVERSIFIER_LEN]> {
    let b = fr_to_bytes(x);
    if b[DIVERSIFIER_LEN..].iter().any(|&v| v != 0) {
        return None;
    }
    let mut d = [0u8; DIVERSIFIER_LEN];
    d.copy_from_slice(&b[..DIVERSIFIER_LEN]);
    Some(d)
}

/// Quadratic non-residue used by the in-circuit non-existence proofs of
/// DiversifyHash. Checked in a test.
pub fn nonresidue() -> Fr {
    Fr::from(7u64)
}

/// Result of DiversifyHash: the point plus the per-candidate square roots
/// that let the circuit check the search deterministically.
#[derive(Clone, Debug)]
pub struct DiversifyResult {
    pub base: EdwardsAffine,
    /// Index k of the candidate y = h + k that landed on the curve.
    pub k: usize,
    /// For each candidate 0..=k: the witnessed square root. For candidates
    /// before k it is sqrt(nonresidue * (y^2 - 1)(d y^2 + 1)); for k it is
    /// the even x coordinate.
    pub roots: Vec<Fr>,
}

/// Jubjub curve coefficient d.
pub fn edwards_d() -> Fr {
    <ark_ed_on_bls12_381::EdwardsConfig as ark_ec::twisted_edwards::TECurveConfig>::COEFF_D
}

/// DiversifyHash(d): try y = Poseidon(DIVERSIFY, d) + k for k = 0, 1, ...
/// until (y^2 - 1)(d y^2 + 1) is a square; take the even x; clear the
/// cofactor by three doublings. None when no candidate lands on the curve.
pub fn diversify_hash(d: &[u8; DIVERSIFIER_LEN]) -> Option<DiversifyResult> {
    let h = poseidon::hash(tag::DIVERSIFY, &[diversifier_to_field(d)]);
    let dd = edwards_d();
    let mut roots = Vec::new();
    for k in 0..DIV_HASH_TRIES {
        let y = h + Fr::from(k as u64);
        let y2 = y.square();
        let num = y2 - Fr::ONE;
        let den = dd * y2 + Fr::ONE;
        let prod = num * den;
        if let Some(x2root) = prod.sqrt() {
            // x^2 = num/den, x = sqrt(num*den)/den
            let x = x2root
                * den
                    .inverse()
                    .expect("den is never zero on a complete curve");
            let x = if is_even(&x) { x } else { -x };
            roots.push(x);
            let raw = EdwardsAffine::new_unchecked(x, y);
            debug_assert!(raw.is_on_curve());
            let cleared = (raw.into_group() * Fs::from(8u64)).into_affine();
            return Some(DiversifyResult {
                base: cleared,
                k,
                roots,
            });
        }
        let w = (nonresidue() * prod)
            .sqrt()
            .expect("prod is a non-square so nr*prod is a square");
        roots.push(w);
    }
    None
}

pub fn is_even(x: &Fr) -> bool {
    !x.into_bigint().is_odd()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WalletKeys {
    pub seed: [u8; 32],
}

/// Derived material. Everything here is recomputable from the seed.
#[derive(Clone, Debug)]
pub struct SpendingKeys {
    pub sk_master: [u8; 32],
    /// Spend authorisation secret, an Fr element used only through Poseidon.
    pub sk_spend: Fr,
    pub sk_nf: Fr,
    pub vk_in: Fr,
    pub sk_view: Fs,
    pub vk_out: [u8; 32],
}

impl WalletKeys {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn derive(&self) -> SpendingKeys {
        let sk_master = hkdf(&self.seed, b"sbp/master");
        let sk_spend = Fr::from_le_bytes_mod_order(&hkdf(&sk_master, b"sbp/spend"));
        let vk_out = hkdf(&sk_master, b"sbp/out");
        let sk_nf = derive_sk_nf(&sk_spend);
        let vk_in = derive_vk_in(&sk_spend);
        let sk_view = derive_sk_view(&vk_in);
        SpendingKeys {
            sk_master,
            sk_spend,
            sk_nf,
            vk_in,
            sk_view,
            vk_out,
        }
    }

    /// Diversified payment address (d, pk_d) for a receive path index.
    pub fn address(&self, index: u32) -> Address {
        let dk = hkdf(&self.derive().sk_master, b"sbp/diversifier");
        let mut d = [0u8; DIVERSIFIER_LEN];
        let raw = hkdf(&dk, &index.to_le_bytes());
        d.copy_from_slice(&raw[..DIVERSIFIER_LEN]);
        address_for(&self.derive(), d)
            .expect("an own diversifier is off-curve with probability 2^-32")
    }
}

pub fn derive_sk_nf(sk_spend: &Fr) -> Fr {
    poseidon::hash(tag::NF_KEY, &[*sk_spend])
}
pub fn derive_vk_in(sk_spend: &Fr) -> Fr {
    poseidon::hash(tag::VK_IN, &[*sk_spend])
}
pub fn derive_sk_view(vk_in: &Fr) -> Fs {
    scalar_from_field(&poseidon::hash(tag::SK_VIEW, &[*vk_in]))
}

pub fn address_for(der: &SpendingKeys, d: [u8; DIVERSIFIER_LEN]) -> Option<Address> {
    let g_d = diversify_hash(&d)?.base;
    let pk_d = (g_d.into_group() * der.sk_view).into_affine();
    Some(Address { d, pk_d })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub d: [u8; DIVERSIFIER_LEN],
    pub pk_d: EdwardsAffine,
}

/// Textual form: "sbp1" + hex(d || pk_d).
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v = self.d.to_vec();
        v.extend_from_slice(&point_to_bytes(&self.pk_d));
        write!(f, "sbp1{}", hex::encode(v))
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("not a shielded address: {0}")]
pub struct ParseAddressError(String);

impl FromStr for Address {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse = || {
            let v = hex::decode(s.strip_prefix("sbp1")?).ok()?;
            if v.len() != DIVERSIFIER_LEN + 32 {
                return None;
            }
            let mut d = [0u8; DIVERSIFIER_LEN];
            d.copy_from_slice(&v[..DIVERSIFIER_LEN]);
            diversify_hash(&d)?;
            let pk_d = point_from_bytes(&v[DIVERSIFIER_LEN..])?;
            Some(Self { d, pk_d })
        };
        parse().ok_or_else(|| ParseAddressError(s.to_owned()))
    }
}

/// Generic point projection used by every scalar multiplication that must
/// match the circuit: the circuit multiplies the affine base by the low
/// SCALAR_BITS bits of a field element, so callers pass the same.
pub fn mul_by_field_scalar(base: &EdwardsAffine, s: &Fr) -> EdwardsAffine {
    (base.into_group() * scalar_from_field(s)).into_affine()
}

pub fn mul(base: &EdwardsAffine, s: &Fs) -> EdwardsAffine {
    (base.into_group() * *s).into_affine()
}

pub fn generator() -> EdwardsAffine {
    EdwardsProjective::generator().into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn nonresidue_has_no_square_root() {
        assert!(nonresidue().sqrt().is_none());
    }

    #[test]
    fn diversify_hash_lands_in_prime_subgroup() {
        for i in 0..20u8 {
            let d = [i; DIVERSIFIER_LEN];
            let r = diversify_hash(&d).unwrap();
            assert!(r.base.is_on_curve());
            assert!(r.base.is_in_correct_subgroup_assuming_on_curve());
            assert_eq!(r.roots.len(), r.k + 1);
        }
    }

    #[test]
    fn diversify_hash_finds_a_point_for_random_diversifiers() {
        let mut rng = rand::thread_rng();
        for _ in 0..300 {
            let mut d = [0u8; DIVERSIFIER_LEN];
            rng.fill_bytes(&mut d);
            let r = diversify_hash(&d).unwrap();
            assert!(r.k < DIV_HASH_TRIES);
        }
    }

    #[test]
    fn address_display_from_str_roundtrip() {
        let w = WalletKeys::from_seed([7u8; 32]);
        let a = w.address(0);
        assert_eq!(a.to_string().parse::<Address>().unwrap(), a);
        assert_ne!(w.address(1).d, a.d);
    }

    #[test]
    fn scalar_from_field_keeps_low_bits() {
        let x = Fr::from(12345u64);
        assert_eq!(scalar_from_field(&x), Fs::from(12345u64));
    }
}

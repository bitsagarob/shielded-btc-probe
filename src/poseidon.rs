//! One Poseidon instance over BLS12-381 Fr (width 3, rate 2), used natively
//! and in-circuit. Every use is domain-separated by a tag absorbed first.

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use std::sync::OnceLock;

pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;
pub const ALPHA: u64 = 5;
pub const RATE: usize = 2;
pub const CAPACITY: usize = 1;

/// Domain tags. Each is absorbed as the first element of the sponge.
pub mod tag {
    pub const NF_KEY: u64 = 1; // sk_nf from sk_spend
    pub const VK_IN: u64 = 2; // vk_in from sk_spend
    pub const SK_VIEW: u64 = 3; // sk_view from vk_in
    pub const DIVERSIFY: u64 = 4; // DiversifyHash(d)
    pub const RHO: u64 = 5; // rho from r_seed
    pub const EPH: u64 = 6; // sk_eph from r_seed
    pub const KDF: u64 = 7; // note key from shared secret and pk_eph
    pub const STREAM: u64 = 8; // keystream block
    pub const MAC: u64 = 9; // ciphertext tag
    pub const LEAF: u64 = 10; // ciphertext-derived note leaf
    pub const MINT_LEAF: u64 = 11; // plaintext peg-in leaf
    pub const NF: u64 = 12; // nullifier
    pub const NODE: u64 = 13; // Merkle inner node
    pub const BODY: u64 = 14; // h_body over canonical body bytes
    pub const STMT: u64 = 15; // public statement digest
}

pub fn config() -> &'static PoseidonConfig<Fr> {
    static CFG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CFG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            255,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
    })
}

/// Poseidon(tag || inputs) -> one field element.
pub fn hash(tag: u64, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(config());
    sponge.absorb(&Fr::from(tag));
    for x in inputs {
        sponge.absorb(x);
    }
    sponge.squeeze_native_field_elements(1)[0]
}

/// Hash arbitrary bytes: packed into 31-byte little-endian field elements,
/// length-prefixed so the map is injective.
pub fn hash_bytes(tag: u64, bytes: &[u8]) -> Fr {
    use ark_ff::PrimeField;
    let mut elems = vec![Fr::from(bytes.len() as u64)];
    for chunk in bytes.chunks(31) {
        elems.push(Fr::from_le_bytes_mod_order(chunk));
    }
    hash(tag, &elems)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_and_tagged() {
        let a = hash(tag::LEAF, &[Fr::from(1u64), Fr::from(2u64)]);
        let b = hash(tag::LEAF, &[Fr::from(1u64), Fr::from(2u64)]);
        let c = hash(tag::NF, &[Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}

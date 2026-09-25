//! Notes, note encryption, leaves and nullifiers (paper sections 5, 9, 12).
//!
//! The recipient channel is a Poseidon stream cipher plus a Poseidon MAC.
//! It is key-committing because the tag is a collision-resistant hash of
//! the key and the ciphertext, which is what the paper's A6 asks for and
//! what a plain AEAD does not give.

use crate::{
    EdwardsAffine, Fr, Fs,
    keys::{self, DIVERSIFIER_LEN},
    poseidon::{self, tag},
};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePlaintext {
    pub v: u64,
    pub d: [u8; DIVERSIFIER_LEN],
    pub r_seed: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct Ciphertext {
    pub c0: Fr,
    pub c1: Fr,
    pub tag: Fr,
}

pub const CIPHERTEXT_LEN: usize = 96;

/// const_salt of sections 9 and 13.3: prefixed to the body under H_body and
/// absorbed first by H_leaf. Sixteen bytes, so the field form is canonical.
pub const CONST_SALT: &[u8; 16] = b"sbp/const_salt/1";

pub fn const_salt() -> Fr {
    Fr::from_le_bytes_mod_order(CONST_SALT)
}

/// aux_null: the h_aux slot of every leaf in this version (section 22.5).
pub fn aux_null() -> Fr {
    Fr::ZERO
}

impl Ciphertext {
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_LEN] {
        let mut out = [0u8; CIPHERTEXT_LEN];
        out[..32].copy_from_slice(&keys::fr_to_bytes(&self.c0));
        out[32..64].copy_from_slice(&keys::fr_to_bytes(&self.c1));
        out[64..].copy_from_slice(&keys::fr_to_bytes(&self.tag));
        out
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != CIPHERTEXT_LEN {
            return None;
        }
        Some(Self {
            c0: keys::fr_from_bytes(&b[..32])?,
            c1: keys::fr_from_bytes(&b[32..64])?,
            tag: keys::fr_from_bytes(&b[64..])?,
        })
    }
    pub fn fields(&self) -> [Fr; 3] {
        [self.c0, self.c1, self.tag]
    }
}

pub fn rho(r_seed: &Fr) -> Fr {
    poseidon::hash(tag::RHO, &[*r_seed])
}

/// The field element from which sk_eph is truncated. The circuit derives
/// the same element and uses its low bits as the scalar.
pub fn sk_eph_field(r_seed: &Fr) -> Fr {
    poseidon::hash(tag::EPH, &[*r_seed])
}

pub fn sk_eph(r_seed: &Fr) -> Fs {
    keys::scalar_from_field(&sk_eph_field(r_seed))
}

/// Packs (v, d) into one field element: v + d * 2^64.
pub fn pack_vd(v: u64, d: &[u8; DIVERSIFIER_LEN]) -> Fr {
    let mut bytes = [0u8; 19];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    bytes[8..].copy_from_slice(d);
    Fr::from_le_bytes_mod_order(&bytes)
}

pub fn unpack_vd(m: &Fr) -> Option<(u64, [u8; DIVERSIFIER_LEN])> {
    let b = m.into_bigint().to_bytes_le();
    if b[19..].iter().any(|&x| x != 0) {
        return None;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[..8]);
    let mut d = [0u8; DIVERSIFIER_LEN];
    d.copy_from_slice(&b[8..19]);
    Some((u64::from_le_bytes(v), d))
}

pub fn note_key(shared: &EdwardsAffine, pk_eph: &EdwardsAffine) -> Fr {
    poseidon::hash(tag::KDF, &[shared.x, shared.y, pk_eph.x, pk_eph.y])
}

pub fn encrypt_with_key(key: &Fr, m0: &Fr, m1: &Fr) -> Ciphertext {
    let c0 = *m0 + poseidon::hash(tag::STREAM, &[*key, Fr::from(0u64)]);
    let c1 = *m1 + poseidon::hash(tag::STREAM, &[*key, Fr::from(1u64)]);
    let t = poseidon::hash(tag::MAC, &[*key, c0, c1]);
    Ciphertext { c0, c1, tag: t }
}

/// Sender side. Returns (pk_eph, ciphertext), None when d has no diversified base.
pub fn encrypt(note: &NotePlaintext, pk_d: &EdwardsAffine) -> Option<(EdwardsAffine, Ciphertext)> {
    let g_d = keys::diversify_hash(&note.d)?.base;
    let s = sk_eph(&note.r_seed);
    let pk_eph = keys::mul(&g_d, &s);
    let shared = keys::mul(pk_d, &s);
    let key = note_key(&shared, &pk_eph);
    Some((
        pk_eph,
        encrypt_with_key(&key, &pack_vd(note.v, &note.d), &note.r_seed),
    ))
}

fn decrypt_with_key(key: &Fr, ct: &Ciphertext) -> Option<NotePlaintext> {
    if poseidon::hash(tag::MAC, &[*key, ct.c0, ct.c1]) != ct.tag {
        return None;
    }
    let m0 = ct.c0 - poseidon::hash(tag::STREAM, &[*key, Fr::from(0u64)]);
    let m1 = ct.c1 - poseidon::hash(tag::STREAM, &[*key, Fr::from(1u64)]);
    let (v, d) = unpack_vd(&m0)?;
    Some(NotePlaintext { v, d, r_seed: m1 })
}

/// Recipient side (paper 16.1), including the post-decryption checks:
/// re-derive sk_eph from r_seed and require pk_eph == [sk_eph] G_d.
pub fn decrypt_as_recipient(
    ct: &Ciphertext,
    pk_eph: &EdwardsAffine,
    sk_view: &Fs,
) -> Option<NotePlaintext> {
    let shared = keys::mul(pk_eph, sk_view);
    let note = decrypt_with_key(&note_key(&shared, pk_eph), ct)?;
    let g_d = keys::diversify_hash(&note.d)?.base;
    (keys::mul(&g_d, &sk_eph(&note.r_seed)) == *pk_eph).then_some(note)
}

/// Sender recovery (paper 16.2) given the (pk_d, sk_eph) record.
pub fn decrypt_as_sender(
    ct: &Ciphertext,
    pk_eph: &EdwardsAffine,
    pk_d: &EdwardsAffine,
    s: &Fs,
) -> Option<NotePlaintext> {
    let shared = keys::mul(pk_d, s);
    let note = decrypt_with_key(&note_key(&shared, pk_eph), ct)?;
    let g_d = keys::diversify_hash(&note.d)?.base;
    (keys::mul(&g_d, &sk_eph(&note.r_seed)) == *pk_eph).then_some(note)
}

/// H_leaf(const_salt, h_body, j, pk_eph, ct, h_aux) of section 9, with
/// h_aux = aux_null.
pub fn leaf(h_body: &Fr, j: u8, pk_eph: &EdwardsAffine, ct: &Ciphertext) -> Fr {
    poseidon::hash(
        tag::LEAF,
        &[
            const_salt(),
            *h_body,
            Fr::from(j as u64),
            pk_eph.x,
            pk_eph.y,
            ct.c0,
            ct.c1,
            ct.tag,
            aux_null(),
        ],
    )
}

/// Peg-in leaf. Outside the paper: a mint publishes the note in plaintext
/// because there is no proof that a ciphertext encrypts the deposited value.
pub fn mint_leaf(v: u64, d: &[u8; DIVERSIFIER_LEN], pk_d: &EdwardsAffine, r_seed: &Fr) -> Fr {
    poseidon::hash(
        tag::MINT_LEAF,
        &[
            Fr::from(v),
            keys::diversifier_to_field(d),
            pk_d.x,
            pk_d.y,
            *r_seed,
        ],
    )
}

pub fn nullifier(sk_nf: &Fr, rho: &Fr, pos: u64) -> Fr {
    poseidon::hash(tag::NF, &[*sk_nf, *rho, Fr::from(pos)])
}

fn recovery_key(vk_out: &[u8; 32], binding: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(binding), vk_out);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    hk.expand(b"sbp/ctout/key", &mut key).expect("valid length");
    hk.expand(b"sbp/ctout/nonce", &mut nonce)
        .expect("valid length");
    (key, nonce)
}

/// Sender-recovery ciphertext ct_out (paper 16.2): the (pk_d, sk_eph) record
/// of every output under ChaCha20-Poly1305, keyed from vk_out and the
/// recovery binding, which is also the associated data.
pub fn encrypt_recovery(
    records: &[(EdwardsAffine, Fs)],
    binding: &[u8; 32],
    vk_out: &[u8; 32],
) -> Vec<u8> {
    let (key, nonce) = recovery_key(vk_out, binding);
    let mut pt = Vec::with_capacity(records.len() * 64);
    for (pk_d, s) in records {
        pt.extend_from_slice(&keys::point_to_bytes(pk_d));
        pt.extend_from_slice(&keys::scalar_to_bytes(s));
    }
    ChaCha20Poly1305::new((&key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &pt,
                aad: binding,
            },
        )
        .expect("aead")
}

pub fn decrypt_recovery(
    ct_out: &[u8],
    binding: &[u8; 32],
    vk_out: &[u8; 32],
) -> Option<Vec<(EdwardsAffine, Fs)>> {
    let (key, nonce) = recovery_key(vk_out, binding);
    let pt = ChaCha20Poly1305::new((&key).into())
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ct_out,
                aad: binding,
            },
        )
        .ok()?;
    if pt.len() % 64 != 0 {
        return None;
    }
    pt.chunks(64)
        .map(|c| {
            Some((
                keys::point_from_bytes(&c[..32])?,
                keys::scalar_from_bytes(&c[32..]),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::WalletKeys;

    #[test]
    fn encrypt_decrypts_for_recipient_and_sender() {
        let bob = WalletKeys::from_seed([1u8; 32]);
        let addr = bob.address(3).unwrap();
        let note = NotePlaintext {
            v: 123_456,
            d: addr.d,
            r_seed: Fr::from(99u64),
        };
        let (pk_eph, ct) = encrypt(&note, &addr.pk_d).unwrap();
        assert_eq!(
            decrypt_as_recipient(&ct, &pk_eph, &bob.derive().sk_view),
            Some(note.clone())
        );
        assert_eq!(
            decrypt_as_sender(&ct, &pk_eph, &addr.pk_d, &sk_eph(&note.r_seed)),
            Some(note.clone())
        );
        let other = WalletKeys::from_seed([2u8; 32]);
        assert_eq!(
            decrypt_as_recipient(&ct, &pk_eph, &other.derive().sk_view),
            None
        );
        assert_eq!(Ciphertext::from_bytes(&ct.to_bytes()), Some(ct));
    }

    #[test]
    fn pack_vd_unpack_vd_roundtrip() {
        let d = [0xabu8; DIVERSIFIER_LEN];
        assert_eq!(unpack_vd(&pack_vd(u64::MAX, &d)), Some((u64::MAX, d)));
    }
}

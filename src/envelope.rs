//! Transfer and mint envelopes, canonical serialisation, h_body and the
//! public statement digest (paper sections 11, 13, A.3, A.5).

use crate::{
    EdwardsAffine, Fr, N_IN, N_OUT,
    keys::{self, DIVERSIFIER_LEN},
    note::{CIPHERTEXT_LEN, CONST_SALT, Ciphertext},
    poseidon::{self, tag},
};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 3] = b"sbp";
pub const VERSION: u8 = 1;
pub const KIND_TRANSFER: u8 = 0x01;
pub const KIND_MINT: u8 = 0x02;
pub const PROOF_LEN: usize = 192;
/// Sender-recovery record per output: pk_d (32) || sk_eph (32).
pub const CT_OUT_LEN: usize = N_OUT * 64 + 16;

/// Why bytes that carry the magic are not an envelope.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unknown version {0}")]
    UnknownVersion(u8),
    #[error("reserved header byte set")]
    ReservedByteSet,
    #[error("unsupported input count")]
    InputCount,
    #[error("unsupported output count")]
    OutputCount,
    #[error("non-canonical nullifier")]
    Nullifier,
    #[error("bad pk_eph")]
    PkEph,
    #[error("bad ciphertext")]
    Ciphertext,
    #[error("payout too short")]
    PayoutTooShort,
    #[error("bad pk_d")]
    PkD,
    #[error("non-canonical r_seed")]
    RSeed,
    #[error("unknown envelope kind {0:#x}")]
    UnknownKind(u8),
    #[error("trailing bytes after envelope")]
    TrailingBytes,
    #[error("non-minimal CompactSize")]
    NonMinimalCount,
    #[error("non-canonical envelope encoding")]
    NonCanonical,
    #[error("envelope truncated")]
    Truncated,
}

/// Optional peg-out request bound into the body: pay `amount` sats to
/// `script_pubkey` from the vault. Outside the paper.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Payout {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferEnvelope {
    pub h_anchor: u32,
    pub nf: [Fr; N_IN],
    pub pk_eph: [EdwardsAffine; N_OUT],
    pub ct: [Ciphertext; N_OUT],
    pub ct_out: Vec<u8>,
    pub payout: Option<Payout>,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintEnvelope {
    pub d: [u8; DIVERSIFIER_LEN],
    pub pk_d: EdwardsAffine,
    pub r_seed: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Envelope {
    Transfer(Box<TransferEnvelope>),
    Mint(MintEnvelope),
}

fn header(kind: u8) -> [u8; 6] {
    [MAGIC[0], MAGIC[1], MAGIC[2], VERSION, kind, 0]
}

/// Bitcoin CompactSize (A.5): one byte below 253, else 0xfd + u16 LE, 0xfe + u32 LE.
fn push_compact_size(v: &mut Vec<u8>, n: usize) {
    match n {
        0..=252 => v.push(n as u8),
        253..=0xffff => {
            v.push(0xfd);
            v.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            v.push(0xfe);
            v.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

impl TransferEnvelope {
    /// Canonical body: everything except the proof.
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(700);
        v.extend_from_slice(&header(KIND_TRANSFER));
        v.extend_from_slice(&self.h_anchor.to_le_bytes());
        push_compact_size(&mut v, N_IN);
        push_compact_size(&mut v, N_OUT);
        for nf in &self.nf {
            v.extend_from_slice(&keys::fr_to_bytes(nf));
        }
        for pk in &self.pk_eph {
            v.extend_from_slice(&keys::point_to_bytes(pk));
        }
        for ct in &self.ct {
            v.extend_from_slice(&ct.to_bytes());
        }
        v.extend_from_slice(&self.ct_out);
        match &self.payout {
            None => v.push(0),
            Some(p) => {
                push_compact_size(&mut v, 8 + p.script_pubkey.len());
                v.extend_from_slice(&p.amount.to_le_bytes());
                v.extend_from_slice(&p.script_pubkey);
            }
        }
        v
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.body_bytes();
        v.extend_from_slice(&self.proof);
        v
    }

    /// H_body(const_salt || canonical_transfer_body), section 13.3.
    pub fn h_body(&self) -> Fr {
        let mut salted = CONST_SALT.to_vec();
        salted.extend_from_slice(&self.body_bytes());
        poseidon::hash_bytes(tag::BODY, &salted)
    }

    /// Digest binding every public field the circuit sees (paper 13.2, 14.2).
    pub fn statement_digest(&self) -> Fr {
        statement_digest(&self.h_body(), &self.nf, &self.pk_eph, &self.ct)
    }

    /// Bytes the sender-recovery AEAD is keyed and authenticated with.
    pub fn recovery_binding(&self) -> [u8; 32] {
        recovery_binding(&self.pk_eph, &self.ct)
    }
}

pub fn statement_digest(
    h_body: &Fr,
    nf: &[Fr; N_IN],
    pk_eph: &[EdwardsAffine; N_OUT],
    ct: &[Ciphertext; N_OUT],
) -> Fr {
    let mut inputs = vec![*h_body, Fr::from(N_IN as u64), Fr::from(N_OUT as u64)];
    inputs.extend_from_slice(nf);
    for pk in pk_eph {
        inputs.push(pk.x);
        inputs.push(pk.y);
    }
    for c in ct {
        inputs.extend_from_slice(&c.fields());
    }
    poseidon::hash(tag::STMT, &inputs)
}

pub fn recovery_binding(pk_eph: &[EdwardsAffine; N_OUT], ct: &[Ciphertext; N_OUT]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([N_OUT as u8]);
    for pk in pk_eph {
        h.update(keys::point_to_bytes(pk));
    }
    for c in ct {
        h.update(c.to_bytes());
    }
    h.finalize().into()
}

impl MintEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(6 + DIVERSIFIER_LEN + 64);
        v.extend_from_slice(&header(KIND_MINT));
        v.extend_from_slice(&self.d);
        v.extend_from_slice(&keys::point_to_bytes(&self.pk_d));
        v.extend_from_slice(&keys::fr_to_bytes(&self.r_seed));
        v
    }
}

impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Envelope::Transfer(t) => t.to_bytes(),
            Envelope::Mint(m) => m.to_bytes(),
        }
    }

    /// Strict canonical parse. Returns None when the bytes are not an
    /// envelope at all (wrong magic), Err when they claim to be one and
    /// fail to decode or do not re-serialise to the same bytes (A.5).
    pub fn parse(b: &[u8]) -> Result<Option<Self>, Error> {
        if b.len() < 6 || &b[..3] != MAGIC {
            return Ok(None);
        }
        if b[3] != VERSION {
            return Err(Error::UnknownVersion(b[3]));
        }
        if b[5] != 0 {
            return Err(Error::ReservedByteSet);
        }
        let mut r = Reader { b, pos: 6 };
        let env = match b[4] {
            KIND_TRANSFER => {
                let h_anchor = u32::from_le_bytes(r.take(4)?.try_into().unwrap());
                if r.compact_size()? != N_IN {
                    return Err(Error::InputCount);
                }
                if r.compact_size()? != N_OUT {
                    return Err(Error::OutputCount);
                }
                let mut nf = [Fr::from(0u64); N_IN];
                for x in nf.iter_mut() {
                    *x = keys::fr_from_bytes(r.take(32)?).ok_or(Error::Nullifier)?;
                }
                let mut pk_eph = [EdwardsAffine::default(); N_OUT];
                for x in pk_eph.iter_mut() {
                    *x = keys::point_from_bytes(r.take(32)?).ok_or(Error::PkEph)?;
                }
                let mut ct = [Ciphertext {
                    c0: Fr::from(0u64),
                    c1: Fr::from(0u64),
                    tag: Fr::from(0u64),
                }; N_OUT];
                for x in ct.iter_mut() {
                    *x =
                        Ciphertext::from_bytes(r.take(CIPHERTEXT_LEN)?).ok_or(Error::Ciphertext)?;
                }
                let ct_out = r.take(CT_OUT_LEN)?.to_vec();
                let plen = r.compact_size()?;
                let payout = if plen == 0 {
                    None
                } else {
                    if plen <= 8 {
                        return Err(Error::PayoutTooShort);
                    }
                    let amount = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
                    let script_pubkey = r.take(plen - 8)?.to_vec();
                    Some(Payout {
                        amount,
                        script_pubkey,
                    })
                };
                let proof = r.take(PROOF_LEN)?.to_vec();
                Envelope::Transfer(Box::new(TransferEnvelope {
                    h_anchor,
                    nf,
                    pk_eph,
                    ct,
                    ct_out,
                    payout,
                    proof,
                }))
            }
            KIND_MINT => {
                let mut d = [0u8; DIVERSIFIER_LEN];
                d.copy_from_slice(r.take(DIVERSIFIER_LEN)?);
                let pk_d = keys::point_from_bytes(r.take(32)?).ok_or(Error::PkD)?;
                let r_seed = keys::fr_from_bytes(r.take(32)?).ok_or(Error::RSeed)?;
                Envelope::Mint(MintEnvelope { d, pk_d, r_seed })
            }
            k => return Err(Error::UnknownKind(k)),
        };
        if r.pos != b.len() {
            return Err(Error::TrailingBytes);
        }
        if env.to_bytes() != b {
            return Err(Error::NonCanonical);
        }
        Ok(Some(env))
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.pos + n > self.b.len() {
            return Err(Error::Truncated);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Minimal CompactSize; 0xff (u64) never occurs in an envelope.
    fn compact_size(&mut self) -> Result<usize, Error> {
        let (n, min) = match self.take(1)?[0] {
            0xff => return Err(Error::NonMinimalCount),
            0xfe => (
                u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize,
                0x1_0000,
            ),
            0xfd => (
                u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize,
                253,
            ),
            b => (b as usize, 0),
        };
        if n < min {
            return Err(Error::NonMinimalCount);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::WalletKeys,
        note::{NotePlaintext, encrypt},
    };

    #[test]
    fn parse_transfer_roundtrip_and_size() {
        let w = WalletKeys::from_seed([3u8; 32]);
        let a = w.address(0);
        let n = NotePlaintext {
            v: 5,
            d: a.d,
            r_seed: Fr::from(8u64),
        };
        let (pk, ct) = encrypt(&n, &a.pk_d).unwrap();
        let env = TransferEnvelope {
            h_anchor: 42,
            nf: [Fr::from(1u64), Fr::from(2u64)],
            pk_eph: [pk, pk],
            ct: [ct, ct],
            ct_out: vec![9u8; CT_OUT_LEN],
            payout: None,
            proof: vec![0u8; PROOF_LEN],
        };
        let bytes = env.to_bytes();
        assert_eq!(
            bytes.len(),
            6 + 4 + 2 + 64 + 64 + 192 + CT_OUT_LEN + 1 + PROOF_LEN
        );
        assert_eq!(
            Envelope::parse(&bytes).unwrap(),
            Some(Envelope::Transfer(Box::new(env.clone())))
        );
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(Envelope::parse(&bad).is_err());
        assert_eq!(Envelope::parse(b"hello").unwrap(), None);
        // input_count as 0xfd 02 00 decodes to 2 but is not minimal.
        let mut wide = bytes[..10].to_vec();
        wide.extend_from_slice(&[0xfd, 2, 0]);
        wide.extend_from_slice(&bytes[11..]);
        assert_eq!(Envelope::parse(&wide), Err(Error::NonMinimalCount));
    }
}

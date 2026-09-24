//! The transfer circuit (paper section 14 and appendix B), fixed at two
//! inputs and two outputs. Public inputs: r_anchor and the statement digest.

use crate::keys::{self, DiversifyResult, SCALAR_BITS};
use crate::poseidon::{self as pos_native, tag};
use crate::tree::MerklePath;
use crate::{EdwardsAffine, EdwardsProjective, Fr, DIV_HASH_TRIES, N_IN, N_OUT, TREE_DEPTH};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_ed_on_bls12_381::EdwardsConfig;
use ark_ff::{AdditiveGroup, Field};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub type PointVar = AffineVar<EdwardsConfig, FpVar<Fr>>;

/// Everything the prover knows about one spent input.
#[derive(Clone, Debug)]
pub struct InputWitness {
    pub enabled: bool,
    pub is_mint: bool,
    pub v: u64,
    pub d: [u8; keys::DIVERSIFIER_LEN],
    pub r_seed: Fr,
    /// Creation data for ciphertext-derived leaves (ignored for mints).
    pub h_body_create: Fr,
    pub j: u8,
    pub path: MerklePath,
}

#[derive(Clone, Debug)]
pub struct OutputWitness {
    pub v: u64,
    pub d: [u8; keys::DIVERSIFIER_LEN],
    pub r_seed: Fr,
    pub pk_d: EdwardsAffine,
}

#[derive(Clone, Debug)]
pub struct TransferWitness {
    pub sk_spend: Fr,
    pub h_body: Fr,
    pub inputs: [InputWitness; N_IN],
    pub outputs: [OutputWitness; N_OUT],
}

#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub r_anchor: Fr,
    pub digest: Fr,
}

impl PublicInputs {
    pub fn to_vec(&self) -> Vec<Fr> {
        vec![self.r_anchor, self.digest]
    }
}

/// Circuit instance. `witness` is None during setup.
#[derive(Clone)]
pub struct TransferCircuit {
    pub public: Option<PublicInputs>,
    pub witness: Option<TransferWitness>,
}

fn missing<T: Clone>(o: &Option<T>) -> Result<T, SynthesisError> {
    o.clone().ok_or(SynthesisError::AssignmentMissing)
}

fn hash_var(cs: &ConstraintSystemRef<Fr>, t: u64, inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), pos_native::config());
    sponge.absorb(&FpVar::constant(Fr::from(t)))?;
    for x in inputs {
        sponge.absorb(x)?;
    }
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}

/// Constrains x < 2^bits and returns its little-endian bits.
fn range_check(x: &FpVar<Fr>, bits: usize) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let all = x.to_bits_le()?;
    for b in &all[bits..] {
        b.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(all[..bits].to_vec())
}

/// Low SCALAR_BITS bits of a field element, as a scalar for point multiplication.
fn scalar_bits(x: &FpVar<Fr>) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    Ok(x.to_bits_le()?[..SCALAR_BITS].to_vec())
}

fn mul_point(base: &PointVar, bits: &[Boolean<Fr>]) -> Result<PointVar, SynthesisError> {
    base.scalar_mul_le(bits.iter())
}

/// In-circuit DiversifyHash. Mirrors keys::diversify_hash exactly.
fn diversify_hash_var(
    cs: &ConstraintSystemRef<Fr>,
    d: &FpVar<Fr>,
    aux: &Option<DiversifyResult>,
) -> Result<PointVar, SynthesisError> {
    let h = hash_var(cs, tag::DIVERSIFY, std::slice::from_ref(d))?;
    let dd = FpVar::constant(keys::edwards_d());
    let nr = FpVar::constant(keys::nonresidue());
    let mut one_hot_sum = FpVar::zero();
    let mut x = FpVar::zero();
    let mut y = FpVar::zero();
    let mut not_yet = FpVar::one();
    for t in 0..DIV_HASH_TRIES {
        let is_k = Boolean::new_witness(cs.clone(), || Ok(aux.as_ref().map(|a| a.k == t).unwrap_or(false)))?;
        let w = FpVar::new_witness(cs.clone(), || {
            Ok(aux.as_ref().and_then(|a| a.roots.get(t).copied()).unwrap_or(Fr::ZERO))
        })?;
        let is_k_f = FpVar::from(is_k.clone());
        let y_t = &h + FpVar::constant(Fr::from(t as u64));
        let y2 = y_t.square()?;
        let num = &y2 - FpVar::one();
        let den = &dd * &y2 + FpVar::one();
        let prod = &num * &den;
        let w2 = w.square()?;
        // Before k: w^2 = nr * prod (no point at this y). At k: w^2 * den = num.
        let miss = &w2 - &nr * &prod;
        let hit = &w2 * &den - &num;
        let branch = (FpVar::one() - &is_k_f) * miss + &is_k_f * hit;
        (&not_yet * branch).enforce_equal(&FpVar::zero())?;
        x += &is_k_f * &w;
        y += &is_k_f * &y_t;
        one_hot_sum += &is_k_f;
        not_yet -= &is_k_f;
    }
    one_hot_sum.enforce_equal(&FpVar::one())?;
    // canonical sign: x even
    let xbits = x.to_bits_le()?;
    xbits[0].enforce_equal(&Boolean::FALSE)?;
    let raw = PointVar::new(x, y);
    // Clear the cofactor 8.
    let p2 = raw.double()?;
    let p4 = p2.double()?;
    p4.double()
}

struct EncryptedOutput {
    pk_eph: PointVar,
    c0: FpVar<Fr>,
    c1: FpVar<Fr>,
    tag: FpVar<Fr>,
}

/// Derives pk_eph and the ciphertext for (v, d, r_seed) sent to pk_d,
/// mirroring note::encrypt.
fn encrypt_var(
    cs: &ConstraintSystemRef<Fr>,
    g_d: &PointVar,
    pk_d: &PointVar,
    v: &FpVar<Fr>,
    d: &FpVar<Fr>,
    r_seed: &FpVar<Fr>,
) -> Result<EncryptedOutput, SynthesisError> {
    let sk_eph_f = hash_var(cs, tag::EPH, std::slice::from_ref(r_seed))?;
    let bits = scalar_bits(&sk_eph_f)?;
    let pk_eph = mul_point(g_d, &bits)?;
    let shared = mul_point(pk_d, &bits)?;
    let key = hash_var(cs, tag::KDF, &[shared.x.clone(), shared.y.clone(), pk_eph.x.clone(), pk_eph.y.clone()])?;
    let m0 = v + d * FpVar::constant(Fr::from(1u128 << 64));
    let c0 = m0 + hash_var(cs, tag::STREAM, &[key.clone(), FpVar::zero()])?;
    let c1 = r_seed + hash_var(cs, tag::STREAM, &[key.clone(), FpVar::one()])?;
    let t = hash_var(cs, tag::MAC, &[key, c0.clone(), c1.clone()])?;
    Ok(EncryptedOutput { pk_eph, c0, c1, tag: t })
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public = self.public;
        let w = self.witness;

        let r_anchor = FpVar::new_input(cs.clone(), || missing(&public).map(|p| p.r_anchor))?;
        let digest = FpVar::new_input(cs.clone(), || missing(&public).map(|p| p.digest))?;

        let sk_spend = FpVar::new_witness(cs.clone(), || missing(&w).map(|w| w.sk_spend))?;
        let h_body = FpVar::new_witness(cs.clone(), || missing(&w).map(|w| w.h_body))?;

        // Spend-authority lineage (paper blocks 3 and 4).
        let sk_nf = hash_var(&cs, tag::NF_KEY, std::slice::from_ref(&sk_spend))?;
        let vk_in = hash_var(&cs, tag::VK_IN, std::slice::from_ref(&sk_spend))?;
        let sk_view_f = hash_var(&cs, tag::SK_VIEW, std::slice::from_ref(&vk_in))?;
        let sk_view_bits = scalar_bits(&sk_view_f)?;

        let mut value_in = FpVar::zero();
        let mut nullifiers = Vec::with_capacity(N_IN);

        for i in 0..N_IN {
            let inp = w.as_ref().map(|w| w.inputs[i].clone());
            let enabled = Boolean::new_witness(cs.clone(), || missing(&inp).map(|x| x.enabled))?;
            let is_mint = Boolean::new_witness(cs.clone(), || missing(&inp).map(|x| x.is_mint))?;
            let v = FpVar::new_witness(cs.clone(), || missing(&inp).map(|x| Fr::from(x.v)))?;
            let d = FpVar::new_witness(cs.clone(), || missing(&inp).map(|x| keys::diversifier_to_field(&x.d)))?;
            let r_seed = FpVar::new_witness(cs.clone(), || missing(&inp).map(|x| x.r_seed))?;
            let h_body_create = FpVar::new_witness(cs.clone(), || missing(&inp).map(|x| x.h_body_create))?;
            let j = FpVar::new_witness(cs.clone(), || missing(&inp).map(|x| Fr::from(x.j as u64)))?;
            let pos = FpVar::new_witness(cs.clone(), || missing(&inp).map(|x| Fr::from(x.path.pos)))?;
            let siblings: Vec<FpVar<Fr>> = (0..TREE_DEPTH)
                .map(|l| FpVar::new_witness(cs.clone(), || missing(&inp).map(|x| x.path.siblings[l])))
                .collect::<Result<_, _>>()?;

            range_check(&v, 64)?;
            range_check(&d, 88)?;
            let pos_bits = range_check(&pos, TREE_DEPTH)?;
            // A disabled input carries no value.
            (&v * FpVar::from(!enabled.clone())).enforce_equal(&FpVar::zero())?;

            // Block 1 and 3: reconstruct the note under the spender's own pk_d.
            let div_aux = inp.as_ref().map(|x| keys::diversify_hash(&x.d));
            let g_d = diversify_hash_var(&cs, &d, &div_aux)?;
            let pk_d = mul_point(&g_d, &sk_view_bits)?;
            let enc = encrypt_var(&cs, &g_d, &pk_d, &v, &d, &r_seed)?;
            let ct_leaf = hash_var(
                &cs,
                tag::LEAF,
                &[h_body_create, j, enc.pk_eph.x.clone(), enc.pk_eph.y.clone(), enc.c0, enc.c1, enc.tag],
            )?;
            let mint_leaf = hash_var(&cs, tag::MINT_LEAF, &[v.clone(), d.clone(), pk_d.x.clone(), pk_d.y.clone(), r_seed.clone()])?;
            let leaf = is_mint.select(&mint_leaf, &ct_leaf)?;

            // Block 2: Merkle membership under r_anchor, only for real inputs.
            let mut cur = leaf;
            for (l, sib) in siblings.iter().enumerate() {
                let left = pos_bits[l].select(sib, &cur)?;
                let right = pos_bits[l].select(&cur, sib)?;
                cur = hash_var(&cs, tag::NODE, &[left, right])?;
            }
            cur.conditional_enforce_equal(&r_anchor, &enabled)?;

            // Block 4: nullifier.
            let rho = hash_var(&cs, tag::RHO, std::slice::from_ref(&r_seed))?;
            let nf = hash_var(&cs, tag::NF, &[sk_nf.clone(), rho, pos])?;
            nullifiers.push(nf);
            value_in += &v;
        }

        let mut value_out = FpVar::zero();
        let mut out_pk = Vec::with_capacity(N_OUT * 2);
        let mut out_ct = Vec::with_capacity(N_OUT * 3);
        for jx in 0..N_OUT {
            let out = w.as_ref().map(|w| w.outputs[jx].clone());
            let v = FpVar::new_witness(cs.clone(), || missing(&out).map(|x| Fr::from(x.v)))?;
            let d = FpVar::new_witness(cs.clone(), || missing(&out).map(|x| keys::diversifier_to_field(&x.d)))?;
            let r_seed = FpVar::new_witness(cs.clone(), || missing(&out).map(|x| x.r_seed))?;
            let pk_d = PointVar::new_witness(cs.clone(), || missing(&out).map(|x| EdwardsProjective::from(x.pk_d)))?;
            range_check(&v, 64)?;
            range_check(&d, 88)?;
            let div_aux = out.as_ref().map(|x| keys::diversify_hash(&x.d));
            let g_d = diversify_hash_var(&cs, &d, &div_aux)?;
            let enc = encrypt_var(&cs, &g_d, &pk_d, &v, &d, &r_seed)?;
            out_pk.extend([enc.pk_eph.x, enc.pk_eph.y]);
            out_ct.extend([enc.c0, enc.c1, enc.tag]);
            value_out += &v;
        }

        // Block 7: conservation. Both sides are sums of two 64-bit values.
        value_in.enforce_equal(&value_out)?;

        // Block 8: bind everything public into the digest.
        let mut stmt = vec![h_body, FpVar::constant(Fr::from(N_IN as u64)), FpVar::constant(Fr::from(N_OUT as u64))];
        stmt.extend(nullifiers);
        stmt.extend(out_pk);
        stmt.extend(out_ct);
        hash_var(&cs, tag::STMT, &stmt)?.enforce_equal(&digest)?;
        Ok(())
    }
}

/// Native side of the statement: computes nullifiers, output ciphertexts and
/// the digest from a witness, so wallet code has one source of truth.
pub struct NativeStatement {
    pub nf: [Fr; N_IN],
    pub pk_eph: [EdwardsAffine; N_OUT],
    pub ct: [crate::note::Ciphertext; N_OUT],
}

pub fn evaluate(w: &TransferWitness) -> NativeStatement {
    use crate::note;
    let sk_nf = keys::derive_sk_nf(&w.sk_spend);
    let nf = std::array::from_fn(|i| {
        let inp = &w.inputs[i];
        note::nullifier(&sk_nf, &note::rho(&inp.r_seed), inp.path.pos)
    });
    let mut pk_eph = [EdwardsAffine::default(); N_OUT];
    let mut ct = [note::Ciphertext { c0: Fr::ZERO, c1: Fr::ZERO, tag: Fr::ZERO }; N_OUT];
    for j in 0..N_OUT {
        let o = &w.outputs[j];
        let (p, c) = note::encrypt(&note::NotePlaintext { v: o.v, d: o.d, r_seed: o.r_seed }, &o.pk_d);
        pk_eph[j] = p;
        ct[j] = c;
    }
    NativeStatement { nf, pk_eph, ct }
}

/// Recomputes the leaf of an input note the way the circuit does.
pub fn input_leaf(sk_spend: &Fr, inp: &InputWitness) -> Fr {
    use crate::note;
    let der_vk_in = keys::derive_vk_in(sk_spend);
    let sk_view = keys::derive_sk_view(&der_vk_in);
    let g_d = keys::diversify_hash(&inp.d).base;
    let pk_d = keys::mul(&g_d, &sk_view);
    if inp.is_mint {
        note::mint_leaf(inp.v, &inp.d, &pk_d, &inp.r_seed)
    } else {
        let (pk_eph, ct) = note::encrypt(&note::NotePlaintext { v: inp.v, d: inp.d, r_seed: inp.r_seed }, &pk_d);
        note::leaf(&inp.h_body_create, inp.j, &pk_eph, &ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::WalletKeys;
    use crate::tree::MerkleTree;
    use ark_relations::r1cs::ConstraintSystem;

    pub fn sample_witness() -> (TransferWitness, PublicInputs) {
        let alice = WalletKeys::from_seed([11u8; 32]);
        let bob = WalletKeys::from_seed([22u8; 32]);
        let der = alice.derive();
        let a0 = alice.address(0);
        let a1 = alice.address(1);
        let b0 = bob.address(0);
        let mut tree = MerkleTree::new();
        // One mint note and one ciphertext note owned by alice.
        let mint = InputWitness {
            enabled: true,
            is_mint: true,
            v: 70_000,
            d: a0.d,
            r_seed: Fr::from(1001u64),
            h_body_create: Fr::ZERO,
            j: 0,
            path: MerklePath { pos: 0, siblings: vec![] },
        };
        let ctn = InputWitness {
            enabled: true,
            is_mint: false,
            v: 30_000,
            d: a1.d,
            r_seed: Fr::from(1002u64),
            h_body_create: Fr::from(555u64),
            j: 1,
            path: MerklePath { pos: 0, siblings: vec![] },
        };
        let p0 = tree.append(input_leaf(&der.sk_spend, &mint));
        tree.append(Fr::from(4242u64)); // someone else's note
        let p1 = tree.append(input_leaf(&der.sk_spend, &ctn));
        let mut mint = mint;
        mint.path = tree.path(p0).unwrap();
        let mut ctn = ctn;
        ctn.path = tree.path(p1).unwrap();
        let w = TransferWitness {
            sk_spend: der.sk_spend,
            h_body: Fr::from(777u64),
            inputs: [mint, ctn],
            outputs: [
                OutputWitness { v: 60_000, d: b0.d, r_seed: Fr::from(2001u64), pk_d: b0.pk_d },
                OutputWitness { v: 40_000, d: a0.d, r_seed: Fr::from(2002u64), pk_d: a0.pk_d },
            ],
        };
        let st = evaluate(&w);
        let digest = crate::envelope::statement_digest(&w.h_body, &st.nf, &st.pk_eph, &st.ct);
        (w, PublicInputs { r_anchor: tree.root(), digest })
    }

    #[test]
    fn circuit_is_satisfied_by_native_witness() {
        let (w, p) = sample_witness();
        let cs = ConstraintSystem::<Fr>::new_ref();
        TransferCircuit { public: Some(p.clone()), witness: Some(w.clone()) }
            .generate_constraints(cs.clone())
            .unwrap();
        eprintln!("constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap(), "unsatisfied at {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn circuit_rejects_inflation() {
        let (mut w, p) = sample_witness();
        w.outputs[0].v += 1;
        let cs = ConstraintSystem::<Fr>::new_ref();
        TransferCircuit { public: Some(p), witness: Some(w) }.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn circuit_rejects_wrong_root() {
        let (w, mut p) = sample_witness();
        p.r_anchor += Fr::ONE;
        let cs = ConstraintSystem::<Fr>::new_ref();
        TransferCircuit { public: Some(p), witness: Some(w) }.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn circuit_rejects_foreign_spend_key() {
        let (mut w, p) = sample_witness();
        w.sk_spend += Fr::ONE;
        let cs = ConstraintSystem::<Fr>::new_ref();
        TransferCircuit { public: Some(p), witness: Some(w) }.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}

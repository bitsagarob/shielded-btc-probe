//! Property tests for the canonical envelope parser and CompactSize.
use ark_ff::PrimeField;
use proptest::prelude::*;
use shielded_btc_probe::{
    EdwardsAffine, Fr, Fs,
    envelope::{CT_OUT_LEN, Envelope, Error, MintEnvelope, PROOF_LEN, Payout, TransferEnvelope},
    keys,
    note::Ciphertext,
};

fn fr() -> impl Strategy<Value = Fr> {
    any::<[u8; 32]>().prop_map(|b| Fr::from_le_bytes_mod_order(&b))
}
fn point() -> impl Strategy<Value = EdwardsAffine> {
    any::<[u8; 32]>().prop_map(|b| keys::mul(&keys::generator(), &Fs::from_le_bytes_mod_order(&b)))
}
fn ct() -> impl Strategy<Value = Ciphertext> {
    (fr(), fr(), fr()).prop_map(|(c0, c1, tag)| Ciphertext { c0, c1, tag })
}
fn payout() -> impl Strategy<Value = Option<Payout>> {
    prop_oneof![
        Just(None),
        (any::<u64>(), prop::collection::vec(any::<u8>(), 1..600)).prop_map(
            |(amount, script_pubkey)| Some(Payout {
                amount,
                script_pubkey
            })
        ),
    ]
}
fn transfer() -> impl Strategy<Value = TransferEnvelope> {
    (
        any::<u32>(),
        [fr(), fr()],
        [point(), point()],
        [ct(), ct()],
        prop::collection::vec(any::<u8>(), CT_OUT_LEN),
        payout(),
        prop::collection::vec(any::<u8>(), PROOF_LEN),
    )
        .prop_map(
            |(h_anchor, nf, pk_eph, ct, ct_out, payout, proof)| TransferEnvelope {
                h_anchor,
                nf,
                pk_eph,
                ct,
                ct_out,
                payout,
                proof,
            },
        )
}
fn mint() -> impl Strategy<Value = MintEnvelope> {
    (any::<[u8; 11]>(), point(), fr()).prop_map(|(d, pk_d, r_seed)| MintEnvelope {
        d,
        pk_d,
        r_seed,
    })
}

const PAYOUT_COUNT_OFFSET: usize = 6 + 4 + 2 + 64 + 64 + 192 + CT_OUT_LEN;

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn transfer_roundtrips(t in transfer()) {
        let b = t.to_bytes();
        prop_assert_eq!(Envelope::parse(&b), Ok(Some(Envelope::Transfer(Box::new(t)))));
    }

    #[test]
    fn mint_roundtrips(m in mint()) {
        let b = m.to_bytes();
        prop_assert_eq!(Envelope::parse(&b), Ok(Some(Envelope::Mint(m))));
    }

    /// Every proper prefix is rejected; nothing shorter parses as something.
    #[test]
    fn every_truncation_is_rejected(t in transfer()) {
        let b = t.to_bytes();
        for n in 0..b.len() {
            match Envelope::parse(&b[..n]) {
                Ok(None) => prop_assert!(n < 6, "prefix of {n} bytes read as no envelope"),
                Ok(Some(_)) => prop_assert!(false, "prefix of {n} bytes parsed"),
                Err(_) => {}
            }
        }
    }

    /// Whatever parses must re-serialise to the exact input (A.5 injectivity).
    #[test]
    fn anything_that_parses_is_canonical(t in transfer(), idx in 0usize..2000, x in 1u8..=255) {
        let mut b = t.to_bytes();
        let i = idx % b.len();
        b[i] ^= x;
        if let Ok(Some(e)) = Envelope::parse(&b) {
            prop_assert_eq!(e.to_bytes(), b);
        }
    }

    #[test]
    fn random_bytes_never_panic(tail in prop::collection::vec(any::<u8>(), 0..900), magic in any::<bool>()) {
        let mut b = if magic { b"sbp".to_vec() } else { vec![] };
        b.extend(tail);
        let _ = Envelope::parse(&b);
    }

    /// A payout count that fits in one byte, written as 0xfd + u16, is non-minimal.
    #[test]
    fn widened_compact_size_is_rejected(t in transfer(), script in prop::collection::vec(any::<u8>(), 1..244)) {
        let mut t = t;
        t.payout = Some(Payout { amount: 1, script_pubkey: script });
        let b = t.to_bytes();
        let n = b[PAYOUT_COUNT_OFFSET];
        prop_assert!(n < 253);
        let mut wide = b[..PAYOUT_COUNT_OFFSET].to_vec();
        wide.extend_from_slice(&[0xfd, n, 0]);
        wide.extend_from_slice(&b[PAYOUT_COUNT_OFFSET + 1..]);
        prop_assert_eq!(Envelope::parse(&wide), Err(Error::NonMinimalCount));
        // And the 0xfe form of the same number.
        let mut wider = b[..PAYOUT_COUNT_OFFSET].to_vec();
        wider.extend_from_slice(&[0xfe, n, 0, 0, 0]);
        wider.extend_from_slice(&b[PAYOUT_COUNT_OFFSET + 1..]);
        prop_assert_eq!(Envelope::parse(&wider), Err(Error::NonMinimalCount));
    }

    /// Payout scripts of 245 bytes and more cross into the 0xfd form and still round-trip.
    #[test]
    fn compact_size_boundary_roundtrips(t in transfer(), len in 244usize..300) {
        let mut t = t;
        t.payout = Some(Payout { amount: 1, script_pubkey: vec![0x51; len] });
        let b = t.to_bytes();
        prop_assert_eq!(b[PAYOUT_COUNT_OFFSET] == 0xfd, len + 8 >= 253);
        prop_assert_eq!(Envelope::parse(&b), Ok(Some(Envelope::Transfer(Box::new(t)))));
    }
}

//! Hex text for field elements in the JSON state and wallet files.

pub use hex::serde as bytes;

pub mod fr {
    use crate::{Fr, keys};
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(x: &Fr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(keys::fr_to_bytes(x)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Fr, D::Error> {
        let bytes: Vec<u8> = hex::serde::deserialize(d)?;
        keys::fr_from_bytes(&bytes).ok_or_else(|| D::Error::custom("non-canonical field element"))
    }
}

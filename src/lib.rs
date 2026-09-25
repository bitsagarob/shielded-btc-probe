//! Shielded Bitcoin transfer-layer probe.
//!
//! A deliberately small implementation of the transfer layer described in
//! "Shielded Bitcoin: Private Transfers on the Bitcoin L1" (Shikhelman,
//! Komarov, Moskvin, 24 Sep 2026). It runs on Bitcoin and on the Bitsaga
//! Signet; the deployment profile (`indexer::Deployment`) selects the network.
//! It is a probe, not a product: the trusted setup is deterministic and
//! therefore insecure, the peg is a single operator key, and every hash that
//! the paper leaves open is instantiated with Poseidon over BLS12-381 Fr.
//! See PROFILE.md for every deviation from the paper.

#![forbid(unsafe_code)]

pub mod chain;
pub mod circuit;
pub mod envelope;
pub mod indexer;
pub mod keys;
pub mod note;
pub mod poseidon;
pub mod prover;
pub mod serde_hex;
pub mod tree;
pub mod wallet;

pub use ark_bls12_381::Fr;
pub use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr as Fs};

/// Merkle tree depth for the global note tree.
pub const TREE_DEPTH: usize = 32;
/// Number of inputs and outputs every transfer envelope carries (fixed arity).
pub const N_IN: usize = 2;
pub const N_OUT: usize = 2;
/// Anchor window: replay accepts H - W <= h_anchor <= H - K_MIN.
pub const WINDOW_W: u32 = 100;
pub const K_MIN: u32 = 1;
/// Wallet anchor depth (A.6 asks for K_WALLET > K_MIN): a transfer built at
/// replayed height H anchors at R[H + 1 - K_WALLET].
pub const K_WALLET: u32 = 2;
/// Number of y-coordinate candidates tried by DiversifyHash before giving up.
pub const DIV_HASH_TRIES: usize = 32;

#![forbid(unsafe_code)]

//! Small Merkle tree lib with domain separation and proofs.
//!
//! Policies:
//! - Leaf: `H(0x00 || message)`
//! - Node: `H(0x01 || left || right)`
//! - Odd leaves: duplicate-last
//!
//! Hashers:
//! - `sha3`)

pub mod hash;
pub mod proof;
pub mod tree;

use core::fmt::{self, Write};

use sha3::{Digest, Sha3_256};

/// 32-byte hash type.
const HASH_SIZE: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash(pub [u8; HASH_SIZE]);

impl Hash {
    pub fn to_hex_lower(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            write!(&mut s, "{:02x}", b).unwrap();
        }
        s
    }

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex_lower())
    }
}

pub trait MerkleHasher {
    /// Algorithm name (sha3-256, ...)
    const NAME: &'static str;

    fn hash(data: &[u8]) -> Hash;
}

pub struct Sha3;
impl MerkleHasher for Sha3 {
    const NAME: &'static str = "sha3-256";

    fn hash(data: &[u8]) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let output = hasher.finalize();
        Hash(output.into())
    }
}

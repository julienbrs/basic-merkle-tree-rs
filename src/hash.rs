use core::fmt::{self, Write};

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

/// Leaf hash with domain separation: `H(0x00 || message)`.
pub fn leaf_hash<H: MerkleHasher>(msg: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + msg.len());
    buf.push(0x00);
    buf.extend_from_slice(msg);
    H::hash(&buf)
}

/// Node hash with domain separation: `H(0x01 || left || right)`.
pub fn node_hash<H: MerkleHasher>(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 1 + 32 + 32]; // input size fixed
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(&left.0);
    buf[33..].copy_from_slice(&right.0);
    H::hash(&buf)
}

/// SHA3-256 hasher (default feature).
#[cfg(feature = "sha3")]
#[derive(Debug)]
pub struct Sha3;
#[cfg(feature = "sha3")]
impl MerkleHasher for Sha3 {
    const NAME: &'static str = "sha3-256";
    fn hash(data: &[u8]) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let out = hasher.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        Hash(a)
    }
}

/// Keccak-256 hasher (opt-in).
#[cfg(feature = "keccak")]
#[derive(Debug)]
pub struct Keccak;

#[cfg(feature = "keccak")]
impl MerkleHasher for Keccak {
    const NAME: &'static str = "keccak-256";
    fn hash(data: &[u8]) -> Hash {
        use tiny_keccak::{Hasher, Keccak};
        let mut k = Keccak::v256();
        k.update(data);
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        Hash(out)
    }
}

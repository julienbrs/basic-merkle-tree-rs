use crate::hash::{Hash, MerkleHasher, node_hash};

/// Merkle inclusion proof (sibling list + original leaf index).
#[derive(Clone, Debug)]
pub struct Proof {
    pub(crate) siblings: Vec<Hash>,
    pub(crate) original_index: usize,
}

impl Proof {
    pub fn new(original_index: usize, siblings: Vec<Hash>) -> Self {
        Self {
            siblings,
            original_index,
        }
    }

    /// Verify a proof against `root` with the supplied `leaf` hash.
    ///
    /// - `leaf` must be the **leaf hash**: `H(0x00 || message)`.
    /// - Uses duplicate-last policy during tree construction
    pub fn verify<H: MerkleHasher>(&self, leaf: Hash, root: Hash) -> bool {
        let mut index = self.original_index;
        let mut acc = leaf;
        for sib in &self.siblings {
            acc = if index % 2 == 0 {
                node_hash::<H>(&acc, sib)
            } else {
                node_hash::<H>(sib, &acc)
            };
            index /= 2;
        }
        acc == root
    }

    pub fn siblings(&self) -> &[Hash] {
        &self.siblings
    }

    pub fn index(&self) -> usize {
        self.original_index
    }
}

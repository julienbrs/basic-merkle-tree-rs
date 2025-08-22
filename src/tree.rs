use std::marker::PhantomData;

use crate::hash::{Hash, MerkleHasher, node_hash};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MerkleError {
    EmptyLeaves,
    IndexOutOfBounds,
}
pub struct MerkleTree<H: MerkleHasher> {
    levels: Vec<Vec<Hash>>,
    _marker: PhantomData<H>,
}

impl<H: MerkleHasher> MerkleTree<H> {
    /// Build from already-hashed leaves
    pub fn from_leaves(leaves: Vec<Hash>) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyLeaves);
        }

        let mut levels = Vec::new();
        levels.push(leaves);

        while levels.last().unwrap().len() > 1 {
            let curr = levels.last().unwrap();
            let mut node_hashes = Vec::with_capacity((curr.len() + 1) / 2);
            let mut i = 0;
            while i < curr.len() {
                let left = curr[i];
                let right = if i + 1 < curr.len() {
                    curr[i + 1]
                } else {
                    left
                };
                node_hashes.push(node_hash::<H>(&left, &right));
                i += 2;
            }
            levels.push(node_hashes);
        }
        Ok(MerkleTree {
            levels,
            _marker: PhantomData,
        })
    }

    pub fn root(&self) -> Hash {
        *self.levels.last().unwrap().first().unwrap()
    }

    pub fn leaf_len(&self) -> usize {
        self.levels.first().unwrap().len()
    }

    /// Get a merkle proof for a leaf index
    pub fn proof(&self, mut index: usize) -> Result<crate::proof::Proof, MerkleError> {
        let original_index = index;

        let leaves_len = self.leaf_len();
        if index > leaves_len {
            return Err(MerkleError::IndexOutOfBounds);
        }

        let mut siblings = Vec::with_capacity(self.levels.len().saturating_sub(1));
        for level in 0..self.levels.len() - 1 {
            let nodes = &self.levels[level];
            let pair_node = if index % 2 == 0 {
                if index + 1 < nodes.len() {
                    nodes[index + 1]
                } else {
                    nodes[index]
                }
            } else {
                nodes[index - 1]
            };
            siblings.push(pair_node);
            index /= 2;
        }

        Ok(crate::proof::Proof {
            siblings,
            original_index,
        })
    }
}

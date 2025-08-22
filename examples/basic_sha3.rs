use basic_merkle_tree_rs::hash::{Sha3, leaf_hash};
use basic_merkle_tree_rs::tree::MerkleTree;
fn main() {
    let msgs = [b"block 1", b"block 2", b"block 3", b"block 4"];
    let leaves = msgs
        .into_iter()
        .map(|m| leaf_hash::<Sha3>(m))
        .collect::<Vec<_>>();

    let tree = MerkleTree::<Sha3>::from_leaves(leaves.clone()).unwrap();
    let root = tree.root();
    println!("Root (hex): {}", root);

    // Proof for "Block 3" (index 2)
    let proof = tree.proof(2).unwrap();
    let ok = proof.verify::<Sha3>(leaf_hash::<Sha3>(b"block 3"), root);
    println!("Proof verified: {ok}");
    assert!(ok);

    // Negative check
    let bad = proof.verify::<Sha3>(leaf_hash::<Sha3>(b"block 5"), root);
    assert!(!bad);
}

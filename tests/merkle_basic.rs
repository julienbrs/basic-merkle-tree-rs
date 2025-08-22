use basic_merkle_tree_rs::{
    hash::{Sha3, leaf_hash, node_hash},
    tree::{MerkleError, MerkleTree},
};

#[test]
fn root_and_proof_roundtrip() {
    let msgs = [b"a", b"b", b"c", b"d", b"e"];
    let leaves = msgs
        .into_iter()
        .map(|m| leaf_hash::<Sha3>(m))
        .collect::<Vec<_>>();
    let tree = MerkleTree::<Sha3>::from_leaves(leaves.clone()).unwrap();
    let root = tree.root();

    for (i, m) in [b"a", b"b", b"c", b"d", b"e"].into_iter().enumerate() {
        let prf = tree.proof(i).unwrap();
        assert!(prf.verify::<Sha3>(leaf_hash::<Sha3>(m), root));
    }
}

#[test]
fn duplicate_last_policy_with_three_leaves() {
    // Leaves: a, b, c -> parent(level1): H(a,b), H(c,c) -> root: H(H(a,b), H(c,c))
    let a = leaf_hash::<Sha3>(b"a");
    let b = leaf_hash::<Sha3>(b"b");
    let c = leaf_hash::<Sha3>(b"c");

    let lvl1_left = node_hash::<Sha3>(&a, &b);
    let lvl1_right = node_hash::<Sha3>(&c, &c);
    let expect_root = node_hash::<Sha3>(&lvl1_left, &lvl1_right);

    let tree = MerkleTree::<Sha3>::from_leaves(vec![a, b, c]).unwrap();
    assert_eq!(tree.root(), expect_root);
}

#[test]
fn domain_separation_sane() {
    // H(0x00||"ab") should differ from H(0x01||H(0x00||"a")||H(0x00||"b"))
    let leaf_ab = leaf_hash::<Sha3>(b"ab");
    let a = leaf_hash::<Sha3>(b"a");
    let b = leaf_hash::<Sha3>(b"b");
    let node_ab = node_hash::<Sha3>(&a, &b);
    assert_ne!(leaf_ab, node_ab);
}

#[test]
fn empty_is_error() {
    let err = MerkleTree::<Sha3>::from_leaves(vec![]).unwrap_err();
    assert!(matches!(err, MerkleError::EmptyLeaves));
}

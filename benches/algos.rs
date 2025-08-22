use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use basic_merkle_tree_rs::hash::{Hash, leaf_hash};
use basic_merkle_tree_rs::tree::MerkleTree;

fn sizes_small() -> &'static [usize] {
    &[16, 64, 256, 1024]
}
fn sizes_medium() -> &'static [usize] {
    &[4096, 16384, 65536]
}

fn make_leaves<H: basic_merkle_tree_rs::hash::MerkleHasher>(n: usize) -> Vec<Hash> {
    (0..n as u64)
        .map(|i| leaf_hash::<H>(&i.to_le_bytes()))
        .collect()
}

fn bench_for_hasher<H: basic_merkle_tree_rs::hash::MerkleHasher>(c: &mut Criterion, name: &str) {
    // Build root
    let mut g = c.benchmark_group(format!("{}/build_root", name));
    for &n in sizes_small().iter().chain(sizes_medium()) {
        g.throughput(Throughput::Elements(n as u64));
        let leaves = make_leaves::<H>(n);
        g.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &_n| {
            b.iter(|| {
                let tree = MerkleTree::<H>::from_leaves(leaves.clone()).unwrap();
                black_box(tree.root());
            });
        });
    }
    g.finish();

    // Prove+verify
    let mut g2 = c.benchmark_group(format!("{}/prove_verify", name));
    for &n in sizes_medium() {
        let leaves = make_leaves::<H>(n);
        let tree = MerkleTree::<H>::from_leaves(leaves.clone()).unwrap();
        let root = tree.root();
        g2.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &_n| {
            let mut idx = 0usize;
            b.iter(|| {
                idx = (idx + 97) % n;
                let proof = tree.proof(idx).unwrap();
                let ok = proof.verify::<H>(leaves[idx], root);
                black_box(ok)
            });
        });
    }
    g2.finish();
}

#[cfg(feature = "sha3")]
mod sha3_group {
    use super::*;
    use basic_merkle_tree_rs::hash::Sha3;
    pub fn group(c: &mut Criterion) {
        bench_for_hasher::<Sha3>(c, "sha3");
    }
}

#[cfg(feature = "keccak")]
mod keccak_group {
    use super::*;
    use basic_merkle_tree_rs::hash::Keccak;
    pub fn group(c: &mut Criterion) {
        bench_for_hasher::<Keccak>(c, "keccak");
    }
}

// Enregistre les groupes en fonction des features actives
#[cfg(all(feature = "sha3", feature = "keccak"))]
criterion_group!(benches, sha3_group::group, keccak_group::group);
#[cfg(all(feature = "sha3", not(feature = "keccak")))]
criterion_group!(benches, sha3_group::group);
#[cfg(all(feature = "keccak", not(feature = "sha3")))]
criterion_group!(benches, keccak_group::group);

criterion_main!(benches);

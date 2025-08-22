use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use merkle_bench_rs::hash::{Hash, MerkleHasher, leaf_hash};
use merkle_bench_rs::tree::MerkleTree;

#[cfg(feature = "blake2")]
use merkle_bench_rs::hash::Blake2b;
#[cfg(feature = "keccak")]
use merkle_bench_rs::hash::Keccak;
#[cfg(feature = "sha2")]
use merkle_bench_rs::hash::Sha2;
#[cfg(feature = "sha3")]
use merkle_bench_rs::hash::Sha3;

fn sizes_small() -> &'static [usize] {
    &[16, 64, 256, 1024] // pas de doublon avec sizes_medium
}
fn sizes_medium() -> &'static [usize] {
    &[4096, 16384, 65536]
}

fn make_leaves<H: MerkleHasher>(n: usize) -> Vec<Hash> {
    (0..n as u64)
        .map(|i| leaf_hash::<H>(&i.to_le_bytes()))
        .collect()
}

fn bench_for_hasher<H: MerkleHasher>(c: &mut Criterion, name: &str) {
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

fn benches(c: &mut Criterion) {
    #[cfg(feature = "sha3")]
    bench_for_hasher::<Sha3>(c, "sha3");
    #[cfg(feature = "keccak")]
    bench_for_hasher::<Keccak>(c, "keccak");
    #[cfg(feature = "sha2")]
    bench_for_hasher::<Sha2>(c, "sha2");
    #[cfg(feature = "blake2")]
    bench_for_hasher::<Blake2b>(c, "blake2b");
}

criterion_group!(benches_group, benches);
criterion_main!(benches_group);

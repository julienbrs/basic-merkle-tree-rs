use basic_merkle_tree_rs::hash::{MerkleHasher, Sha3, leaf_hash};
use basic_merkle_tree_rs::tree::MerkleTree;
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(65_536);
    let rounds: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);

    println!(
        "Hasher: {}, leaves: {}, rounds: {}",
        <Sha3 as MerkleHasher>::NAME,
        n,
        rounds
    );

    // Prépare les feuilles
    let leaves = (0..n as u64)
        .map(|i| leaf_hash::<Sha3>(&i.to_le_bytes()))
        .collect::<Vec<_>>();

    // Build root (moyenne)
    let mut total = 0f64;
    for _ in 0..rounds {
        let t0 = Instant::now();
        let tree = MerkleTree::<Sha3>::from_leaves(leaves.clone()).unwrap();
        let dt = t0.elapsed().as_secs_f64();
        total += dt;
        // imprime le root pour éviter l'optimisation
        println!("root={}", tree.root());
    }
    let avg = total / rounds as f64;
    println!(
        "Build avg: {:.3} ms (≈ {:.1} leaves/s)",
        avg * 1e3,
        n as f64 / avg
    );

    // Proof+verify (utilise l’arbre d’un build)
    let tree = MerkleTree::<Sha3>::from_leaves(leaves.clone()).unwrap();
    let root = tree.root();
    let t0 = Instant::now();
    let mut ok_count = 0usize;
    for i in 0..n {
        let p = tree.proof(i).unwrap();
        if p.verify::<Sha3>(leaves[i], root) {
            ok_count += 1;
        }
    }
    let dt = t0.elapsed().as_secs_f64();
    println!("Prove+verify all: {:.3} ms ({} ok)", dt * 1e3, ok_count);
}

# merkle-bench-rs

Small, idiomatic **Merkle tree** library in Rust with domain separation, inclusion proofs, and **multi-hasher benchmarks** with Criterion. Quick comparisons across SHA3, Keccak, SHA2, and BLAKE2b.

## Highlights

- **Domain separation:** `leaf = H(0x00 || msg)`, `node = H(0x01 || left || right)`
- **Odd leaves:** duplicate-last policy
- **Proofs:** build and verify inclusion proofs
- **Pluggable hashers:** `sha3-256` (default), `keccak-256`, `sha2-256`, `blake2b-256`
- **Benchmarks:** single `cargo bench` comparing hashers; HTML report

## Benchmarks

Single consolidated bench lives at benches/algos.rs.

Default (SHA3 only):
```sh
cargo bench
```

Compare all:
```sh
cargo bench --features all-hashers
```

View report at:
```sh
open target/criterion/report/index.html
```
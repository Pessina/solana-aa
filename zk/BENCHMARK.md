# ZK guest program benchmarks

Measured via `cd zk/script && cargo run --release -- fixture --execute-only`
(SP1 executor cycle count for one JWT verification; same test JWT/key for all rows).
Proving wall-clock is the timed `fixture` Groth16 run on an Apple Silicon CPU with
circuit artifacts cached and the script binary prebuilt.

| Configuration | zkVM cycles | CPU proving | On-chain verifiable | Notes |
|---|---|---|---|---|
| SP1 5.0.x, vanilla `rsa` 0.9.6 + `sha2` 0.10.8 | 10,278,741 | ~8.9 min | yes (260-byte proof) | Initial port of the hackathon guest |
| SP1 6.2.4, sp1-patches `rsa` + `sha2` | 1,670,087 | — | **no** | 6.2x fewer cycles, but v6 emits 356-byte gnark-commitment proofs that `sp1-solana` cannot parse — kept out of the tree, see below |
| SP1 5.0.x, sp1-patches `rsa` + `sha2` (**current**) | 1,374,806 | 3.7 min | yes (260-byte proof) | **7.5x fewer cycles, 2.4x faster proving.** Precompile syscalls on the v5 runtime |

The wall-clock improves less than the cycle count because the Groth16 wrapper
(recursion + gnark in Docker) is a large fixed cost independent of guest size. The
cycle count is what scales prover-network/GPU cost.

## Why not SP1 v6

SP1 v6.x cuts cycles further and is the actively developed line, but its Groth16
wrapper switched to gnark's commitment scheme: proofs are 356 bytes (vs 260) with a
different verification equation. [`sp1-solana`](https://github.com/succinctlabs/sp1-solana)
— the only Groth16 verifier backed by Solana's alt_bn128 syscalls (via Light
Protocol's `groth16-solana`) — only parses the classic format; its embedded VKs stop
at v5.0.0 and master has no v6 support. The generic `sp1-verifier` crate handles v6
but does pairing in pure Rust, which is far beyond Solana's compute budget.

Until upstream adds v6 proof support, the guest and host script stay pinned at SP1
5.0.x. The optimization (precompile-accelerated `rsa`/`sha2` forks from sp1-patches)
applies on v5 with version-matched tags, so most of the cycle win is retained.

Two further v6-era notes for when the upgrade unblocks:
- The v6 SDK is async-first; the sync API moved behind the `blocking` feature.
- The v6.1.0 `sp1-gnark` Docker image ships no arm64 manifest; on Apple Silicon use
  the `native-gnark` SDK feature (requires Go) for the Groth16 wrap.

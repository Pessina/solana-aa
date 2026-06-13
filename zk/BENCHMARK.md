# ZK guest program benchmarks

Measured via `cd zk/script && cargo run --release -- fixture --execute-only`
(SP1 executor cycle count for one JWT verification; same test JWT/key for all rows).
Proving wall-clock is the timed `fixture` Groth16 run on an Apple Silicon CPU with
circuit artifacts cached and the script binary prebuilt.

| Configuration | zkVM cycles | CPU proving | On-chain verifiable | Notes |
|---|---|---|---|---|
| SP1 5.0.x, vanilla `rsa` 0.9.6 + `sha2` 0.10.8, Poseidon2 identity hashes | 10,278,741 | ~8.9 min | yes (260-byte proof) | Initial port of the hackathon guest |
| SP1 6.2.4, sp1-patches `rsa` + `sha2` | 1,670,087 | — | **no** | 6.2x fewer cycles, but v6 emits 356-byte gnark-commitment proofs that `sp1-solana` cannot parse — kept out of the tree, see below |
| SP1 5.0.x, sp1-patches `rsa` + `sha2`, Poseidon2 identity hashes | 1,374,806 | 3.7 min | yes (260-byte proof) | Precompiled RSA/SHA-256 for the JWT signature; identity email/key hashing still Poseidon2 (which has no SP1 precompile, ~350k cycles) |
| SP1 5.0.x, sp1-patches `rsa` + `sha2`, **SHA-256 identity hashes** (**current**) | 1,022,777 | 3.4 min | yes (260-byte proof) | **10.0x fewer cycles.** Poseidon2 → precompiled SHA-256 identity hashing (~350k → ~3.4k cycles) + typed-struct JWT claim parsing; `rsa_verify` (967k, 94%) is the RS256 floor (see below) |

The wall-clock improves less than the cycle count because the Groth16 wrapper
(recursion + gnark in Docker) is a large fixed cost independent of guest size. The
cycle count is what scales prover-network/GPU cost.

## Why RSA-2048 is the floor

`rsa_verify` is 967k of the 1.02M cycles (94%). RS256 over RSA-2048 reduces to
`s^65537 mod n`, and the sp1-patches `rsa` fork already runs it on the optimal
path: the `syscall_u256x2048_mul` precompile with non-deterministic modular
reduction (the host hints the quotient/remainder, the guest verifies
`a·b = q·n + r`). The executor's syscall counts confirm it — one execute run fires
`U256XU2048_MUL` exactly **272** times = 17 modmuls (e=65537 → 16 squarings + 1
multiply) × 16 precompile calls each (8 for `a·b`, 8 for `q·n`). A pure-Rust
fallback would report zero here and cost ~5–6M cycles instead.

There is no wider modular-multiply or modexp precompile in SP1 v5, and the
"hint the result" trick that accelerates RSA *signing* (a large secret exponent)
does not help *verification*, where computing `s^65537` already is the ~17-modmul
check. So 967k is the practical floor for this operation on the v5 pin.

The signing algorithm is set by the OIDC provider, not the protocol. Every major
social provider signs ID tokens with RS256/RSA-2048 today (Google, Apple, Microsoft
Entra, Facebook — verified against their live JWKS), so RSA-2048 is the operative
floor for social login. Providers that emit ES256 (P-256) or EdDSA would instead
hit SP1's `secp256r1` / `ed25519` precompiles and prove several-fold cheaper, but
that is an enterprise / self-hosted-IdP scenario, not consumer social login.

## Production proving

Local CPU proving (~3.4 min) is fine for fixtures and CI but too slow for
interactive signing. The host script calls `ProverClient::from_env()`, so the
[Succinct Prover Network](https://docs.succinct.xyz) proves the same guest with no
code change — set these and re-run `fixture`:

```
SP1_PROVER=network
NETWORK_PRIVATE_KEY=<key>   # required; the network account that pays for proofs
NETWORK_RPC_URL=...         # optional, defaults to https://rpc.production.succinct.xyz/
```

Network proving cost scales with the guest cycle count, so the reduction above is
what ultimately makes the production path cheaper.

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

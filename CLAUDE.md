# CLAUDE.md

Guidance for agents working in this repo. See [`README.md`](README.md) for the full design and [`ROADMAP.md`](ROADMAP.md) for direction.

## What this is

An experimental [Anchor](https://www.anchor-lang.com/) program for account abstraction on Solana: each smart account is a PDA controlled by external credentials — Ethereum (secp256k1), WebAuthn (secp256r1), and OIDC (RS256 JWT verified inside an SP1 ZK proof) — rather than a Solana Ed25519 key. Signature checks are delegated to Solana's native precompiles and read back via instruction introspection.

Research prototype: not audited, and several auth checks are **intentionally** incomplete (see "Known gaps" in the README). Program ID (localnet): `2PYNfKSoM7rFJeMuvEidASxgpdPAXYascVDmH6jpBa7o`.

## Commands

```bash
yarn install
anchor build
anchor test     # build, deploy to a local validator, run all specs
yarn lint       # prettier check (yarn lint:fix to write)

# single spec against an already-running validator
yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/<name>.spec.ts
```

ZK OIDC fixtures are committed under `tests/fixtures/`, so `anchor test` needs **neither** the SP1 toolchain nor Docker. Regenerating them does — see the README "Development" section.

## Test validator

- **Keep `bind_address = "127.0.0.1"` in `Anchor.toml`.** Anchor 0.31.1 otherwise passes `--bind-address 0.0.0.0`, which panics Agave 3.1.x's gossip node (`UnspecifiedIpAddr`) and kills the validator before any test runs.
- **Mainnet feature parity is not enforced by default** — plain `anchor test` runs with all runtime features on. To test under mainnet's feature set, start a validator with `--clone-feature-set` and use `anchor test --skip-local-validator` (see "Mainnet feature parity" in the README). Do this before any devnet/mainnet deploy.

## Layout

`programs/solana-aa/src/` — on-chain program: `lib.rs` entrypoints → `contract/` handlers (`auth/`, `transaction/`) → `types/`. `zk/` — SP1 OIDC guest + host tooling. `borsh/` + `utils/` — TS client helpers mirroring the on-chain types. `tests/` — ts-mocha suite. Full tree in the README.

## Conventions

- Conventional Commits, imperative mood, ≤72-char subject; no AI attribution in any git content.
- Stay scoped — don't "fix" the intentionally-incomplete auth checks unless that's the task.
- Build (`anchor build`) and run the affected spec(s) before calling a change done.

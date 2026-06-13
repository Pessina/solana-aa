# Roadmap

This document tracks the path from research prototype to a production-ready program. It complements the [README](README.md), which describes what exists today, and preserves the feature backlog from the original design notes. Items are ordered by priority, not scheduled — sequencing follows what each phase unblocks.

Where a gap is already visible in the code, the item links to the file carrying the relevant `TODO`.

## P0 — Security foundation

Everything blocking a deployment beyond localnet.

- [ ] **Enforce permissions during validation.** `IdentityPermissions` is stored per identity but [`is_transaction_authorized`](programs/solana-aa/src/contract/transaction/validation.rs) never reads it. Define the permission model (at minimum: which identities may add/remove identities or close the account) and enforce it on every action.
- [ ] **Validate `act_as` delegation.** `UserOp.act_as` exists in the types but is never checked; `enable_act_as` should gate it (same `TODO` in [`validation.rs`](programs/solana-aa/src/contract/transaction/validation.rs)).
- [ ] **Remove or secure the unauthenticated mutation instructions.** `delete_account`, `add_identity` and `remove_identity` in [`lib.rs`](programs/solana-aa/src/lib.rs) mutate accounts without signature verification. They exist as development helpers and must not ship.
- [ ] **WebAuthn execution path.** Verification works ([`secp256r1_sha256.rs`](programs/solana-aa/src/contract/auth/secp256r1_sha256.rs)) but there is no `execute_*` instruction for passkey-signed transactions: bind `client_data.challenge` to the transaction hash and dispatch the same way `execute_ek256` does.
- [ ] **Bind WebAuthn identities to their relying party.** Store and check `client_data.origin` / `rpIdHash` so a key pair reused across sites cannot be replayed cross-origin (noted in [`webauthn.rs`](programs/solana-aa/src/types/identity/webauthn.rs)).
- [ ] **Bound account growth.** The identity vector can grow until the 32 KB heap limit aborts deserialization ([`account.rs`](programs/solana-aa/src/types/account.rs)). Enforce a maximum identity count/size at add time.
- [ ] **Eliminate panics in instruction paths.** Replace `unwrap()`/`expect()` (e.g. `get_eth_data`, `IdentityWithPermissions::byte_size`) with typed errors.

## P1 — Core capabilities

What makes the account useful beyond managing itself.

- [ ] **Arbitrary transaction execution (`Sign` action).** `Action` currently only covers identity management; the commented-out `Sign(SignPayloadsRequest)` in [`transaction.rs`](programs/solana-aa/src/types/transaction/transaction.rs) is the actual product — let the abstract account CPI into other programs and move funds, authorized by any registered identity.
- [ ] **`AddIdentityWithAuth`.** Adding an identity should optionally require proof of ownership of the identity being added (its own signature over `account_id`, nonce, action and permissions), preventing unilateral grants and binding the new identity to this specific account (design sketched in [`transaction.rs`](programs/solana-aa/src/types/transaction/transaction.rs)).
- [ ] **Transaction expiration.** Add a validity window to `Transaction` so stale signed messages cannot be executed later.
- [ ] **Multi-signature / threshold authentication.** Precompile introspection currently rejects instructions carrying more than one signature; support N-of-M across an account's identities.
- [x] **OIDC as a first-class identity.** Shipped: `Identity::Oidc(iss, aud, email_hash)` authorized by an on-chain Groth16 proof of an SP1 zkVM JWT verification, with the `nonce` claim bound to the transaction hash ([`zk_oidc.rs`](programs/solana-aa/src/contract/auth/zk_oidc.rs), [`zk/`](zk)). Remaining hardening:
  - Key the identity on the stable `sub` claim and require `email_verified` — `email` is mutable/reassignable, so it is a weaker user key.
  - Validate the JWT `exp` in-circuit; today only the transaction + account-nonce binding makes a token single-use.
  - `sha256(email)` is unsalted and reversible for known addresses — a blinded commitment would make the on-chain identity private, not merely pseudonymous.
- [ ] **Automated JWKS key management & registry governance.** The on-chain [`OidcKeyRegistry`](programs/solana-aa/src/types/oidc_key_registry.rs) pins provider `(iss, pk_hash)` keys and is authority-managed ([`oidc_registry.rs`](programs/solana-aa/src/contract/oidc_registry.rs)), but the authority is a single trusted signer that must track provider rotation by hand — a stale or malicious authority can lock out or forge identities. Production needs an oracle/governance flow: multisig authority plus automated JWKS sync.

## P2 — Account features

- [ ] Spending limits per identity (value and frequency caps)
- [ ] Time-based restrictions (validity windows, session timeouts)
- [ ] Hierarchical roles (owner / admin / user / recovery-only)
- [ ] Social recovery with configurable time delays
- [ ] Batch transactions (multiple actions under one signature)
- [ ] Session keys (short-lived delegated keys for frequent operations)
- [ ] Fee abstraction / paymaster (third party pays fees on the user's behalf)
- [ ] Client SDK (a proper TypeScript package beyond the test utilities in `utils/`)

## Engineering & hardening

- [ ] **Transaction buffer rework** ([`transaction_buffer.rs`](programs/solana-aa/src/contract/transaction_buffer.rs)): zero-copy accounts to escape the 32 KB heap limit, and pre-allocation from `total_chunks` so chunks can be written in parallel instead of realloc-per-chunk.
- [ ] **Benchmark identity storage.** `Vec` vs `BTreeMap`/`HashMap` for the identity list ([`account.rs`](programs/solana-aa/src/types/account.rs)) — `Vec` is likely right at ~10 identities per account; verify with CU measurements.
- [ ] **Remove debug instructions.** `verify_eth` / `get_eth_data` / `verify_webauthn` / `get_webauthn_data` are introspection helpers marked as debug code ([`ek256.rs`](programs/solana-aa/src/contract/auth/ek256.rs)).
- [ ] **Compute and memory budgeting.** Measure and document per-instruction CU cost across execution paths.
- [ ] **Security audit** once P0 and the `Sign` action land.

## Open questions

- **On-chain RSA verification — resolved via ZK** ([#13](https://github.com/Pessina/solana-aa/issues/13)): direct on-chain RS256 is still non-viable (`big_mod_exp` remains mainnet-inactive, [solana-labs/solana#32520](https://github.com/solana-labs/solana/pull/32520); the pure-Rust `rsa` crate exceeds the compute and heap limits), so we shipped candidate option 2 — an SP1 zkVM proof of JWT verification checked on-chain via the alt_bn128 syscalls ([`zk_oidc.rs`](programs/solana-aa/src/contract/auth/zk_oidc.rs)). The trusted-attestation fallback (an off-chain co-signer) was not pursued. The trade-off it introduces is prover infrastructure: local proving is ~3.4 min, so production would offload to the Succinct Prover Network.
- **Nonce model vs. parallelism.** A single sequential `u128` nonce serializes all of an account's transactions; if concurrent submission matters, consider nonce spaces or expiring nonces.
- **Account discovery by identity.** Finding the accounts an identity controls requires scanning sequential IDs today; a reverse-index PDA keyed by identity hash would make lookups O(1) at the cost of extra rent and bookkeeping.

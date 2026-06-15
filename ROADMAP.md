# Roadmap

This document tracks the path from research prototype to a production-ready program. It complements the [README](README.md), which describes what exists today, and preserves the feature backlog from the original design notes. Items are ordered by priority, not scheduled — sequencing follows what each phase unblocks.

Where a gap is already visible in the code, the item links to the file carrying the relevant `TODO`.

## P0 — Security foundation

Everything blocking a deployment beyond localnet.

- [ ] **Enforce permissions during validation.** `IdentityPermissions` is stored per identity but [`is_transaction_authorized`](programs/solana-aa/src/contract/transaction/validation.rs) never reads it. Define the permission model (at minimum: which identities may add/remove identities or close the account) and enforce it on every action.
- [ ] **Validate `act_as` delegation.** `UserOp.act_as` exists in the types but is never checked; `enable_act_as` should gate it (same `TODO` in [`validation.rs`](programs/solana-aa/src/contract/transaction/validation.rs)).
- [x] **Secured the unauthenticated mutation instructions.** `add_identity` and `remove_identity` were removed — all identity changes now flow through the authenticated `execute_*` paths. `delete_account` is retained only as an admin-gated close, restricted to the deployment `admin` recorded on the `AccountManager` at `init_contract` ([`lib.rs`](programs/solana-aa/src/lib.rs)). Letting an account's own identities authorize closing (via `RemoveAccount`) instead of a central admin is folded into the permission work above.
- [x] **WebAuthn execution path.** `execute_webauthn` ([`execute.rs`](programs/solana-aa/src/contract/transaction/execute.rs)) verifies a passkey assertion via the secp256r1 precompile, re-binds `authenticator_data || sha256(clientDataJSON)`, requires the user-present flag, binds `client_data.challenge` to `sha256(borsh(Transaction))`, and dispatches like `execute_ek256`.
- [x] **Bound WebAuthn identities to their relying party.** `WebAuthnAuthenticator` stores `rp_id_hash` + `origin`, and identity equality matches on `compressed_public_key` + `rp_id_hash` + `origin`, so a key reused on another origin cannot authorize ([`webauthn.rs`](programs/solana-aa/src/types/identity/webauthn.rs)).
- [x] **Bounded account growth.** `AbstractAccount::add_identity` enforces `MAX_IDENTITIES` (16) and `MAX_ACCOUNT_SIZE` (8 KB) before reallocating ([`account.rs`](programs/solana-aa/src/types/account.rs)).
- [x] **Eliminated panics in instruction paths.** `IdentityWithPermissions::byte_size` is now fallible, `get_eth_data` returns a typed error, and the secp256r1 program id is a `const` (no `from_str().unwrap()`); the remaining `unwrap()`s live only in `#[cfg(test)]` modules.

## P1 — Core capabilities

What makes the account useful beyond managing itself.

- [x] **`Sign` action (chain-signatures CPI).** `Action::Sign(SignRequest)` lets the abstract account — authorized by any registered identity — CPI into the Sig Network chain-signatures `sign` instruction via `invoke_signed` (the AA PDA is the requester, the outer signer pays fees). The target program id is deployment config set on the `AccountManager` at `init_contract`, and dispatch rejects any program account that does not match it ([`sign.rs`](programs/solana-aa/src/contract/transaction/sign.rs)).
- [ ] **Generic arbitrary execution.** Broaden beyond the single chain-signatures target: let the account CPI into arbitrary programs and move native funds, and gate the `Sign` action per identity once the permission model lands.
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

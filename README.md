# Solana Account Abstraction

An experimental [Anchor](https://www.anchor-lang.com/) program exploring account abstraction on Solana: smart accounts that are owned by a PDA and controlled by external credentials — Ethereum wallets, WebAuthn passkeys, and (experimentally) OIDC tokens — instead of Solana Ed25519 keypairs.

> **Status: research prototype.** Not audited, several security checks are intentionally incomplete (see [Known gaps](#known-gaps)). Do not use with real funds.

Program ID (localnet): `2PYNfKSoM7rFJeMuvEidASxgpdPAXYascVDmH6jpBa7o`

## Design

Solana ties account ownership to a single Ed25519 key. This program decouples the two: each abstract account is a PDA that stores a list of *identities* (authentication methods), and any registered identity can authorize transactions for the account. A Solana keypair is still needed to pay fees, but it carries no authority — authorization comes entirely from the external signature.

Signature verification is delegated to Solana's native precompiles rather than done in-program:

| Identity | Scheme | Verified by | Status |
|---|---|---|---|
| Ethereum wallet | secp256k1 + keccak256 ("ek256") | [secp256k1 precompile](https://docs.anza.xyz/runtime/programs#secp256k1-program) | Verification + execution |
| WebAuthn passkey | secp256r1 (P-256) + SHA-256 | [secp256r1 precompile](https://docs.anza.xyz/runtime/programs#secp256r1-program) | Verification only |
| OIDC | RS256 JWT inside an SP1 zkVM proof | Groth16 over [alt_bn128 syscalls](https://docs.anza.xyz/proposals/precompiles) (`sp1-solana`) | Verification + execution |

The pattern is the standard precompile + instruction introspection flow: the client places the precompile verification instruction immediately before the program instruction in the same transaction. If the signature is invalid the runtime aborts the whole transaction, so by the time the program runs, the signature is known-good. The program then reads the precompile instruction back through the instructions sysvar to learn *what* was verified (signer + message) and uses that as the authenticated caller identity.

### On-chain state

Two account types, defined in [`programs/solana-aa/src/types`](programs/solana-aa/src/types):

- **`AccountManager`** — singleton PDA, seed `["account_manager"]`. Holds `next_account_id`, a monotonically increasing `u64`. Accounts get sequential IDs; IDs of deleted accounts are never reused. This enables cheap account discovery and prevents recreate-at-same-address attacks.
- **`AbstractAccount`** — one PDA per account, seeds `["abstract_account", account_id_le_bytes]`. Holds:
  - `nonce: u128` — incremented on every executed transaction, for replay protection
  - `identities: Vec<IdentityWithPermissions>` — the authentication methods that control the account
  - `bump: u8` — cached to skip re-derivation on later calls

The account is reallocated as identities are added and removed; rent for freed space is refunded to the signer ([`utils/pda.rs`](programs/solana-aa/src/utils/pda.rs)).

### Transaction execution (`execute_ek256`)

The only fully wired execution path today is Ethereum-signed transactions ([`contract/transaction/execute.rs`](programs/solana-aa/src/contract/transaction/execute.rs)):

1. The client Borsh-serializes `Transaction { account_id, nonce, action }` and signs `keccak256(bytes)` with an Ethereum key.
2. The client submits one Solana transaction containing two instructions:
   ```
   ix N-1: secp256k1 precompile   (signature, eth_address, message)
   ix N:   solana_aa::execute_ek256(account_id)
   ```
3. The runtime verifies the secp256k1 signature; an invalid signature aborts the transaction.
4. `execute_ek256` loads instruction `N-1` from the instructions sysvar and validates its shape ([`contract/auth/ek256.rs`](programs/solana-aa/src/contract/auth/ek256.rs)): it must be the secp256k1 program, carry exactly one signature, and all offsets must point into that same instruction (cross-instruction data references are rejected).
5. The Ethereum address from the precompile data becomes the caller identity, and the signed message is deserialized into a `Transaction`.
6. Validation ([`contract/transaction/validation.rs`](programs/solana-aa/src/contract/transaction/validation.rs)) checks that the identity is registered on the account, the transaction nonce matches the account nonce, and the signed `account_id` matches the PDA being operated on — then increments the nonce.
7. The action is dispatched:
   - `RemoveAccount` — close the PDA and refund rent
   - `AddIdentity(IdentityWithPermissions)` — register a new authentication method
   - `RemoveIdentity(Identity)` — remove one

Because the signed message embeds the account ID, the nonce, and the action, a signature cannot be replayed against another account, replayed twice, or repurposed for a different operation.

WebAuthn has the verification half implemented ([`contract/auth/secp256r1_sha256.rs`](programs/solana-aa/src/contract/auth/secp256r1_sha256.rs)) — same introspection pattern against the secp256r1 precompile, where the signed payload is `authenticator_data || sha256(client_data_json)` and the transaction hash travels in the client data challenge — but there is no `execute_*` path for it yet.

### Instructions

| Instruction | Purpose |
|---|---|
| `init_contract` / `close_contract` | Create / close the `AccountManager` singleton |
| `create_account` | Create an `AbstractAccount` with its first identity. Deliberately unauthenticated: anyone can create an account, but only its registered identities can control it |
| `execute_ek256` | Execution entrypoint — verify an Ethereum-signed `Transaction` and dispatch its action |
| `execute_zk_oidc` | Execution entrypoint — verify an SP1 Groth16 proof of an OIDC JWT, check transaction binding and key registry, dispatch the action |
| `init_oidc_registry` / `add_oidc_key` / `remove_oidc_key` / `close_oidc_registry` | Authority-managed registry pinning the OIDC provider signing keys (JWKS) accepted by `execute_zk_oidc` |
| `delete_account` / `add_identity` / `remove_identity` | Direct account mutations that **bypass signature auth** — development helpers only, must be removed or secured before any real deployment |
| `verify_eth` / `get_eth_data` | Debug helpers for secp256k1 precompile introspection |
| `verify_webauthn` / `get_webauthn_data` | Same for the secp256r1 precompile |
| `init_storage` / `store_chunk` / `retrieve_chunk` / `get_data_metadata` / `close_storage` | Transaction buffer (below) |

### Transaction buffer

[`contract/transaction_buffer.rs`](programs/solana-aa/src/contract/transaction_buffer.rs) implements chunked storage for payloads that exceed Solana's ~1232-byte transaction size limit (e.g. OIDC JWTs). Data is split into ≤900-byte chunks and written across multiple transactions into a per-payer PDA keyed by `data_id`, with a hash of the full dataset for integrity. Current implementation loads the whole chunk vector on the heap, so it is bounded by Solana's 32 KB heap limit — zero-copy accounts are the planned fix.

### ZK OIDC execution (`execute_zk_oidc`)

OIDC tokens (e.g. Google sign-in) authorize transactions through a zero-knowledge proof instead of on-chain RSA, since direct RSA verification is not viable on Solana (see the legacy PoC below). The JWT is verified inside an SP1 zkVM guest program ([`zk/jwt-program`](zk/jwt-program)) and only a 260-byte Groth16 proof goes on-chain, verified via the alt_bn128 syscalls (`sp1-solana`) — which, unlike `big_mod_exp`, are enabled on mainnet.

The guest program verifies the RS256 signature against a caller-supplied RSA key and commits public outputs: SHA-256 hashes of the email and of the signing key (the raw email never appears on-chain), plus the `iss`, `aud` and `nonce` claims. It fails closed — no proof exists for an invalid JWT. [`contract/auth/zk_oidc.rs`](programs/solana-aa/src/contract/auth/zk_oidc.rs) then enforces three bindings:

1. **Guest binding** — the Groth16 proof must match the pinned `JWT_VKEY_HASH`, so only the exact audited guest binary counts. Regenerate with `cd zk/script && cargo run --release -- vkey` after any guest change.
2. **Key binding** — the committed signing-key hash must exist in the `OidcKeyRegistry` PDA for that issuer. The registry is authority-managed (`init_oidc_registry` / `add_oidc_key` / `remove_oidc_key`) and stands in for the provider's JWKS endpoint, since anyone can generate a valid proof against a self-chosen key.
3. **Transaction binding** — the JWT `nonce` claim must equal `hex(sha256(borsh(Transaction)))`. The client puts that hash into the OAuth request, so the provider-signed token authorizes exactly one transaction; the account nonce then prevents replay, exactly as in `execute_ek256`.

The OIDC identity stored on the account is `(iss, aud, email_hash)` — binding to `aud` prevents tokens minted by a different OAuth client for the same email from controlling the identity.

Costs (measured, see [`zk/BENCHMARK.md`](zk/BENCHMARK.md)): ~1.02M zkVM cycles per JWT (10x below the unoptimized port — SP1's precompile-accelerated `rsa`/`sha2` forks plus SHA-256 identity hashing; `rsa_verify` is now 94% of cycles, the RS256 floor), ~3.4 min CPU proving (`zk/script`, Docker required for the Groth16 wrapper), 260-byte proof, verification fits in a 500k CU budget. SP1 is pinned at 5.0.x until [`sp1-solana`](https://github.com/succinctlabs/sp1-solana) can verify the v6 proof format. Tests use a committed golden fixture (`tests/fixtures/`) generated from a self-signed JWT, so `anchor test` needs neither the SP1 toolchain nor Docker.

Known limitations of this path: local CPU proving latency (~3.4 min) makes it unsuitable for interactive signing today — production offloads to the [Succinct Prover Network](https://docs.succinct.xyz) (`SP1_PROVER=network`) with no code change; JWT `exp`/`iat` are not validated (the transaction binding + account nonce already make a token single-use); the vkey and registry lifecycles need governance before any real deployment.

### Removed: direct on-chain RSA verification

Two earlier PoCs verified RS256 directly on-chain; both were dead ends and have been removed from the tree (see git history): `big_mod_exp`-syscall verification (syscall not enabled on mainnet/devnet, [solana-labs/solana#32520](https://github.com/solana-labs/solana/pull/32520)) and pure-Rust `rsa`-crate verification (exceeds the compute limit; multi-transaction splitting exceeds the heap limit). Tracked in [#13](https://github.com/Pessina/solana-aa/issues/13); superseded by the ZK path above.

Removal wasn't just cleanup: a program whose binary references an inactive syscall fails loader ELF verification with `Unresolved symbol (sol_big_mod_exp)` — merely containing the PoC made the program **undeployable on mainnet**, even if the instruction was never called. Caught by mainnet-feature-parity testing (below).

## Known gaps

What the validation layer enforces today: identity membership, nonce equality (then increment), and account-ID binding. What it does not:

- **Permissions are stored but never enforced.** `IdentityPermissions { enable_act_as }` is persisted, and `UserOp.act_as` exists in the types, but `is_transaction_authorized` checks neither.
- **Unauthenticated mutation instructions.** `delete_account`, `add_identity`, `remove_identity` operate without any signature verification.
- **No WebAuthn execution path**, and the `WebAuthnAuthenticator` identity does not yet bind `client_data.origin` / `rpIdHash` — a passkey reused across sites could be replayed cross-origin.
- **No bounds on account growth.** The identity list can grow toward the heap limit without a guard.
- **Single-signature only.** The precompile introspection rejects multi-signature instructions; there is no multisig or threshold support.

## Repository layout

```
programs/solana-aa/src/
├── lib.rs                       # Instruction entrypoints
├── pda_seeds.rs                 # PDA seed constants
├── contract/
│   ├── accounts.rs              # Abstract account creation
│   ├── contract_lifecycle.rs    # AccountManager init/close
│   ├── oidc_registry.rs         # OIDC signing-key registry (JWKS pinning)
│   ├── transaction_buffer.rs    # Chunked storage for large payloads
│   ├── auth/
│   │   ├── ek256.rs             # secp256k1 (Ethereum) precompile introspection
│   │   ├── secp256r1_sha256.rs  # secp256r1 (WebAuthn) precompile introspection
│   │   └── zk_oidc.rs           # SP1 Groth16 verification of the JWT guest program
│   └── transaction/
│       ├── execute.rs           # execute_ek256 / execute_zk_oidc → validate → dispatch
│       └── validation.rs        # Identity membership + nonce + account binding
├── types/
│   ├── account.rs               # AbstractAccount (nonce, identities, realloc)
│   ├── account_manager.rs       # Sequential account-ID counter
│   ├── identity/                # Identity enum: Wallet (Ethereum), WebAuthn, Oidc
│   ├── oidc_key_registry.rs     # Registry account: authority + (iss, pk_hash) entries
│   └── transaction/             # Transaction { account_id, nonce, action }
└── utils/pda.rs                 # PDA realloc/close helpers with rent accounting

zk/jwt-program/   # SP1 zkVM guest: verifies the RS256 JWT, commits public outputs
zk/script/        # Host tooling: vkey printing + golden fixture generation
borsh/            # TS Borsh schemas mirroring the on-chain types
utils/            # TS client helpers: precompile instruction builders, signers, PDAs
tests/            # Integration tests (ts-mocha against a local validator)
tests/fixtures/   # Committed SP1 Groth16 golden fixtures
```

## Development

Requirements: Rust, [Solana CLI (Agave) 2.x](https://docs.anza.xyz/cli/install), [Anchor CLI 0.31.1](https://www.anchor-lang.com/docs/installation), Node.js with Yarn.

```bash
yarn install
anchor build
anchor test      # builds, deploys to a local validator, runs all specs
yarn lint        # prettier check
```

Regenerating ZK artifacts additionally requires the [SP1 toolchain](https://docs.succinct.xyz/docs/sp1/getting-started/install) (`cargo prove install-toolchain`) and Docker (Groth16 wrapper):

```bash
cd zk/script
cargo run --release -- vkey      # guest vkey hash, pinned in contract/auth/zk_oidc.rs
cargo run --release -- fixture --out ../../tests/fixtures/zk-oidc-add-identity.json
```

### Test suite

| Spec | Covers |
|---|---|
| [`tests/accounts.spec.ts`](tests/accounts.spec.ts) | Account creation, sequential IDs, identity add/remove, closing |
| [`tests/execute_ek256.spec.ts`](tests/execute_ek256.spec.ts) | End-to-end signed-transaction execution with Ethereum keys |
| [`tests/borsh-ek256-auth.spec.ts`](tests/borsh-ek256-auth.spec.ts) | secp256k1 precompile verification and introspection |
| [`tests/secp256r1-sha256-auth.spec.ts`](tests/secp256r1-sha256-auth.spec.ts) | WebAuthn (P-256) verification, precompile and program error cases |
| [`tests/zk-oidc.spec.ts`](tests/zk-oidc.spec.ts) | ZK OIDC execution against the golden Groth16 fixture: happy path, replay, transaction-binding, registry and identity-membership rejections |
| [`tests/transaction-buffer.spec.ts`](tests/transaction-buffer.spec.ts) | Chunked storage lifecycle |

### Mainnet feature parity

By default `solana-test-validator` enables **all** runtime features, including ones inactive on mainnet — which makes mainnet-incompatible code look fine (it hid both the `big_mod_exp` dead end and the deploy blocker above). This repo pins the test validator to mainnet's feature set: `[test.validator] deactivate_feature` in [`Anchor.toml`](Anchor.toml) lists every mainnet-inactive feature, so plain `anchor test` runs under real mainnet conditions. The full suite passes there — the secp256k1/secp256r1 precompiles and the alt_bn128 syscalls used by ZK OIDC are all mainnet-active.

Mainnet activations move over time; refresh the list with `solana feature status -um | grep inactive | awk '{print $1}'`.

The Ethereum test keys are the standard Hardhat/Anvil development accounts.

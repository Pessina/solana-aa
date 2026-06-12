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
| OIDC (Google) | RSA-2048 PKCS#1 v1.5 + SHA-256 (RS256) | `big_mod_exp` syscall / `rsa` crate | PoC, localnet only |

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
| `execute_ek256` | Main entrypoint — verify an Ethereum-signed `Transaction` and dispatch its action |
| `delete_account` / `add_identity` / `remove_identity` | Direct account mutations that **bypass signature auth** — development helpers only, must be removed or secured before any real deployment |
| `verify_eth` / `get_eth_data` | Debug helpers for secp256k1 precompile introspection |
| `verify_webauthn` / `get_webauthn_data` | Same for the secp256r1 precompile |
| `verify_oidc_rsa_native` / `verify_oidc_rsa_crate` | Experimental RSA verification of OIDC token signatures |
| `init_storage` / `store_chunk` / `retrieve_chunk` / `get_data_metadata` / `close_storage` | Transaction buffer (below) |

### Transaction buffer

[`contract/transaction_buffer.rs`](programs/solana-aa/src/contract/transaction_buffer.rs) implements chunked storage for payloads that exceed Solana's ~1232-byte transaction size limit (e.g. OIDC JWTs). Data is split into ≤900-byte chunks and written across multiple transactions into a per-payer PDA keyed by `data_id`, with a hash of the full dataset for integrity. Current implementation loads the whole chunk vector on the heap, so it is bounded by Solana's 32 KB heap limit — zero-copy accounts are the planned fix.

### OIDC / RSA verification (PoC)

Two proof-of-concept paths for verifying Google OIDC JWT signatures (RS256) on-chain, both currently dead ends outside localnet ([`contract/auth/rsa`](programs/solana-aa/src/contract/auth/rsa), [`tests/rsa/README.md`](tests/rsa/README.md)):

- **`rsa_native`** — uses the `big_mod_exp` syscall. Works on localnet, but the syscall is not enabled on mainnet/devnet ([solana-labs/solana#32520](https://github.com/solana-labs/solana/pull/32520)).
- **`rsa_rsa_crate`** — pure-Rust modular exponentiation via the `rsa` crate. Exceeds the compute unit limit.
- Splitting verification across multiple transactions was also tried and removed — it exceeds the heap limit.

Tracked in [#13](https://github.com/Pessina/solana-aa/issues/13). Google's JWKS public keys are currently hardcoded in [`constants.rs`](programs/solana-aa/src/contract/auth/rsa/constants.rs); a real implementation would need an oracle/governance flow to keep them rotated.

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
│   ├── transaction_buffer.rs    # Chunked storage for large payloads
│   ├── auth/
│   │   ├── ek256.rs             # secp256k1 (Ethereum) precompile introspection
│   │   ├── secp256r1_sha256.rs  # secp256r1 (WebAuthn) precompile introspection
│   │   └── rsa/                 # OIDC RSA verification PoC (localnet only)
│   └── transaction/
│       ├── execute.rs           # execute_ek256: authenticate → validate → dispatch
│       └── validation.rs        # Identity membership + nonce + account binding
├── types/
│   ├── account.rs               # AbstractAccount (nonce, identities, realloc)
│   ├── account_manager.rs       # Sequential account-ID counter
│   ├── identity/                # Identity enum: Wallet (Ethereum), WebAuthn
│   └── transaction/             # Transaction { account_id, nonce, action }
└── utils/pda.rs                 # PDA realloc/close helpers with rent accounting

borsh/      # TS Borsh schemas mirroring the on-chain types
utils/      # TS client helpers: precompile instruction builders, signers, PDAs
tests/      # Integration tests (ts-mocha against a local validator)
```

## Development

Requirements: Rust, [Solana CLI (Agave) 2.x](https://docs.anza.xyz/cli/install), [Anchor CLI 0.31.1](https://www.anchor-lang.com/docs/installation), Node.js with Yarn.

```bash
yarn install
anchor build
anchor test      # builds, deploys to a local validator, runs all specs
yarn lint        # prettier check
```

### Test suite

| Spec | Covers |
|---|---|
| [`tests/accounts.spec.ts`](tests/accounts.spec.ts) | Account creation, sequential IDs, identity add/remove, closing |
| [`tests/execute_ek256.spec.ts`](tests/execute_ek256.spec.ts) | End-to-end signed-transaction execution with Ethereum keys |
| [`tests/borsh-ek256-auth.spec.ts`](tests/borsh-ek256-auth.spec.ts) | secp256k1 precompile verification and introspection |
| [`tests/secp256r1-sha256-auth.spec.ts`](tests/secp256r1-sha256-auth.spec.ts) | WebAuthn (P-256) verification, precompile and program error cases |
| [`tests/transaction-buffer.spec.ts`](tests/transaction-buffer.spec.ts) | Chunked storage lifecycle |
| [`tests/rsa/*.spec.ts`](tests/rsa) | OIDC RSA verification PoCs (localnet only) |

The Ethereum test keys are the standard Hardhat/Anvil development accounts.

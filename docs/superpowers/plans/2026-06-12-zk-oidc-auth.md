# ZK OIDC Authentication Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a working OIDC authentication path to solana-aa: a Google-style JWT is verified inside an SP1 zkVM proof off-chain, and the program verifies the resulting Groth16 proof on-chain (alt_bn128 syscalls, mainnet-compatible) to authorize abstract-account transactions.

**Architecture:** Port the validated approach from `~/Documents/hackathon` with three security fixes it lacked: (1) the JWT `nonce` claim must equal `hex(sha256(borsh(Transaction)))`, binding each proof to one transaction; (2) the RSA signing key's Poseidon hash must be present in an on-chain authority-managed registry (JWKS pinning); (3) OIDC becomes a first-class `Identity` variant `(iss, aud, email_hash)` flowing through the existing `is_transaction_authorized` validation (membership + account nonce + account-id binding). The SP1 guest program fails closed (panics on invalid signature → no proof exists). Tests use a golden Groth16 fixture generated from a self-signed test JWT.

**Tech Stack:** SP1 zkVM 5.0.0 (`sp1-zkvm`, `sp1-sdk`, `sp1-build`), `sp1-solana` (rev `768d62d9a8831f2b5600574fd5d96948eb7ebfc0`), `p3-baby-bear`/`p3-field` 0.2.3-succinct, Anchor 0.31.1, golden-fixture testing via ts-mocha.

**Reference implementation:** `~/Documents/hackathon` (guest: `jwt-zk-proving-server/program`, on-chain verifier: `zk-solana-aa/programs/zk-solana-aa/src/contract/auth.rs`). Proven numbers: 260-byte proof, ~4.6 min proving, 500k CU on-chain, Docker available for Groth16 wrapping, `cargo-prove` installed.

---

### Task 1: SP1 guest program (`zk/jwt-program`)

**Files:**
- Create: `zk/jwt-program/Cargo.toml`
- Create: `zk/jwt-program/src/main.rs`

Standalone crate (NOT part of the Anchor workspace — root workspace members glob is `programs/*`). Differences vs hackathon guest: commits `nonce`, drops `sub` (privacy) and `verified` flag (fail-closed panic instead), no in-guest issuer policy (policy lives on-chain via identity matching + registry).

- [ ] **Step 1: Write `zk/jwt-program/Cargo.toml`**

```toml
[workspace]

[package]
name = "jwt-program"
version = "0.1.0"
edition = "2021"

[dependencies]
sp1-zkvm = "5.0.0"
sp1-primitives = "5.0.0"
rsa = "0.9.6"
sha2 = { version = "0.10.8", features = ["oid"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.22.1"
p3-baby-bear = "0.2.3-succinct"
p3-field = "0.2.3-succinct"
```

- [ ] **Step 2: Write `zk/jwt-program/src/main.rs`**

```rust
#![no_main]
sp1_zkvm::entrypoint!(main);

use base64::Engine;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_primitives::poseidon2_hash;

type PoseidonHash = [BabyBear; 8];

/// Public outputs committed by this guest program.
///
/// MUST stay field-for-field compatible (bincode order) with `PublicOutputs`
/// in `programs/solana-aa/src/contract/auth/zk_oidc.rs`. The golden fixture
/// test catches drift.
#[derive(Serialize, Deserialize, Debug)]
pub struct PublicOutputs {
    pub email_hash: PoseidonHash,
    pub pk_hash: PoseidonHash,
    pub iss: String,
    pub aud: String,
    pub nonce: String,
}

pub fn main() {
    let pk_der = sp1_zkvm::io::read::<Vec<u8>>();
    let jwt_header = sp1_zkvm::io::read::<Vec<u8>>();
    let jwt_payload = sp1_zkvm::io::read::<Vec<u8>>();
    let signature = sp1_zkvm::io::read::<Vec<u8>>();

    let public_key = RsaPublicKey::from_public_key_der(&pk_der).expect("invalid public key DER");

    // JWT signing input: base64url(header) || '.' || base64url(payload)
    let mut signing_input = jwt_header;
    signing_input.push(b'.');
    signing_input.extend_from_slice(&jwt_payload);

    let hashed_msg = Sha256::digest(&signing_input);

    // Fail closed: a proof can only exist for a JWT with a valid signature.
    public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_msg, &signature)
        .expect("RSA signature verification failed");

    let claims = extract_claims(&jwt_payload).expect("invalid JWT claims");

    sp1_zkvm::io::commit(&PublicOutputs {
        email_hash: poseidon_hash_bytes(claims.email.as_bytes()),
        pk_hash: poseidon_hash_bytes(&pk_der),
        iss: claims.iss,
        aud: claims.aud,
        nonce: claims.nonce,
    });
}

struct Claims {
    iss: String,
    aud: String,
    email: String,
    nonce: String,
}

fn extract_claims(jwt_payload: &[u8]) -> Result<Claims, &'static str> {
    let payload_b64 = core::str::from_utf8(jwt_payload).map_err(|_| "payload not UTF-8")?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "payload base64 decode failed")?;
    let json: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| "payload not valid JSON")?;

    let get = |key: &str| -> Result<String, &'static str> {
        json[key]
            .as_str()
            .map(str::to_string)
            .ok_or("missing claim")
    };

    Ok(Claims {
        iss: get("iss")?,
        aud: get("aud")?,
        email: get("email")?,
        nonce: get("nonce")?,
    })
}

/// Pack bytes into BabyBear field elements (4 bytes per element, LE) and
/// Poseidon2-hash them. Must match `poseidon_to_bytes` on-chain.
fn poseidon_hash_bytes(data: &[u8]) -> PoseidonHash {
    let mut field_elements = Vec::with_capacity(data.len().div_ceil(4));
    for chunk in data.chunks(4) {
        let mut value = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u32) << (i * 8);
        }
        field_elements.push(BabyBear::from_canonical_u32(value));
    }
    poseidon2_hash(field_elements)
}
```

- [ ] **Step 3: Commit** — `git add zk/jwt-program && git commit -m "feat: add SP1 guest program for ZK JWT verification"`

### Task 2: Host script (`zk/script`) — vkey, guest execution, fixture generation

**Files:**
- Create: `zk/script/Cargo.toml`
- Create: `zk/script/build.rs`
- Create: `zk/script/src/main.rs`
- Create: `zk/script/fixtures/test_rsa_private.pem` (via `openssl genrsa -traditional -out ... 2048`; test-only key, safe to commit)

Subcommands:
- `vkey` — print the guest vkey hash (`vk.bytes32()`) to pin on-chain.
- `fixture --account-id 0 --account-nonce 0 --eth-address 0x7099... [--execute-only] --out <path>` — builds the Borsh `Transaction` **using the program crate's own types** (path dep, golden/DRY), computes `nonce = hex(sha256(borsh(tx)))`, self-signs a JWT with the test RSA key carrying that nonce, then either executes the guest (fast, validates outputs) or proves Groth16 (~5 min, Docker) and writes a JSON fixture with proof + public values + parsed fields for the TS tests.

```toml
[workspace]

[package]
name = "zk-script"
version = "0.1.0"
edition = "2021"

[build-dependencies]
sp1-build = "5.0.0"

[dependencies]
sp1-sdk = "5.0.0"
solana-aa = { path = "../../programs/solana-aa", features = ["no-entrypoint"] }
anchor-lang = "0.31.1"
clap = { version = "4", features = ["derive"] }
serde_json = "1.0"
rsa = { version = "0.9.6", features = ["sha2", "pem"] }
sha2 = "0.10.8"
base64 = "0.22.1"
hex = "0.4.3"
```

`build.rs`: `fn main() { sp1_build::build_program_with_args("../jwt-program", Default::default()) }`

Main flow (full code in repo, see `zk/script/src/main.rs`): construct `Transaction { account_id, nonce, action: Action::AddIdentity(IdentityWithPermissions { identity: Identity::Wallet(WalletType::Ethereum(eth)), permissions: Some(IdentityPermissions { enable_act_as: true }) }) }`, serialize with `AnchorSerialize`, sha256+hex → JWT nonce; JWT header `{"alg":"RS256","typ":"JWT","kid":"test-key-1"}`, payload with `iss=https://test-issuer.solana-aa.dev`, `aud=solana-aa-tests`, `email=test@solana-aa.dev`, `nonce=<hex>`; sign PKCS#1 v1.5/SHA-256; SP1Stdin gets (pk_der, header_b64, payload_b64, signature); `client.execute(...)` or `client.prove(&pk, &stdin).groth16().run()`; fixture JSON fields: `proof`, `publicValues`, `vkeyHash`, `emailHash` (32-byte hex via poseidon_to_bytes), `pkHash`, `iss`, `aud`, `nonce`, `accountId`, `accountNonce`, `ethAddress`.

- [ ] Requires `programs/solana-aa/Cargo.toml` types to be publicly constructible (`IdentityPermissions` field `enable_act_as` is currently private → make `pub`).
- [ ] Run `cargo run --release -- vkey` (builds guest via sp1-build; needs `cargo-prove` toolchain, confirmed installed).
- [ ] Run `cargo run --release -- fixture --execute-only ...` to validate guest logic fast.
- [ ] Run `cargo run --release -- fixture ... --out ../../tests/fixtures/zk-oidc-add-identity.json` (Groth16, ~5 min, Docker) in background.
- [ ] Commit: `feat: add zk script for vkey and golden fixture generation`

### Task 3: `Identity::Oidc` variant (Rust + TS)

**Files:**
- Create: `programs/solana-aa/src/types/identity/oidc.rs`
- Modify: `programs/solana-aa/src/types/identity/mod.rs` (append variant — Borsh enum tag order: Wallet=0, WebAuthn=1, Oidc=2; make `IdentityPermissions.enable_act_as` pub)
- Modify: `borsh/index.ts`, `borsh/schemas/identity/index.ts` (+ new `oidc` schema), `utils/identity/` (+ `buildOidcIdentity`)

```rust
// types/identity/oidc.rs
use anchor_lang::prelude::*;

/// OIDC identity. The email is never stored or revealed on-chain — only its
/// Poseidon2 hash as committed by the ZK guest program.
#[derive(Debug, AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone)]
pub struct OidcIdentity {
    pub iss: String,
    pub aud: String,
    pub email_hash: [u8; 32],
}
```

TS borsh: `oidcIdentitySchema = { struct: { iss: "string", aud: "string", email_hash: { array: { type: "u8", len: 32 } } } }`; appended third in `identitySchema` enum. Anchor-format helper mirrors `buildEthereumIdentity` tuple-variant shape: `{ identity: { oidc: { "0": { iss, aud, emailHash } } }, permissions }`.

- [ ] Commit: `feat: add OIDC identity type`

### Task 4: OIDC key registry (JWKS pinning)

**Files:**
- Create: `programs/solana-aa/src/types/oidc_key_registry.rs`
- Create: `programs/solana-aa/src/contract/oidc_registry.rs`
- Modify: `programs/solana-aa/src/pda_seeds.rs` (+`OIDC_KEY_REGISTRY_SEED`), `types/mod.rs`, `contract/mod.rs`, `lib.rs`

Singleton PDA `["oidc_key_registry"]`: `{ authority: Pubkey, keys: Vec<OidcKeyEntry { iss: String, pk_hash: [u8;32] }>, bump }`. Instructions: `init_oidc_registry` (authority = signer), `add_oidc_key` (authority-gated, Anchor `realloc` constraint grows by `4 + iss.len() + 32`), `remove_oidc_key` (authority-gated, keeps capacity — no shrink), `close_oidc_registry` (authority-gated, `close = authority`). `contains(iss, pk_hash)` lookup.

- [ ] Commit: `feat: add OIDC key registry for JWKS pinning`

### Task 5: On-chain ZK verification module

**Files:**
- Create: `programs/solana-aa/src/contract/auth/zk_oidc.rs`
- Create: `programs/solana-aa/src/contract/auth/groth16_vk.bin` (copy of hackathon's 396-byte SP1 v5.0.0 Groth16 VK)
- Modify: `programs/solana-aa/Cargo.toml` (+serde, sp1-solana pinned rev, sp1-primitives 5.0.0, p3-baby-bear/p3-field 0.2.3-succinct), `contract/auth/mod.rs`

Core: `Sp1Groth16Proof { proof: Vec<u8>, public_values: Vec<u8> }` (Anchor-serializable instruction arg); serde-mirrored `PublicOutputs`; `verify_zk_oidc_proof` = `sp1_solana::verify_proof(proof, public_values, JWT_VKEY_HASH, GROTH16_VK_BYTES)` → parse via `SP1PublicValues::read` (safe post-verification: the proof commits the public-values digest) → length-cap iss (≤64)/aud (≤256) → `VerifiedJwt { email_hash, pk_hash: [u8;32] via poseidon_to_bytes, iss, aud, nonce }`. `JWT_VKEY_HASH` pinned from Task 2's `vkey` output. `transaction_nonce_hex(tx_bytes) = hex(sha256(tx_bytes))`.

- [ ] Commit: `feat: add on-chain SP1 Groth16 verification for OIDC JWTs`

### Task 6: `execute_zk_oidc` + shared dispatch

**Files:**
- Modify: `programs/solana-aa/src/contract/transaction/execute.rs` (extract `dispatch_action(accounts, action)` used by both paths; add `ExecuteZkOidc` accounts + impl)
- Modify: `programs/solana-aa/src/lib.rs` (4 new instructions: `init_oidc_registry`, `add_oidc_key`, `remove_oidc_key`, `close_oidc_registry`, `execute_zk_oidc`)

`execute_zk_oidc(account_id, transaction: Transaction, proof: Sp1Groth16Proof)`:
1. `verify_zk_oidc_proof(&proof)?`
2. `require!(jwt.nonce == transaction_nonce_hex(&transaction.try_to_vec()?))` — **transaction binding**
3. `require!(registry.contains(&jwt.iss, &jwt.pk_hash))` — **JWKS pinning**
4. `Identity::Oidc(OidcIdentity { iss, aud, email_hash })` → existing `is_transaction_authorized` (membership + account nonce + account-id, increments nonce — **replay protection**)
5. `dispatch_action(...)`

Accounts: signer (fee payer, no authority), abstract_account PDA, oidc_key_registry PDA, system_program. No instructions sysvar (no precompile in this path).

- [ ] `anchor build` passes; commit: `feat: add execute_zk_oidc instruction with transaction binding`

### Task 7: Integration tests (golden fixture)

**Files:**
- Create: `tests/zk-oidc.spec.ts`
- Create: `utils/zk-oidc.ts` (fixture loader, registry PDA finder)
- Fixture: `tests/fixtures/zk-oidc-add-identity.json` (from Task 2)

Tests (each with `ComputeBudgetProgram.setComputeUnitLimit({ units: 500_000 })`):
1. **Cross-language golden check:** TS-side `sha256(borshUtils.serialize.transaction(tx))` hex equals `fixture.nonce` (catches Rust/TS Borsh drift).
2. **Happy path:** create account with OIDC identity from fixture (account_id 0 after cleanup) → init registry + add fixture pkHash → `executeZkOidc` with fixture proof + reconstructed tx → identity list contains the added Ethereum identity, account nonce == 1.
3. **Replay rejected:** resubmit same proof+tx → `NonceMismatch`.
4. **Wrong transaction rejected:** same proof, different tx → `TransactionBindingMismatch`.
5. **Unregistered key rejected:** remove key from registry first → `OidcKeyNotRegistered`.
6. **Foreign identity rejected:** account without the OIDC identity → `IdentityNotFound`.

- [ ] `anchor test` (background, full suite) passes including all pre-existing specs.
- [ ] Commit: `test: add ZK OIDC golden-fixture integration tests`

### Task 8: Docs

- Modify: `README.md` — OIDC row in the auth table → implemented via SP1 Groth16; replace the "OIDC / RSA verification (PoC)" section with the ZK design (guest program, proving flow, binding rules, registry); update repo layout + known gaps (proving latency, vkey lifecycle); keep the legacy RSA PoC note.
- [ ] `yarn lint` passes; commit: `docs: document ZK OIDC authentication path`

## Self-review notes

- Spec coverage: nonce binding (T2 fixture + T6 step 2 + T7 tests 3/4), JWKS registry (T4 + T6 step 3 + T7 test 5), OIDC identity (T3 + T7 test 6) — all covered.
- Type consistency: `PublicOutputs` duplicated guest/on-chain by design (no shared crate across zkVM/SBF targets); golden fixture test is the drift guard. `Sp1Groth16Proof` field names match IDL camelCase (`publicValues`) in TS.
- Risk log: (a) Groth16 proving needs Docker — verified installed; (b) vkey chicken-and-egg — Task 2 prints it before Task 5 pins it; (c) `p3-baby-bear` on SBF — proven by hackathon build; (d) account_id determinism — `cleanUpProgramState` closes + re-inits the contract, resetting `next_account_id` to 0.

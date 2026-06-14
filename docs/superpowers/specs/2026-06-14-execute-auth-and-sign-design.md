# Design: Execution paths for all auth methods + `Sign` action + P0 hardening

- **Date:** 2026-06-14
- **Branch:** `feature/execute-auth-and-sign` (off synced `main` @ `d3458eb`)
- **Status:** Draft for review
- **Related:** `ROADMAP.md` (P0 security foundation, P1 `Sign` action)

## 1. Summary

Today only Ethereum (`execute_ek256`) and OIDC (`execute_zk_oidc`) can authorize
transactions, and the only `Action`s are identity management (`RemoveAccount`,
`AddIdentity`, `RemoveIdentity`). This work:

1. Adds a **WebAuthn execution path** (`execute_webauthn`) so passkeys are a
   first-class auth method, including the P0 origin/rpIdHash binding.
2. Adds a **`Sign` action** that lets an abstract account request an MPC signature
   from the Sig Network **chain-signatures** program via CPI — and *only* that
   program, whose ID is **set per deployment at init** (not hardcoded). This is
   the account's first outward-facing capability (control of external-chain
   keys), shared by all three auth methods.
3. Lands the P0 hardening that gates any non-localnet use: remove the
   unauthenticated mutation instructions, bound account growth, and eliminate
   panics in instruction paths.

Explicitly **deferred at the user's direction:** permission enforcement, and
therefore `act_as` validation (it is gated by `enable_act_as`).

## 2. Scope

**In scope**

- `execute_webauthn` instruction (P-256 passkey-authorized transactions).
- WebAuthn transaction-binding (via `client_data.challenge`) + origin/rpIdHash
  binding; tightened `WebAuthnAuthenticator` equality.
- `Sign(SignRequest)` action → CPI into chain-signatures `sign`, available from
  all three execute paths. The target program ID is **deployment config** set at
  init, so devnet/mainnet/forks differ with no code change.
- Extend `AccountManager` + `init_contract` to store the chain-signatures program
  ID.
- Remove `delete_account` / `add_identity` / `remove_identity` (unauthenticated)
  and rewire dependent tests + the `cleanUpProgramState` helper.
- Bound account growth at identity-add time.
- Replace `unwrap()`/`expect()` in instruction paths with typed errors.
- TS client helpers + Borsh schemas + tests for the above.
- Sync `README.md` / `ROADMAP.md` to the shipped state.

**Out of scope** (deferred)

- Permission model / enforcement; `act_as` delegation validation.
- An authority-gated instruction to **update** the chain-signatures program ID
  after init (today it is set once at init; changing it means close + reinit).
- `AddIdentityWithAuth`, multi-signature / threshold, transaction expiration.
- Removal of debug introspection instructions (`verify_eth` / `get_eth_data` /
  `verify_webauthn` / `get_webauthn_data`) — but their panics are fixed (§9).
- OIDC registry governance / JWKS automation; `sub`-claim keying; salted email
  commitment.

## 3. Target program — chain-signatures interface (facts)

Source: `sig-net/solana-signet-program`, crate `chain-signatures-solana-program`
(docs.rs).

- **Program ID (canonical devnet/mainnet):**
  `SigMcRMjKfnC7RDG5q4yUMZM1s5KJ9oYTPP4NmJRDRw` — used as the default in
  clients/tests, but on-chain it is **deployment config** (§A.0), not a const.
- **Instruction:**
  ```rust
  pub fn sign(
      ctx: Context<Sign>,
      payload: [u8; 32],
      key_version: u32,
      path: String,
      algo: String,
      dest: String,
      params: String,
  ) -> Result<()>
  ```
- **`Sign` accounts (order):**
  ```rust
  pub struct Sign<'info> {
      pub program_state: Account<'info, ProgramState>,
      pub requester: Signer<'info>,
      pub fee_payer: Option<Signer<'info>>,
      pub system_program: Program<'info, System>,
      pub event_authority: AccountInfo<'info>, // chain-signatures self-CPI event PDA
      pub program: AccountInfo<'info>,         // chain-signatures program account
  }
  ```
- Charges a per-request **deposit** (`get_signature_deposit` view; `deposit`
  field on the event) paid by `fee_payer` if present, else `requester`.
- Emits `SignatureRequestedEvent { sender, payload, key_version, deposit,
  chain_id, path, algo, dest, params, fee_payer }`. An off-chain MPC network
  watches for it and later calls `respond`. `sender` is the requester pubkey, and
  the derived cross-chain key is a function of `(requester, path)`.

**Implementation note (verify against the IDL before finalizing metas):** the
exact `mut`/`signer` flags per account are not in the rendered docs. They must be
read from the chain-signatures IDL/source when constructing the `AccountMeta`
list. Best current inference: `program_state` mut; `requester` signer;
`fee_payer` signer + mut (pays deposit); `system_program` ro; `event_authority`
ro; `program` ro.

## 4. Architecture — one spine, three front-doors

All execute paths already converge:

```
auth layer ─→ (Identity, Transaction) ─→ is_transaction_authorized ─→ dispatch_action(action)
   ek256  ┐                                (membership, nonce==, id==,        │
 webauthn ┼─ each produces an Identity      then nonce += 1)                   ├─ RemoveAccount
  zk_oidc ┘  + the Transaction                                                ├─ AddIdentity
                                                                              ├─ RemoveIdentity
                                                                              └─ Sign  ← NEW
```

`Sign` is a new `Action` variant handled in the shared `dispatch_action`, so
implementing it once enables it for **all three** auth methods. The Sign
parameters live *inside* the signed `Transaction`, so the existing per-method
binding already authorizes the exact payload/path:

- `execute_ek256`: the `Transaction` Borsh bytes *are* the signed message.
- `execute_zk_oidc`: `jwt.nonce == hex(sha256(borsh(Transaction)))`.
- `execute_webauthn`: `client_data.challenge == base64url(sha256(borsh(Transaction)))`.

The account `nonce` still increments in `is_transaction_authorized`, so each
signed Sign request is single-use (replay-protected) exactly like the identity
actions.

## 5. Component A — `Sign` action (chain-signatures CPI)

### A.0 Deployment config — chain-signatures program ID

The target program ID is stored on the `AccountManager` singleton (seed
`["account_manager"]`) and set at init, so each deployment points at its own
chain-signatures instance.

`types/account_manager.rs`:
```rust
pub struct AccountManager {
    pub next_account_id: AccountId,
    pub chain_signatures_program_id: Pubkey, // NEW (32 bytes)
    pub bump: u8,
}
// INIT_SIZE += PUBKEY_SIZE (32): 8 disc + 8 id + 32 pk + 1 bump = 49
```

`contract/contract_lifecycle.rs` — `init_contract` gains the ID:
```rust
pub fn init_contract_impl(
    ctx: Context<InitContract>,
    chain_signatures_program_id: Pubkey,
) -> Result<()> {
    let m = &mut ctx.accounts.account_manager;
    m.next_account_id = 0;
    m.chain_signatures_program_id = chain_signatures_program_id;
    m.bump = ctx.bumps.account_manager;
    Ok(())
}
```
`InitContract` already sizes by `AccountManager::INIT_SIZE`, so the +32 is
automatic. Init stays permissionless (the deployer initializes the singleton);
making the ID updatable later is governance work (deferred, §2/§16).

### A.1 Types (`types/transaction/transaction.rs`)

```rust
pub enum Action {
    RemoveAccount,
    AddIdentity(IdentityWithPermissions),
    RemoveIdentity(Identity),
    Sign(SignRequest),                 // appended — keeps Borsh tags stable
}

pub struct SignRequest {
    pub payload: [u8; 32],
    pub key_version: u32,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
}
```

`path`/`algo`/`dest`/`params` get length caps (consts, mirroring `MAX_ISS_LEN`)
to bound heap use during deserialization — proposed `MAX_PATH_LEN = 64`,
`MAX_ALGO_LEN = MAX_DEST_LEN = MAX_PARAMS_LEN = 64`; tune in implementation.

### A.2 CPI construction (`contract/transaction/sign.rs`, new)

```rust
// Anchor global instruction discriminator = sha256("global:sign")[..8].
// Pinned as a const and asserted by a golden test (so a wrong value fails CI,
// not mainnet).
const SIGN_DISCRIMINATOR: [u8; 8] = /* pinned */;
```

The target **program ID comes from `account_manager.chain_signatures_program_id`**
(deployment config, §A.0), not a const. The instruction is built **manually**
(configured program ID + discriminator + Borsh args) rather than by depending on
the chain-signatures crate, to avoid Anchor-version coupling and keep the
minimal-deps posture of this repo. Args are Borsh-serialized in declared order:
`payload, key_version, path, algo, dest, params`.

Alternative considered: depend on `chain-signatures-solana-program` with the
`cpi` feature and call `cpi::sign`. Rejected for now (heavier dependency, version
coupling); revisit if the manual discriminator/IDL drift becomes a maintenance
burden.

### A.3 Accounts & fee model

The execute instruction names what it can (the AA PDA, the signer, the system
program, the config) and takes the remaining chain-signatures accounts via
`ctx.remaining_accounts`. The CPI meta list is built in struct order:

| # | Account | Source | Flags (verify vs IDL) |
|---|---|---|---|
| 0 | `program_state` | `remaining_accounts[0]` | mut |
| 1 | `requester` | named `abstract_account` (AA PDA) | signer (via `invoke_signed`) |
| 2 | `fee_payer` | named `signer` (outer) | signer, mut |
| 3 | `system_program` | named `system_program` | ro |
| 4 | `event_authority` | `remaining_accounts[1]` | ro |
| 5 | `program` | `remaining_accounts[2]` (must == configured id) | ro |

So `remaining_accounts` carries just `[program_state, event_authority, program]`;
`requester`/`fee_payer`/`system_program` are reused from the execute
instruction's named accounts.

Each of the three execute account structs (`ExecuteEk256`, `ExecuteWebauthn`,
`ExecuteZkOidc`) gains a read-only `account_manager` (seeds `["account_manager"]`,
`bump = account_manager.bump`) so dispatch can read the configured program ID.
Cost is one ro account per execute tx; keeps the target Anchor-validated and
identical across all paths.

**Fee model (decided):** the *outer Solana signer* is `fee_payer` and covers the
deposit; the AA PDA is only `requester` and needs no SOL balance. Relayer- and
fresh-account-friendly.

The CPI signs as the AA PDA:
```rust
invoke_signed(&ix, &account_infos,
    &[&[ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref(), &[abstract_account.bump]]])
```

### A.4 Security properties

- **Single-target is structural.** We construct the `Instruction` with
  `program_id = account_manager.chain_signatures_program_id` (deployment config,
  immutable per call) and additionally require the passed `program` account to
  equal it, so the CPI can only ever reach the configured chain-signatures
  program. No arbitrary-CPI surface exists; the only trust is in whoever
  initialized the deployment (the deployer) — the standard deploy-time trust
  boundary.
- **No self-reentrancy.** The CPI target is never `solana_aa`, so `Sign` cannot
  re-enter to mutate the account or bypass auth.
- **Exact-intent binding.** `SignRequest` is inside the signed `Transaction`;
  payload/path/etc. cannot be swapped after signing. Nonce increment makes each
  request single-use.

### A.5 `dispatch_action` refactor

Current signature:
```rust
fn dispatch_action(operation_accounts: AbstractAccountOperationAccounts, action: Action) -> Result<()>
```
`Sign` needs `remaining_accounts`, `account_id`, the configured program ID, the
PDA `bump`, and the outer signer (fee_payer). Proposed:
```rust
fn dispatch_action<'info>(
    operation_accounts: AbstractAccountOperationAccounts<'_, 'info>,
    account_id: AccountId,
    chain_signatures_program_id: Pubkey,       // from account_manager
    remaining_accounts: &[AccountInfo<'info>],
    action: Action,
) -> Result<()>
```
`bump` is read from `abstract_account.bump`; `signer` is `operation_accounts
.signer_info`. The three callers pass `account_id`,
`ctx.accounts.account_manager.chain_signatures_program_id`, and
`ctx.remaining_accounts`. `RemoveAccount`/`AddIdentity`/`RemoveIdentity` ignore
the new params.

## 6. Component B — WebAuthn execution (`execute_webauthn`)

### B.1 Instruction & accounts (`contract/transaction/execute.rs`)

```rust
pub fn execute_webauthn(
    ctx: Context<ExecuteWebauthn>,
    account_id: AccountId,
    transaction: Transaction,
    auth: WebAuthnAuthData,           // new arg type
) -> Result<()>
```
`ExecuteWebauthn` mirrors `ExecuteEk256`: `signer`, `abstract_account` (mut,
seeds), `account_manager` (ro), `system_program`, and the `instructions` sysvar
(for secp256r1 introspection). Follows the OIDC shape (the `Transaction` is an
explicit arg, bound by the challenge rather than recovered from the signed
message).

```rust
pub struct WebAuthnAuthData {
    pub client_data: String,        // clientDataJSON
    pub authenticator_data: Vec<u8>,// raw authenticatorData
}
```

### B.2 Verification flow

1. Recover `(pubkey, signed_message)` from the secp256r1 precompile via
   `get_secp256r1_sha256_data_impl`, **refactored to take the instructions-sysvar
   `AccountInfo`** (like `get_ek256_data_impl`) instead of its current
   `Context<VerifyWebauthnSignature>`.
2. Recompute `expected = authenticator_data || sha256(client_data)` and require
   `expected == signed_message`. (Proves the passkey signed this exact
   authenticator_data + client_data.)
3. Parse `client_data` with a typed serde_json struct (only `type`, `challenge`,
   `origin`; no `Value` tree — mirrors the ZK guest). Require:
   - `type == "webauthn.get"`,
   - `base64url_nopad_decode(challenge) == sha256(borsh(transaction))`
     (**transaction binding**),
   - `origin == identity.origin` (**origin binding**).
4. **rpIdHash binding:** require `authenticator_data[0..32] == identity.rp_id_hash`
   and the User-Present flag (`authenticator_data[32] & 0x01`) set.
5. Build `Identity::WebAuthn(WebAuthnAuthenticator { compressed_public_key:
   Some(hex(pubkey)), .. })`, then shared `is_transaction_authorized` →
   `dispatch_action`.

### B.3 Identity type changes (`types/identity/webauthn.rs`)

```rust
pub struct WebAuthnAuthenticator {
    pub key_id: String,
    pub compressed_public_key: Option<String>,
    pub rp_id_hash: [u8; 32],   // NEW — sha256(rpId), checked vs authenticatorData
    pub origin: String,          // NEW — checked vs clientDataJSON.origin (capped len)
}
```
- **Tighten `eq`:** require equal `compressed_public_key` (and `rp_id_hash`).
  Remove today's `_ => true` arm that lets a `None` pubkey match anything — at
  execute time we always have the real pubkey from the precompile.
- This changes the Borsh layout of the `WebAuthn` identity variant. Acceptable:
  no WebAuthn identities exist in production (research prototype; no prior execute
  path). Borsh **enum tag** order is unchanged (variant stays in place).

### B.4 Client / TS

- New `utils/identity/webauthn.ts` (build `Identity::WebAuthn`, compute
  `rp_id_hash`, assemble `WebAuthnAuthData`).
- A secp256r1 verification-instruction builder (mirror
  `utils/ethereum.ts::createSecp256k1VerificationInstruction`), reusing knowledge
  in `tests/secp256r1-sha256-auth.spec.ts`.
- Update `borsh/schemas/identity/webauthn.ts` for the new fields.

## 7. Component C — Remove unauthenticated mutation instructions

Delete from `lib.rs`: `delete_account`, `add_identity`, `remove_identity` (they
take `ExecuteEk256` ctx but perform **no** signature check).

**Test/util rewire (required — these are used):**
- `utils/program.ts:53` `cleanUpProgramState` calls `.deleteAccount(i)` to tear
  down accounts in `beforeEach` for **every** spec. Rewire to close via the
  authenticated path: sign a `RemoveAccount` `Transaction` with the test Ethereum
  key and submit through `execute_ek256` (+ secp256k1 pre-instruction). Helper
  must know an account's registered Ethereum identity + current nonce. (Also
  update `utils/program.ts:76` `initContract()` → `initContract(chainSigId)`.)
- `tests/accounts.spec.ts` lines 152, 234, 271, 313 (`deleteAccount`,
  `addIdentity`, `removeIdentity`): rewire to the `execute_ek256` signed path.
- `tests/zk-oidc.spec.ts:56,177` use `addIdentity` as an **Action** key
  (`{ addIdentity: {...} }`), not the instruction — **no change needed**.

## 8. Component D — Bound account growth

In `AbstractAccount::add_identity`, before `realloc_account`:
- `require!(self.identities.len() < MAX_IDENTITIES, TooManyIdentities)` —
  proposed `MAX_IDENTITIES = 16`.
- `require!(new_size <= MAX_ACCOUNT_SIZE, AccountTooLarge)` — proposed
  `MAX_ACCOUNT_SIZE = 8 KiB`, comfortably under the +10 KiB/realloc and 32 KiB
  heap limits.

Tune constants during implementation; values documented in code.

## 9. Component E — Eliminate panics

Replace the 4 sites with typed errors / infallible constructs:

| File:line | Current | Fix |
|---|---|---|
| `contract/auth/secp256r1_sha256.rs:51` | `Pubkey::from_str("Secp256r1…").unwrap()` (real verify path) | `const` pubkey via `pubkey!` (no parse, no panic) |
| `types/identity/mod.rs:25` | `byte_size()` `.expect("Failed to serialize identity")` (real add/remove path) | return `Result<usize>`, propagate with `?` at callers |
| `lib.rs:100` | `get_eth_data` `try_from_slice(..).unwrap()` (debug ix) | `?` with typed error |
| `lib.rs:116` | `get_webauthn_data` `from_utf8(..).unwrap()` (debug ix) | `?` with typed error |

## 10. End-to-end data flows

**Sign (Ethereum-authorized example):**
1. Client builds `Transaction { account_id, nonce, action: Sign(SignRequest{ payload, key_version, path, algo, dest, params }) }`.
2. Signs `keccak256(borsh(tx))` with the Ethereum key.
3. Submits one Solana tx: `[secp256k1 precompile ix, execute_ek256(account_id)]`.
   `execute_ek256`'s named accounts include `account_manager`; the
   chain-signatures `program_state`/`event_authority`/`program` are appended as
   `remaining_accounts`.
4. `execute_ek256` → identity = Ethereum addr; validate; dispatch `Sign` → build
   the `sign` ix with `program_id = account_manager.chain_signatures_program_id`;
   `invoke_signed` as the AA PDA; outer signer pays deposit;
   `SignatureRequestedEvent` emitted; MPC network responds off-chain.

**WebAuthn execute:**
1. Client builds the `Transaction`; sets WebAuthn `challenge =
   base64url(sha256(borsh(tx)))`; obtains a passkey assertion.
2. Submits `[secp256r1 precompile ix, execute_webauthn(account_id, tx, auth)]`.
3. Program checks message reconstruction, transaction binding, origin/rpIdHash,
   identity membership, nonce → dispatch.

## 11. Error handling (new error codes)

- Sign: `InvalidChainSignaturesAccounts` (missing/short remaining_accounts),
  `InvalidSignParams` (cap exceeded), `ChainSignaturesProgramMismatch` (passed
  `program` account ≠ configured id).
- WebAuthn: `WebAuthnMessageMismatch`, `WebAuthnChallengeMismatch`,
  `WebAuthnOriginMismatch`, `WebAuthnRpIdMismatch`, `WebAuthnUserNotPresent`,
  `InvalidClientData`.
- Account: `TooManyIdentities`, `AccountTooLarge`.
- Replace panics with: `InvalidEthDataMessage`, `IdentitySerializationFailed`,
  etc.

## 12. Testing strategy

- **Config**: `init_contract` now takes the chain-signatures program ID; test
  setup passes the cloned program's (canonical) ID; `utils/program.ts` +
  `cleanUpProgramState` updated; add the ID to `utils/constants.ts`.
- **WebAuthn** (`tests/execute_webauthn.spec.ts`, new): happy path (passkey
  `AddIdentity` + `RemoveIdentity`); rejections for transaction-binding,
  origin, rpIdHash, user-present, replay (nonce), unregistered identity.
- **Sign instruction construction** (always-on golden): assert the built
  instruction's discriminator + Borsh arg bytes + account-meta order against a
  committed golden vector. Guards the hardcoded discriminator.
- **Sign end-to-end CPI** (recommended): clone the chain-signatures program and
  its initialized `program_state` (+ `event_authority`) from devnet into the test
  validator at the canonical address via `Anchor.toml`
  `[[test.validator.clone]]`, init the contract with that ID, then assert a real
  CPI emits `SignatureRequestedEvent`. **Open decision in §16.**
- Rerun the full suite under the existing mainnet-feature-parity validator
  config; keep the `bind_address = 127.0.0.1` workaround.

## 13. Invariants preserved

- Precompile + instruction-introspection auth model unchanged; single-signature
  constraint unchanged.
- Replay protection (nonce increment) and account-ID binding apply to `Sign`.
- Mainnet feature parity: chain-signatures CPI is a normal cross-program invoke
  (mainnet-safe); no new inactive syscalls introduced.

## 14. Documentation updates

- `README.md`: WebAuthn → "verification + execution"; add `Sign` action + the
  chain-signatures integration; note the outer-signer-pays fee model and that the
  chain-signatures program ID is set at `init_contract` per deployment.
- `ROADMAP.md`: check off WebAuthn execution + RP binding; add `Sign` (constrained
  to the configured chain-signatures program) under P1, with generic arbitrary
  execution still noted as deferred.

## 15. Out of scope / future

Permissions + `act_as`; an authority-gated update of the chain-signatures program
ID after init; generic arbitrary-program CPI (this work is chain-signatures-only
by design); multisig; expiration; debug-instruction removal; OIDC `sub` keying
and registry governance.

## 16. Open decisions

1. **Sign e2e test infra** — clone chain-signatures + `program_state` from devnet
   for a true CPI test (needs cluster access at test setup; real coverage), or
   ship only the always-on golden construction test now and defer the live CPI
   test? Recommendation: do both — golden always-on, plus the cloned e2e test.
2. **Account-flag confirmation** — the per-account `mut`/`signer` flags for the
   chain-signatures `Sign` CPI must be confirmed against its IDL/source before
   finalizing (§3 note). Resolved during implementation.

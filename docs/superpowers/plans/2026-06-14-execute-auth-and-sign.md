# Execute paths for all auth methods + `Sign` action + P0 hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make WebAuthn a first-class execution path, add a `Sign` action that CPIs into the deployment-configured Sig Network chain-signatures program (and only that program), and land the P0 hardening (remove unauthenticated mutations, bound growth, kill panics).

**Architecture:** All three auth front-doors (`execute_ek256`, `execute_webauthn`, `execute_zk_oidc`) converge on `auth → (Identity, Transaction) → is_transaction_authorized → dispatch_action`. `Sign` is a new `Action` variant handled in the shared `dispatch_action`, so it lights up for all three at once. The chain-signatures program ID is stored on the `AccountManager` singleton (set at `init_contract`), and the CPI instruction is constructed with that ID hardcoded into the `Instruction`, making the single-target guarantee structural.

**Tech Stack:** Rust / Anchor 0.31.1, `invoke_signed` CPI, secp256k1 / secp256r1 precompiles via instructions-sysvar introspection, TypeScript + `borsh` + `@coral-xyz/anchor` + `viem` for client/tests, ts-mocha against `solana-test-validator` (mainnet feature parity).

**Reference spec:** `docs/superpowers/specs/2026-06-14-execute-auth-and-sign-design.md`

**Conventions for every task:** commit messages use Conventional Commits, imperative, ≤72-char subject, no AI attribution. Build the program with `anchor build`; run the suite with `anchor test`; a single spec with `yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/<file>.spec.ts` (validator must be running, or use `anchor test`).

---

## Phase 0 — Foundation: deployment config + dispatch refactor

### Task 1: Store the chain-signatures program ID on `AccountManager`, set at init

**Files:**
- Modify: `programs/solana-aa/src/types/account_manager.rs`
- Modify: `programs/solana-aa/src/contract/contract_lifecycle.rs`
- Modify: `programs/solana-aa/src/lib.rs:30-32` (`init_contract` signature)
- Modify: `utils/constants.ts` (add the canonical ID)
- Modify: `utils/program.ts:76` (`initContract` call)

- [ ] **Step 1: Add the field + grow `INIT_SIZE`** in `types/account_manager.rs`

```rust
use super::account::AccountId;
use anchor_lang::prelude::*;

#[account]
pub struct AccountManager {
    pub next_account_id: AccountId,
    /// Sig Network chain-signatures program the `Sign` action may CPI into.
    /// Deployment config so devnet/mainnet/forks differ without a code change.
    pub chain_signatures_program_id: Pubkey,
    pub bump: u8,
}

impl AccountManager {
    const PDA_DISCRIMINATOR_SIZE: usize = 8;
    const ACCOUNT_ID_SIZE: usize = 8;
    const PUBKEY_SIZE: usize = 32;
    const BUMP_SIZE: usize = 1;

    pub const INIT_SIZE: usize = Self::PDA_DISCRIMINATOR_SIZE
        + Self::ACCOUNT_ID_SIZE
        + Self::PUBKEY_SIZE
        + Self::BUMP_SIZE;

    pub fn increment_next_account_id(&mut self) -> AccountId {
        let old_next_account_id = self.next_account_id;
        self.next_account_id = self.next_account_id.saturating_add(1);
        old_next_account_id
    }
}
```

- [ ] **Step 2: Set it in `init_contract_impl`** in `contract/contract_lifecycle.rs` (replace `init_contract_impl`)

```rust
pub fn init_contract_impl(
    ctx: Context<InitContract>,
    chain_signatures_program_id: Pubkey,
) -> Result<()> {
    let account_manager = &mut ctx.accounts.account_manager;
    account_manager.next_account_id = 0;
    account_manager.chain_signatures_program_id = chain_signatures_program_id;
    account_manager.bump = ctx.bumps.account_manager;

    Ok(())
}
```

- [ ] **Step 3: Thread the arg through `lib.rs`** (replace the `init_contract` wrapper)

```rust
    pub fn init_contract(
        ctx: Context<InitContract>,
        chain_signatures_program_id: Pubkey,
    ) -> Result<()> {
        init_contract_impl(ctx, chain_signatures_program_id)
    }
```

- [ ] **Step 4: Add the canonical ID constant** to `utils/constants.ts`

```typescript
import { PublicKey } from "@solana/web3.js";

// Sig Network chain-signatures program (canonical devnet/mainnet). Stored on
// AccountManager at init; the program enforces only what is configured.
export const CHAIN_SIGNATURES_PROGRAM_ID = new PublicKey(
  "SigMcRMjKfnC7RDG5q4yUMZM1s5KJ9oYTPP4NmJRDRw"
);
```

- [ ] **Step 5: Pass it from `cleanUpProgramState`** in `utils/program.ts` — change line 76:

```typescript
    const initSignature = await program.methods
      .initContract(CHAIN_SIGNATURES_PROGRAM_ID)
      .rpc();
```
Add `CHAIN_SIGNATURES_PROGRAM_ID` to the `../utils/constants` import at the top.

- [ ] **Step 6: Build + run a spec to verify init still works**

Run: `anchor build && anchor test`
Expected: full suite passes (the new field serializes; `initContract` now takes the ID). If `cargo`/IDL complains about an arg, confirm Step 3 landed.

- [ ] **Step 7: Commit**

```bash
git add programs/solana-aa/src/types/account_manager.rs programs/solana-aa/src/contract/contract_lifecycle.rs programs/solana-aa/src/lib.rs utils/constants.ts utils/program.ts
git commit -m "feat: store chain-signatures program id on AccountManager at init"
```

---

### Task 2: Add `account_manager` to execute structs + refactor `dispatch_action` signature

This is a no-behavior-change refactor that prepares `dispatch_action` for `Sign`. `account_manager` uses a constant seed, so Anchor (resolution = true) auto-derives it for clients — no TS account-passing needed.

**Files:**
- Modify: `programs/solana-aa/src/contract/transaction/execute.rs`

- [ ] **Step 1: Add `account_manager` to `ExecuteEk256` and `ExecuteZkOidc`**

In `execute.rs`, add the import and the account to both structs:

```rust
use crate::pda_seeds::{ABSTRACT_ACCOUNT_SEED, ACCOUNT_MANAGER_SEED, OIDC_KEY_REGISTRY_SEED};
use crate::types::account_manager::AccountManager;
```

Add this account (after `abstract_account`) in **both** `ExecuteEk256` and `ExecuteZkOidc`:

```rust
    #[account(
        seeds = [ACCOUNT_MANAGER_SEED],
        bump = account_manager.bump,
    )]
    pub account_manager: Account<'info, AccountManager>,
```

- [ ] **Step 2: Extend `dispatch_action`** to accept the data `Sign` will need (replace the fn signature + each call site; the match body is unchanged for now)

```rust
fn dispatch_action<'info>(
    operation_accounts: AbstractAccountOperationAccounts<'_, 'info>,
    account_id: AccountId,
    chain_signatures_program_id: Pubkey,
    remaining_accounts: &[AccountInfo<'info>],
    action: Action,
) -> Result<()> {
    let _ = (account_id, chain_signatures_program_id, remaining_accounts); // used by Sign in Task 5
    match action {
        Action::RemoveAccount => AbstractAccount::close_account(operation_accounts),
        Action::AddIdentity(identity_with_permissions) => {
            AbstractAccount::add_identity(operation_accounts, identity_with_permissions)
        }
        Action::RemoveIdentity(identity) => {
            AbstractAccount::remove_identity(operation_accounts, &identity)
        }
    }
}
```

- [ ] **Step 3: Update both call sites** in `execute_ek256_impl` and `execute_zk_oidc_impl` to pass the new args. For `execute_ek256_impl` replace the `dispatch_action(...)` call:

```rust
    dispatch_action(
        AbstractAccountOperationAccounts {
            abstract_account: &mut ctx.accounts.abstract_account,
            signer_info: ctx.accounts.signer.to_account_info(),
            system_program_info: ctx.accounts.system_program.to_account_info(),
        },
        account_id,
        ctx.accounts.account_manager.chain_signatures_program_id,
        ctx.remaining_accounts,
        transaction.action,
    )
```
Apply the identical change in `execute_zk_oidc_impl` (it already has `account_id` in scope).

- [ ] **Step 4: Build + test**

Run: `anchor build && anchor test`
Expected: full suite still passes (no behavior change; `_ = (...)` silences unused warnings).

- [ ] **Step 5: Commit**

```bash
git add programs/solana-aa/src/contract/transaction/execute.rs
git commit -m "refactor: thread account_manager + config into dispatch_action"
```

---

## Phase 1 — `Sign` action (chain-signatures CPI)

### Task 3: Add `SignRequest` type + `Action::Sign` variant (Rust + TS schemas)

**Files:**
- Modify: `programs/solana-aa/src/types/transaction/transaction.rs`
- Modify: `programs/solana-aa/src/contract/transaction/execute.rs` (temporary match arm)
- Modify: `borsh/schemas/transaction/transaction.ts`
- Modify: `borsh/index.ts`

- [ ] **Step 1: Add the Rust type + variant** in `types/transaction/transaction.rs`

```rust
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum Action {
    RemoveAccount,
    AddIdentity(IdentityWithPermissions),
    RemoveIdentity(Identity),
    Sign(SignRequest),
}

/// Request to the Sig Network chain-signatures `sign` instruction. Lives inside
/// the signed `Transaction`, so the per-method binding + nonce already authorize
/// exactly this payload/path (no extra binding needed).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub key_version: u32,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
}
```

- [ ] **Step 2: Add a temporary match arm** so the program still compiles. In `execute.rs` `dispatch_action`, add to the `match`:

```rust
        Action::Sign(_) => Err(ErrorCode::SignNotImplemented.into()),
```
And add `SignNotImplemented` to the `ErrorCode` enum in `execute.rs`:

```rust
    #[msg("Sign action not yet implemented")]
    SignNotImplemented,
```

- [ ] **Step 3: Mirror the TS borsh schema** in `borsh/schemas/transaction/transaction.ts`

```typescript
import { Schema } from "borsh";
import { identityWithPermissionsSchema, identitySchema } from "../identity";

export const signRequestSchema: Schema = {
  struct: {
    payload: { array: { type: "u8", len: 32 } },
    key_version: "u32",
    path: "string",
    algo: "string",
    dest: "string",
    params: "string",
  },
};

export const actionSchema: Schema = {
  enum: [
    { struct: { RemoveAccount: { struct: {} } } },
    { struct: { AddIdentity: identityWithPermissionsSchema } },
    { struct: { RemoveIdentity: identitySchema } },
    { struct: { Sign: signRequestSchema } },
  ],
};

export const transactionSchema: Schema = {
  struct: {
    account_id: "u64",
    nonce: "u128",
    action: actionSchema,
  },
};
```

- [ ] **Step 4: Add the TS types** in `borsh/index.ts` (after `RemoveIdentityAction`)

```typescript
export interface SignRequest {
  payload: Uint8Array;
  key_version: number;
  path: string;
  algo: string;
  dest: string;
  params: string;
}

export interface SignAction {
  Sign: SignRequest;
}

export type Action =
  | RemoveAccountAction
  | AddIdentityAction
  | RemoveIdentityAction
  | SignAction;
```

- [ ] **Step 5: Build + test**

Run: `anchor build && anchor test`
Expected: passes; no test exercises `Sign` yet.

- [ ] **Step 6: Commit**

```bash
git add programs/solana-aa/src/types/transaction/transaction.rs programs/solana-aa/src/contract/transaction/execute.rs borsh/schemas/transaction/transaction.ts borsh/index.ts
git commit -m "feat: add Sign action + SignRequest type and schemas"
```

---

### Task 4: `sign.rs` — manual chain-signatures `sign` instruction builder + golden test

**Files:**
- Create: `programs/solana-aa/src/contract/transaction/sign.rs`
- Modify: `programs/solana-aa/src/contract/transaction/mod.rs` (add `pub mod sign;`)

- [ ] **Step 1: Write the failing golden test first.** Create `sign.rs` with only the test (and a stub) so it fails to compile/assert:

```rust
use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};

use crate::types::transaction::transaction::SignRequest;

/// Anchor global instruction discriminator for `sign`:
/// sha256("global:sign")[..8]. Verified by the golden test below.
pub const SIGN_DISCRIMINATOR: [u8; 8] = [5, 221, 155, 46, 237, 91, 28, 236];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminator_matches_anchor_global_sign() {
        let h = anchor_lang::solana_program::hash::hash(b"global:sign");
        assert_eq!(&h.to_bytes()[..8], &SIGN_DISCRIMINATOR);
    }

    #[test]
    fn encodes_args_after_discriminator() {
        let req = SignRequest {
            payload: [7u8; 32],
            key_version: 1,
            path: "m/44".to_string(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
        };
        let data = build_sign_data(&req).unwrap();
        assert_eq!(&data[..8], &SIGN_DISCRIMINATOR);
        // payload (32) then key_version u32 LE = 01 00 00 00
        assert_eq!(&data[8..40], &[7u8; 32]);
        assert_eq!(&data[40..44], &[1, 0, 0, 0]);
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p solana-aa --lib sign 2>&1 | tail -20`
Expected: FAIL — `build_sign_data` not found. (If host build of the crate fails entirely, skip to Step 4 and rely on the e2e CPI test in Task 6 + the const-equality check; note the deviation in the commit.)

- [ ] **Step 3: Implement the builder** (add above the `#[cfg(test)]` block)

```rust
/// Serialize chain-signatures `sign` instruction data: discriminator ++ borsh args.
fn build_sign_data(req: &SignRequest) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(8 + 32 + 4 + req.path.len() + 16);
    data.extend_from_slice(&SIGN_DISCRIMINATOR);
    req.payload.serialize(&mut data)?;
    req.key_version.serialize(&mut data)?;
    req.path.serialize(&mut data)?;
    req.algo.serialize(&mut data)?;
    req.dest.serialize(&mut data)?;
    req.params.serialize(&mut data)?;
    Ok(data)
}

/// Build the chain-signatures `sign` Instruction. `program_id` comes from
/// AccountManager config; account order matches chain-signatures' `Sign` struct
/// (with #[event_cpi] appending event_authority + program):
/// program_state, requester, fee_payer, system_program, event_authority, program.
///
/// Flags CONFIRMED against chain-signatures source (docs.rs):
///   #[event_cpi] pub struct Sign { program_state: mut+seeds[b"program-state"];
///   requester: mut+Signer; fee_payer: mut+Option<Signer>; system_program }.
#[allow(clippy::too_many_arguments)]
pub fn build_sign_instruction(
    program_id: Pubkey,
    req: &SignRequest,
    program_state: Pubkey,
    requester: Pubkey,
    fee_payer: Pubkey,
    system_program: Pubkey,
    event_authority: Pubkey,
    chain_sig_program: Pubkey,
) -> Result<Instruction> {
    Ok(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(program_state, false),
            AccountMeta::new(requester, true),
            AccountMeta::new(fee_payer, true),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(event_authority, false),
            AccountMeta::new_readonly(chain_sig_program, false),
        ],
        data: build_sign_data(req)?,
    })
}
```

- [ ] **Step 4: Register the module** — add to `contract/transaction/mod.rs`:

```rust
pub mod sign;
```

- [ ] **Step 5: Run the golden test**

Run: `cargo test -p solana-aa --lib sign 2>&1 | tail -20`
Expected: PASS (2 tests). Then `anchor build` to confirm the SBF build is intact.

- [ ] **Step 6: Commit**

```bash
git add programs/solana-aa/src/contract/transaction/sign.rs programs/solana-aa/src/contract/transaction/mod.rs
git commit -m "feat: add chain-signatures sign instruction builder with golden test"
```

---

### Task 5: Wire the `Sign` dispatch arm (invoke_signed) + program-account validation

**Files:**
- Modify: `programs/solana-aa/src/contract/transaction/execute.rs`

- [ ] **Step 1: Replace the temporary `Sign` arm** in `dispatch_action` with the real CPI. Add imports at the top of `execute.rs`:

```rust
use anchor_lang::solana_program::program::invoke_signed;
use crate::contract::transaction::sign::build_sign_instruction;
```

Replace the `match` body so it threads the new params and handles `Sign`:

```rust
    match action {
        Action::RemoveAccount => AbstractAccount::close_account(operation_accounts),
        Action::AddIdentity(identity_with_permissions) => {
            AbstractAccount::add_identity(operation_accounts, identity_with_permissions)
        }
        Action::RemoveIdentity(identity) => {
            AbstractAccount::remove_identity(operation_accounts, &identity)
        }
        Action::Sign(req) => dispatch_sign(
            operation_accounts,
            account_id,
            chain_signatures_program_id,
            remaining_accounts,
            req,
        ),
    }
```

- [ ] **Step 2: Implement `dispatch_sign`** (add below `dispatch_action`)

```rust
/// remaining_accounts layout for Sign: [program_state, event_authority, program].
/// requester = abstract-account PDA (signs via invoke_signed); fee_payer = outer
/// signer; system_program reused from the operation context.
fn dispatch_sign<'info>(
    operation_accounts: AbstractAccountOperationAccounts<'_, 'info>,
    account_id: AccountId,
    chain_signatures_program_id: Pubkey,
    remaining_accounts: &[AccountInfo<'info>],
    req: SignRequest,
) -> Result<()> {
    require!(req.path.len() <= MAX_PATH_LEN, ErrorCode::InvalidSignParams);
    require!(req.algo.len() <= MAX_STR_LEN, ErrorCode::InvalidSignParams);
    require!(req.dest.len() <= MAX_STR_LEN, ErrorCode::InvalidSignParams);
    require!(req.params.len() <= MAX_STR_LEN, ErrorCode::InvalidSignParams);

    let [program_state, event_authority, chain_sig_program] = remaining_accounts else {
        return Err(ErrorCode::InvalidChainSignaturesAccounts.into());
    };
    require_keys_eq!(
        *chain_sig_program.key,
        chain_signatures_program_id,
        ErrorCode::ChainSignaturesProgramMismatch
    );

    let abstract_account_info = operation_accounts.abstract_account.to_account_info();
    let bump = operation_accounts.abstract_account.bump;
    let system_program_info = operation_accounts.system_program_info.clone();
    let signer_info = operation_accounts.signer_info.clone();

    let ix = build_sign_instruction(
        chain_signatures_program_id,
        &req,
        *program_state.key,
        *abstract_account_info.key,
        *signer_info.key,
        *system_program_info.key,
        *event_authority.key,
        *chain_sig_program.key,
    )?;

    invoke_signed(
        &ix,
        &[
            program_state.clone(),
            abstract_account_info.clone(),
            signer_info,
            system_program_info,
            event_authority.clone(),
            chain_sig_program.clone(),
        ],
        &[&[
            ABSTRACT_ACCOUNT_SEED,
            account_id.to_le_bytes().as_ref(),
            &[bump],
        ]],
    )?;

    Ok(())
}
```

- [ ] **Step 3: Add consts + error codes** in `execute.rs` (drop the temporary `SignNotImplemented`)

```rust
const MAX_PATH_LEN: usize = 64;
const MAX_STR_LEN: usize = 64;
```
Add to `ErrorCode`:
```rust
    #[msg("Invalid chain-signatures accounts")]
    InvalidChainSignaturesAccounts,
    #[msg("Passed program account does not match configured chain-signatures id")]
    ChainSignaturesProgramMismatch,
    #[msg("Invalid Sign parameters")]
    InvalidSignParams,
```
Also add `use crate::types::transaction::transaction::SignRequest;` if not already imported (it's re-exported via `Action`; import explicitly).

- [ ] **Step 4: Build**

Run: `anchor build`
Expected: compiles. (The `let [..] = slice else` pattern needs Rust 2021 + recent toolchain; if it errors, use `if remaining_accounts.len() != 3 { return Err(...) }` then index.)

- [ ] **Step 5: Commit** (e2e test lands in Task 6)

```bash
git add programs/solana-aa/src/contract/transaction/execute.rs
git commit -m "feat: dispatch Sign action via invoke_signed into chain-signatures"
```

---

### Task 6: Sign end-to-end test — clone chain-signatures on localnet + assert CPI

This is the §16 open item; the recommendation (do both: golden in Task 4 + this e2e) is followed here.

**Files:**
- Modify: `Anchor.toml` (clone the program + accounts from devnet)
- Create: `tests/sign-action.spec.ts`
- Create: `utils/chain-signatures.ts` (derive `program_state` / `event_authority` PDAs)

- [ ] **Step 1: Clone chain-signatures into the test validator.** Add to `Anchor.toml` under `[test.validator]` (the program is fetched from devnet at its canonical address):

```toml
[[test.validator.clone]]
address = "SigMcRMjKfnC7RDG5q4yUMZM1s5KJ9oYTPP4NmJRDRw"

# program_state PDA (derive from the chain-signatures IDL seed; confirm address
# with `solana account -u d <program_state_pda>`), cloned so deposits/account
# checks pass:
[[test.validator.clone]]
address = "<PROGRAM_STATE_PDA>"
```
Also set the clone source URL if needed: `--url devnet` is configured via `anchor test --provider.cluster localnet` with `[test.validator] url = "https://api.devnet.solana.com"`. Confirm the exact `program_state` seed from the chain-signatures IDL during execution (spec §16.2).

- [ ] **Step 2: Add PDA helpers** in `utils/chain-signatures.ts`

```typescript
import { PublicKey } from "@solana/web3.js";
import { CHAIN_SIGNATURES_PROGRAM_ID } from "./constants";

// Anchor event authority PDA used for self-CPI event emission.
export const findEventAuthorityPDA = (programId = CHAIN_SIGNATURES_PROGRAM_ID) =>
  PublicKey.findProgramAddressSync(
    [Buffer.from("__event_authority")],
    programId
  );

// program_state seed — confirm against the chain-signatures IDL.
export const findProgramStatePDA = (programId = CHAIN_SIGNATURES_PROGRAM_ID) =>
  PublicKey.findProgramAddressSync([Buffer.from("program-state")], programId);
```

- [ ] **Step 3: Write the e2e test** in `tests/sign-action.spec.ts` (Ethereum-authorized Sign). Reuse the `executeEk256Action` helper created in Task 11.

```typescript
import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import { assert } from "chai";
import { SolanaAa } from "../target/types/solana_aa";
import { CHAIN_SIGNATURES_PROGRAM_ID } from "../utils/constants";
import { findEventAuthorityPDA, findProgramStatePDA } from "../utils/chain-signatures";
import { cleanUpProgramState } from "../utils/program";
import { createControlledAccount, executeEk256Action } from "../utils/test-helpers";
import { SystemProgram } from "@solana/web3.js";

const HARDHAT_0 =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

describe("Sign action (chain-signatures CPI)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.solanaAa as anchor.Program<SolanaAa>;
  const connection = provider.connection;

  beforeEach(() => cleanUpProgramState(program, connection, provider));

  it("emits SignatureRequested via the AA PDA", async () => {
    const { accountId } = await createControlledAccount(program, {
      ethPrivateKey: HARDHAT_0,
    });

    const [programState] = findProgramStatePDA();
    const [eventAuthority] = findEventAuthorityPDA();

    const sig = await executeEk256Action(program, {
      accountId,
      ethPrivateKey: HARDHAT_0,
      action: {
        Sign: {
          payload: new Uint8Array(32).fill(1),
          key_version: 0,
          path: "m/44'/60'/0'/0/0",
          algo: "",
          dest: "",
          params: "",
        },
      },
      remainingAccounts: [
        { pubkey: programState, isSigner: false, isWritable: true },
        { pubkey: eventAuthority, isSigner: false, isWritable: false },
        { pubkey: CHAIN_SIGNATURES_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
    });

    assert.ok(sig, "Sign CPI should succeed");
    // Optional: parse logs for the SignatureRequested event / program invoke.
  });

  it("rejects a wrong target program account", async () => {
    const { accountId } = await createControlledAccount(program, {
      ethPrivateKey: HARDHAT_0,
    });
    const [programState] = findProgramStatePDA();
    const [eventAuthority] = findEventAuthorityPDA();

    try {
      await executeEk256Action(program, {
        accountId,
        ethPrivateKey: HARDHAT_0,
        action: {
          Sign: { payload: new Uint8Array(32), key_version: 0, path: "x", algo: "", dest: "", params: "" },
        },
        remainingAccounts: [
          { pubkey: programState, isSigner: false, isWritable: true },
          { pubkey: eventAuthority, isSigner: false, isWritable: false },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // wrong
        ],
      });
      assert.fail("should reject wrong program account");
    } catch (e: any) {
      assert.match(e.toString(), /ChainSignaturesProgramMismatch/);
    }
  });
});
```

- [ ] **Step 4: Run the spec**

Run: `anchor test`
Expected: both pass. Iterate the `program_state` seed/clone addresses against devnet until the CPI succeeds (this is the known fiddly piece — confirm via `solana account -u d`).

- [ ] **Step 5: Commit**

```bash
git add Anchor.toml tests/sign-action.spec.ts utils/chain-signatures.ts
git commit -m "test: end-to-end Sign CPI against cloned chain-signatures program"
```

---

## Phase 2 — WebAuthn execution path

### Task 7: Refactor secp256r1 introspection to take the instructions sysvar

**Files:**
- Modify: `programs/solana-aa/src/contract/auth/secp256r1_sha256.rs`
- Modify: `programs/solana-aa/src/lib.rs` (`verify_webauthn` / `get_webauthn_data` callers)

- [ ] **Step 1: Change `get_secp256r1_sha256_data_impl` to take `&AccountInfo`** (mirror `get_ek256_data_impl`). Replace its signature + first lines:

```rust
pub fn get_secp256r1_sha256_data_impl(
    instructions_sysvar: &AccountInfo<'_>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let current_index = load_current_index_checked(instructions_sysvar)?;
    if current_index < 1 {
        return Err(ErrorCode::MissingVerificationInstruction.into());
    }
    let verification_instruction =
        load_instruction_at_checked((current_index - 1) as usize, instructions_sysvar)?;
    // ... rest unchanged ...
```

- [ ] **Step 2: Update `verify_secp256r1_sha256_impl`** to forward the sysvar (it currently takes `&Context<VerifyWebauthnSignature>`):

```rust
pub fn verify_secp256r1_sha256_impl(
    instructions_sysvar: &AccountInfo<'_>,
    signed_message: Vec<u8>,
    signer_compressed_public_key: String,
) -> Result<bool> {
    let (pubkey_bytes, message_bytes) = get_secp256r1_sha256_data_impl(instructions_sysvar)?;
    // ... rest unchanged ...
```

- [ ] **Step 3: Replace the `Pubkey::from_str(...).unwrap()` panic** (line ~51) with a const (this also covers a Task 14 site):

```rust
use anchor_lang::solana_program::pubkey;
const SECP256R1_PROGRAM_ID: Pubkey = pubkey!("Secp256r1SigVerify1111111111111111111111111");
```
and replace the body that built it with `if verification_instruction.program_id != SECP256R1_PROGRAM_ID {`.
Remove the now-unused `use std::str::FromStr;`.

- [ ] **Step 4: Fix the `lib.rs` callers**

```rust
    pub fn verify_webauthn(
        ctx: Context<VerifyWebauthnSignature>,
        signed_message: Vec<u8>,
        signer_compressed_public_key: String,
    ) -> Result<bool> {
        verify_secp256r1_sha256_impl(
            &ctx.accounts.instructions,
            signed_message,
            signer_compressed_public_key,
        )
    }

    pub fn get_webauthn_data(ctx: Context<VerifyWebauthnSignature>) -> Result<(String, String)> {
        let (pubkey_bytes, message_bytes) =
            get_secp256r1_sha256_data_impl(&ctx.accounts.instructions)?;
        Ok((
            hex::encode(pubkey_bytes),
            String::from_utf8(message_bytes).map_err(|_| ErrorCode::InvalidWebauthnMessage)?,
        ))
    }
```
Add `InvalidWebauthnMessage` to the relevant `ErrorCode` (the `secp256r1_sha256` one, re-exported) or define a small lib-level error; simplest: add to `secp256r1_sha256::ErrorCode` and import it.

- [ ] **Step 5: Build + test**

Run: `anchor build && anchor test`
Expected: `secp256r1-sha256-auth.spec.ts` still passes (introspection unchanged, only the param type).

- [ ] **Step 6: Commit**

```bash
git add programs/solana-aa/src/contract/auth/secp256r1_sha256.rs programs/solana-aa/src/lib.rs
git commit -m "refactor: secp256r1 introspection takes instructions sysvar; drop from_str panic"
```

---

### Task 8: WebAuthn identity — add `rp_id_hash` + `origin`, tighten equality (Rust + TS)

**Files:**
- Modify: `programs/solana-aa/src/types/identity/webauthn.rs`
- Modify: `borsh/schemas/identity/webauthn.ts`
- Modify: `borsh/index.ts` (`WebAuthnAuthenticator` interface)

- [ ] **Step 1: Update the Rust struct + equality** in `types/identity/webauthn.rs`

```rust
use anchor_lang::prelude::*;

#[derive(Debug, AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WebAuthnAuthenticator {
    pub key_id: String,
    pub compressed_public_key: Option<String>,
    /// sha256(rpId); checked against authenticatorData[0..32].
    pub rp_id_hash: [u8; 32],
    /// Expected clientDataJSON.origin (e.g. "https://example.com").
    pub origin: String,
}

impl PartialEq for WebAuthnAuthenticator {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id
            && self.compressed_public_key == other.compressed_public_key
            && self.rp_id_hash == other.rp_id_hash
    }
}

impl Eq for WebAuthnAuthenticator {}
```
Delete the old `WebAuthnCredentials` / `WebAuthnValidationData` structs if unused (grep first; remove only if no references).

- [ ] **Step 2: Mirror the TS schema** in `borsh/schemas/identity/webauthn.ts`

```typescript
import { Schema } from "borsh";

export const webAuthnAuthenticatorSchema: Schema = {
  struct: {
    key_id: "string",
    compressed_public_key: { option: "string" },
    rp_id_hash: { array: { type: "u8", len: 32 } },
    origin: "string",
  },
};
```

- [ ] **Step 3: Update the TS interface** in `borsh/index.ts`

```typescript
export interface WebAuthnAuthenticator {
  key_id: string;
  compressed_public_key: string | null;
  rp_id_hash: Uint8Array;
  origin: string;
}
```

- [ ] **Step 4: Build + test**

Run: `anchor build && anchor test`
Expected: passes (no test constructs a WebAuthn identity yet; if one does, update it).

- [ ] **Step 5: Commit**

```bash
git add programs/solana-aa/src/types/identity/webauthn.rs borsh/schemas/identity/webauthn.ts borsh/index.ts
git commit -m "feat: bind WebAuthn identity to rp_id_hash + origin; tighten equality"
```

---

### Task 9: `execute_webauthn` instruction + verification flow

**Files:**
- Modify: `programs/solana-aa/src/contract/transaction/execute.rs`
- Modify: `programs/solana-aa/src/lib.rs` (add the `execute_webauthn` entrypoint)
- Modify: `programs/solana-aa/src/types/transaction/transaction.rs` (add `WebAuthnAuthData`)
- Modify: `programs/solana-aa/Cargo.toml` (add `serde_json`)

- [ ] **Step 1: Add the arg type** in `types/transaction/transaction.rs`

```rust
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WebAuthnAuthData {
    pub client_data: String,
    pub authenticator_data: Vec<u8>,
}
```

- [ ] **Step 2: Add `serde_json`** to `programs/solana-aa/Cargo.toml` dependencies:

```toml
serde_json = "1.0"
```

- [ ] **Step 3: Add `ExecuteWebauthn` accounts + impl** in `execute.rs`

```rust
#[derive(Accounts)]
#[instruction(account_id: AccountId)]
pub struct ExecuteWebauthn<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref()],
        bump = abstract_account.bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    #[account(seeds = [ACCOUNT_MANAGER_SEED], bump = account_manager.bump)]
    pub account_manager: Account<'info, AccountManager>,

    pub system_program: Program<'info, System>,

    /// CHECK: Instructions sysvar, verified by address
    #[account(address = solana_program::sysvar::instructions::id())]
    pub instructions: AccountInfo<'info>,
}

pub fn execute_webauthn_impl(
    ctx: Context<ExecuteWebauthn>,
    account_id: AccountId,
    transaction: Transaction,
    auth: WebAuthnAuthData,
) -> Result<()> {
    use anchor_lang::solana_program::hash::hash as sha256;

    let (pubkey, signed_message) =
        get_secp256r1_sha256_data_impl(&ctx.accounts.instructions)?;

    // 1. Reconstruct authenticatorData || sha256(clientDataJSON) and match.
    let client_data_hash = sha256(auth.client_data.as_bytes());
    let mut expected = auth.authenticator_data.clone();
    expected.extend_from_slice(&client_data_hash.to_bytes());
    require!(expected == signed_message, ErrorCode::WebAuthnMessageMismatch);

    // 2. Parse clientDataJSON (typed; no Value tree).
    #[derive(serde::Deserialize)]
    struct ClientData {
        r#type: String,
        challenge: String,
        origin: String,
    }
    let cd: ClientData = serde_json::from_str(&auth.client_data)
        .map_err(|_| ErrorCode::InvalidClientData)?;
    require!(cd.r#type == "webauthn.get", ErrorCode::InvalidClientData);

    // 3. Transaction binding: challenge == base64url(sha256(borsh(tx))).
    let tx_hash = sha256(&transaction.try_to_vec()?).to_bytes();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cd.challenge.as_bytes())
        .map_err(|_| ErrorCode::InvalidClientData)?;
    require!(challenge == tx_hash, ErrorCode::WebAuthnChallengeMismatch);

    // 4. Build identity (origin/rpIdHash checked via has_identity match below).
    require!(auth.authenticator_data.len() >= 37, ErrorCode::InvalidClientData);
    require!(auth.authenticator_data[32] & 0x01 == 0x01, ErrorCode::WebAuthnUserNotPresent);
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth.authenticator_data[0..32]);

    let identity = Identity::WebAuthn(WebAuthnAuthenticator {
        key_id: String::new(),
        compressed_public_key: Some(hex::encode(&pubkey)),
        rp_id_hash,
        origin: cd.origin,
    });

    is_transaction_authorized(&mut ctx.accounts.abstract_account, account_id, &identity, &transaction)?;

    dispatch_action(
        AbstractAccountOperationAccounts {
            abstract_account: &mut ctx.accounts.abstract_account,
            signer_info: ctx.accounts.signer.to_account_info(),
            system_program_info: ctx.accounts.system_program.to_account_info(),
        },
        account_id,
        ctx.accounts.account_manager.chain_signatures_program_id,
        ctx.remaining_accounts,
        transaction.action,
    )
}
```

Add imports at top of `execute.rs`:
```rust
use base64::Engine;
use crate::contract::auth::secp256r1_sha256::get_secp256r1_sha256_data_impl;
use crate::types::identity::webauthn::WebAuthnAuthenticator;
use crate::types::transaction::transaction::WebAuthnAuthData;
```
Add error codes: `WebAuthnMessageMismatch`, `WebAuthnChallengeMismatch`, `WebAuthnUserNotPresent`, `InvalidClientData`.

> **Note on identity matching:** `has_identity` compares via the tightened `eq` (key_id + compressed_public_key + rp_id_hash). The reconstructed identity sets `key_id = ""`, so the **registered** identity must also use `key_id = ""` (or relax `eq` to ignore `key_id` and match on pubkey + rp_id_hash). Decision: match on `compressed_public_key` + `rp_id_hash` only — update `eq` in Task 8 to drop `key_id` from equality. Apply that and additionally verify `origin` here by finding the identity and comparing `origin`. Revisit during execution: add an explicit `origin` check against the registered identity via `find_identity`.

- [ ] **Step 4: Add the `lib.rs` entrypoint**

```rust
    pub fn execute_webauthn(
        ctx: Context<ExecuteWebauthn>,
        account_id: AccountId,
        transaction: Transaction,
        auth: WebAuthnAuthData,
    ) -> Result<()> {
        execute_webauthn_impl(ctx, account_id, transaction, auth)
    }
```
Add `WebAuthnAuthData` to the `types::transaction::transaction` import and `ExecuteWebauthn` to the `execute::*` glob (already glob-imported).

- [ ] **Step 5: Build**

Run: `anchor build`
Expected: compiles. Resolve the `eq`/`origin` matching decision from the Step 3 note.

- [ ] **Step 6: Commit**

```bash
git add programs/solana-aa/src/contract/transaction/execute.rs programs/solana-aa/src/lib.rs programs/solana-aa/src/types/transaction/transaction.rs programs/solana-aa/Cargo.toml
git commit -m "feat: add execute_webauthn with transaction + origin/rpIdHash binding"
```

---

### Task 10: WebAuthn client helpers + `execute_webauthn` spec

**Files:**
- Create: `utils/identity/webauthn.ts`
- Move: secp256r1 instruction builder into `utils/webauthn.ts` (from `tests/secp256r1-sha256-auth.spec.ts:35`)
- Create: `tests/execute_webauthn.spec.ts`

- [ ] **Step 1: Extract the secp256r1 verification-instruction builder** into `utils/webauthn.ts` (copy `createSecp256r1VerificationInstruction` from `tests/secp256r1-sha256-auth.spec.ts:24-70`, export it), and re-import it in that existing spec to avoid duplication.

- [ ] **Step 2: Add `buildWebauthnIdentity`** in `utils/identity/webauthn.ts` (Anchor camelCase tuple-variant format, mirroring `buildOidcIdentity`)

```typescript
import { createHash } from "crypto";

type Permissions = { enableActAs: boolean } | null;

export const buildWebauthnIdentity = (
  {
    compressedPublicKey,
    rpId,
    origin,
    keyId = "",
  }: { compressedPublicKey: string; rpId: string; origin: string; keyId?: string },
  permissions: Permissions
) => {
  const rpIdHash = Array.from(createHash("sha256").update(rpId).digest());
  return {
    identity: {
      webAuthn: {
        "0": {
          keyId,
          compressedPublicKey,
          rpIdHash,
          origin,
        },
      },
    },
    permissions,
  };
};
```
Export it from `utils/identity/index.ts` (`export * from "./webauthn";`).

- [ ] **Step 3: Write the happy-path test** in `tests/execute_webauthn.spec.ts`. Use a P-256 keypair (the existing `secp256r1-sha256-auth.spec.ts` shows how to generate/sign with `@noble/curves/p256` or the project's current approach — reuse it). Core shape:

```typescript
// pseudo-flow (adapt signing to the project's existing P-256 utility):
// 1. tx = { account_id, nonce, action: { AddIdentity: <some identity> } }
// 2. txHash = sha256(borsh.transaction(tx))
// 3. clientData = JSON.stringify({ type:"webauthn.get",
//      challenge: base64url(txHash), origin })
// 4. authenticatorData = sha256(rpId)(32) || 0x01 (flags UP) || 0x00000000 (counter)
// 5. message = authenticatorData || sha256(clientData)
// 6. sign message with the P-256 key → precompile ix via createSecp256r1VerificationInstruction
// 7. create account whose first identity = buildWebauthnIdentity({compressedPublicKey, rpId, origin})
// 8. program.methods.executeWebauthn(accountId, tx, { clientData, authenticatorData })
//      .preInstructions([precompileIx]).rpc()
// 9. assert the AddIdentity took effect
```
Write it out fully against the existing P-256 helper during execution.

- [ ] **Step 4: Add rejection tests** (one `it` each): tampered challenge → `WebAuthnChallengeMismatch`; wrong origin/rpId → identity-not-found / origin mismatch; flags without UP bit → `WebAuthnUserNotPresent`; reused nonce → `NonceMismatch`; unregistered pubkey → `IdentityNotFound`.

- [ ] **Step 5: Run**

Run: `anchor test`
Expected: new spec passes; iterate P-256 signing details against the validator.

- [ ] **Step 6: Commit**

```bash
git add utils/identity/webauthn.ts utils/identity/index.ts utils/webauthn.ts tests/execute_webauthn.spec.ts tests/secp256r1-sha256-auth.spec.ts
git commit -m "feat: WebAuthn client helpers + execute_webauthn integration tests"
```

---

## Phase 3 — P0 hardening

### Task 11: Authenticated test teardown helpers (precedes removing unauth instructions)

**Files:**
- Create: `utils/test-helpers.ts`
- Modify: `utils/program.ts` (`cleanUpProgramState` uses the registry)

- [ ] **Step 1: Build shared helpers** in `utils/test-helpers.ts` — `executeEk256Action` (sign a `Transaction` with an ETH key, submit via `execute_ek256` with the secp256k1 pre-instruction; accepts optional `remainingAccounts`) and `createControlledAccount` (create an account with an ETH identity and register `{accountId, ethPrivateKey}` in a module-level `trackedAccounts` array). Extract the signing/precompile flow from `tests/execute_ek256.spec.ts:44-80`.

```typescript
import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import { Hex, keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { AccountMeta } from "@solana/web3.js";
import { SolanaAa } from "../target/types/solana_aa";
import { borshUtils, Action, Transaction } from "../borsh";
import { signWithEthereum } from "./secp256k1-signer";
import {
  parseEthereumSignature,
  ethereumAddressToBytes,
  createSecp256k1VerificationInstruction,
} from "./ethereum";
import { buildEthereumIdentity } from "./identity";
import { findAbstractAccountPDA, findAccountManagerPDA } from "./program";

export const trackedAccounts: { accountId: bigint; ethPrivateKey: Hex }[] = [];

export async function executeEk256Action(
  program: anchor.Program<SolanaAa>,
  opts: {
    accountId: bigint;
    ethPrivateKey: Hex;
    action: Action;
    nonce?: bigint;
    remainingAccounts?: AccountMeta[];
  }
): Promise<string> {
  const acct = await program.account.abstractAccount.fetch(
    findAbstractAccountPDA(new BN(opts.accountId.toString()), program.programId)[0]
  );
  const nonce = opts.nonce ?? BigInt(acct.nonce.toString());
  const tx: Transaction = { account_id: opts.accountId, nonce, action: opts.action };
  const message = Buffer.from(borshUtils.serialize.transaction(tx));
  const sig = await signWithEthereum({ hash: keccak256(message), privateKey: opts.ethPrivateKey });
  const { signature, recoveryId } = parseEthereumSignature(sig.signature);
  const ix = createSecp256k1VerificationInstruction(
    signature, recoveryId, ethereumAddressToBytes(sig.address), message
  );
  const builder = program.methods
    .executeEk256(new BN(opts.accountId.toString()))
    .preInstructions([ix]);
  if (opts.remainingAccounts) builder.remainingAccounts(opts.remainingAccounts);
  return builder.rpc();
}

export async function createControlledAccount(
  program: anchor.Program<SolanaAa>,
  { ethPrivateKey }: { ethPrivateKey: Hex }
): Promise<{ accountId: bigint }> {
  const address = privateKeyToAccount(ethPrivateKey).address;
  const [mgr] = findAccountManagerPDA(program.programId);
  const before = await program.account.accountManager.fetch(mgr);
  const accountId = BigInt(before.nextAccountId.toString());
  await program.methods.createAccount(buildEthereumIdentity(address, null)).rpc();
  trackedAccounts.push({ accountId, ethPrivateKey });
  return { accountId };
}
```

- [ ] **Step 2: Rewire `cleanUpProgramState`** to close tracked accounts via `executeEk256Action({ action: { RemoveAccount: {} } })` instead of `.deleteAccount(...)`, then `closeContract` + `initContract(CHAIN_SIGNATURES_PROGRAM_ID)`. Iterate `trackedAccounts`, skip any already closed, then clear the array.

- [ ] **Step 3: Run the suite** (still has the unauth instructions; both paths work)

Run: `anchor test`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add utils/test-helpers.ts utils/program.ts
git commit -m "test: add authenticated teardown helpers and account registry"
```

---

### Task 12: Rewire `accounts.spec.ts` to the authenticated path + remove unauth instructions

**Files:**
- Modify: `tests/accounts.spec.ts`
- Modify: `programs/solana-aa/src/lib.rs` (delete `delete_account`, `add_identity`, `remove_identity`)

- [ ] **Step 1: Rewrite `accounts.spec.ts`** to use standard Hardhat keypairs (so the authenticated path can sign) and `createControlledAccount` / `executeEk256Action` for add/remove/delete. Replace each `.addIdentity(0, id)` with `executeEk256Action(program, { accountId, ethPrivateKey, action: { AddIdentity: id } })`, `.removeIdentity(0, id.identity)` with `{ RemoveIdentity: id.identity }`, and `.deleteAccount(i)` with `{ RemoveAccount: {} }`. Keep the balance/identity-count assertions.

- [ ] **Step 2: Run `accounts.spec.ts`**

Run: `yarn run ts-mocha -p ./tsconfig.json -t 1000000 tests/accounts.spec.ts`
Expected: passes via the authenticated path.

- [ ] **Step 3: Delete the unauthenticated instructions** from `lib.rs` (`delete_account`, `add_identity`, `remove_identity` wrappers). Leave `execute_ek256` / `execute_zk_oidc` / `execute_webauthn` as the only mutation paths.

- [ ] **Step 4: Build + full suite**

Run: `anchor build && anchor test`
Expected: passes (no caller references the removed instructions; `zk-oidc.spec.ts` uses `addIdentity` only as an Action key).

- [ ] **Step 5: Commit**

```bash
git add tests/accounts.spec.ts programs/solana-aa/src/lib.rs
git commit -m "feat!: remove unauthenticated mutation instructions; route via execute"
```

---

### Task 13: Bound account growth

**Files:**
- Modify: `programs/solana-aa/src/types/account.rs`
- Modify: `tests/accounts.spec.ts` (add a growth-bound test)

- [ ] **Step 1: Write the failing test** — add an `it` to `accounts.spec.ts` that adds identities past `MAX_IDENTITIES` and asserts `TooManyIdentities`.

```typescript
it("rejects adding identities beyond MAX_IDENTITIES", async () => {
  const { accountId } = await createControlledAccount(program, { ethPrivateKey: HARDHAT_0 });
  // add 16 more distinct identities; the 16th (total 17) should fail
  // ... loop using executeEk256Action with distinct Hardhat addresses,
  //     expect the over-limit call to reject with /TooManyIdentities/
});
```

- [ ] **Step 2: Run to verify it fails** (`anchor test` — the add succeeds today). Expected: FAIL.

- [ ] **Step 3: Add the guard** in `AbstractAccount::add_identity` (before `realloc_account`)

```rust
const MAX_IDENTITIES: usize = 16;
const MAX_ACCOUNT_SIZE: usize = 8 * 1024;
// ...
let new_size = account_info.data_len() + identity_with_permissions.byte_size()?;
require!(abstract_account.identities.len() < MAX_IDENTITIES, ErrorCode::TooManyIdentities);
require!(new_size <= MAX_ACCOUNT_SIZE, ErrorCode::AccountTooLarge);
```
Add `TooManyIdentities`, `AccountTooLarge` to the account `ErrorCode`. (`byte_size()?` reflects Task 14.)

- [ ] **Step 4: Run** — `anchor test` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add programs/solana-aa/src/types/account.rs tests/accounts.spec.ts
git commit -m "feat: bound abstract account identity growth"
```

---

### Task 14: Eliminate remaining panics

**Files:**
- Modify: `programs/solana-aa/src/types/identity/mod.rs`
- Modify: `programs/solana-aa/src/types/account.rs` (callers of `byte_size`)
- Modify: `programs/solana-aa/src/contract/accounts.rs` (`space = ... byte_size()`)
- Modify: `programs/solana-aa/src/lib.rs` (`get_eth_data` unwrap)

(The `secp256r1` `from_str` panic was fixed in Task 7.)

- [ ] **Step 1: Make `byte_size` fallible** in `types/identity/mod.rs`

```rust
impl IdentityWithPermissions {
    pub fn byte_size(&self) -> Result<usize> {
        Ok(self.try_to_vec()
            .map_err(|_| error!(crate::contract::transaction::execute::ErrorCode::InvalidSignParams))?
            .len())
    }
}
```
(Or define a dedicated `IdentitySerializationFailed` error in this module and use it — preferred; avoids cross-module coupling.)

- [ ] **Step 2: Update callers** — in `account.rs` `add_identity`/`remove_identity` use `.byte_size()?`. In `accounts.rs` the `space = AbstractAccount::INIT_SIZE + identity_with_permissions.byte_size()` constraint can't use `?`; switch to an infallible size via Borsh length already computed, or precompute in the handler. Simplest: keep `space` using a non-panicking helper `byte_size_or(0)` is wrong for init — instead compute with `.try_to_vec().map(|v| v.len()).unwrap_or(0)` ONLY inside the `space =` macro is still a panic-free fallback. Decide during execution; the cleanest is a `const`-ish upper bound. **Resolution:** add `pub fn byte_size_unchecked(&self) -> usize { self.try_to_vec().map(|v| v.len()).unwrap_or(usize::MAX) }` for the `space` constraint (an over-large size simply fails init cleanly via rent), and the fallible `byte_size()?` everywhere else.

- [ ] **Step 3: Fix `get_eth_data`** in `lib.rs`

```rust
    pub fn get_eth_data(ctx: Context<VerifyEthereumSignature>) -> Result<(String, Transaction)> {
        let (eth_address, message) = get_ek256_data_impl(&ctx.accounts.instructions)?;
        let transaction = Transaction::try_from_slice(&message)
            .map_err(|_| ek256::ErrorCode::InvalidInstructionData)?;
        Ok((hex::encode(eth_address), transaction))
    }
```

- [ ] **Step 4: Build + test**

Run: `anchor build && anchor test`
Expected: passes; `grep -rn "unwrap()\|expect(" programs/solana-aa/src/` returns no hits in instruction paths.

- [ ] **Step 5: Commit**

```bash
git add programs/solana-aa/src/types/identity/mod.rs programs/solana-aa/src/types/account.rs programs/solana-aa/src/contract/accounts.rs programs/solana-aa/src/lib.rs
git commit -m "refactor: replace panics in instruction paths with typed errors"
```

---

## Phase 4 — Documentation

### Task 15: Sync README + ROADMAP

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: README** — in the identity table mark WebAuthn "Verification + execution"; add a `Sign` action row to the instructions/execution sections describing the chain-signatures CPI, the outer-signer-pays fee model, and that the target program ID is set at `init_contract` per deployment; update "Known gaps" (remove the unauthenticated-instructions and WebAuthn-execution bullets; keep permissions deferred).

- [ ] **Step 2: ROADMAP** — check off "WebAuthn execution path", "Bind WebAuthn identities to their relying party", "Bound account growth", "Eliminate panics", and "Remove or secure the unauthenticated mutation instructions". Add a P1 entry for the shipped `Sign` action (chain-signatures-only), noting generic arbitrary execution + permissions remain deferred.

- [ ] **Step 3: Lint + final full run**

Run: `yarn lint && anchor test`
Expected: clean + green.

- [ ] **Step 4: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: sync README and ROADMAP with execute paths + Sign action"
```

---

## Self-review notes (spec coverage)

- Spec §A.0 config → Task 1. §A.1 types → Task 3. §A.2 builder/discriminator → Task 4. §A.3 accounts/fee + execute structs → Tasks 2, 5. §A.4 security (program match) → Task 5. §A.5 dispatch refactor → Tasks 2, 5.
- §B WebAuthn → Tasks 7 (introspection), 8 (identity), 9 (execute), 10 (client/tests).
- §C remove unauth + rewire → Tasks 11, 12. §D growth → Task 13. §E panics → Tasks 7, 14.
- §12 testing → golden (Task 4), e2e clone (Task 6), WebAuthn (Task 10). §14 docs → Task 15.
- **Known iteration points (validated against the running validator, not pre-knowable):** chain-signatures `program_state` seed/clone address (Task 6); exact P-256 signing util reuse (Task 10); the WebAuthn `eq`/`origin` matching decision (Task 9 Step 3); host-target `cargo test` availability for the golden (Task 4 Step 2). Each step says how to confirm.

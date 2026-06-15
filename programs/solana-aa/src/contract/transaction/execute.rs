use crate::{
    contract::auth::{
        ek256::get_ek256_data_impl,
        secp256r1_sha256::get_secp256r1_sha256_data_impl,
        zk_oidc::{transaction_nonce_hex, verify_zk_oidc_proof, Sp1Groth16Proof},
    },
    pda_seeds::{ABSTRACT_ACCOUNT_SEED, ACCOUNT_MANAGER_SEED, OIDC_KEY_REGISTRY_SEED},
    types::{
        account::{AbstractAccount, AbstractAccountOperationAccounts, AccountId},
        account_manager::AccountManager,
        identity::{
            oidc::OidcIdentity, wallet::WalletType, webauthn::WebAuthnAuthenticator, Identity,
        },
        oidc_key_registry::OidcKeyRegistry,
        transaction::transaction::{Action, SignRequest, Transaction, WebAuthnAuthData},
    },
};
use anchor_lang::prelude::*;
use anchor_lang::solana_program;
use anchor_lang::solana_program::program::invoke_signed;
use base64::Engine;

use super::sign::build_sign_instruction;
use super::validation::is_transaction_authorized;

#[derive(Accounts)]
#[instruction(account_id: AccountId)]
pub struct ExecuteEk256<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref()],
        bump = abstract_account.bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    #[account(
        seeds = [ACCOUNT_MANAGER_SEED],
        bump = account_manager.bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    pub system_program: Program<'info, System>,

    /// CHECK: Instructions sysvar, verified by address
    #[account(address = solana_program::sysvar::instructions::id())]
    pub instructions: AccountInfo<'info>,
}

pub fn execute_ek256_impl<'info>(
    ctx: Context<'_, '_, '_, 'info, ExecuteEk256<'info>>,
    account_id: AccountId,
) -> Result<()> {
    let (eth_address, signed_message) = get_ek256_data_impl(&ctx.accounts.instructions)?;

    let transaction = Transaction::try_from_slice(&signed_message)?;
    let identity = Identity::Wallet(WalletType::Ethereum(
        eth_address
            .try_into()
            .map_err(|_| ErrorCode::InvalidEthereumAddress)?,
    ));
    let abstract_account = &mut ctx.accounts.abstract_account;

    is_transaction_authorized(abstract_account, account_id, &identity, &transaction)?;

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

#[derive(Accounts)]
#[instruction(account_id: AccountId)]
pub struct ExecuteZkOidc<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref()],
        bump = abstract_account.bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    #[account(
        seeds = [ACCOUNT_MANAGER_SEED],
        bump = account_manager.bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    #[account(
        seeds = [OIDC_KEY_REGISTRY_SEED],
        bump = oidc_key_registry.bump,
    )]
    pub oidc_key_registry: Account<'info, OidcKeyRegistry>,

    pub system_program: Program<'info, System>,
}

pub fn execute_zk_oidc_impl<'info>(
    ctx: Context<'_, '_, '_, 'info, ExecuteZkOidc<'info>>,
    account_id: AccountId,
    transaction: Transaction,
    groth16_proof: Sp1Groth16Proof,
) -> Result<()> {
    let jwt = verify_zk_oidc_proof(&groth16_proof)?;

    // Proof/transaction binding: the JWT was minted with the hash of this exact
    // transaction as its nonce claim, so the proof authorizes nothing else.
    let expected_nonce = transaction_nonce_hex(&transaction.try_to_vec()?);
    require!(
        jwt.nonce == expected_nonce,
        ErrorCode::TransactionBindingMismatch
    );

    // JWKS pinning: only proofs against registry-approved provider keys count.
    require!(
        ctx.accounts.oidc_key_registry.contains(&jwt.iss, &jwt.pk_hash),
        ErrorCode::OidcKeyNotRegistered
    );

    let identity = Identity::Oidc(OidcIdentity {
        iss: jwt.iss,
        aud: jwt.aud,
        email_hash: jwt.email_hash,
    });

    is_transaction_authorized(
        &mut ctx.accounts.abstract_account,
        account_id,
        &identity,
        &transaction,
    )?;

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

    #[account(
        seeds = [ACCOUNT_MANAGER_SEED],
        bump = account_manager.bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    pub system_program: Program<'info, System>,

    /// CHECK: Instructions sysvar, verified by address
    #[account(address = solana_program::sysvar::instructions::id())]
    pub instructions: AccountInfo<'info>,
}

pub fn execute_webauthn_impl<'info>(
    ctx: Context<'_, '_, '_, 'info, ExecuteWebauthn<'info>>,
    account_id: AccountId,
    transaction: Transaction,
    auth: WebAuthnAuthData,
) -> Result<()> {
    use anchor_lang::solana_program::hash::hash as sha256;

    let (pubkey, signed_message) = get_secp256r1_sha256_data_impl(&ctx.accounts.instructions)?;

    // 1. The precompile verified a signature over
    //    `authenticator_data || sha256(clientDataJSON)`. Re-bind the raw
    //    client_data + authenticator_data we were handed to that signed message,
    //    so nothing below trusts unsigned input.
    let client_data_hash = sha256(auth.client_data.as_bytes());
    let mut expected = auth.authenticator_data.clone();
    expected.extend_from_slice(&client_data_hash.to_bytes());
    require!(expected == signed_message, ErrorCode::WebAuthnMessageMismatch);

    // 2. Parse clientDataJSON as JSON (never template-match — WebAuthn spec).
    #[derive(serde::Deserialize)]
    struct ClientData {
        r#type: String,
        challenge: String,
        origin: String,
    }
    let client_data: ClientData =
        serde_json::from_str(&auth.client_data).map_err(|_| ErrorCode::InvalidClientData)?;
    require!(
        client_data.r#type == "webauthn.get",
        ErrorCode::InvalidClientData
    );

    // 3. Transaction binding: challenge == base64url(sha256(borsh(transaction))).
    let tx_hash = sha256(&transaction.try_to_vec()?).to_bytes();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(client_data.challenge.as_bytes())
        .map_err(|_| ErrorCode::InvalidClientData)?;
    require!(challenge == tx_hash, ErrorCode::WebAuthnChallengeMismatch);

    // 4. authenticatorData layout: rpIdHash[0..32], flags[32], counter[33..37].
    //    Require the user-present (UP) bit so a stored signature can't be replayed
    //    without an actual authenticator gesture.
    require!(
        auth.authenticator_data.len() >= 37,
        ErrorCode::InvalidAuthenticatorData
    );
    require!(
        auth.authenticator_data[32] & 0x01 == 0x01,
        ErrorCode::WebAuthnUserNotPresent
    );
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth.authenticator_data[0..32]);

    // 5. Reconstruct the identity. Equality (pubkey + rpIdHash + origin) is what
    //    binds this assertion to a registered credential inside
    //    is_transaction_authorized — a key reused on another origin won't match.
    let identity = Identity::WebAuthn(WebAuthnAuthenticator {
        key_id: String::new(),
        compressed_public_key: Some(format!("0x{}", hex::encode(&pubkey))),
        rp_id_hash,
        origin: client_data.origin,
    });

    is_transaction_authorized(
        &mut ctx.accounts.abstract_account,
        account_id,
        &identity,
        &transaction,
    )?;

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

fn dispatch_action<'info>(
    operation_accounts: AbstractAccountOperationAccounts<'_, 'info>,
    account_id: AccountId,
    chain_signatures_program_id: Pubkey,
    remaining_accounts: &[AccountInfo<'info>],
    action: Action,
) -> Result<()> {
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
}

/// Forward a `Sign` action to the deployment-configured chain-signatures
/// program. The abstract-account PDA is the `requester` (signed via
/// `invoke_signed`, so the MPC-derived key belongs to the account); the outer
/// signer is the `fee_payer`. `remaining_accounts` must be exactly the three
/// chain-signatures-owned accounts the CPI needs, in this order:
/// `[program_state, event_authority, chain_signatures_program]`.
fn dispatch_sign<'info>(
    operation_accounts: AbstractAccountOperationAccounts<'_, 'info>,
    account_id: AccountId,
    chain_signatures_program_id: Pubkey,
    remaining_accounts: &[AccountInfo<'info>],
    req: SignRequest,
) -> Result<()> {
    let [program_state, event_authority, chain_sig_program] = remaining_accounts else {
        return Err(ErrorCode::InvalidChainSignaturesAccounts.into());
    };

    // Structural security: the CPI may only target the configured program. The
    // chain-signatures program validates program_state / event_authority against
    // its own seeds, so pinning the program id here is sufficient.
    require_keys_eq!(
        *chain_sig_program.key,
        chain_signatures_program_id,
        ErrorCode::ChainSignaturesProgramMismatch
    );

    let requester_info = operation_accounts.abstract_account.to_account_info();
    let bump = operation_accounts.abstract_account.bump;

    let instruction = build_sign_instruction(
        chain_signatures_program_id,
        &req,
        *program_state.key,
        *requester_info.key,
        *operation_accounts.signer_info.key,
        *operation_accounts.system_program_info.key,
        *event_authority.key,
        *chain_sig_program.key,
    )?;

    let account_id_bytes = account_id.to_le_bytes();
    let bump_seed = [bump];
    let signer_seeds: &[&[u8]] = &[ABSTRACT_ACCOUNT_SEED, account_id_bytes.as_ref(), &bump_seed];

    invoke_signed(
        &instruction,
        &[
            program_state.clone(),
            requester_info.clone(),
            operation_accounts.signer_info.clone(),
            operation_accounts.system_program_info.clone(),
            event_authority.clone(),
            chain_sig_program.clone(),
        ],
        &[signer_seeds],
    )?;

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid Ethereum address in verification instruction")]
    InvalidEthereumAddress,
    #[msg("JWT nonce does not match the transaction hash")]
    TransactionBindingMismatch,
    #[msg("OIDC signing key not present in the registry")]
    OidcKeyNotRegistered,
    #[msg("Sign action requires [program_state, event_authority, chain_signatures_program] as remaining accounts")]
    InvalidChainSignaturesAccounts,
    #[msg("Provided chain-signatures program does not match the configured deployment id")]
    ChainSignaturesProgramMismatch,
    #[msg("Reconstructed WebAuthn message does not match the verified signature")]
    WebAuthnMessageMismatch,
    #[msg("clientDataJSON challenge does not match the transaction hash")]
    WebAuthnChallengeMismatch,
    #[msg("WebAuthn user-present flag not set")]
    WebAuthnUserNotPresent,
    #[msg("Malformed authenticatorData")]
    InvalidAuthenticatorData,
    #[msg("Malformed clientDataJSON")]
    InvalidClientData,
}

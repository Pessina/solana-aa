use crate::{
    contract::auth::{
        ek256::get_ek256_data_impl,
        zk_oidc::{transaction_nonce_hex, verify_zk_oidc_proof, Sp1Groth16Proof},
    },
    pda_seeds::{ABSTRACT_ACCOUNT_SEED, OIDC_KEY_REGISTRY_SEED},
    types::{
        account::{AbstractAccount, AbstractAccountOperationAccounts, AccountId},
        identity::{oidc::OidcIdentity, wallet::WalletType, Identity},
        oidc_key_registry::OidcKeyRegistry,
        transaction::transaction::{Action, Transaction},
    },
};
use anchor_lang::prelude::*;
use anchor_lang::solana_program;

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

    pub system_program: Program<'info, System>,

    /// CHECK: Instructions sysvar, verified by address
    #[account(address = solana_program::sysvar::instructions::id())]
    pub instructions: AccountInfo<'info>,
}

pub fn execute_ek256_impl(ctx: Context<ExecuteEk256>, account_id: AccountId) -> Result<()> {
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
        seeds = [OIDC_KEY_REGISTRY_SEED],
        bump = oidc_key_registry.bump,
    )]
    pub oidc_key_registry: Account<'info, OidcKeyRegistry>,

    pub system_program: Program<'info, System>,
}

pub fn execute_zk_oidc_impl(
    ctx: Context<ExecuteZkOidc>,
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
        transaction.action,
    )
}

fn dispatch_action(
    operation_accounts: AbstractAccountOperationAccounts,
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
    }
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid Ethereum address in verification instruction")]
    InvalidEthereumAddress,
    #[msg("JWT nonce does not match the transaction hash")]
    TransactionBindingMismatch,
    #[msg("OIDC signing key not present in the registry")]
    OidcKeyNotRegistered,
}

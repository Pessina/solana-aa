use crate::{
    pda_seeds::{ABSTRACT_ACCOUNT_SEED, ACCOUNT_MANAGER_SEED},
    types::{
        account::{AbstractAccount, AccountId},
        account_manager::AccountManager,
        identity::*,
    },
    utils::pda::{close_pda, realloc_account},
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(account_id: AccountId)]
pub struct DeleteAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ACCOUNT_MANAGER_SEED],
        bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    #[account(
        mut,
        seeds = [ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub system_program: Program<'info, System>,
}

pub fn delete_account_impl(ctx: Context<DeleteAccount>) -> Result<()> {
    ctx.accounts
        .account_manager
        .update_max_nonce(ctx.accounts.abstract_account.nonce);

    close_pda(
        &ctx.accounts.abstract_account.to_account_info(),
        &ctx.accounts.signer.to_account_info(),
    )?;

    Ok(())
}

#[derive(Accounts)]
#[instruction(identity_with_permissions: IdentityWithPermissions)]
pub struct CreateAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ACCOUNT_MANAGER_SEED],
        bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    // Account creating can be done by anyone and it doesn't pose a security risk.
    // The user will be able to create the account but won't be able to modify it
    // or use it for malicious transactions.
    #[account(
        init_if_needed,
        payer = signer,
        space = AbstractAccount::initial_size(&identity_with_permissions),
        seeds = [ABSTRACT_ACCOUNT_SEED, account_manager.next_account_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub system_program: Program<'info, System>,
}

pub fn create_account_impl(
    ctx: Context<CreateAccount>,
    identity_with_permissions: IdentityWithPermissions,
) -> Result<()> {
    ctx.accounts.abstract_account.nonce = ctx.accounts.account_manager.max_nonce;
    ctx.accounts.abstract_account.identities = vec![identity_with_permissions];

    ctx.accounts.account_manager.increment_next_account_id();

    Ok(())
}

/*
   We plan to use a single entry point for all transactions, we need to research how to handle realloc in a dynamic way.
   For that we can have a realloc function or research what's the Anchor idiomatic way to handle it.
*/
#[derive(Accounts)]
#[instruction(account_id: AccountId, identity_with_permissions: IdentityWithPermissions)]
pub struct AddIdentity<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub rent: Sysvar<'info, Rent>,

    pub system_program: Program<'info, System>,
}

pub fn add_identity_impl(
    ctx: Context<AddIdentity>,
    _account_id: AccountId,
    identity_with_permissions: IdentityWithPermissions,
) -> Result<()> {
    let new_size = ctx.accounts.abstract_account.to_account_info().data_len()
        + identity_with_permissions.byte_size();

    realloc_account(
        &mut ctx.accounts.abstract_account.to_account_info(),
        new_size,
        &mut ctx.accounts.signer.to_account_info(),
        &ctx.accounts.system_program.to_account_info(),
    )?;

    ctx.accounts
        .abstract_account
        .add_identity(identity_with_permissions);

    Ok(())
}

#[derive(Accounts)]
#[instruction(account_id: AccountId, identity: Identity)]
pub struct RemoveIdentity<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub system_program: Program<'info, System>,
}

pub fn remove_identity_impl(ctx: Context<RemoveIdentity>, identity: Identity) -> Result<()> {
    let identity_size = match ctx.accounts.abstract_account.find_identity(&identity) {
        Some(identity_with_permissions) => identity_with_permissions.byte_size(),
        None => return Err(ErrorCode::IdentityNotFound.into()),
    };

    ctx.accounts.abstract_account.remove_identity(&identity);

    let new_size = ctx.accounts.abstract_account.to_account_info().data_len() - identity_size;

    realloc_account(
        &mut ctx.accounts.abstract_account.to_account_info(),
        new_size,
        &mut ctx.accounts.signer.to_account_info(),
        &ctx.accounts.system_program.to_account_info(),
    )?;

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Identity not found")]
    IdentityNotFound,
}

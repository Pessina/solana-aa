use crate::types::{
    account::{AbstractAccount, AccountId},
    account_manager::AccountManager,
    identity::*,
};
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(account_id: AccountId)]
pub struct DeleteAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"account_manager"],
        bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    #[account(
        mut,
        seeds = [b"account", account_id.to_le_bytes().as_ref()],
        bump,
        close = signer
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub system_program: Program<'info, System>,
}

pub fn delete_account_impl(ctx: Context<DeleteAccount>) -> Result<()> {
    ctx.accounts
        .account_manager
        .update_max_nonce(ctx.accounts.abstract_account.nonce);

    Ok(())
}

#[derive(Accounts)]
#[instruction(identity_with_permissions: IdentityWithPermissions)]
pub struct CreateAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"account_manager"],
        bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    #[account(
        init_if_needed,
        payer = signer,
        space = AbstractAccount::initial_size(&identity_with_permissions),
        seeds = [b"account", account_manager.next_account_id.to_le_bytes().as_ref()],
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

#[derive(Accounts)]
#[instruction(account_id: AccountId, identity_with_permissions: IdentityWithPermissions)]
pub struct AddIdentity<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"account", account_id.to_le_bytes().as_ref()],
        bump,
        realloc = abstract_account.to_account_info().data_len() + identity_with_permissions.byte_size(),
        realloc::payer = signer,
        realloc::zero = false
    )]
    pub abstract_account: Account<'info, AbstractAccount>,
    pub system_program: Program<'info, System>,
}

pub fn add_identity_impl(
    ctx: Context<AddIdentity>,
    _account_id: AccountId,
    identity_with_permissions: IdentityWithPermissions,
) -> Result<()> {
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
        seeds = [b"account", account_id.to_le_bytes().as_ref()],
        bump,
        // TODO: Throw proper error
        realloc = abstract_account.to_account_info().data_len() - abstract_account.find_identity(&identity).expect("Identity not found").byte_size(),
        realloc::payer = signer,
        realloc::zero = false
    )]
    pub abstract_account: Account<'info, AbstractAccount>,
    pub system_program: Program<'info, System>,
}

pub fn remove_identity_impl(
    ctx: Context<RemoveIdentity>,
    _account_id: AccountId,
    identity: Identity,
) -> Result<()> {
    ctx.accounts.abstract_account.remove_identity(&identity);
    Ok(())
}

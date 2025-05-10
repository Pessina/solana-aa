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

/*
    The account creation is implemented as a separate method for several reasons:

    1. It bypasses the authentication process since anyone should be able to create an account with any identity.

    2. This design is secure because an account can only be controlled by the identities that have been added to the account..

    3. Separating account creation optimizes the remaining methods by:
       - Bump can't be provided with init, therefore the other methods can include the bump
       - Account Manger is only used by the account creation, saving memory on other methods
*/
#[derive(Accounts)]
#[instruction(identity_with_permissions: IdentityWithPermissions)]
pub struct CreateAbstractAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ACCOUNT_MANAGER_SEED],
        bump = account_manager.bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    #[account(
        init,
        payer = signer,
        space = AbstractAccount::INIT_SIZE + identity_with_permissions.byte_size(),
        seeds = [ABSTRACT_ACCOUNT_SEED, account_manager.next_account_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub system_program: Program<'info, System>,
}

pub fn create_account_impl(
    ctx: Context<CreateAbstractAccount>,
    identity_with_permissions: IdentityWithPermissions,
) -> Result<()> {
    ctx.accounts.abstract_account.nonce = 0;
    ctx.accounts.abstract_account.identities = vec![identity_with_permissions];
    ctx.accounts.abstract_account.bump = ctx.bumps.abstract_account;

    ctx.accounts.account_manager.increment_next_account_id();

    Ok(())
}

#[derive(Accounts)]
#[instruction(account_id: AccountId)]
pub struct AbstractAccountOperation<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref()],
        bump = abstract_account.bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub system_program: Program<'info, System>,
}

pub fn add_identity_impl(
    ctx: Context<AbstractAccountOperation>,
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

pub fn remove_identity_impl(
    ctx: Context<AbstractAccountOperation>,
    identity: Identity,
) -> Result<()> {
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

pub fn delete_account_impl(ctx: Context<AbstractAccountOperation>) -> Result<()> {
    close_pda(
        &ctx.accounts.abstract_account.to_account_info(),
        &ctx.accounts.signer.to_account_info(),
    )?;

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Identity not found")]
    IdentityNotFound,
}

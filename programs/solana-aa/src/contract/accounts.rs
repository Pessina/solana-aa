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

// TODO: This context should not exist, as the methods bellow are not directly callable without authentication
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

// TODO: As the methods bellow are the minimum necessary steps to perform the AbstractAccount operations,
// we should move them to the account.rs file where we defined the internal methods on the AbstractAccount

pub struct AbstractAccountOperationArgs<'a, 'info> {
    pub abstract_account: &'a mut Account<'info, AbstractAccount>,
    pub signer_info: AccountInfo<'info>,
    pub system_program_info: AccountInfo<'info>,
}

pub fn add_identity_impl(
    args: AbstractAccountOperationArgs,
    identity_with_permissions: IdentityWithPermissions,
) -> Result<()> {
    // Get account info and calculate new size
    let account_info = args.abstract_account.to_account_info();
    let current_size = account_info.data_len();
    let identity_size = identity_with_permissions.byte_size();
    let new_size = current_size + identity_size;

    // Reallocate the account using our utility function
    realloc_account(
        &account_info,
        new_size,
        &args.signer_info,
        &args.system_program_info,
    )?;

    // Add the identity after reallocation is complete
    args.abstract_account
        .add_identity(identity_with_permissions);

    Ok(())
}

pub fn remove_identity_impl(args: AbstractAccountOperationArgs, identity: Identity) -> Result<()> {
    // Find the identity and get its size
    let identity_size = match args.abstract_account.find_identity(&identity) {
        Some(identity_with_permissions) => identity_with_permissions.byte_size(),
        None => return Err(ErrorCode::IdentityNotFound.into()),
    };

    // Remove the identity from the account
    args.abstract_account.remove_identity(&identity);

    // Calculate new size and reallocate
    let account_info = args.abstract_account.to_account_info();
    let current_size = account_info.data_len();
    let new_size = current_size - identity_size;

    // Reallocate the account using our utility function
    realloc_account(
        &account_info,
        new_size,
        &args.signer_info,
        &args.system_program_info,
    )?;

    Ok(())
}

pub fn delete_account_impl(args: AbstractAccountOperationArgs) -> Result<()> {
    // Close the PDA using our utility function
    close_pda(&args.abstract_account.to_account_info(), &args.signer_info)?;

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Identity not found")]
    IdentityNotFound,
}

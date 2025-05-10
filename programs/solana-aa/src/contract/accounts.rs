use crate::{
    pda_seeds::{ABSTRACT_ACCOUNT_SEED, ACCOUNT_MANAGER_SEED},
    types::{account::AbstractAccount, account_manager::AccountManager, identity::*},
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

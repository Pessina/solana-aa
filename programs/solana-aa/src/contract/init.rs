use crate::types::account_manager::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct InitContract<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        init_if_needed,
        payer = signer,
        space = AccountManager::INIT_SIZE,
        seeds = [b"account_manager"],
        bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    pub system_program: Program<'info, System>,
}

pub fn init_contract_impl(ctx: Context<InitContract>) -> Result<()> {
    ctx.accounts.account_manager.max_nonce = 0;
    ctx.accounts.account_manager.latest_account_id = 0;

    Ok(())
}

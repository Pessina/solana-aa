use anchor_lang::prelude::*;

use crate::{pda_seeds::ACCOUNT_MANAGER_SEED, types::account_manager::AccountManager};

#[derive(Accounts)]
pub struct CloseContract<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ACCOUNT_MANAGER_SEED],
        bump = account_manager.bump,
        close = signer
    )]
    pub account_manager: Account<'info, AccountManager>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitContract<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        init,
        payer = signer,
        space = AccountManager::INIT_SIZE,
        seeds = [ACCOUNT_MANAGER_SEED],
        bump,
    )]
    pub account_manager: Account<'info, AccountManager>,

    pub system_program: Program<'info, System>,
}

pub fn init_contract_impl(ctx: Context<InitContract>) -> Result<()> {
    ctx.accounts.account_manager.next_account_id = 0;
    ctx.accounts.account_manager.bump = ctx.bumps.account_manager;

    Ok(())
}

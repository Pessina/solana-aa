use anchor_lang::prelude::*;

use crate::types::account_manager::AccountManager;

#[derive(Accounts)]
pub struct CloseContract<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"account_manager"],
        bump,
        close = signer
    )]
    pub account_manager: Account<'info, AccountManager>,

    pub system_program: Program<'info, System>,
}

use crate::{
    contract::auth::ek256::get_ek256_data_impl,
    pda_seeds::ABSTRACT_ACCOUNT_SEED,
    types::{
        account::{AbstractAccount, AccountId},
        identity::{wallet::WalletType, Identity},
        transaction::transaction::Transaction,
    },
};
use anchor_lang::prelude::*;
use anchor_lang::solana_program;

use super::validation::is_transaction_authorized;

pub fn execute_ek256_impl(ctx: Context<ExecuteEk256>) -> Result<()> {
    let (eth_address, signed_message) = get_ek256_data_impl(&ctx.accounts.instructions)?;

    let transaction = Transaction::try_from_slice(&signed_message)?;
    let identity = Identity::Wallet(WalletType::Ethereum(eth_address.try_into().unwrap()));

    is_transaction_authorized(&mut ctx.accounts.abstract_account, &identity, &transaction)?;

    Ok(())
}

#[derive(Accounts)]
#[instruction(account_id: AccountId)]
pub struct ExecuteEk256<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [ABSTRACT_ACCOUNT_SEED, account_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub system_program: Program<'info, System>,

    /// CHECK: Instructions sysvar, verified by address
    #[account(address = solana_program::sysvar::instructions::id())]
    pub instructions: AccountInfo<'info>,
}

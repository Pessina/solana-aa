use crate::{
    contract::auth::ek256::get_ek256_data_impl,
    pda_seeds::ABSTRACT_ACCOUNT_SEED,
    types::{
        account::{AbstractAccount, AbstractAccountOperationAccounts, AccountId},
        identity::{wallet::WalletType, Identity},
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
    let identity = Identity::Wallet(WalletType::Ethereum(eth_address.try_into().unwrap()));
    let abstract_account = &mut ctx.accounts.abstract_account;

    is_transaction_authorized(abstract_account, account_id, &identity, &transaction)?;

    let abstract_account_operation_accounts = AbstractAccountOperationAccounts {
        abstract_account: &mut ctx.accounts.abstract_account,
        signer_info: ctx.accounts.signer.to_account_info(),
        system_program_info: ctx.accounts.system_program.to_account_info(),
    };

    match transaction.action {
        Action::RemoveAccount => {
            AbstractAccount::close_account(abstract_account_operation_accounts)?
        }
        Action::AddIdentity(identity_with_permissions) => {
            AbstractAccount::add_identity(
                abstract_account_operation_accounts,
                identity_with_permissions,
            )?;
        }
        Action::RemoveIdentity(identity) => {
            AbstractAccount::remove_identity(abstract_account_operation_accounts, &identity)?;
        }
    }

    Ok(())
}

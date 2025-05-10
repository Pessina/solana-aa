use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke, system_instruction};

/// Reallocates an account's data to a new size.
/// This function handles the reallocation of account data by calculating the rent exemption
/// for the new size and transferring the necessary lamports to or from the account.
///
/// # Arguments
///
/// * `account` - The account to reallocate
/// * `new_size` - The new size in bytes for the account's data
/// * `payer` - The account that will pay for additional space if needed
/// * `system_program` - The system program account info for CPI
///
/// # Returns
///
/// * `Result<()>` - Success or an error if funds are insufficient or reallocation fails
pub fn realloc_account<'info>(
    account: &AccountInfo<'info>,
    new_size: usize,
    payer: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
) -> Result<()> {
    let rent = Rent::get()?;
    let current_size = account.data_len();

    let current_minimum_balance = rent.minimum_balance(current_size);
    let new_minimum_balance = rent.minimum_balance(new_size);

    if new_minimum_balance > current_minimum_balance {
        let lamports_diff = new_minimum_balance.saturating_sub(current_minimum_balance);

        if payer.lamports() < lamports_diff {
            return Err(ProgramError::InsufficientFunds.into());
        }

        invoke(
            &system_instruction::transfer(payer.key, account.key, lamports_diff),
            &[payer.clone(), account.clone(), system_program.clone()],
        )?;
    }

    account.realloc(new_size, false)?;

    if new_minimum_balance < current_minimum_balance {
        let lamports_diff = current_minimum_balance.saturating_sub(new_minimum_balance);
        **account.try_borrow_mut_lamports()? = account.lamports().saturating_sub(lamports_diff);
        **payer.try_borrow_mut_lamports()? = payer.lamports().saturating_add(lamports_diff);
    }

    Ok(())
}

/// Closes a PDA account by transferring its lamports to a recipient.
/// This function transfers all lamports from the PDA to the recipient and clears its data,
/// effectively making it unusable.
///
/// # Arguments
///
/// * `account` - The PDA account to close
/// * `recipient` - The account receiving the lamports
///
/// # Returns
///
/// * `Result<()>` - Success or an error if the operation fails
pub fn close_pda<'info>(
    account: &AccountInfo<'info>,
    recipient: &AccountInfo<'info>,
) -> Result<()> {
    let account_lamports = account.lamports();
    **account.try_borrow_mut_lamports()? = 0;
    **recipient.try_borrow_mut_lamports()? += account_lamports;

    let mut data = account.try_borrow_mut_data()?;
    for byte in data.iter_mut() {
        *byte = 0;
    }

    Ok(())
}

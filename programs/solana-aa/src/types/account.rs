use crate::utils::pda::{close_pda, realloc_account};

use super::identity::{Identity, IdentityWithPermissions};
use anchor_lang::prelude::*;

pub type AccountId = u64;
pub type Nonce = u128;

/**
* Abstract Account PDA
*
* - Accounts are created sequentially with unique IDs managed by the AccountManager PDA
* - Once an account is deleted, its ID cannot be reused or recreated
* - This sequential creation pattern enables efficient account discovery and security by disallowing the reuse of account IDs
*
* Improvements:
*
* - The methods on the struct don't take self as args because self donn't expose `get_account_info` method and other essential PDA methods.
*/
#[account]
pub struct AbstractAccount {
    pub nonce: Nonce,

    // TODO: Benchmark other data structures; BtreeMap, HashMap, etc.
    // Considering ~10 identities per account, a Vec might be the best choice.
    // Vec avoid the overhead of Key-Value pair of BTreeMap and HashMap softening the usage of Heap and Stack.
    pub identities: Vec<IdentityWithPermissions>,

    // PDA discriminator to optimize Anchor account validation
    pub bump: u8,
}

impl AbstractAccount {
    const PDA_DISCRIMINATOR_SIZE: usize = 8;
    const NONCE_SIZE: usize = 16;
    const VEC_SIZE: usize = 4;
    const BUMP_SIZE: usize = 1;

    pub const INIT_SIZE: usize =
        Self::PDA_DISCRIMINATOR_SIZE + Self::NONCE_SIZE + Self::VEC_SIZE + Self::BUMP_SIZE;

    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }

    pub fn has_identity(&self, identity: &Identity) -> bool {
        self.identities.iter().any(|i| &i.identity == identity)
    }

    pub fn find_identity(&self, identity: &Identity) -> Option<&IdentityWithPermissions> {
        self.identities.iter().find(|i| &i.identity == identity)
    }

    // TODO: Include memory usage check to avoid overflowing solana heap limit (32kb)
    pub fn add_identity(
        abstract_account_operation_accounts: AbstractAccountOperationAccounts,
        identity_with_permissions: IdentityWithPermissions,
    ) -> Result<()> {
        let AbstractAccountOperationAccounts {
            abstract_account,
            signer_info,
            system_program_info,
        } = abstract_account_operation_accounts;

        let account_info = abstract_account.to_account_info();
        let new_size = account_info.data_len() + identity_with_permissions.byte_size();

        realloc_account(&account_info, new_size, &signer_info, &system_program_info)?;

        if !abstract_account.has_identity(&identity_with_permissions.identity) {
            abstract_account.identities.push(identity_with_permissions);
        }

        Ok(())
    }

    pub fn remove_identity(
        abstract_account_operation_accounts: AbstractAccountOperationAccounts,
        identity: &Identity,
    ) -> Result<()> {
        let AbstractAccountOperationAccounts {
            abstract_account,
            signer_info,
            system_program_info,
        } = abstract_account_operation_accounts;

        let identity_size = match abstract_account.find_identity(&identity) {
            Some(identity_with_permissions) => identity_with_permissions.byte_size(),
            None => return Err(ErrorCode::IdentityNotFound.into()),
        };

        let initial_len = abstract_account.identities.len();
        abstract_account
            .identities
            .retain(|i| &i.identity != identity);

        if initial_len > abstract_account.identities.len() {
            let account_info = abstract_account.to_account_info();
            let new_size = account_info.data_len() - identity_size;

            realloc_account(&account_info, new_size, &signer_info, &system_program_info)?;
        }

        Ok(())
    }

    pub fn close_account(
        abstract_account_operation_accounts: AbstractAccountOperationAccounts,
    ) -> Result<()> {
        let AbstractAccountOperationAccounts {
            abstract_account,
            signer_info,
            ..
        } = abstract_account_operation_accounts;

        close_pda(&abstract_account.to_account_info(), &signer_info)?;
        Ok(())
    }
}

pub struct AbstractAccountOperationAccounts<'a, 'info> {
    pub abstract_account: &'a mut Account<'info, AbstractAccount>,
    pub signer_info: AccountInfo<'info>,
    pub system_program_info: AccountInfo<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Identity not found")]
    IdentityNotFound,
}

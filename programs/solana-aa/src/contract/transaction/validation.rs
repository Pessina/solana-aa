use anchor_lang::prelude::*;

use crate::types::{
    account::AbstractAccount, identity::Identity, transaction::transaction::Transaction,
};

/// Validates the user operation against the abstract account
///
/// This function performs the following validations:
/// 1. Checks if the identity in the user operation exists in the abstract account
/// 2. Verifies that the nonce in the transaction matches the account's current nonce
/// 3. Increments the account nonce to prevent replay attacks
///
/// # Arguments
/// * `abstract_account` - The abstract account to validate against
/// * `user_op` - The user operation containing the transaction details
///
/// # Returns
/// * `Result<()>` - Returns Ok() if validation succeeds, or the error code if validation fails
pub fn is_transaction_authorized(
    abstract_account: &mut AbstractAccount,
    identity: &Identity,
    transaction: &Transaction,
) -> Result<()> {
    if !abstract_account.has_identity(&identity) {
        return Err(ErrorCode::IdentityNotFound.into());
    }

    if !abstract_account.nonce.eq(&transaction.nonce) {
        return Err(ErrorCode::NonceMismatch.into());
    }

    abstract_account.nonce += 1;

    // TODO: Include verification for act_as

    // TODO: Verify permissions

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Identity not found in account")]
    IdentityNotFound,
    #[msg("Nonce mismatch")]
    NonceMismatch,
}

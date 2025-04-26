use std::io::Read;

use anchor_lang::{prelude::*, solana_program};

use crate::{
    contract::{accounts::AbstractAccount, transaction::types::UserOp},
    traits::signable_message::SignableMessage,
    types::identities::IdentityWithPermissions,
};

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::types::VerificationContext;

pub fn execute_impl(ctx: Context<VerifyEthereumSignature>, user_op: &UserOp) -> Result<()> {
    let abstract_account = &mut ctx.accounts.abstract_account;

    validate_user_operation(abstract_account, user_op)?;

    Ok(())
}

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
/// * `Result<bool>` - Returns Ok(true) if validation succeeds, or an error if validation fails
fn validate_user_operation(
    abstract_account: &mut AbstractAccount,
    user_op: &UserOp,
) -> Result<bool> {
    if !abstract_account.has_identity(&user_op.auth.identity) {
        return Err(ErrorCode::IdentityNotFound.into());
    }

    if !abstract_account.nonce.eq(&user_op.transaction.nonce) {
        return Err(ErrorCode::NonceMismatch.into());
    }

    abstract_account.nonce += 1;

    // TODO: Include verification for act_as

    // TODO: Verify permissions

    Ok(true)
}

fn get_signed_message(user_op: &UserOp) -> Result<Vec<u8>> {
    let auth = &user_op.auth;
    let transaction = &user_op.transaction;

    if let Some(verification_context) = &auth.verification_context {
        match verification_context {
            VerificationContext::WebAuthn(verification_data) => {
                let signed_message = transaction.to_signable_message(());

                let signed_message =
                    URL_SAFE_NO_PAD.encode(Sha256::digest(signed_message.as_bytes()));

                let client_data: serde_json::Value =
                    serde_json::from_str(&verification_data.client_data)
                        .map_err(|_| ErrorCode::InvalidClientDataJSON)?;

                let client_challenge = client_data["challenge"]
                    .as_str()
                    .ok_or(ErrorCode::InvalidChallenge)?;

                if signed_message != client_challenge {
                    return Err(ErrorCode::ChallengeMismatch.into());
                }

                // Compute expected data and compare in parts
                let authenticator_data_bytes =
                    hex::decode(&verification_data.authenticator_data[2..])
                        .map_err(|_| ErrorCode::InvalidHexEncoding)?;
                let client_data_hash = Sha256::digest(verification_data.client_data.as_bytes());

                return Ok([authenticator_data_bytes, client_data_hash.as_slice().into()].concat());
            }
        }
    }

    let signed_message = transaction.to_signable_message(());

    Ok(signed_message.as_bytes().to_vec())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Identity not found in account")]
    IdentityNotFound,
    #[msg("Nonce mismatch")]
    NonceMismatch,
    #[msg("Invalid client data JSON")]
    InvalidClientDataJSON,
    #[msg("Invalid challenge")]
    InvalidChallenge,
    #[msg("Challenge mismatch")]
    ChallengeMismatch,
    #[msg("Invalid hex encoding")]
    InvalidHexEncoding,
}

#[derive(Accounts)]
#[instruction(user_op: UserOp)]
pub struct VerifyEthereumSignature<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    /// CHECK: instructions sysvar, includes information for signature verification from pre-compiled program
    #[account(address = solana_program::sysvar::instructions::id())]
    pub instructions: AccountInfo<'info>,

    #[account(
        mut,
        seeds = [b"account", user_op.transaction.account_id.as_bytes()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,

    pub system_program: Program<'info, System>,
}

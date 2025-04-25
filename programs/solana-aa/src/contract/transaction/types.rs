use crate::{
    traits::signable_message::SignableMessage,
    types::identities::{Identity, IdentityWithPermissions},
};
use anchor_lang::prelude::*;
use serde::Serialize;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Serialize)]
pub struct UserOp {
    // Credentials must contain the signature of the transaction message in canonical JSON format.
    // The message is canonicalized to ensure consistent signatures across different platforms.
    pub auth: Auth,
    pub act_as: Option<Identity>,
    pub transaction: Transaction,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Serialize)]
pub struct Auth {
    pub identity: Identity,
    pub verification_context: Option<VerificationContext>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Serialize)]
pub struct Transaction {
    pub account_id: String,
    pub nonce: u128,
    pub action: Action,
}

impl SignableMessage for Transaction {
    type Context<'a> = ();

    fn to_signable_message(&self, _: ()) -> String {
        serde_json_canonicalizer::to_string(&self).expect("Failed to canonicalize transaction")
    }
}

#[error_code]
pub enum ErrorCode {
    #[msg("Failed to canonicalize transaction")]
    FailedToCanonicalizeTransaction,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Serialize)]
pub enum Action {
    RemoveAccount,
    /*
    Credentials must contain the signature of account_id, nonce, action, permissions to:
    1. Prove ownership of the IdentityWithPermissions
    2. Declare which account it intends to be added to
    3. Prevent replay attacks
    4. Declare intention to add the IdentityWithPermissions to the account with the given permissions
    */
    // AddIdentityWithAuth(AddIdentityWithAuth),
    AddIdentity(IdentityWithPermissions),
    RemoveIdentity(Identity),
    // Sign(SignPayloadsRequest),
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Serialize)]
pub enum VerificationContext {
    WebAuthn(WebAuthnVerificationContext),
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Serialize)]
pub struct WebAuthnVerificationContext {
    pub authenticator_data: String,
    pub client_data: String,
}

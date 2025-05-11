use anchor_lang::prelude::*;

use crate::types::{
    account::AccountId,
    identity::{Identity, IdentityWithPermissions},
};

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UserOp {
    // Credentials must contain the signature of the transaction message in canonical JSON format.
    // The message is canonicalized to ensure consistent signatures across different platforms.
    pub auth: Auth,
    pub act_as: Option<Identity>,
    pub transaction: Transaction,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Auth {
    /*
    Identity is not necessary, it will be provided to the pre-compiled contract, so we can extract it from the instructions sysvar and verify if it exist on the target account_id.

    - Wallet: pre-compiled program receives the public key
    - Webauthn: pre-compiled program receives the public key
    - OIDC: pre-compiled program receives the id token, and from the token we can extract issuer, audience, email/sub.

    */
    // pub identity: Identity,

    /*
    Any extra data necessary to compute the signed hash.

    - Wallet: Not necessary as the hash is computed using the transaction
    - Webauthn: Necessary as the hash signed it's computed by hashing the client_data, so the transaction it's not enough
    - OIDC: Not necessary as the nonce on OIDC it's computed using the transaction
    */
    pub verification_context: Option<VerificationContext>,
}

/*
Transaction to be executed by the AA.

It's mandatory to provide it's not possible to compute from the signed data.

- Wallet: Not necessary as the transaction it's provided to the pre-compiled contract as a verification step
- Webauthn: Necessary as the transaction exist as a hash on the client_data challenge
- OIDC: Necessary as the transaction exist as a hash on the nonce
*/
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct Transaction {
    pub account_id: AccountId,
    pub nonce: u128,
    pub action: Action,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
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

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub enum VerificationContext {
    WebAuthn(WebAuthnVerificationContext),
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WebAuthnVerificationContext {
    /*
    JSON stringified client data.

    Necessary field because the Webauthn signs: sign([authenticator_data.as_bytes(), sha256(client_data).as_bytes()])
    Therefore if we have the client_data and transaction, we can compute the hash signed

    Considerations:

    - It's not possible to use Borsh because the Client Data keys are unknown.
    - Consider using CBOR to make it more compact for transaction size
    - Verifying that the client_data.challenge was signed by a authorized identity it's enough for security. We don't need to include the Authenticator Data on verification.
    */
    pub client_data: String,
}

use anchor_lang::prelude::*;

pub mod oidc;
pub mod wallet;
pub mod webauthn;

// New variants must be appended to keep Borsh enum tags stable for
// already-serialized accounts and the TS schemas in `borsh/schemas`.
#[derive(Debug, AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone)]
pub enum Identity {
    Wallet(wallet::WalletType),
    WebAuthn(webauthn::WebAuthnAuthenticator),
    Oidc(oidc::OidcIdentity),
}

#[derive(Debug, AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone)]
pub struct IdentityWithPermissions {
    pub identity: Identity,
    pub permissions: Option<IdentityPermissions>,
}

impl IdentityWithPermissions {
    pub fn byte_size(&self) -> Result<usize> {
        Ok(self
            .try_to_vec()
            .map_err(|_| error!(ErrorCode::IdentitySerializationFailed))?
            .len())
    }
}

#[derive(Debug, AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone)]
pub struct IdentityPermissions {
    pub enable_act_as: bool,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Failed to serialize identity")]
    IdentitySerializationFailed,
}

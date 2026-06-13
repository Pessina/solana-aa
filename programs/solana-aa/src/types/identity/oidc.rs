use anchor_lang::prelude::*;

/// OIDC identity, verified through a ZK proof of the provider-signed JWT.
///
/// The email address is never stored or revealed on-chain — only its SHA-256
/// hash as committed by the guest program (`zk/jwt-program`). `iss` and `aud`
/// bind the identity to a specific provider and OAuth client so a token minted
/// by another application for the same email cannot control this identity.
#[derive(Debug, AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone)]
pub struct OidcIdentity {
    pub iss: String,
    pub aud: String,
    pub email_hash: [u8; 32],
}

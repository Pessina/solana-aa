use anchor_lang::prelude::*;

pub mod wallet;
pub mod webauthn;

#[derive(Debug, AnchorSerialize, AnchorDeserialize, Clone)]
pub enum Identity {
    Wallet(wallet::WalletAuthenticator),
    WebAuthn(webauthn::WebAuthnAuthenticator),
}

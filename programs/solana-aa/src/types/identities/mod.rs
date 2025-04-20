use anchor_lang::prelude::*;

pub mod wallet;
pub mod webauthn;

#[derive(Debug, AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone)]
pub enum Identity {
    Wallet(wallet::WalletAuthenticator),
    WebAuthn(webauthn::WebAuthnAuthenticator),
}

impl Identity {
    pub fn byte_size(&self) -> usize {
        self.try_to_vec()
            .expect("Failed to serialize identity")
            .len()
    }
}

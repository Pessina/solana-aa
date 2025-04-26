use anchor_lang::prelude::*;

// use crate::traits::path::Path;

#[derive(Debug, AnchorDeserialize, AnchorSerialize, PartialEq, Eq, Clone)]
pub enum WalletType {
    Ethereum,
}

#[derive(Debug, AnchorDeserialize, AnchorSerialize, PartialEq, Eq, Clone)]
pub struct WalletAuthenticator {
    pub wallet_type: WalletType,
    pub compressed_public_key: [u8; 20],
}

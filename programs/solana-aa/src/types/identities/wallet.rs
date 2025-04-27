use anchor_lang::prelude::*;

// use crate::traits::path::Path;

#[derive(Debug, AnchorDeserialize, AnchorSerialize, PartialEq, Eq, Clone)]
pub enum WalletType {
    Ethereum([u8; 20]),
}

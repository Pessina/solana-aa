use anchor_lang::prelude::*;

// use crate::traits::path::Path;

#[derive(Debug, AnchorDeserialize, AnchorSerialize, PartialEq, Eq, Clone)]
pub enum WalletType {
    Ethereum,
}

#[derive(Debug, AnchorDeserialize, AnchorSerialize, PartialEq, Eq, Clone)]
pub struct WalletAuthenticator {
    pub wallet_type: WalletType,
    pub compressed_public_key: String,
}

// impl Path for WalletAuthenticator {
//     fn path(&self) -> String {
//         let path = match self.wallet_type {
//             WalletType::Ethereum => {
//                 let key = self
//                     .public_key
//                     .strip_prefix("0x")
//                     .unwrap_or(&self.public_key);

//                 if let Ok(public_key) = hex::decode(key) {
//                     let hash = near_sdk::env::keccak256(&public_key[1..]);
//                     let address = &hash[12..];
//                     format!("0x{}", hex::encode(address))
//                 } else {
//                     self.public_key.clone()
//                 }
//             }
//             WalletType::Solana => self.public_key.clone(),
//         };

//         format!("wallet/{}", path)
//     }
// }

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct WalletCredentials {
    pub signature: String,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct WalletValidationData {
    pub signature: String,
    pub message: String,
}

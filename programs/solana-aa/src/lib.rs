use anchor_lang::prelude::*;

mod contract;
// mod traits;
mod types;

use crate::contract::accounts::*;
use crate::contract::auth::secp256k1_keccak256::*;
use crate::contract::auth::secp256r1_sha256::*;
use crate::contract::transaction_buffer::*;
use crate::types::identities::*;

declare_id!("2PYNfKSoM7rFJeMuvEidASxgpdPAXYascVDmH6jpBa7o");

#[program]
pub mod solana_aa {

    use super::*;

    pub fn init_storage(
        ctx: Context<InitStorage>,
        data_id: [u8; 32],
        chunk_index: u16,
        total_chunks: u16,
        data_hash: [u8; 32],
        chunk_data: Vec<u8>,
    ) -> Result<()> {
        init_storage_impl(
            ctx,
            data_id,
            chunk_index,
            total_chunks,
            data_hash,
            chunk_data,
        )
    }

    pub fn store_chunk(
        ctx: Context<StoreChunk>,
        data_id: [u8; 32],
        chunk_index: u16,
        total_chunks: u16,
        data_hash: [u8; 32],
        chunk_data: Vec<u8>,
    ) -> Result<()> {
        store_chunk_impl(
            ctx,
            data_id,
            chunk_index,
            total_chunks,
            data_hash,
            chunk_data,
        )
    }

    pub fn retrieve_chunk(ctx: Context<RetrieveChunk>, chunk_index: u16) -> Result<Vec<u8>> {
        retrieve_chunk_impl(ctx, chunk_index)
    }

    pub fn get_data_metadata(ctx: Context<GetDataMetadata>) -> Result<DataMetadata> {
        get_data_metadata_impl(ctx)
    }

    pub fn close_storage(ctx: Context<CloseStorage>) -> Result<()> {
        close_storage_impl(ctx)
    }

    pub fn verify_eth(
        _ctx: Context<VerifyEthereumSignature>,
        signed_message: Vec<u8>,
        signer_compressed_public_key: String,
    ) -> Result<bool> {
        verify_secp256k1_keccak256_impl(&_ctx, signed_message, signer_compressed_public_key)
    }

    // TODO: Debug code
    pub fn get_eth_data(ctx: Context<VerifyEthereumSignature>) -> Result<(String, String)> {
        let (eth_address, message) = get_secp256k1_keccak256_data_impl(&ctx)?;

        msg!("ETH Address: {}", hex::encode(eth_address.clone()));
        msg!("Message: {}", String::from_utf8(message.clone()).unwrap());

        Ok((
            hex::encode(eth_address),
            String::from_utf8(message).unwrap(),
        ))
    }

    pub fn verify_webauthn(
        ctx: Context<VerifyWebauthnSignature>,
        signed_message: Vec<u8>,
        signer_compressed_public_key: String,
    ) -> Result<bool> {
        verify_secp256r1_sha256_impl(&ctx, signed_message, signer_compressed_public_key)
    }

    // TODO: Debug code
    pub fn get_webauthn_data(ctx: Context<VerifyWebauthnSignature>) -> Result<(String, String)> {
        let (pubkey_bytes, message_bytes) = get_secp256r1_sha256_data_impl(&ctx)?;

        msg!("Pubkey: {}", hex::encode(pubkey_bytes.clone()));
        msg!(
            "Message: {}",
            String::from_utf8(message_bytes.clone()).unwrap()
        );

        Ok((
            hex::encode(pubkey_bytes),
            String::from_utf8(message_bytes).unwrap(),
        ))
    }

    pub fn create_account(
        ctx: Context<CreateAccount>,
        account_id: String,
        identity_with_permissions: IdentityWithPermissions,
    ) -> Result<()> {
        create_account_impl(ctx, account_id, identity_with_permissions)
    }

    pub fn delete_account(ctx: Context<DeleteAccount>, account_id: String) -> Result<()> {
        delete_account_impl(ctx, account_id)
    }

    pub fn add_identity(
        ctx: Context<AddIdentity>,
        account_id: String,
        identity_with_permissions: IdentityWithPermissions,
    ) -> Result<()> {
        add_identity_impl(ctx, account_id, identity_with_permissions)
    }

    pub fn remove_identity(
        ctx: Context<RemoveIdentity>,
        account_id: String,
        identity: Identity,
    ) -> Result<()> {
        remove_identity_impl(ctx, account_id, identity)
    }
}

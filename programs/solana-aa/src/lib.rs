use anchor_lang::prelude::*;

mod contract;

use crate::contract::ethereum_auth::*;
use crate::contract::transaction_buffer::*;
use crate::contract::webauthn_auth::*;

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

    pub fn verify_ethereum_signature(
        _ctx: Context<VerifyEthereumSignature>,
        eth_data: WalletValidationData,
        compressed_public_key: String,
    ) -> Result<bool> {
        verify_ethereum_signature_impl(&_ctx, &eth_data, &compressed_public_key)
    }

    pub fn verify_webauthn_signature(
        ctx: Context<VerifyWebauthnSignature>,
        webauthn_data: WebauthnValidationData,
        compressed_public_key: String,
    ) -> Result<bool> {
        verify_webauthn_signature_impl(&ctx, &webauthn_data, compressed_public_key)
    }
}

use anchor_lang::prelude::*;

mod contract;
mod pda_seeds;
mod types;
mod utils;

use crate::contract::accounts::*;
use crate::contract::auth::ek256::*;
use crate::contract::auth::rsa::{rsa_multi_tx::*, rsa_native::*, utils::*};
use crate::contract::auth::secp256r1_sha256::*;
use crate::contract::contract_lifecycle::*;
use crate::contract::transaction::execute::*;
use crate::contract::transaction_buffer::*;
use crate::types::{
    account::{AbstractAccount, AbstractAccountOperationAccounts, AccountId},
    identity::*,
    transaction::transaction::Transaction,
};

declare_id!("2PYNfKSoM7rFJeMuvEidASxgpdPAXYascVDmH6jpBa7o");

#[program]
pub mod solana_aa {

    use super::*;

    pub fn init_contract(ctx: Context<InitContract>) -> Result<()> {
        init_contract_impl(ctx)
    }

    pub fn close_contract(_ctx: Context<CloseContract>) -> Result<()> {
        Ok(())
    }

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

    // TODO: Debug code
    pub fn verify_eth(
        ctx: Context<VerifyEthereumSignature>,
        signed_message: Vec<u8>,
        signer_compressed_public_key: String,
    ) -> Result<bool> {
        verify_ek256_impl(
            &ctx.accounts.instructions,
            signed_message,
            signer_compressed_public_key,
        )
    }

    // TODO: Debug code
    pub fn get_eth_data(ctx: Context<VerifyEthereumSignature>) -> Result<(String, Transaction)> {
        let (eth_address, message) = get_ek256_data_impl(&ctx.accounts.instructions)?;

        let transaction = Transaction::try_from_slice(&message).unwrap();

        Ok((hex::encode(eth_address), transaction))
    }

    pub fn verify_webauthn(
        ctx: Context<VerifyWebauthnSignature>,
        signed_message: Vec<u8>,
        signer_compressed_public_key: String,
    ) -> Result<bool> {
        verify_secp256r1_sha256_impl(&ctx, signed_message, signer_compressed_public_key)
    }

    // TODO: debug code
    pub fn get_webauthn_data(ctx: Context<VerifyWebauthnSignature>) -> Result<(String, String)> {
        let (pubkey_bytes, message_bytes) = get_secp256r1_sha256_data_impl(&ctx)?;

        Ok((
            hex::encode(pubkey_bytes),
            String::from_utf8(message_bytes).unwrap(),
        ))
    }

    pub fn verify_oidc_rsa_native(
        _ctx: Context<VerifyOidcRsaSignature>,
        verification_data: OidcVerificationData,
    ) -> Result<bool> {
        verify_oidc_native(&verification_data)
    }

    pub fn verify_oidc_rsa_crate(
        _ctx: Context<VerifyOidcRsaSignature>,
        verification_data: OidcVerificationData,
    ) -> Result<bool> {
        crate::contract::auth::rsa::rsa_rsa_crate::verify_oidc_rsa_crate(&verification_data)
    }

    pub fn init_rsa_verification_multi_tx(
        ctx: Context<InitRsaVerification>,
        verification_data: OidcVerificationData,
    ) -> Result<()> {
        init_rsa_verification(ctx, verification_data)
    }

    pub fn continue_rsa_verification_multi_tx(
        ctx: Context<ContinueRsaVerification>,
    ) -> Result<bool> {
        continue_rsa_verification(ctx)
    }

    pub fn finalize_rsa_verification_multi_tx(
        ctx: Context<FinalizeRsaVerification>,
        verification_data: OidcVerificationData,
    ) -> Result<bool> {
        finalize_rsa_verification(ctx, verification_data)
    }

    pub fn cleanup_rsa_verification_multi_tx(ctx: Context<CleanupRsaVerification>) -> Result<()> {
        cleanup_rsa_verification(ctx)
    }

    // Alternative RSA verification approach with simplified arithmetic
    pub fn init_rsa_verification_simple(
        ctx: Context<InitRsaVerification>,
        verification_data: OidcVerificationData,
    ) -> Result<()> {
        init_rsa_verification(ctx, verification_data)
    }

    pub fn continue_rsa_verification_simple(ctx: Context<ContinueRsaVerification>) -> Result<bool> {
        continue_rsa_verification(ctx)
    }

    pub fn finalize_rsa_verification_simple(
        ctx: Context<FinalizeRsaVerification>,
        verification_data: OidcVerificationData,
    ) -> Result<bool> {
        finalize_rsa_verification(ctx, verification_data)
    }

    pub fn cleanup_rsa_verification_simple(ctx: Context<CleanupRsaVerification>) -> Result<()> {
        cleanup_rsa_verification(ctx)
    }

    pub fn create_account(
        ctx: Context<CreateAbstractAccount>,
        identity_with_permissions: IdentityWithPermissions,
    ) -> Result<()> {
        create_account_impl(ctx, identity_with_permissions)
    }

    // TODO: Debug code, will be remove as those methods need to go through auth
    pub fn delete_account(ctx: Context<ExecuteEk256>, _account_id: AccountId) -> Result<()> {
        AbstractAccount::close_account(AbstractAccountOperationAccounts {
            abstract_account: &mut ctx.accounts.abstract_account,
            signer_info: ctx.accounts.signer.to_account_info(),
            system_program_info: ctx.accounts.system_program.to_account_info(),
        })
    }

    // TODO: Debug code, will be remove as those methods need to go through auth
    pub fn add_identity(
        ctx: Context<ExecuteEk256>,
        _account_id: AccountId,
        identity_with_permissions: IdentityWithPermissions,
    ) -> Result<()> {
        AbstractAccount::add_identity(
            AbstractAccountOperationAccounts {
                abstract_account: &mut ctx.accounts.abstract_account,
                signer_info: ctx.accounts.signer.to_account_info(),
                system_program_info: ctx.accounts.system_program.to_account_info(),
            },
            identity_with_permissions,
        )
    }

    // TODO: Debug code, will be remove as those methods need to go through auth
    pub fn remove_identity(
        ctx: Context<ExecuteEk256>,
        _account_id: AccountId,
        identity: Identity,
    ) -> Result<()> {
        AbstractAccount::remove_identity(
            AbstractAccountOperationAccounts {
                abstract_account: &mut ctx.accounts.abstract_account,
                signer_info: ctx.accounts.signer.to_account_info(),
                system_program_info: ctx.accounts.system_program.to_account_info(),
            },
            &identity,
        )
    }

    pub fn execute_ek256(ctx: Context<ExecuteEk256>, account_id: AccountId) -> Result<()> {
        execute_ek256_impl(ctx, account_id)
    }
}

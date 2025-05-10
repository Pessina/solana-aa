use std::str::FromStr;

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    self,
    pubkey::Pubkey,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};
use bytemuck::{Pod, Zeroable};
use hex;

pub fn verify_secp256r1_sha256_impl(
    ctx: &Context<VerifyWebauthnSignature>,
    signed_message: Vec<u8>,
    signer_compressed_public_key: String,
) -> Result<bool> {
    let (pubkey_bytes, message_bytes) = get_secp256r1_sha256_data_impl(&ctx)?;

    let expected_pubkey = hex::decode(&signer_compressed_public_key[2..])
        .map_err(|_| ErrorCode::InvalidHexEncoding)?;

    if pubkey_bytes != expected_pubkey.as_slice() {
        return Err(ErrorCode::PublicKeyMismatch.into());
    }

    if message_bytes.len() != signed_message.len() {
        return Err(ErrorCode::SignedDataMismatch.into());
    }

    if message_bytes != signed_message.as_slice() {
        return Err(ErrorCode::SignedDataMismatch.into());
    }

    Ok(true)
}

pub fn get_secp256r1_sha256_data_impl(
    ctx: &Context<VerifyWebauthnSignature>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let instructions_sysvar = &ctx.accounts.instructions;

    let current_index = load_current_index_checked(instructions_sysvar)?;
    if current_index < 1 {
        return Err(ErrorCode::MissingVerificationInstruction.into());
    }

    let verification_instruction =
        load_instruction_at_checked((current_index - 1) as usize, instructions_sysvar)?;

    let secp256r1_program_id =
        Pubkey::from_str("Secp256r1SigVerify1111111111111111111111111").unwrap();
    if verification_instruction.program_id != secp256r1_program_id {
        return Err(ErrorCode::InvalidVerificationInstruction.into());
    }

    let data = &verification_instruction.data;
    if data.len() < 2 {
        return Err(ErrorCode::InvalidInstructionData.into());
    }

    let num_signatures = data[0] as usize;
    if num_signatures != 1 {
        return Err(ErrorCode::MultipleSignaturesNotSupported.into());
    }

    let offsets_start = 2;
    let offsets_end = offsets_start + 14;
    if data.len() < offsets_end {
        return Err(ErrorCode::InvalidInstructionData.into());
    }
    let offsets_data = &data[offsets_start..offsets_end];

    let offsets: &Secp256r1SignatureOffsets =
        bytemuck::try_from_bytes(offsets_data).map_err(|_| ErrorCode::InvalidOffsets)?;

    if offsets.signature_instruction_index != u16::MAX
        || offsets.public_key_instruction_index != u16::MAX
        || offsets.message_instruction_index != u16::MAX
    {
        return Err(ErrorCode::DataInOtherInstructionsNotSupported.into());
    }

    let pubkey_start = offsets.public_key_offset as usize;
    let pubkey_end = pubkey_start + 33;
    if pubkey_end > data.len() {
        return Err(ErrorCode::InvalidOffsets.into());
    }
    let pubkey_bytes = &data[pubkey_start..pubkey_end];

    let message_start = offsets.message_data_offset as usize;
    let message_end = message_start + offsets.message_data_size as usize;
    if message_end > data.len() {
        return Err(ErrorCode::InvalidOffsets.into());
    }
    let message_bytes = &data[message_start..message_end];

    Ok((pubkey_bytes.to_vec(), message_bytes.to_vec()))
}

#[derive(Accounts)]
pub struct VerifyWebauthnSignature<'info> {
    /// CHECK: This is a system account
    #[account(address = solana_program::sysvar::instructions::id())]
    pub instructions: AccountInfo<'info>,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct Secp256r1SignatureOffsets {
    signature_offset: u16,
    signature_instruction_index: u16,
    public_key_offset: u16,
    public_key_instruction_index: u16,
    message_data_offset: u16,
    message_data_size: u16,
    message_instruction_index: u16,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Missing secp256r1 verification instruction")]
    MissingVerificationInstruction,
    #[msg("Invalid verification instruction program ID")]
    InvalidVerificationInstruction,
    #[msg("Invalid instruction data format")]
    InvalidInstructionData,
    #[msg("Multiple signatures not supported")]
    MultipleSignaturesNotSupported,
    #[msg("Invalid offsets in instruction data")]
    InvalidOffsets,
    #[msg("Data in other instructions not supported")]
    DataInOtherInstructionsNotSupported,
    #[msg("Invalid hex encoding")]
    InvalidHexEncoding,
    #[msg("Public key mismatch")]
    PublicKeyMismatch,
    #[msg("Signed data mismatch")]
    SignedDataMismatch,
}

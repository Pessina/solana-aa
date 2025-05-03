use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    self, secp256k1_program,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};

/*
    Utility methods to interact with the secp256k1 keccak256 pre-compiled program from Solana

    Reference:

       - https://docs.rs/solana-secp256k1-program/latest/solana_secp256k1_program/
       - https://solana.com/docs/core/programs

    ek256 stands for secp256k1 keccak256
*/

/// Verifies a secp256k1 signature using the Solana precompiled program
/// and returns the Ethereum address (in hex format) and the message (as UTF-8 JSON)
///
/// This function extracts the signature, Ethereum address, and message from the
/// secp256k1 program instruction and verifies that the signature is valid.
///
/// # Arguments
///
/// * `ctx` - The context containing the instructions account
///
/// # Returns
///
/// A tuple containing:
/// - The Ethereum address as a hex string with "0x" prefix
/// - The message as a UTF-8 decoded string
///
/// # Errors
///
/// Returns an error if:
/// - The verification instruction is missing or invalid
/// - The instruction data format is invalid
/// - The signature verification fails
pub fn get_ek256_data_impl(instructions_sysvar: &AccountInfo<'_>) -> Result<(Vec<u8>, Vec<u8>)> {
    let current_index = load_current_index_checked(instructions_sysvar)? as usize;
    if current_index < 1 {
        return Err(ErrorCode::MissingVerificationInstruction.into());
    }

    let secp_index = current_index - 1;
    let secp_instruction = load_instruction_at_checked(secp_index, instructions_sysvar)?;
    if secp_instruction.program_id != secp256k1_program::id() {
        return Err(ErrorCode::InvalidVerificationInstruction.into());
    }

    let data = &secp_instruction.data;
    if data.is_empty() {
        return Err(ErrorCode::InvalidInstructionData.into());
    }

    let num_signatures = data[0] as usize;
    if num_signatures != 1 {
        return Err(ErrorCode::MultipleSignaturesNotSupported.into());
    }

    let offsets_start = 1;
    let offsets_end = offsets_start + 11;
    if data.len() < offsets_end {
        return Err(ErrorCode::InvalidInstructionData.into());
    }
    let offsets_data = &data[offsets_start..offsets_end];
    let offsets = Secp256k1SignatureOffsets::from_bytes(offsets_data)?;

    if offsets.signature_instruction_index as usize != secp_index
        || offsets.eth_address_instruction_index as usize != secp_index
        || offsets.message_instruction_index as usize != secp_index
    {
        return Err(ErrorCode::DataInOtherInstructionsNotSupported.into());
    }

    let eth_address_start = offsets.eth_address_offset as usize;
    let eth_address_end = eth_address_start + 20;
    if eth_address_end > data.len() {
        return Err(ErrorCode::InvalidOffsets.into());
    }
    let eth_address = &data[eth_address_start..eth_address_end];

    let message_start = offsets.message_data_offset as usize;
    let message_end = message_start + offsets.message_data_size as usize;
    if message_end > data.len() {
        return Err(ErrorCode::InvalidMessageSize.into());
    }
    let message = &data[message_start..message_end];

    Ok((eth_address.to_vec(), message.to_vec()))
}

// TODO: Debug code
pub fn verify_ek256_impl(
    instructions_sysvar: &AccountInfo<'_>,
    signed_message: Vec<u8>,
    signer_eth_address: String,
) -> Result<bool> {
    let (eth_address, message) = get_ek256_data_impl(instructions_sysvar)?;

    let expected_eth_address =
        hex::decode(&signer_eth_address[2..]).map_err(|_| ErrorCode::InvalidHexEncoding)?;
    if expected_eth_address.len() != 20 {
        return Err(ErrorCode::InvalidAddressLength.into());
    }

    if eth_address != expected_eth_address.as_slice() {
        return Err(ErrorCode::AddressMismatch.into());
    }

    if message != signed_message.as_slice() {
        return Err(ErrorCode::MessageMismatch.into());
    }

    Ok(true)
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Secp256k1SignatureOffsets {
    pub signature_offset: u16,
    pub signature_instruction_index: u8,
    pub eth_address_offset: u16,
    pub eth_address_instruction_index: u8,
    pub message_data_offset: u16,
    pub message_data_size: u16,
    pub message_instruction_index: u8,
}

impl Secp256k1SignatureOffsets {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 11 {
            return Err(ErrorCode::InvalidInstructionData.into());
        }
        Ok(Self {
            signature_offset: u16::from_le_bytes([data[0], data[1]]),
            signature_instruction_index: data[2],
            eth_address_offset: u16::from_le_bytes([data[3], data[4]]),
            eth_address_instruction_index: data[5],
            message_data_offset: u16::from_le_bytes([data[6], data[7]]),
            message_data_size: u16::from_le_bytes([data[8], data[9]]),
            message_instruction_index: data[10],
        })
    }
}
#[derive(Accounts)]
pub struct VerifyEthereumSignature<'info> {
    /// CHECK: Instructions sysvar, verified by address
    #[account(address = solana_program::sysvar::instructions::id())]
    pub instructions: AccountInfo<'info>,
}

// Custom error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Missing secp256k1 verification instruction")]
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
    #[msg("Invalid address length")]
    InvalidAddressLength,
    #[msg("Ethereum address mismatch")]
    AddressMismatch,
    #[msg("Message mismatch")]
    MessageMismatch,
    #[msg("Invalid message size")]
    InvalidMessageSize,
}

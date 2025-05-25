use super::constants::*;
use anchor_lang::prelude::*;

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct OidcVerificationData {
    /// SHA-256 hash of signing input (header.payload)
    pub signing_input_hash: [u8; 32],
    /// RSA signature bytes (256 bytes for 2048-bit keys)
    pub signature: Vec<u8>,
    /// OIDC provider (Google, etc.)
    pub provider: OidcProvider,
    /// Key index for provider's key array
    pub key_index: u8,
}

impl OidcVerificationData {
    /// Validates the verification data structure for security
    pub fn validate(&self) -> Result<()> {
        if self.signature.is_empty() {
            return Err(error!(ErrorCode::InvalidSignatureFormat));
        }

        // Validate signature length for 2048-bit RSA
        if self.signature.len() != RSA_2048_SIGNATURE_LENGTH {
            return Err(error!(ErrorCode::InvalidSignatureLength));
        }

        // Validate key index
        let max_key_index = match self.provider {
            OidcProvider::Google => GOOGLE_RSA_PUBLIC_KEYS.len() as u8,
        };

        if self.key_index >= max_key_index {
            return Err(error!(ErrorCode::InvalidKeyIndex));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub enum OidcProvider {
    Google,
}

/// Validates PKCS#1 v1.5 padding structure
pub fn validate_pkcs1_padding(decrypted_signature: &[u8]) -> Result<&[u8]> {
    // PKCS#1 v1.5 padding validation
    if decrypted_signature.len() != RSA_2048_SIGNATURE_LENGTH {
        return Err(error!(ErrorCode::InvalidSignatureLength));
    }

    // Validate structure: 0x00 0x01 [padding] 0x00 [DigestInfo]
    if decrypted_signature[0] != 0x00 || decrypted_signature[1] != 0x01 {
        return Err(error!(ErrorCode::InvalidSignatureFormat));
    }

    // Find separator after padding
    let separator_pos = decrypted_signature.iter().skip(2).position(|&x| x == 0x00);
    if separator_pos.is_none() {
        return Err(error!(ErrorCode::InvalidSignatureFormat));
    }

    let separator_index = separator_pos.unwrap() + 2;

    // Verify padding bytes are 0xFF
    let padding = &decrypted_signature[2..separator_index];
    if padding.is_empty() || !padding.iter().all(|&x| x == 0xFF) {
        return Err(error!(ErrorCode::InvalidSignatureFormat));
    }

    // Extract DigestInfo + hash
    let digest_info = &decrypted_signature[separator_index + 1..];

    // Validate DigestInfo for SHA-256 (51 bytes total)
    if digest_info.len() != FULL_DIGEST_INFO_LENGTH {
        return Err(error!(ErrorCode::InvalidSignatureFormat));
    }

    // Verify DigestInfo structure
    if &digest_info[..SHA256_DIGEST_INFO_LENGTH] != SHA256_DIGEST_INFO {
        return Err(error!(ErrorCode::InvalidSignatureFormat));
    }

    // Return the extracted hash
    Ok(&digest_info[SHA256_DIGEST_INFO_LENGTH..FULL_DIGEST_INFO_LENGTH])
}

/// Constant-time hash comparison
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut matches = true;
    for i in 0..a.len() {
        if a[i] != b[i] {
            matches = false;
        }
    }
    matches
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid signature format")]
    InvalidSignatureFormat,
    #[msg("Invalid signature length")]
    InvalidSignatureLength,
    #[msg("Invalid key index")]
    InvalidKeyIndex,
    #[msg("Invalid DER encoding")]
    InvalidDerEncoding,
    #[msg("Invalid modulus")]
    InvalidModulus,
    #[msg("Modpow operation not complete")]
    ModpowNotComplete,
    #[msg("Verification data mismatch")]
    VerificationDataMismatch,
}

#[derive(Accounts)]
pub struct VerifyOidcRsaSignature {}

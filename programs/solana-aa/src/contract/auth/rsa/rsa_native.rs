use anchor_lang::prelude::*;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;

// Import Solana native big modular exponentiation
// Note: This is not enabled on mainnet/devnet, tracking: https://github.com/solana-labs/solana/pull/32520, https://solana.stackexchange.com/questions/22276/when-the-big-mod-exp-syscall-will-be-enabled
use anchor_lang::solana_program::big_mod_exp::big_mod_exp;

use super::constants::*;
use super::utils::{
    constant_time_compare, validate_pkcs1_padding, OidcProvider, OidcVerificationData,
};

/// OIDC RSA verification using Solana native big_mod_exp syscall
pub fn verify_oidc_native(verification_data: &OidcVerificationData) -> Result<bool> {
    verification_data.validate()?;

    // Get public key based on provider and key index
    let public_key_der = match verification_data.provider {
        OidcProvider::Google => GOOGLE_RSA_PUBLIC_KEYS[verification_data.key_index as usize],
    };

    // Parse DER-encoded public key
    let public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
        .map_err(|_| error!(ErrorCode::InvalidDerEncoding))?;

    // Extract RSA components
    let modulus_bytes = public_key.n().to_bytes_be();
    let exponent_bytes = public_key.e().to_bytes_be();

    // Perform RSA verification using syscall: signature^exponent mod modulus
    let decrypted_signature = big_mod_exp(
        &verification_data.signature,
        &exponent_bytes,
        &modulus_bytes,
    );

    // Validate PKCS#1 v1.5 padding and extract hash
    let extracted_hash = validate_pkcs1_padding(&decrypted_signature)?;

    // Constant-time hash comparison
    let verification_result =
        constant_time_compare(extracted_hash, &verification_data.signing_input_hash);

    Ok(verification_result)
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid DER encoding")]
    InvalidDerEncoding,
}

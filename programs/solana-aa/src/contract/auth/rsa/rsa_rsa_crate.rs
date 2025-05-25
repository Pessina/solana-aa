use anchor_lang::prelude::*;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::BigUint;
use rsa::RsaPublicKey;

use super::constants::*;
use super::utils::{
    constant_time_compare, validate_pkcs1_padding, ErrorCode, OidcProvider, OidcVerificationData,
};

/// OIDC RSA verification using RSA crate's BigUint
/// Fallback implementation for environments without syscall support
pub fn verify_oidc_rsa_crate(verification_data: &OidcVerificationData) -> Result<bool> {
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

    // Perform RSA verification using BigUint: signature^exponent mod modulus
    let decrypted_signature = rsa_modpow(
        &verification_data.signature,
        &exponent_bytes,
        &modulus_bytes,
    )?;

    // Validate PKCS#1 v1.5 padding and extract hash
    let extracted_hash = validate_pkcs1_padding(&decrypted_signature)?;

    // Constant-time hash comparison
    let verification_result =
        constant_time_compare(extracted_hash, &verification_data.signing_input_hash);

    Ok(verification_result)
}

/// RSA modular exponentiation using BigUint
/// Implements: base^exponent mod modulus
fn rsa_modpow(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    let modulus_len = modulus.len();

    // Convert bytes to BigUint
    let base_bigint = BigUint::from_bytes_be(base);
    let exponent_bigint = BigUint::from_bytes_be(exponent);
    let modulus_bigint = BigUint::from_bytes_be(modulus);

    // Validate modulus is not zero or one
    if modulus_bigint == BigUint::from(0u32) || modulus_bigint == BigUint::from(1u32) {
        return Err(error!(ErrorCode::InvalidModulus));
    }

    // Perform modular exponentiation
    let result = base_bigint.modpow(&exponent_bigint, &modulus_bigint);

    // Convert back to bytes with proper padding
    let result_bytes = result.to_bytes_be();
    let mut padded_result = vec![0u8; modulus_len.saturating_sub(result_bytes.len())];
    padded_result.extend(result_bytes);

    Ok(padded_result)
}

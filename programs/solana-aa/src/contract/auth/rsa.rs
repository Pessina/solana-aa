use anchor_lang::prelude::*;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::SignatureScheme;
use rsa::{pkcs1v15::Pkcs1v15Sign, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};

// Ring implementation kept for experimentation (commented out)
// use ring::signature;

// Google's actual RSA public keys from JWKS endpoint (DER format)
// Converted from Google's JWKS endpoint: https://www.googleapis.com/oauth2/v3/certs
// These keys are in PKCS#1 DER format as required by Ring
// Keys obtained on: [current date - these should be updated periodically]

// Key 1: kid=89ce3598c473af1bda4bff95e6c8736450206fba
const GOOGLE_RSA_PUBLIC_KEY_1: &[u8] = &[
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc2, 0xf2, 0xd4, 0x9b, 0x20, 0x25, 0x46,
    0x12, 0x64, 0x16, 0x0a, 0x24, 0xf7, 0xba, 0xe8, 0x8e, 0xd8, 0x34, 0xc6, 0x4a, 0xac, 0x43, 0xa0,
    0x8f, 0x3e, 0x8a, 0x91, 0x51, 0x25, 0xc3, 0x21, 0x87, 0x23, 0x7d, 0x55, 0x8c, 0xcb, 0x56, 0x78,
    0x86, 0x4f, 0xfe, 0xf7, 0x46, 0x39, 0xe7, 0x82, 0x93, 0xb8, 0x00, 0xdf, 0x4f, 0xfd, 0x05, 0x03,
    0x8e, 0x85, 0x59, 0xbf, 0xa9, 0xaf, 0x84, 0x9c, 0x9b, 0x4d, 0x20, 0x07, 0x70, 0xa7, 0x33, 0xcc,
    0x06, 0x2d, 0x98, 0x9a, 0x51, 0xe0, 0xd4, 0x3a, 0xef, 0x38, 0xfd, 0x98, 0xe1, 0xf9, 0x83, 0xd5,
    0x02, 0xe6, 0xba, 0x87, 0x3e, 0x95, 0x15, 0xae, 0xdc, 0xa4, 0xe5, 0x0e, 0x43, 0x96, 0x42, 0xc4,
    0x29, 0x04, 0x40, 0xc8, 0xed, 0xae, 0x67, 0xa2, 0xdb, 0x56, 0xba, 0x8a, 0x3c, 0xb9, 0x2d, 0x2d,
    0x67, 0xf5, 0xf7, 0x62, 0x52, 0xc8, 0xce, 0xb9, 0x85, 0x99, 0x4a, 0x82, 0x10, 0x09, 0x48, 0xf9,
    0xa3, 0x0e, 0x63, 0xd9, 0xab, 0x2a, 0x61, 0x82, 0xd1, 0x7e, 0x9d, 0x0e, 0x7b, 0x29, 0x98, 0x7f,
    0xab, 0xe7, 0xb6, 0xd6, 0x30, 0xcf, 0x78, 0xd2, 0xe7, 0x85, 0xde, 0xee, 0xd6, 0x07, 0x5b, 0x66,
    0x49, 0xfc, 0x32, 0xc2, 0x8d, 0xae, 0xa6, 0xcf, 0xef, 0x47, 0xcc, 0x87, 0x09, 0x1f, 0x94, 0xe6,
    0xbf, 0x9b, 0x50, 0x46, 0x10, 0x14, 0xb3, 0x76, 0xa8, 0x3c, 0xaa, 0x02, 0x43, 0xc7, 0x1e, 0x0c,
    0x73, 0x1b, 0x94, 0x35, 0xcd, 0x57, 0x68, 0x41, 0xa6, 0x4b, 0xfd, 0x07, 0xa3, 0xe4, 0xe5, 0x05,
    0x64, 0xa0, 0x34, 0xf2, 0x12, 0xce, 0xe5, 0x6c, 0xf6, 0xa0, 0x59, 0x0d, 0x6e, 0xcf, 0xa6, 0xdd,
    0x93, 0x13, 0x3e, 0x0e, 0x78, 0xdc, 0x31, 0x42, 0x76, 0x9e, 0x1f, 0x34, 0x47, 0xf0, 0xdc, 0x6e,
    0x1c, 0xaa, 0x90, 0xae, 0x1c, 0xac, 0xda, 0xcc, 0xd7, 0x02, 0x03, 0x01, 0x00, 0x01,
];

// Key 2: kid=dd125d5f462fbc6014aedab81ddf3bcedab70847
const GOOGLE_RSA_PUBLIC_KEY_2: &[u8] = &[
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x8f, 0x0b, 0x2d, 0xa8, 0x8e, 0x30, 0xd9,
    0xda, 0xea, 0x6d, 0x34, 0xd5, 0x44, 0x3a, 0xe2, 0x16, 0xa7, 0xa9, 0xc1, 0x55, 0x48, 0xd7, 0x2d,
    0x39, 0x0f, 0x94, 0xd9, 0x0a, 0x61, 0xaf, 0x80, 0xc2, 0xb9, 0x87, 0x23, 0xac, 0x55, 0x6d, 0x2d,
    0x05, 0x18, 0x98, 0xf4, 0x99, 0x3d, 0x1c, 0xa0, 0xd1, 0xb9, 0xed, 0xef, 0x75, 0x78, 0x8c, 0x81,
    0xaa, 0xf0, 0xa9, 0x91, 0x03, 0x3b, 0x23, 0x80, 0xd2, 0xba, 0x56, 0x87, 0xe3, 0x3b, 0xe9, 0xe6,
    0xae, 0x16, 0x14, 0x65, 0xf6, 0x54, 0xd7, 0x77, 0x98, 0x24, 0x5f, 0x4a, 0x29, 0xc2, 0x1d, 0xbe,
    0x75, 0x4d, 0x63, 0xe9, 0x4b, 0x1d, 0x5a, 0x63, 0x1a, 0xe4, 0xea, 0x55, 0x98, 0xfb, 0x6a, 0x5e,
    0x5e, 0x28, 0xad, 0x8a, 0xf6, 0xff, 0x78, 0x80, 0xc4, 0xc3, 0xa1, 0x1d, 0x9f, 0xef, 0xb9, 0x37,
    0x83, 0xd0, 0xa1, 0x9e, 0x02, 0x06, 0xde, 0x69, 0xbe, 0xff, 0xe2, 0x28, 0xf2, 0x2d, 0xe2, 0x7e,
    0x6b, 0xc5, 0x26, 0x58, 0xf5, 0x64, 0x82, 0x59, 0xcd, 0x6f, 0x92, 0x66, 0x1b, 0xc4, 0xe8, 0xef,
    0xbb, 0x52, 0x5c, 0x67, 0x0f, 0xa4, 0x17, 0x00, 0x16, 0x97, 0x48, 0xfe, 0x37, 0xed, 0x09, 0x6a,
    0xfa, 0xe5, 0xe2, 0xf5, 0xbe, 0x60, 0x24, 0x3c, 0xd2, 0x60, 0x51, 0x38, 0x08, 0xe2, 0xc1, 0xae,
    0x9f, 0x36, 0xb2, 0x6d, 0xff, 0x7c, 0x2d, 0x2b, 0xff, 0xc3, 0x82, 0x04, 0x05, 0xcd, 0xfe, 0x9d,
    0x8e, 0x46, 0x7c, 0xbf, 0xa6, 0x8c, 0xf4, 0x6a, 0x54, 0x24, 0x4b, 0x52, 0xd6, 0xe1, 0x1c, 0xef,
    0xf9, 0x01, 0x80, 0xe9, 0xa8, 0x68, 0xfa, 0xce, 0x42, 0xab, 0x78, 0x9f, 0x7e, 0x2a, 0xca, 0x10,
    0x50, 0xfe, 0x91, 0xac, 0x05, 0x71, 0x90, 0xdb, 0x8e, 0x1d, 0x5f, 0x60, 0xd4, 0x6f, 0x82, 0x1e,
    0x28, 0x4a, 0xb3, 0x20, 0x22, 0x7f, 0x13, 0x4d, 0xd9, 0x02, 0x03, 0x01, 0x00, 0x01,
];

// Array of all Google public keys for key rotation support
const GOOGLE_RSA_PUBLIC_KEYS: &[&[u8]] = &[GOOGLE_RSA_PUBLIC_KEY_1, GOOGLE_RSA_PUBLIC_KEY_2];

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub enum RsaAlgorithm {
    RS256,
    RS384,
    RS512,
}

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub enum OidcProvider {
    Google,
}

/// Compact verification data structure for maximum efficiency
/// All data should be pre-processed off-chain to minimize transaction size and compute costs
///
/// # Transaction Size Optimization:
/// This struct is designed to minimize serialized size when sent to Solana:
/// - Uses Vec<u8> for binary data (more efficient than String)
/// - Enums use minimal representation
/// - No redundant fields or metadata
///
/// # Example off-chain preprocessing (TypeScript/JavaScript):
/// ```typescript
/// import { createHash } from 'crypto';
/// import * as base64url from 'base64url';
///
/// function prepareOidcVerification(jwtToken: string): OidcVerificationData {
///   const [header, payload, signature] = jwtToken.split('.');
///   
///   // Decode header to extract algorithm and key ID
///   const headerData = JSON.parse(base64url.decode(header));
///   const algorithm = headerData.alg; // e.g., "RS256"
///   const kid = headerData.kid; // Key ID for selecting the right public key
///   
///   // Decode payload to extract issuer  
///   const payloadData = JSON.parse(base64url.decode(payload));
///   const issuer = payloadData.iss; // e.g., "https://accounts.google.com"
///   
///   // Determine key index from kid (requires mapping kid to array index)
///   const keyIndex = getKeyIndexFromKid(kid, issuer); // Custom function
///   
///   // Construct signing input
///   const signingInput = Buffer.from(`${header}.${payload}`, 'utf8');
///   
///   // Decode signature
///   const signatureBytes = base64url.toBuffer(signature);
///   
///   return {
///     signing_input: Array.from(signingInput),
///     signature: Array.from(signatureBytes),
///     provider: issuer.includes('google') ? 'Google' : 'Microsoft',
///     algorithm: algorithm.replace('RS', 'RS'), // RS256 -> RS256
///     key_index: keyIndex
///   };
/// }
/// ```
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct OidcVerificationData {
    /// SHA-256 hash of the signing input (header.payload) - processed off-chain
    /// This reduces transaction size while maintaining security
    /// The hash is verified against the decrypted signature
    pub signing_input_hash: [u8; 32],

    /// Pre-decoded signature bytes (raw signature, not base64) - processed off-chain  
    /// Must be exactly 256 bytes for 2048-bit RSA keys
    pub signature: Vec<u8>,

    /// OIDC provider identifier - determined off-chain from issuer claim
    /// Used to select the appropriate public key array for verification
    pub provider: OidcProvider,

    /// RSA algorithm identifier - extracted off-chain from JWT header alg field
    /// Determines which hash algorithm is used (SHA256, SHA384, SHA512)
    pub algorithm: RsaAlgorithm,

    /// Key index - specifies which public key to use from the provider's key array
    /// Must be determined off-chain from JWT header kid field or by trying keys
    /// This eliminates the need for on-chain key rotation loops
    pub key_index: u8,
}

impl OidcVerificationData {
    /// Validates the verification data structure for security
    pub fn validate(&self) -> Result<()> {
        // Hash validation is implicit - it's always 32 bytes
        // No additional validation needed for the hash

        if self.signature.is_empty() {
            return Err(error!(ErrorCode::InvalidSignatureFormat));
        }

        // Validate signature length based on algorithm (security check)
        let expected_sig_len = match self.algorithm {
            RsaAlgorithm::RS256 | RsaAlgorithm::RS384 | RsaAlgorithm::RS512 => 256, // 2048-bit RSA = 256 bytes
        };

        if self.signature.len() != expected_sig_len {
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

/// OPTIMIZED OIDC RSA verification - accepts compact pre-processed data
/// This is the most efficient way to verify OIDC tokens on Solana
///
/// # Performance Benefits:
/// - Minimal transaction size (only essential verification data)
/// - No string parsing on-chain
/// - No base64 decoding on-chain
/// - No JSON parsing on-chain
/// - Optimized compute unit usage
///
/// # Security Critical (on-chain):
/// - RSA signature verification using ring crate
/// - Public key selection based on provider
/// - Algorithm validation
/// - Signature length validation
///
/// # Off-chain preprocessing required:
/// 1. Parse JWT token (header.payload.signature)
/// 2. Validate JWT format and structure
/// 3. Base64url decode signature
/// 4. Extract algorithm from header.alg field
/// 5. Extract key ID (kid) from header and map to array index
/// 6. Determine provider from payload.iss claim
/// 7. Construct signing input as bytes (header + "." + payload)
/// 8. Package into OidcVerificationData struct
/// 9. Validate expiration and other non-cryptographic claims
pub fn verify_oidc_compact(verification_data: &OidcVerificationData) -> Result<bool> {
    // Validate input data for security
    verification_data.validate()?;

    // Get the specific public key based on provider and key index (security critical - must be on-chain)
    let public_key_der = match verification_data.provider {
        OidcProvider::Google => GOOGLE_RSA_PUBLIC_KEYS[verification_data.key_index as usize],
    };

    // Parse the DER-encoded public key
    let public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
        .map_err(|_| error!(ErrorCode::InvalidDerEncoding))?;

    // Create the appropriate signature scheme based on algorithm
    let scheme = match verification_data.algorithm {
        RsaAlgorithm::RS256 => Pkcs1v15Sign::new::<Sha256>(),
        RsaAlgorithm::RS384 => Pkcs1v15Sign::new::<Sha384>(),
        RsaAlgorithm::RS512 => Pkcs1v15Sign::new::<Sha512>(),
    };

    // Verify the signature against the provided hash
    // The hash represents the original signing input (header.payload)
    match scheme.verify(
        &public_key,
        &verification_data.signing_input_hash,
        &verification_data.signature,
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[derive(Accounts)]
pub struct VerifyOidcRsaSignature<'info> {
    // For RSA OIDC verification, we don't need any special accounts
    // since all verification is done on-chain using hardcoded public keys
    pub signer: Signer<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid signature format")]
    InvalidSignatureFormat,
    #[msg("Invalid signing input")]
    InvalidSigningInput,
    #[msg("Invalid signature length")]
    InvalidSignatureLength,
    #[msg("Invalid key index")]
    InvalidKeyIndex,
    #[msg("Signature verification failed")]
    SignatureVerificationFailed,
    #[msg("Invalid DER encoding")]
    InvalidDerEncoding,
}

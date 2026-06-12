//! ZK guest program: verifies an RS256-signed JWT and commits privacy-preserving
//! facts about it as public outputs.
//!
//! The program fails closed — any invalid input (bad DER, bad signature, missing
//! claims) panics, so a proof can only exist for a JWT whose signature verifies
//! against the provided public key. Policy decisions (trusted issuer keys, identity
//! membership, transaction binding) belong to the on-chain program.
//!
//! RSA and SHA-256 use SP1's precompile-accelerated forks (see [patch.crates-io]
//! in Cargo.toml), turning the dominant bigint/hash work into syscalls.

#![no_main]
sp1_zkvm::entrypoint!(main);

use base64::Engine;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField32};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_primitives::poseidon2_hash;

/// Public outputs committed by this guest program.
///
/// MUST stay field-for-field compatible (bincode order) with `PublicOutputs`
/// in `programs/solana-aa/src/contract/auth/zk_oidc.rs`. The golden fixture
/// test in `tests/zk-oidc.spec.ts` catches drift. Hashes are committed as
/// plain bytes so the on-chain program needs no SP1 field-type dependencies.
#[derive(Serialize, Deserialize, Debug)]
pub struct PublicOutputs {
    pub email_hash: [u8; 32],
    pub pk_hash: [u8; 32],
    pub iss: String,
    pub aud: String,
    pub nonce: String,
}

pub fn main() {
    let pk_der = sp1_zkvm::io::read::<Vec<u8>>();
    let jwt_header = sp1_zkvm::io::read::<Vec<u8>>();
    let jwt_payload = sp1_zkvm::io::read::<Vec<u8>>();
    let signature = sp1_zkvm::io::read::<Vec<u8>>();

    let public_key = RsaPublicKey::from_public_key_der(&pk_der).expect("invalid public key DER");

    // JWT signing input: base64url(header) || '.' || base64url(payload)
    let mut signing_input = jwt_header;
    signing_input.push(b'.');
    signing_input.extend_from_slice(&jwt_payload);

    let hashed_msg = Sha256::digest(&signing_input);

    public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_msg, &signature)
        .expect("RSA signature verification failed");

    let claims = extract_claims(&jwt_payload).expect("invalid JWT claims");

    sp1_zkvm::io::commit(&PublicOutputs {
        email_hash: poseidon_hash_bytes(claims.email.as_bytes()),
        pk_hash: poseidon_hash_bytes(&pk_der),
        iss: claims.iss,
        aud: claims.aud,
        nonce: claims.nonce,
    });
}

struct Claims {
    iss: String,
    aud: String,
    email: String,
    nonce: String,
}

fn extract_claims(jwt_payload: &[u8]) -> Result<Claims, &'static str> {
    let payload_b64 = core::str::from_utf8(jwt_payload).map_err(|_| "payload not UTF-8")?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "payload base64 decode failed")?;
    let json: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| "payload not valid JSON")?;

    let get = |key: &str| -> Result<String, &'static str> {
        json[key]
            .as_str()
            .map(str::to_string)
            .ok_or("missing claim")
    };

    Ok(Claims {
        iss: get("iss")?,
        aud: get("aud")?,
        email: get("email")?,
        nonce: get("nonce")?,
    })
}

/// Poseidon2 hash over bytes, returned as 32 plain bytes.
///
/// Bytes are packed 3 per field element so every packed value (< 2^24) is
/// strictly below the 31-bit field modulus — no modular aliasing between
/// distinct inputs. The 8 output elements are emitted as canonical u32 LE.
fn poseidon_hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut field_elements = Vec::with_capacity(data.len().div_ceil(3));
    for chunk in data.chunks(3) {
        let mut value = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u32) << (i * 8);
        }
        field_elements.push(BabyBear::from_canonical_u32(value));
    }

    let hash = poseidon2_hash(field_elements);

    let mut bytes = [0u8; 32];
    for (i, elem) in hash.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&elem.as_canonical_u32().to_le_bytes());
    }
    bytes
}

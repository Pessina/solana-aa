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
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Public outputs committed by this guest program.
///
/// MUST stay field-for-field compatible (bincode order) with `PublicOutputs`
/// in `programs/solana-aa/src/contract/auth/zk_oidc.rs`. The golden fixture
/// test in `tests/zk-oidc.spec.ts` catches drift.
///
/// `email_hash` and `pk_hash` are sha256: the precompile makes it ~100x
/// cheaper in-guest than Poseidon2 (which has no precompile), and any
/// external tooling can recompute it (e.g. a JWKS updater hashing key DERs).
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

    let email_hash: [u8; 32] = Sha256::digest(claims.email.as_bytes()).into();
    let pk_hash: [u8; 32] = Sha256::digest(&pk_der).into();

    sp1_zkvm::io::commit(&PublicOutputs {
        email_hash,
        pk_hash,
        iss: claims.iss,
        aud: claims.aud,
        nonce: claims.nonce,
    });
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    email: String,
    nonce: String,
}

fn extract_claims(jwt_payload: &[u8]) -> Result<Claims, &'static str> {
    // jwt_payload is base64url(JSON). Decode straight from the b64 bytes — the
    // base64 alphabet is ASCII, so a separate UTF-8 check would be redundant.
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt_payload)
        .map_err(|_| "payload base64 decode failed")?;
    // Deserialize only the claims we consume directly into the struct: serde
    // skips the other JWT fields (sub/iat/exp/…) without building a Value tree,
    // and a missing or non-string claim fails closed via the caller's expect.
    serde_json::from_slice(&payload_bytes).map_err(|_| "payload missing required claims")
}


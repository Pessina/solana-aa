use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash as sha256;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};
use sp1_primitives::io::SP1PublicValues;
use sp1_solana::verify_proof;

/*
    ZK OIDC authentication.

    An RS256 JWT is verified inside the SP1 zkVM guest program (`zk/jwt-program`),
    which commits privacy-preserving public outputs (Poseidon hashes of the email
    and signing key, plus iss/aud/nonce). The Groth16 wrapper proof is verified
    here through the alt_bn128 syscalls (sp1-solana), which — unlike `big_mod_exp`
    used by the legacy `rsa` PoC — are enabled on mainnet.

    Trust chain enforced by `execute_zk_oidc`:
    1. Groth16 proof valid for `JWT_VKEY_HASH` -> the exact guest binary ran and
       the JWT signature verified against the committed `pk_hash` key.
    2. `(iss, pk_hash)` present in the on-chain `OidcKeyRegistry` -> the JWT was
       signed by a key the registry authority pinned for that provider.
    3. JWT `nonce` == hex(sha256(borsh(transaction))) -> the user approved this
       exact transaction when the token was minted (proof/transaction binding).
*/

type PoseidonHash = [BabyBear; 8];

/// Verification key hash of `zk/jwt-program`.
/// Regenerate with `cd zk/script && cargo run --release -- vkey` after any guest change.
pub const JWT_VKEY_HASH: &str =
    "0x0024a3c1b09701dfa9d52ba9367becaa628a45506855cfca16d95ae90b7ae680";

/// SP1 v5 universal Groth16 verification key.
const GROTH16_VK_BYTES: &[u8] = include_bytes!("groth16_vk.bin");

// Policy caps: bound attacker-controlled string growth on the heap and in
// account storage. Google's iss is 30 chars; aud (OAuth client id) ~73.
const MAX_ISS_LEN: usize = 64;
const MAX_AUD_LEN: usize = 256;

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Sp1Groth16Proof {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

/// Mirror of the guest program's `PublicOutputs` (bincode field order must match
/// `zk/jwt-program/src/main.rs`). The golden fixture test catches drift.
#[derive(Serialize, Deserialize)]
struct PublicOutputs {
    email_hash: PoseidonHash,
    pk_hash: PoseidonHash,
    iss: String,
    aud: String,
    nonce: String,
}

/// Facts established by a verified proof.
pub struct VerifiedJwt {
    pub email_hash: [u8; 32],
    pub pk_hash: [u8; 32],
    pub iss: String,
    pub aud: String,
    pub nonce: String,
}

pub fn verify_zk_oidc_proof(groth16_proof: &Sp1Groth16Proof) -> Result<VerifiedJwt> {
    verify_proof(
        &groth16_proof.proof,
        &groth16_proof.public_values,
        JWT_VKEY_HASH,
        GROTH16_VK_BYTES,
    )
    .map_err(|_| ErrorCode::ProofVerificationFailed)?;

    // Safe to parse only after verification: the Groth16 proof commits to the
    // digest of `public_values`, so these bytes are exactly what the guest wrote.
    let mut public_values = SP1PublicValues::from(&groth16_proof.public_values);
    let outputs: PublicOutputs = public_values.read();

    require!(outputs.iss.len() <= MAX_ISS_LEN, ErrorCode::IssuerTooLong);
    require!(outputs.aud.len() <= MAX_AUD_LEN, ErrorCode::AudienceTooLong);

    Ok(VerifiedJwt {
        email_hash: poseidon_to_bytes(&outputs.email_hash),
        pk_hash: poseidon_to_bytes(&outputs.pk_hash),
        iss: outputs.iss,
        aud: outputs.aud,
        nonce: outputs.nonce,
    })
}

/// The JWT nonce format that binds a token to one transaction:
/// lowercase hex of sha256 over the Borsh-serialized `Transaction`.
pub fn transaction_nonce_hex(transaction_bytes: &[u8]) -> String {
    hex::encode(sha256(transaction_bytes).to_bytes())
}

/// 8 BabyBear elements -> 32 bytes (canonical u32, little-endian each).
/// Inverse layout of the guest's `poseidon_hash_bytes` packing.
fn poseidon_to_bytes(hash: &PoseidonHash) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, elem) in hash.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&elem.as_canonical_u32().to_le_bytes());
    }
    bytes
}

#[error_code]
pub enum ErrorCode {
    #[msg("ZK proof verification failed")]
    ProofVerificationFailed,
    #[msg("Issuer exceeds maximum length")]
    IssuerTooLong,
    #[msg("Audience exceeds maximum length")]
    AudienceTooLong,
}

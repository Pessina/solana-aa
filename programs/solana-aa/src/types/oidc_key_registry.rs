use anchor_lang::prelude::*;

/// Registry of OIDC provider signing keys trusted by the program.
///
/// `execute_zk_oidc` only accepts proofs whose `(iss, pk_hash)` pair is present
/// here, pinning the JWKS keys a JWT may be signed with. Without this check a
/// proof generated against any self-chosen RSA key would verify. The authority
/// is expected to follow provider key rotation (e.g. Google's JWKS endpoint).
#[account]
pub struct OidcKeyRegistry {
    pub authority: Pubkey,
    pub keys: Vec<OidcKeyEntry>,

    // PDA discriminator to optimize Anchor account validation
    pub bump: u8,
}

#[derive(Debug, AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone)]
pub struct OidcKeyEntry {
    pub iss: String,
    /// Poseidon2 hash of the provider RSA public key (SPKI DER), as committed
    /// by the guest program and converted with `poseidon_to_bytes`.
    pub pk_hash: [u8; 32],
}

impl OidcKeyEntry {
    pub fn byte_size(&self) -> usize {
        4 + self.iss.len() + 32
    }
}

impl OidcKeyRegistry {
    const PDA_DISCRIMINATOR_SIZE: usize = 8;
    const AUTHORITY_SIZE: usize = 32;
    const VEC_SIZE: usize = 4;
    const BUMP_SIZE: usize = 1;

    pub const INIT_SIZE: usize =
        Self::PDA_DISCRIMINATOR_SIZE + Self::AUTHORITY_SIZE + Self::VEC_SIZE + Self::BUMP_SIZE;

    pub fn contains(&self, iss: &str, pk_hash: &[u8; 32]) -> bool {
        self.keys
            .iter()
            .any(|key| key.iss == iss && &key.pk_hash == pk_hash)
    }
}

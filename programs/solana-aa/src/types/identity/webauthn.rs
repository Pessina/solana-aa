use anchor_lang::prelude::*;

#[derive(Debug, AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WebAuthnAuthenticator {
    pub key_id: String,
    // The compressed public key is optional since it cannot be obtained during passkey signing.
    // It must be stored during key creation and retrieved during authentication.
    pub compressed_public_key: Option<String>,
    /// sha256(rpId); checked against authenticatorData[0..32] during execute.
    pub rp_id_hash: [u8; 32],
    /// Expected clientDataJSON.origin (e.g. "https://example.com"). Binds the
    /// credential to a single origin so a key reused on another site cannot
    /// authorize for this account.
    pub origin: String,
}

/// Equality intentionally ignores `key_id` — it cannot be recovered from a
/// passkey assertion at execute time — and matches on the fields that ARE
/// re-derivable and security-relevant: the public key, the authenticator's
/// rpIdHash, and the client-data origin. Because `is_transaction_authorized`
/// matches identities via this `eq`, requiring all three here is what enforces
/// the origin/rpIdHash binding on the execute path.
impl PartialEq for WebAuthnAuthenticator {
    fn eq(&self, other: &Self) -> bool {
        self.compressed_public_key == other.compressed_public_key
            && self.rp_id_hash == other.rp_id_hash
            && self.origin == other.origin
    }
}

impl Eq for WebAuthnAuthenticator {}

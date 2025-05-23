use anchor_lang::prelude::*;

// use crate::traits::path::Path;

#[derive(Debug, AnchorSerialize, AnchorDeserialize, Clone)]
pub struct WebAuthnAuthenticator {
    pub key_id: String,
    // The compressed public key is optional since it cannot be obtained during passkey signing.
    // It must be stored during key creation and retrieved during authentication.
    pub compressed_public_key: Option<String>,
    // Should likely have to include the client_data.origin and authenticators.rpIdHash as the same key-pair can be re-used across different websites.
    // So if we only check the public key malicious.com would be able to generate a valid signature for example.com if the key-pair is reused.
}

// impl Path for WebAuthnAuthenticator {
//     fn path(&self) -> String {
//         format!(
//             "webauthn/{}",
//             self.compressed_public_key
//                 .as_ref()
//                 .expect("Compressed public key not set for WebAuthn")
//         )
//     }
// }

impl PartialEq for WebAuthnAuthenticator {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id
            && match (&self.compressed_public_key, &other.compressed_public_key) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

impl Eq for WebAuthnAuthenticator {}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct WebAuthnCredentials {
    pub signature: String,
    pub authenticator_data: String,
    pub client_data: String,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct WebAuthnValidationData {
    pub signature: String,
    pub authenticator_data: String,
    pub client_data: String,
}

use super::identity::{Identity, IdentityWithPermissions};
use anchor_lang::prelude::*;

pub type AccountId = u64;
pub type Nonce = u128;

/*
    Once the accounts is deleted it can't be recreated, all the accounts are created in sequence, tracked by the AccountManager PDA.
*/
#[account]
pub struct AbstractAccount {
    // Account identifier stored as a number for compactness and to enable sequential account discovery.
    pub account_id: AccountId,
    pub nonce: Nonce,

    // TODO: Benchmark other data structures; BtreeMap, HashMap, etc.
    // Considering ~10 identities per account, a Vec might be the best choice.
    // Vec avoid the overhead of Key-Value pair of BTreeMap and HashMap softening the usage of Heap and Stack.
    pub identities: Vec<IdentityWithPermissions>,

    // PDA discriminator to optimize Anchor account validation
    pub bump: u8,
}

impl AbstractAccount {
    const PDA_DISCRIMINATOR_SIZE: usize = 8;
    const ACCOUNT_ID_SIZE: usize = 8;
    const NONCE_SIZE: usize = 16;
    const VEC_SIZE: usize = 4;
    const BUMP_SIZE: usize = 1;

    pub const INIT_SIZE: usize = Self::PDA_DISCRIMINATOR_SIZE
        + Self::ACCOUNT_ID_SIZE
        + Self::NONCE_SIZE
        + Self::VEC_SIZE
        + Self::BUMP_SIZE;

    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }

    // TODO: Include memory usage check to avoid overflowing solana limits
    pub fn add_identity(&mut self, identity_with_permissions: IdentityWithPermissions) {
        if !self.has_identity(&identity_with_permissions.identity) {
            self.identities.push(identity_with_permissions);
        }
    }

    pub fn remove_identity(&mut self, identity: &Identity) -> bool {
        let initial_len = self.identities.len();
        self.identities.retain(|i| &i.identity != identity);

        initial_len > self.identities.len()
    }

    pub fn has_identity(&self, identity: &Identity) -> bool {
        self.identities.iter().any(|i| &i.identity == identity)
    }

    pub fn find_identity(&self, identity: &Identity) -> Option<&IdentityWithPermissions> {
        self.identities.iter().find(|i| &i.identity == identity)
    }
}

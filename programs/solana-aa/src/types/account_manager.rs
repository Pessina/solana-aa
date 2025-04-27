use super::account::{AccountId, Nonce};
use anchor_lang::prelude::*;

#[account]
pub struct AccountManager {
    /*
    Tracks the latest account_id created.

    Every time an account is created, the account_id is incremented by 1.
    If an account is deleted, we will have gap on the account_id.

    Enabling sequential account discovery and use minimal storage.
    */
    pub next_account_id: AccountId,

    /*
    Tracks the maximum nonce of the accounts deleted.

    When an account is deleted and recreated, its nonce would normally reset to 0.
    This would allow previously used signatures (with nonces 0 through N) to be
    replayed on the new account.

    By tracking the global maximum nonce, we ensure that even recreated accounts
    start with the max_nonce avoiding replay attacks.
    */
    pub max_nonce: Nonce,
}

impl AccountManager {
    pub const INIT_SIZE: usize = 8 + 8 + 16; // discriminator + account_id + max_nonce

    pub fn new() -> Self {
        Self {
            next_account_id: 0,
            max_nonce: 0,
        }
    }

    pub fn increment_next_account_id(&mut self) -> AccountId {
        let old_next_account_id = self.next_account_id;
        self.next_account_id = self.next_account_id.saturating_add(1);
        old_next_account_id
    }

    pub fn update_max_nonce(&mut self, new_max_nonce: Nonce) -> Nonce {
        let old_max_nonce = self.max_nonce;
        self.max_nonce = new_max_nonce;
        old_max_nonce
    }
}

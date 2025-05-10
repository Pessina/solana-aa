use super::account::AccountId;
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

    // PDA discriminator to optimize Anchor account validation
    pub bump: u8,
}

impl AccountManager {
    const PDA_DISCRIMINATOR_SIZE: usize = 8;
    const ACCOUNT_ID_SIZE: usize = 8;
    const BUMP_SIZE: usize = 1;

    pub const INIT_SIZE: usize =
        Self::PDA_DISCRIMINATOR_SIZE + Self::ACCOUNT_ID_SIZE + Self::BUMP_SIZE;

    pub fn increment_next_account_id(&mut self) -> AccountId {
        let old_next_account_id = self.next_account_id;
        self.next_account_id = self.next_account_id.saturating_add(1);
        old_next_account_id
    }
}

use crate::types::identities::*;
use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
}

#[derive(Accounts)]
#[instruction(account_id: String)]
pub struct DeleteAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"account", account_id.as_bytes()],
        bump,
        close = signer
    )]
    pub abstract_account: Account<'info, AbstractAccount>,
    pub system_program: Program<'info, System>,
}

pub fn delete_account_impl(ctx: Context<DeleteAccount>, account_id: String) -> Result<()> {
    msg!("Deleting account: {}", account_id);
    // TODO: Update global nonce to avoid account reuse

    Ok(())
}

#[derive(Accounts)]
#[instruction(account_id: String, identity: Identity)]
pub struct CreateAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        init_if_needed,
        payer = signer,
        space = estimate_account_size(&identity),
        seeds = [b"account", account_id.as_bytes()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,
    pub system_program: Program<'info, System>,
}

fn estimate_account_size(identity: &Identity) -> usize {
    const PDA_DISCRIMINATOR_SIZE: usize = 8;
    const NONCE_SIZE: usize = 8;
    const VEC_SIZE: usize = 4;

    let mut size = PDA_DISCRIMINATOR_SIZE + NONCE_SIZE + VEC_SIZE;
    size += identity.byte_size();

    size
}

pub fn create_account_impl(
    ctx: Context<CreateAccount>,
    _account_id: String,
    identity: Identity,
) -> Result<()> {
    // TODO: Create manager account that track the global nonce and initialize this with the global nonce
    ctx.accounts.abstract_account.nonce = 0;
    ctx.accounts.abstract_account.identities = vec![identity];

    Ok(())
}

#[derive(Accounts)]
#[instruction(account_id: String, identity: Identity)]
pub struct AddIdentity<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"account", account_id.as_bytes()],
        bump,
        realloc = abstract_account.to_account_info().data_len() + identity.byte_size(),
        realloc::payer = signer,
        realloc::zero = false
    )]
    pub abstract_account: Account<'info, AbstractAccount>,
    pub system_program: Program<'info, System>,
}

pub fn add_identity_impl(
    ctx: Context<AddIdentity>,
    _account_id: String,
    identity: Identity,
) -> Result<()> {
    ctx.accounts.abstract_account.add_identity(identity);
    Ok(())
}

#[derive(Accounts)]
#[instruction(account_id: String, identity: Identity)]
pub struct RemoveIdentity<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"account", account_id.as_bytes()],
        bump,
        realloc = abstract_account.to_account_info().data_len() - identity.byte_size(),
        realloc::payer = signer,
        realloc::zero = false
    )]
    pub abstract_account: Account<'info, AbstractAccount>,
    pub system_program: Program<'info, System>,
}

pub fn remove_identity_impl(
    ctx: Context<RemoveIdentity>,
    _account_id: String,
    identity: Identity,
) -> Result<()> {
    ctx.accounts.abstract_account.remove_identity(&identity);
    Ok(())
}

#[account]
pub struct AbstractAccount {
    pub nonce: u64,
    // TODO: Benchmark other data structures; BtreeMap, HashMap, etc.
    // TODO: Do not allow duplicate identities
    // Considering ~10 identities per account, a Vec might be the best choice.
    // Vec avoid the overhead of Key-Value pair of BTreeMap and HashMap softening the usage of Heap and Stack.
    pub identities: Vec<Identity>,
}

impl AbstractAccount {
    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }

    // TODO: Include memory usage check to avoid overflowing solana limits
    pub fn add_identity(&mut self, identity: Identity) {
        if !self.has_identity(&identity) {
            self.identities.push(identity);
        }
    }

    pub fn remove_identity(&mut self, identity: &Identity) -> bool {
        let initial_len = self.identities.len();
        self.identities.retain(|i| i != identity);

        initial_len > self.identities.len()
    }

    pub fn has_identity(&self, identity: &Identity) -> bool {
        self.identities.iter().any(|i| i == identity)
    }

    pub fn find_identity(&self, identity: &Identity) -> Option<&Identity> {
        self.identities.iter().find(|i| *i == identity)
    }
}

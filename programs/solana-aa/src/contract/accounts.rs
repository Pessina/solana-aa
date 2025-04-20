use crate::types::identities::*;
use anchor_lang::prelude::*;

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

pub fn get_account_impl(ctx: &Context<GetAccount>, account_id: String) -> Result<()> {
    let abstract_account = &ctx.accounts.abstract_account;
    msg!("Account ID: {}", account_id);
    msg!("PDA Account: {}", abstract_account.nonce);
    msg!("Identities: {:?}", abstract_account.identities);
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
    size += identity
        .try_to_vec()
        .expect("Failed to serialize identity")
        .len();

    size
}

#[derive(Accounts)]
#[instruction(account_id: String)]
pub struct GetAccount<'info> {
    #[account(
        seeds = [b"account", account_id.as_bytes()],
        bump,
    )]
    pub abstract_account: Account<'info, AbstractAccount>,
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

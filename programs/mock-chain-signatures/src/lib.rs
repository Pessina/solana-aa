use anchor_lang::prelude::*;

declare_id!("F4KaC593TkwxSgrej1q1QiqHsmeSXmJBniPTBNjUtuou");

/// Test-only stand-in for the Sig Network chain-signatures program. It mirrors
/// the real `sign` instruction's discriminator (`sha256("global:sign")`),
/// argument order, and account layout so the AA program's `Sign` CPI can be
/// exercised deterministically on a local validator — no devnet cloning needed.
#[program]
pub mod mock_chain_signatures {
    use super::*;

    pub fn sign(
        ctx: Context<Sign>,
        _payload: [u8; 32],
        _key_version: u32,
        _path: String,
        _algo: String,
        _dest: String,
        _params: String,
    ) -> Result<()> {
        // The property under test: the abstract-account PDA signed the CPI as
        // `requester` via `invoke_signed`.
        require!(
            ctx.accounts.requester.is_signer,
            MockError::RequesterNotSigner
        );
        msg!("mock sign ok: requester={}", ctx.accounts.requester.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Sign<'info> {
    /// CHECK: mock — accepted as-is, not validated against any seeds.
    #[account(mut)]
    pub program_state: UncheckedAccount<'info>,
    #[account(mut)]
    pub requester: Signer<'info>,
    #[account(mut)]
    pub fee_payer: Signer<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: mock — mirrors the `#[event_cpi]` event authority slot.
    pub event_authority: UncheckedAccount<'info>,
    /// CHECK: mock — mirrors the `#[event_cpi]` program slot.
    pub program: UncheckedAccount<'info>,
}

#[error_code]
pub enum MockError {
    #[msg("Requester did not sign the CPI")]
    RequesterNotSigner,
}

use anchor_lang::prelude::*;

use crate::{
    pda_seeds::OIDC_KEY_REGISTRY_SEED,
    types::oidc_key_registry::{OidcKeyEntry, OidcKeyRegistry},
};

#[derive(Accounts)]
pub struct InitOidcRegistry<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = OidcKeyRegistry::INIT_SIZE,
        seeds = [OIDC_KEY_REGISTRY_SEED],
        bump,
    )]
    pub oidc_key_registry: Account<'info, OidcKeyRegistry>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(key_entry: OidcKeyEntry)]
pub struct AddOidcKey<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [OIDC_KEY_REGISTRY_SEED],
        bump = oidc_key_registry.bump,
        has_one = authority,
        realloc = oidc_key_registry.to_account_info().data_len() + key_entry.byte_size(),
        realloc::payer = authority,
        realloc::zero = false,
    )]
    pub oidc_key_registry: Account<'info, OidcKeyRegistry>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemoveOidcKey<'info> {
    pub authority: Signer<'info>,

    // Capacity is intentionally kept on removal: registries are small and keys
    // rotate, so the space is reused by the next addition.
    #[account(
        mut,
        seeds = [OIDC_KEY_REGISTRY_SEED],
        bump = oidc_key_registry.bump,
        has_one = authority,
    )]
    pub oidc_key_registry: Account<'info, OidcKeyRegistry>,
}

#[derive(Accounts)]
pub struct CloseOidcRegistry<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [OIDC_KEY_REGISTRY_SEED],
        bump = oidc_key_registry.bump,
        has_one = authority,
        close = authority,
    )]
    pub oidc_key_registry: Account<'info, OidcKeyRegistry>,
}

pub fn init_oidc_registry_impl(ctx: Context<InitOidcRegistry>) -> Result<()> {
    ctx.accounts.oidc_key_registry.authority = ctx.accounts.authority.key();
    ctx.accounts.oidc_key_registry.keys = vec![];
    ctx.accounts.oidc_key_registry.bump = ctx.bumps.oidc_key_registry;

    Ok(())
}

pub fn add_oidc_key_impl(ctx: Context<AddOidcKey>, key_entry: OidcKeyEntry) -> Result<()> {
    let registry = &mut ctx.accounts.oidc_key_registry;

    require!(
        !registry.contains(&key_entry.iss, &key_entry.pk_hash),
        ErrorCode::OidcKeyAlreadyRegistered
    );

    registry.keys.push(key_entry);

    Ok(())
}

pub fn remove_oidc_key_impl(ctx: Context<RemoveOidcKey>, key_entry: OidcKeyEntry) -> Result<()> {
    let registry = &mut ctx.accounts.oidc_key_registry;

    require!(
        registry.contains(&key_entry.iss, &key_entry.pk_hash),
        ErrorCode::OidcKeyNotFound
    );

    registry.keys.retain(|key| key != &key_entry);

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("OIDC key already registered")]
    OidcKeyAlreadyRegistered,
    #[msg("OIDC key not found")]
    OidcKeyNotFound,
}

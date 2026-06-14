use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};

use crate::types::transaction::transaction::SignRequest;

/// Anchor global instruction discriminator for chain-signatures `sign`:
/// `sha256("global:sign")[..8]`. Verified by the golden test below.
pub const SIGN_DISCRIMINATOR: [u8; 8] = [5, 221, 155, 46, 237, 91, 28, 236];

/// Serialize the `sign` instruction data: discriminator ++ Borsh(args).
/// `SignRequest`'s field order matches the `sign` argument order exactly, so its
/// Borsh encoding is the argument encoding.
fn build_sign_data(req: &SignRequest) -> Result<Vec<u8>> {
    let mut data = SIGN_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&req.try_to_vec().map_err(|_| SignError::Serialization)?);
    Ok(data)
}

/// Build the chain-signatures `sign` `Instruction`. `program_id` is the
/// deployment-configured chain-signatures program. Account order matches
/// `#[event_cpi] pub struct Sign` (the macro appends event_authority + program):
/// program_state(mut), requester(mut+signer), fee_payer(mut+signer),
/// system_program, event_authority, program.
#[allow(clippy::too_many_arguments)]
pub fn build_sign_instruction(
    program_id: Pubkey,
    req: &SignRequest,
    program_state: Pubkey,
    requester: Pubkey,
    fee_payer: Pubkey,
    system_program: Pubkey,
    event_authority: Pubkey,
    chain_sig_program: Pubkey,
) -> Result<Instruction> {
    Ok(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(program_state, false),
            AccountMeta::new(requester, true),
            AccountMeta::new(fee_payer, true),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(event_authority, false),
            AccountMeta::new_readonly(chain_sig_program, false),
        ],
        data: build_sign_data(req)?,
    })
}

#[error_code]
pub enum SignError {
    #[msg("Failed to serialize sign request")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminator_matches_anchor_global_sign() {
        let h = anchor_lang::solana_program::hash::hash(b"global:sign");
        assert_eq!(&h.to_bytes()[..8], &SIGN_DISCRIMINATOR);
    }

    #[test]
    fn encodes_args_after_discriminator() {
        let req = SignRequest {
            payload: [7u8; 32],
            key_version: 1,
            path: "m/44".to_string(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
        };
        let data = build_sign_data(&req).unwrap();
        assert_eq!(&data[..8], &SIGN_DISCRIMINATOR);
        assert_eq!(&data[8..40], &[7u8; 32]);
        assert_eq!(&data[40..44], &[1, 0, 0, 0]); // key_version u32 LE
    }

    #[test]
    fn instruction_account_layout_matches_chain_signatures() {
        let program_id = Pubkey::new_unique();
        let req = SignRequest {
            payload: [0u8; 32],
            key_version: 0,
            path: String::new(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
        };
        let program_state = Pubkey::new_unique();
        let requester = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let system_program = Pubkey::new_unique();
        let event_authority = Pubkey::new_unique();

        let ix = build_sign_instruction(
            program_id,
            &req,
            program_state,
            requester,
            fee_payer,
            system_program,
            event_authority,
            program_id,
        )
        .unwrap();

        assert_eq!(ix.program_id, program_id);

        // Order + flags mirror chain-signatures `#[event_cpi] Sign`:
        // program_state(mut), requester(mut,signer), fee_payer(mut,signer),
        // system_program(ro), event_authority(ro), program(ro).
        let expected = [
            (program_state, false, true),
            (requester, true, true),
            (fee_payer, true, true),
            (system_program, false, false),
            (event_authority, false, false),
            (program_id, false, false),
        ];
        assert_eq!(ix.accounts.len(), expected.len());
        for (i, (key, is_signer, is_writable)) in expected.iter().enumerate() {
            assert_eq!(ix.accounts[i].pubkey, *key, "account {i} pubkey");
            assert_eq!(ix.accounts[i].is_signer, *is_signer, "account {i} signer");
            assert_eq!(ix.accounts[i].is_writable, *is_writable, "account {i} writable");
        }
    }
}

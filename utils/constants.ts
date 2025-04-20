export const SOLANA_MAX_COMPUTE_UNITS = 1_400_000;

/**
 * Error codes thrown by the Solana precompiled programs for secp256k1, secp256r1 and ed25519.
 * @see https://docs.rs/solana-precompile-error/latest/solana_precompile_error/enum.PrecompileError.html
 */
export const SOLANA_PRE_COMPILED_ERRORS = {
  INVALID_PUBLIC_KEY: "0x0",
  INVALID_RECOVERY_ID: "0x1",
  INVALID_SIGNATURE: "0x2",
  INVALID_DATA_OFFSETS: "0x3",
  INVALID_INSTRUCTION_DATA_SIZE: "0x4",
};

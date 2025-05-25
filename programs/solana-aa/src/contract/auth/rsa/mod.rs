//! RSA Authentication Module (Experimental)
//!
//! Provides RSA signature verification for OIDC tokens with known limitations:
//!
//! - **Native syscall**: Uses `big_mod_exp` syscall (localnet only, not mainnet/devnet)
//! - **RSA crate**: Pure Rust implementation (exceeds compute unit limits)
//! - **Multi-transaction**: Splitting verification exceeds Solana memory limits ("Program log: Error: memory allocation failed, out of memory")
//!
//! Currently suitable for localnet testing only.

pub mod constants;
pub mod rsa_native;
pub mod rsa_rsa_crate;
pub mod utils;

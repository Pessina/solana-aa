//! Host-side tooling for the ZK OIDC path.
//!
//! - `vkey`: print the guest program's verification key hash, pinned on-chain as
//!   `JWT_VKEY_HASH` in `programs/solana-aa/src/contract/auth/zk_oidc.rs`.
//! - `fixture`: build the canonical test `Transaction` with the program's own Borsh
//!   types, self-sign a JWT whose `nonce` is `hex(sha256(borsh(transaction)))`, run
//!   the guest (execute or Groth16 prove), and emit a JSON fixture for the TS tests.

use anchor_lang::AnchorSerialize;
use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePublicKey},
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Stdin};
use solana_aa::types::{
    identity::{wallet::WalletType, Identity, IdentityPermissions, IdentityWithPermissions},
    transaction::transaction::{Action, Transaction},
};

const JWT_PROGRAM_ELF: &[u8] = include_elf!("jwt-program");

const TEST_RSA_PRIVATE_KEY_PEM: &str = include_str!("../fixtures/test_rsa_private.pem");
const TEST_ISS: &str = "https://test-issuer.solana-aa.dev";
const TEST_AUD: &str = "solana-aa-tests";
const TEST_EMAIL: &str = "test@solana-aa.dev";

/// Mirror of the guest program's `PublicOutputs` (bincode field order must match).
#[derive(Serialize, Deserialize, Debug)]
struct PublicOutputs {
    email_hash: [u8; 32],
    pk_hash: [u8; 32],
    iss: String,
    aud: String,
    nonce: String,
}

#[derive(Parser)]
#[command(about = "ZK OIDC host tooling for solana-aa")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the guest program verification key hash (pin as JWT_VKEY_HASH on-chain)
    Vkey,
    /// Generate the golden test fixture (JWT -> SP1 proof -> JSON)
    Fixture {
        /// Abstract account id the test transaction targets
        #[arg(long, default_value_t = 0)]
        account_id: u64,
        /// Abstract account nonce the test transaction carries
        #[arg(long, default_value_t = 0)]
        account_nonce: u128,
        /// Ethereum address added by the AddIdentity action (0x-prefixed)
        #[arg(long, default_value = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")]
        eth_address: String,
        /// Only execute the guest (fast); skip Groth16 proving and fixture output
        #[arg(long)]
        execute_only: bool,
        /// Output path for the fixture JSON
        #[arg(long, default_value = "../../tests/fixtures/zk-oidc-add-identity.json")]
        out: String,
    },
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();

    match Cli::parse().command {
        Command::Vkey => vkey(),
        Command::Fixture {
            account_id,
            account_nonce,
            eth_address,
            execute_only,
            out,
        } => fixture(account_id, account_nonce, &eth_address, execute_only, &out),
    }
}

fn vkey() -> Result<()> {
    let client = ProverClient::from_env();
    let (_, vk) = client.setup(JWT_PROGRAM_ELF);
    println!("{}", vk.bytes32());
    Ok(())
}

fn fixture(
    account_id: u64,
    account_nonce: u128,
    eth_address: &str,
    execute_only: bool,
    out: &str,
) -> Result<()> {
    let eth_bytes: [u8; 20] = hex::decode(eth_address.trim_start_matches("0x"))
        .context("invalid eth address hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("eth address must be 20 bytes"))?;

    let transaction = Transaction {
        account_id,
        nonce: account_nonce,
        action: Action::AddIdentity(IdentityWithPermissions {
            identity: Identity::Wallet(WalletType::Ethereum(eth_bytes)),
            permissions: Some(IdentityPermissions {
                enable_act_as: true,
            }),
        }),
    };

    let transaction_bytes = transaction.try_to_vec()?;
    let jwt_nonce = hex::encode(Sha256::digest(&transaction_bytes));
    println!("transaction borsh: {}", hex::encode(&transaction_bytes));
    println!("jwt nonce (sha256): {jwt_nonce}");

    let private_key = RsaPrivateKey::from_pkcs8_pem(TEST_RSA_PRIVATE_KEY_PEM)?;
    let public_key = RsaPublicKey::from(&private_key);
    let pk_der = public_key.to_public_key_der()?.to_vec();

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = b64.encode(r#"{"alg":"RS256","typ":"JWT","kid":"test-key-1"}"#);
    let payload_json = serde_json::json!({
        "iss": TEST_ISS,
        "aud": TEST_AUD,
        "sub": "test-subject-1",
        "email": TEST_EMAIL,
        "nonce": jwt_nonce,
        "iat": 1749700000u64,
        "exp": 1749703600u64,
    });
    let payload_b64 = b64.encode(payload_json.to_string());

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = private_key.sign(
        Pkcs1v15Sign::new::<Sha256>(),
        &Sha256::digest(signing_input.as_bytes()),
    )?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&pk_der);
    stdin.write(&header_b64.as_bytes().to_vec());
    stdin.write(&payload_b64.as_bytes().to_vec());
    stdin.write(&signature);

    let client = ProverClient::from_env();

    if execute_only {
        let (mut public_values, report) = client.execute(JWT_PROGRAM_ELF, &stdin).run()?;
        let outputs: PublicOutputs = public_values.read();
        println!("cycles: {}", report.total_instruction_count());
        print_outputs(&outputs);
        anyhow::ensure!(outputs.nonce == jwt_nonce, "guest nonce mismatch");
        return Ok(());
    }

    let (pk, vk) = client.setup(JWT_PROGRAM_ELF);
    let mut proof = client.prove(&pk, &stdin).groth16().run()?;
    client.verify(&proof, &vk)?;

    // The TEE attestation is not part of the on-chain Groth16 verification.
    proof.tee_proof = None;

    let mut public_values = proof.public_values.clone();
    let outputs: PublicOutputs = public_values.read();
    print_outputs(&outputs);
    anyhow::ensure!(outputs.nonce == jwt_nonce, "guest nonce mismatch");

    let fixture = serde_json::json!({
        "proof": hex::encode(proof.bytes()),
        "publicValues": hex::encode(proof.public_values.to_vec()),
        "vkeyHash": vk.bytes32(),
        "emailHash": hex::encode(outputs.email_hash),
        "pkHash": hex::encode(outputs.pk_hash),
        "iss": outputs.iss,
        "aud": outputs.aud,
        "nonce": outputs.nonce,
        "accountId": account_id.to_string(),
        "accountNonce": account_nonce.to_string(),
        "ethAddress": eth_address,
        "transactionBorsh": hex::encode(&transaction_bytes),
    });

    std::fs::write(out, serde_json::to_string_pretty(&fixture)?)?;
    println!("fixture written to {out} (proof size: {} bytes)", proof.bytes().len());
    Ok(())
}

fn print_outputs(outputs: &PublicOutputs) {
    println!("iss: {}", outputs.iss);
    println!("aud: {}", outputs.aud);
    println!("nonce: {}", outputs.nonce);
    println!("email_hash: {}", hex::encode(outputs.email_hash));
    println!("pk_hash: {}", hex::encode(outputs.pk_hash));
}

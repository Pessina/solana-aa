import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import { AccountMeta } from "@solana/web3.js";
import { Hex, keccak256 } from "viem";
import { SolanaAa } from "../target/types/solana_aa";
import { Action, borshUtils, Transaction } from "../borsh";
import { signWithEthereum } from "./secp256k1-signer";
import {
  createSecp256k1VerificationInstruction,
  ethereumAddressToBytes,
  parseEthereumSignature,
} from "./ethereum";
import { findAbstractAccountPDA } from "./program";
import { confirmTransaction } from "./solana";

/**
 * Sign a `Transaction` with an Ethereum key and submit it through the
 * authenticated `execute_ek256` path (with the secp256k1 precompile
 * pre-instruction). Fetches the account's current nonce unless one is supplied.
 */
export async function executeEk256Action(
  program: anchor.Program<SolanaAa>,
  opts: {
    accountId: bigint;
    ethPrivateKey: Hex;
    action: Action;
    nonce?: bigint;
    remainingAccounts?: AccountMeta[];
  }
): Promise<string> {
  let nonce = opts.nonce;
  if (nonce === undefined) {
    const [accountPDA] = findAbstractAccountPDA(
      new BN(opts.accountId.toString()),
      program.programId
    );
    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    nonce = BigInt(accountInfo.nonce.toString());
  }

  const transaction: Transaction = {
    account_id: opts.accountId,
    nonce,
    action: opts.action,
  };
  const message = Buffer.from(borshUtils.serialize.transaction(transaction));

  const ethSignature = await signWithEthereum({
    hash: keccak256(message),
    privateKey: opts.ethPrivateKey,
  });
  const { signature, recoveryId } = parseEthereumSignature(
    ethSignature.signature
  );
  const verificationInstruction = createSecp256k1VerificationInstruction(
    signature,
    recoveryId,
    ethereumAddressToBytes(ethSignature.address),
    message
  );

  const builder = program.methods
    .executeEk256(new BN(opts.accountId.toString()))
    .preInstructions([verificationInstruction]);
  if (opts.remainingAccounts) {
    builder.remainingAccounts(opts.remainingAccounts);
  }

  const txSignature = await builder.rpc();
  await confirmTransaction(program.provider.connection, txSignature);
  return txSignature;
}

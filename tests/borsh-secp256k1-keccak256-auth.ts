import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { signWithEthereum } from "../utils/secp256k1-signer";
import { borshUtils, Transaction } from "../utils/borsh";
import { SolanaAa } from "../target/types/solana_aa";
import {
  confirmTransaction,
  getTransactionReturnValue,
  getTxInfo,
  logComputeUnitsUsed,
} from "../utils/solana";
import {
  parseEthereumSignature,
  ethereumAddressToBytes,
  createSecp256k1VerificationInstruction,
} from "../utils/ethereum";
import { keccak256 } from "viem";

describe.only("Ethereum Signature Verification", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  it("should validate Ethereum signature correctly", async () => {
    const message =
      '{"account_id":"1","action":{"AddIdentity":{"identity":{"Wallet":{"public_key":"0x0304ab3cb2897344aa3f6ffaac94e477aeac170b9235d2416203e2a72bc9b8a7c7","wallet_type":"Ethereum"}},"permissions":{"enable_act_as":false}}},"nonce":135}';

    const messageJson = JSON.parse(message);

    const transaction: Transaction = {
      account_id: BigInt(messageJson.account_id),
      nonce: BigInt(messageJson.nonce),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              wallet_type: { Ethereum: {} },
              compressed_public_key: new Uint8Array(
                Buffer.from(
                  messageJson.action.AddIdentity.identity.Wallet.public_key.slice(
                    2
                  ),
                  "hex"
                )
              ).slice(0, 20),
            },
          },
          permissions: {
            enable_act_as:
              messageJson.action.AddIdentity.permissions.enable_act_as,
          },
        },
      },
    };

    const serializedMessage = Buffer.from(
      borshUtils.serialize.transaction(transaction)
    );

    const privateKey =
      "0x4646464646464646464646464646464646464646464646464646464646464646" as const;
    const ethSignature = await signWithEthereum({
      hash: keccak256(serializedMessage),
      privateKey,
    });

    const {
      signature: precompileSignatureBuffer,
      recoveryId: precompileRecoveryId,
    } = parseEthereumSignature(ethSignature.signature);
    const precompileAddressBytes = ethereumAddressToBytes(ethSignature.address);

    console.log(ethSignature.address);

    const verificationInstruction = createSecp256k1VerificationInstruction(
      precompileSignatureBuffer,
      precompileRecoveryId,
      precompileAddressBytes,
      serializedMessage
    );

    const txSignature = await program.methods
      .getEthData()
      .accounts({
        instructions_sysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .preInstructions([verificationInstruction])
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    const result = await getTxInfo({ txSignature });

    console.log(JSON.stringify(result, null, 2));
  });
});

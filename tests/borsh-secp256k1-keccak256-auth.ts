import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { signWithEthereum } from "../utils/secp256k1-signer";
import { AddIdentityAction, borshUtils, Transaction } from "../utils/borsh";
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
import { expect } from "chai";

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
              Ethereum: new Uint8Array(
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

    const returnData = result?.meta?.returnData?.data[0];
    const decodedData = Buffer.from(returnData, "base64");

    const ethAddressLength = decodedData.readUInt32LE(0);
    const ethAddressHex = decodedData.slice(4, 4 + ethAddressLength).toString();
    expect(ethAddressHex).to.equal(ethSignature.address.slice(2).toLowerCase());

    const transactionDataStart = 4 + ethAddressLength;
    const transactionData = decodedData.slice(transactionDataStart);

    const deserializedTransaction =
      borshUtils.deserialize.transaction(transactionData);

    expect(deserializedTransaction.account_id.toString()).to.equal(
      transaction.account_id.toString()
    );
    expect(deserializedTransaction.nonce.toString()).to.equal(
      transaction.nonce.toString()
    );

    expect("AddIdentity" in deserializedTransaction.action).to.be.true;
    expect("AddIdentity" in transaction.action).to.be.true;

    if (
      "AddIdentity" in transaction.action &&
      "AddIdentity" in deserializedTransaction.action
    ) {
      const sentIdentity = transaction.action.AddIdentity;
      const receivedIdentity = deserializedTransaction.action.AddIdentity;

      expect("Wallet" in receivedIdentity.identity).to.be.true;
      expect("Wallet" in sentIdentity.identity).to.be.true;

      if (
        "Wallet" in sentIdentity.identity &&
        "Wallet" in receivedIdentity.identity
      ) {
        expect("Ethereum" in receivedIdentity.identity.Wallet).to.be.true;
        expect("Ethereum" in sentIdentity.identity.Wallet).to.be.true;

        if (
          "Ethereum" in sentIdentity.identity.Wallet &&
          "Ethereum" in receivedIdentity.identity.Wallet
        ) {
          expect(
            Buffer.from(receivedIdentity.identity.Wallet.Ethereum)
          ).to.deep.equal(Buffer.from(sentIdentity.identity.Wallet.Ethereum));
        }
      }

      expect(receivedIdentity.permissions).to.not.be.null;
      expect(sentIdentity.permissions).to.not.be.null;

      if (sentIdentity.permissions && receivedIdentity.permissions) {
        expect(receivedIdentity.permissions.enable_act_as).to.equal(
          sentIdentity.permissions.enable_act_as
        );
      }
    }
  });
});

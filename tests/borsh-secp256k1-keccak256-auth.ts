import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { signWithEthereum } from "../utils/secp256k1-signer";
import {
  borshUtils,
  Identity,
  IdentityWithPermissions,
  Transaction,
} from "../utils/borsh";
import { SolanaAa } from "../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../utils/solana";
import {
  parseEthereumSignature,
  ethereumAddressToBytes,
  createSecp256k1VerificationInstruction,
} from "../utils/ethereum";
import { keccak256, toBytes } from "viem";
import { expect } from "chai";
import * as _ from "lodash";
import { normalize } from "../utils/utils";

const PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const ETH_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

describe("Ethereum Signature Verification", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  async function verifyEthereumSignature(transaction: Transaction): Promise<{
    deserializedTransaction: Transaction;
    ethAddressHex: string;
  }> {
    const serializedMessage = Buffer.from(
      borshUtils.serialize.transaction(transaction)
    );

    const ethSignature = await signWithEthereum({
      hash: keccak256(serializedMessage),
      privateKey: PRIVATE_KEY,
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

    return { deserializedTransaction, ethAddressHex };
  }

  it("should validate Ethereum signature correctly", async () => {
    const transaction: Transaction = {
      account_id: 1n,
      nonce: 135n,
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

    const { deserializedTransaction } = await verifyEthereumSignature(
      transaction
    );

    const normalizedOriginal = normalize(transaction);
    const normalizedDeserialized = normalize(deserializedTransaction);

    expect(normalizedDeserialized).to.deep.equal(normalizedOriginal);
  });

  it("should verify a transaction with RemoveAccount action", async () => {
    const transaction: Transaction = {
      account_id: BigInt(1),
      nonce: BigInt(Date.now()),
      action: { RemoveAccount: {} },
    };

    const { deserializedTransaction } = await verifyEthereumSignature(
      transaction
    );

    const normalizedOriginal = normalize(transaction);
    const normalizedDeserialized = normalize(deserializedTransaction);

    expect(normalizedDeserialized).to.deep.equal(normalizedOriginal);
  });

  it("should verify a transaction with RemoveIdentity action", async () => {
    const identity: Identity = {
      Wallet: {
        Ethereum: toBytes(ETH_ADDRESS),
      },
    };

    const transaction: Transaction = {
      account_id: BigInt(1),
      nonce: BigInt(Date.now()),
      action: { RemoveIdentity: identity },
    };

    const { deserializedTransaction } = await verifyEthereumSignature(
      transaction
    );

    const normalizedOriginal = normalize(transaction);
    const normalizedDeserialized = normalize(deserializedTransaction);

    expect(normalizedDeserialized).to.deep.equal(normalizedOriginal);
  });

  it("should verify a transaction with AddIdentity action", async () => {
    const identity: Identity = {
      Wallet: {
        Ethereum: toBytes(ETH_ADDRESS),
      },
    };

    const identityWithPermissions: IdentityWithPermissions = {
      identity,
      permissions: {
        enable_act_as: true,
      },
    };

    const transaction: Transaction = {
      account_id: BigInt(1),
      nonce: BigInt(Date.now()),
      action: { AddIdentity: identityWithPermissions },
    };

    const { deserializedTransaction } = await verifyEthereumSignature(
      transaction
    );

    const normalizedOriginal = normalize(transaction);
    const normalizedDeserialized = normalize(deserializedTransaction);

    expect(normalizedDeserialized).to.deep.equal(normalizedOriginal);
  });
});

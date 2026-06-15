import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { signWithEthereum } from "../utils/secp256k1-signer";
import {
  borshUtils,
  Identity,
  IdentityWithPermissions,
  Transaction,
} from "../borsh";
import { SolanaAa } from "../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../utils/solana";
import {
  parseEthereumSignature,
  ethereumAddressToBytes,
  createSecp256k1VerificationInstruction,
  SECP256K1_PROGRAM_ID,
} from "../utils/ethereum";
import { keccak256, toBytes } from "viem";
import { expect } from "chai";
import _ from "lodash";
import { normalizeObject } from "../utils/utils";

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

    const normalizedOriginal = normalizeObject(transaction);
    const normalizedDeserialized = normalizeObject(deserializedTransaction);

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

    const normalizedOriginal = normalizeObject(transaction);
    const normalizedDeserialized = normalizeObject(deserializedTransaction);

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

    const normalizedOriginal = normalizeObject(transaction);
    const normalizedDeserialized = normalizeObject(deserializedTransaction);

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

    const normalizedOriginal = normalizeObject(transaction);
    const normalizedDeserialized = normalizeObject(deserializedTransaction);

    expect(normalizedDeserialized).to.deep.equal(normalizedOriginal);
  });

  // --- Negative cases: secp256k1 introspection (get_ek256_data_impl) ---
  // Each case is built so the native secp256k1 precompile ACCEPTS the
  // instruction; otherwise the runtime would abort before the program runs and
  // we would be exercising the precompile, not our own checks.

  const ETH_ADDRESS_2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

  const sampleTransaction: Transaction = {
    account_id: 1n,
    nonce: 7n,
    action: { RemoveAccount: {} },
  };
  const sampleMessage = Buffer.from(
    borshUtils.serialize.transaction(sampleTransaction)
  );

  async function buildValidSecp256k1Ix(
    privateKey: `0x${string}`,
    message: Buffer
  ): Promise<anchor.web3.TransactionInstruction> {
    const signed = await signWithEthereum({
      hash: keccak256(message),
      privateKey,
    });
    const { signature, recoveryId } = parseEthereumSignature(signed.signature);
    return createSecp256k1VerificationInstruction(
      signature,
      recoveryId,
      ethereumAddressToBytes(signed.address),
      message
    );
  }

  // A structurally valid secp256k1 instruction carrying TWO signatures (the same
  // one twice). The precompile verifies both; the program must reject anything
  // other than exactly one signature.
  async function buildTwoSignatureSecp256k1Ix(
    privateKey: `0x${string}`,
    message: Buffer
  ): Promise<anchor.web3.TransactionInstruction> {
    const signed = await signWithEthereum({
      hash: keccak256(message),
      privateKey,
    });
    const { signature, recoveryId } = parseEthereumSignature(signed.signature);
    const addr = ethereumAddressToBytes(signed.address);

    const NUM_SIGS = 2;
    const OFFSETS_SIZE = 11;
    const headerSize = 1 + NUM_SIGS * OFFSETS_SIZE;
    const blockSize = 20 + 64 + 1; // eth address + signature + recovery id
    const messageOffset = headerSize + NUM_SIGS * blockSize;
    const data = Buffer.alloc(messageOffset + message.length);

    data.writeUInt8(NUM_SIGS, 0);
    for (let i = 0; i < NUM_SIGS; i++) {
      const blockStart = headerSize + i * blockSize;
      const ethAddressOffset = blockStart;
      const signatureOffset = blockStart + 20;
      const recoveryIdOffset = blockStart + 20 + 64;
      const structAt = 1 + i * OFFSETS_SIZE;
      data.writeUInt16LE(signatureOffset, structAt);
      data.writeUInt8(0, structAt + 2);
      data.writeUInt16LE(ethAddressOffset, structAt + 3);
      data.writeUInt8(0, structAt + 5);
      data.writeUInt16LE(messageOffset, structAt + 6);
      data.writeUInt16LE(message.length, structAt + 8);
      data.writeUInt8(0, structAt + 10);

      addr.copy(data, ethAddressOffset);
      signature.copy(data, signatureOffset);
      data.writeUInt8(recoveryId, recoveryIdOffset);
    }
    message.copy(data, messageOffset);

    return new anchor.web3.TransactionInstruction({
      keys: [],
      programId: SECP256K1_PROGRAM_ID,
      data,
    });
  }

  async function expectGetEthDataError(
    preInstructions: anchor.web3.TransactionInstruction[],
    expectedError: string
  ) {
    try {
      await program.methods
        .getEthData()
        .accounts({
          instructions_sysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .preInstructions(preInstructions)
        .rpc();
      expect.fail("getEthData resolved but a rejection was expected");
    } catch (error: any) {
      expect(error.toString()).to.include(expectedError);
    }
  }

  it("rejects execution with no preceding verification instruction", async () => {
    await expectGetEthDataError([], "MissingVerificationInstruction");
  });

  it("rejects a preceding instruction that is not the secp256k1 program", async () => {
    await expectGetEthDataError(
      [
        anchor.web3.ComputeBudgetProgram.setComputeUnitLimit({
          units: 200_000,
        }),
      ],
      "InvalidVerificationInstruction"
    );
  });

  it("rejects an instruction carrying more than one signature", async () => {
    const ix = await buildTwoSignatureSecp256k1Ix(PRIVATE_KEY, sampleMessage);
    await expectGetEthDataError([ix], "MultipleSignaturesNotSupported");
  });

  it("rejects offsets that reference a different instruction", async () => {
    // The same valid instruction placed twice. Its offsets declare
    // instruction_index 0; for the instruction at index 1 (= secp_index) that
    // points at instruction 0, so the precompile still verifies (instruction 0
    // holds identical data) while the program rejects the cross-instruction
    // reference.
    const ix = await buildValidSecp256k1Ix(PRIVATE_KEY, sampleMessage);
    await expectGetEthDataError(
      [ix, ix],
      "DataInOtherInstructionsNotSupported"
    );
  });

  it("rejects a mismatched recovered address (verify_eth)", async () => {
    const ix = await buildValidSecp256k1Ix(PRIVATE_KEY, sampleMessage);
    try {
      await program.methods
        .verifyEth(sampleMessage, ETH_ADDRESS_2)
        .accounts({
          instructions_sysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .preInstructions([ix])
        .rpc();
      expect.fail("verifyEth resolved but a rejection was expected");
    } catch (error: any) {
      expect(error.toString()).to.include("AddressMismatch");
    }
  });

  it("rejects a mismatched signed message (verify_eth)", async () => {
    const ix = await buildValidSecp256k1Ix(PRIVATE_KEY, sampleMessage);
    const otherMessage = Buffer.from(
      borshUtils.serialize.transaction({
        account_id: 2n,
        nonce: 9n,
        action: { RemoveAccount: {} },
      })
    );
    try {
      await program.methods
        .verifyEth(otherMessage, ETH_ADDRESS)
        .accounts({
          instructions_sysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .preInstructions([ix])
        .rpc();
      expect.fail("verifyEth resolved but a rejection was expected");
    } catch (error: any) {
      expect(error.toString()).to.include("MessageMismatch");
    }
  });
});

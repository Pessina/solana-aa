import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  ComputeBudgetProgram,
  PublicKey,
  TransactionInstruction,
} from "@solana/web3.js";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import {
  confirmTransaction,
  getTransactionReturnValue,
  logComputeUnitsUsed,
} from "../utils/solana";
import {
  addEthereumMessagePrefix,
  parseEthereumSignature,
  ethereumAddressToBytes,
} from "../utils/ethereum";
import {
  SOLANA_MAX_COMPUTE_UNITS,
  SOLANA_PRE_COMPILED_ERRORS,
} from "../utils/constants";

const SECP256K1_PROGRAM_ID = new PublicKey(
  "KeccakSecp256k11111111111111111111111111111"
);

const SIGNATURE_OFFSETS_SERIALIZED_SIZE = 11;
const DATA_START = SIGNATURE_OFFSETS_SERIALIZED_SIZE + 1;
const SIGNATURE_SERIALIZED_SIZE = 64;
const HASHED_PUBKEY_SERIALIZED_SIZE = 20;

/**
 * Creates a secp256k1 verification instruction for Ethereum signatures
 */
function createSecp256k1VerificationInstruction(
  signature: Buffer,
  recoveryId: number,
  ethAddressBytes: Buffer,
  messageBytes: Buffer
): TransactionInstruction {
  const messageOffset =
    DATA_START + HASHED_PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE + 1;
  const messageSize = messageBytes.length;
  const instructionDataSize = messageOffset + messageSize;
  const instructionData = Buffer.alloc(instructionDataSize);

  instructionData.writeUInt8(1, 0);

  const ethAddressOffset = DATA_START;
  const signatureOffset = DATA_START + HASHED_PUBKEY_SERIALIZED_SIZE;
  const recoveryIdOffset =
    DATA_START + HASHED_PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE;

  const offsetsBuffer = Buffer.alloc(SIGNATURE_OFFSETS_SERIALIZED_SIZE);
  offsetsBuffer.writeUInt16LE(signatureOffset, 0);
  offsetsBuffer.writeUInt8(0, 2);
  offsetsBuffer.writeUInt16LE(ethAddressOffset, 3);
  offsetsBuffer.writeUInt8(0, 5);
  offsetsBuffer.writeUInt16LE(messageOffset, 6);
  offsetsBuffer.writeUInt16LE(messageSize, 8);
  offsetsBuffer.writeUInt8(0, 10);
  offsetsBuffer.copy(instructionData, 1);

  ethAddressBytes.copy(instructionData, ethAddressOffset);
  signature.copy(instructionData, signatureOffset);
  instructionData.writeUInt8(recoveryId, recoveryIdOffset);
  messageBytes.copy(instructionData, messageOffset);

  return new TransactionInstruction({
    keys: [],
    programId: SECP256K1_PROGRAM_ID,
    data: instructionData,
  });
}

/**
 * Prepares Ethereum data for verification
 */
function prepareEthereumData(
  ethData: { signature: string; message: string },
  ethAddress: string
) {
  const { signature, recoveryId } = parseEthereumSignature(ethData.signature);

  const messageWithPrefix = addEthereumMessagePrefix(ethData.message);
  const messageBytes = Buffer.from(messageWithPrefix, "utf8");

  const ethAddressBytes = ethereumAddressToBytes(ethAddress);

  return {
    signature,
    recoveryId,
    messageBytes,
    ethAddressBytes,
    ethDataArgs: {
      signature: ethData.signature,
      message: messageWithPrefix,
    },
  };
}

/**
 * Verifies an Ethereum signature by constructing a Secp256k1 instruction and calling the program.
 * @param programData - Data for the contract verification
 * @param nativeProgramData - Data for the precompiled program verification (optional)
 * @param options - Additional verification options
 * @returns Result of the verification operation
 */
async function verifyEthSignature({
  programData,
  nativeProgramData,
  options = {},
}: {
  programData: {
    signature: string;
    message: string;
    ethAddress: string;
  };
  nativeProgramData?: {
    signature?: string;
    message?: string;
    ethAddress?: string;
  };
  options?: {
    skipPrecompileVerification?: boolean;
    additionalInstructions?: TransactionInstruction[];
  };
}): Promise<{
  success: boolean;
  returnValue: 1 | 0 | null;
  error?: any;
  txSignature: string | null;
}> {
  const { skipPrecompileVerification = false, additionalInstructions = [] } =
    options;

  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;

  try {
    const {
      signature: contractSignature,
      recoveryId: contractRecoveryId,
      messageBytes: contractMessageBytes,
      ethAddressBytes: contractAddressBytes,
      ethDataArgs,
    } = prepareEthereumData(
      {
        signature: programData.signature,
        message: programData.message,
      },
      programData.ethAddress
    );

    const instructions = [...additionalInstructions];

    if (!skipPrecompileVerification) {
      const precompileSignature =
        nativeProgramData?.signature || programData.signature;
      const precompileMessage =
        nativeProgramData?.message || programData.message;
      const precompileAddress =
        nativeProgramData?.ethAddress || programData.ethAddress;

      let precompileSignatureBuffer: Buffer,
        precompileRecoveryId: number,
        precompileMessageBytes: Buffer,
        precompileAddressBytes: Buffer;

      if (
        precompileSignature !== programData.signature ||
        precompileMessage !== programData.message ||
        precompileAddress !== programData.ethAddress
      ) {
        if (precompileSignature !== programData.signature) {
          const parsed = parseEthereumSignature(precompileSignature);
          precompileSignatureBuffer = parsed.signature;
          precompileRecoveryId = parsed.recoveryId;
        } else {
          precompileSignatureBuffer = contractSignature;
          precompileRecoveryId = contractRecoveryId;
        }

        if (precompileMessage !== programData.message) {
          const precompileWithPrefix =
            addEthereumMessagePrefix(precompileMessage);
          precompileMessageBytes = Buffer.from(precompileWithPrefix, "utf8");
        } else {
          precompileMessageBytes = contractMessageBytes;
        }

        if (precompileAddress !== programData.ethAddress) {
          precompileAddressBytes = ethereumAddressToBytes(precompileAddress);
        } else {
          precompileAddressBytes = contractAddressBytes;
        }
      } else {
        precompileSignatureBuffer = contractSignature;
        precompileRecoveryId = contractRecoveryId;
        precompileMessageBytes = contractMessageBytes;
        precompileAddressBytes = contractAddressBytes;
      }

      const verificationInstruction = createSecp256k1VerificationInstruction(
        precompileSignatureBuffer,
        precompileRecoveryId,
        precompileAddressBytes,
        precompileMessageBytes
      );

      instructions.push(verificationInstruction);
    }

    const txSignature = await program.methods
      .verifyEthereumSignature(ethDataArgs, programData.ethAddress)
      .accounts({
        instructions_sysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .preInstructions(instructions)
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    const result = await getTransactionReturnValue<Uint8Array | null>(
      provider.connection,
      txSignature
    );

    return {
      txSignature,
      returnValue: result ? (result[0] as 0 | 1) : null,
      success: true,
    };
  } catch (error) {
    return {
      error,
      success: false,
      txSignature: null,
      returnValue: null,
    };
  }
}

describe("Ethereum Signature Verification", () => {
  anchor.setProvider(anchor.AnchorProvider.env());

  const TEST_INPUTS = {
    SET_1: {
      ETH_ADDRESS: "0x4174678c78fEaFd778c1ff319D5D326701449b25",
      INPUTS: [
        {
          SIGNATURE:
            "0xee6c2fbbf7aac694fad3a339fd293cb85468014be0e06f69f37377e6a79250c40301ff174204df48cb25921d93ca816d64ac9a675f3c19ad09351315c3c58d461b",
          MESSAGE:
            '{"account_id":"felipe-1234","action":{"AddIdentity":{"identity":{"Wallet":{"public_key":"0x0304ab3cb2897344aa3f6ffaac94e477aeac170b9235d2416203e2a72bc9b8a7c7","wallet_type":"Ethereum"}},"permissions":{"enable_act_as":false}}},"nonce":135}',
        },
        {
          SIGNATURE:
            "0x304842ae53be02b44f8658fd0cad7faeff556e4073e9367eaaa7cdddca216f2e1450bb97779a66ea9d57c3e036e5a01582cb98affca4ac0391cdd3323c5ab4511c",
          MESSAGE:
            '{"account_id":"felipe-1234","action":{"RemoveIdentity":{"Wallet":{"public_key":"0x0304ab3cb2897344aa3f6ffaac94e477aeac170b9235d2416203e2a72bc9b8a7c7","wallet_type":"Ethereum"}}},"nonce":136}',
        },
        {
          SIGNATURE:
            "0x490c54fe4cdcf16fdf3dea3a376c0c8b18a3e43960190e3cc490f9cf56031f8b650d796d2a63e5f5e8c990d50585ded2266115880c3504ffba2004603bc8faa31c",
          MESSAGE:
            '{"account_id":"felipe-1234","action":{"Sign":{"contract_id":"v1.signer-prod.testnet","payloads":[{"key_version":0,"path":"","payload":[73,182,212,181,169,186,176,251,251,166,237,0,44,6,211,221,164,196,67,218,252,168,127,199,138,162,253,57,51,236,7,173]}]}},"nonce":138}',
        },
      ],
    },
    SET_2: {
      ETH_ADDRESS: "0xC5fFedAd2701BeB8F70F4a7887A63f8E95db607a",
      INPUTS: [
        {
          SIGNATURE:
            "0x7de7f67fc96926eefb26e6a7772d25008350d8e10c0f663336ae13b109d089d30bc15318055b6343ff477c12006fbf49865c3edad248bd7cc13b414d46aafa211b",
          MESSAGE:
            '{"account_id":"felipe-1234","action":"AddIdentityWithAuth","nonce":"139","permissions":{"enable_act_as":false}}',
        },
        {
          SIGNATURE:
            "0xbbabc2f32d9d1bef538ed72b153f1bb0998e8d04833ef82f0e64951f403722b247ad83bbfd2f7f157396b9c0de71e538b3cbbc95f5cffc542dc6a17dbabb7d611b",
          MESSAGE:
            '{"account_id":"felipe-1234","action":{"RemoveIdentity":{"Wallet":{"public_key":"0x0304ab3cb2897344aa3f6ffaac94e477aeac170b9235d2416203e2a72bc9b8a7c7","wallet_type":"Ethereum"}}},"nonce":140}',
        },
        {
          SIGNATURE:
            "0x6ea8eafcd2dc326d5108de3fe1fa9cd6c5ab3a25ef9cd414d7781d3aa036520e39ea7202ad29403cc714f5a1d7aece3c84ecc719cdcb87c57be975a3ef30e1bf1c",
          MESSAGE:
            '{"account_id":"felipe-1234","action":{"Sign":{"contract_id":"v1.signer-prod.testnet","payloads":[{"key_version":0,"path":"","payload":[37,215,161,181,118,110,180,233,17,222,195,6,17,221,230,189,92,181,114,206,107,90,202,150,251,42,250,189,140,105,149,142]}]}},"nonce":141}',
        },
      ],
    },
  };

  it("should validate Ethereum signature correctly", async () => {
    const testPromises = [];

    for (const testSet of Object.values(TEST_INPUTS)) {
      const ethAddress = testSet.ETH_ADDRESS;

      for (const input of testSet.INPUTS) {
        const programData = {
          signature: input.SIGNATURE,
          message: input.MESSAGE,
          ethAddress: ethAddress,
        };

        testPromises.push(
          (async () => {
            const result = await verifyEthSignature({
              programData,
            });

            // logComputeUnitsUsed({
            //   txSignature: result.txSignature,
            // });

            assert.strictEqual(
              result.returnValue,
              1,
              `Should have a successful return value for address ${ethAddress}`
            );
          })()
        );
      }
    }

    await Promise.all(testPromises);
  });

  describe("Solana precompiled program errors", () => {
    it("should fail to validate Ethereum signature with wrong public key", async () => {
      const computeUnitsInstruction = ComputeBudgetProgram.setComputeUnitPrice({
        microLamports: SOLANA_MAX_COMPUTE_UNITS,
      });

      const testSet = TEST_INPUTS.SET_1;
      const wrongEthAddress = "0x1234567890123456789012345678901234567890";

      const programData = {
        signature: testSet.INPUTS[0].SIGNATURE,
        message: testSet.INPUTS[0].MESSAGE,
        ethAddress: wrongEthAddress,
      };

      const result = await verifyEthSignature({
        programData,
        options: {
          additionalInstructions: [computeUnitsInstruction],
        },
      });

      assert.strictEqual(
        result.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 1: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid signature error"
      );
    });

    it("should fail to validate Ethereum signature with tampered message", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const programData = {
        signature: testSet.INPUTS[0].SIGNATURE,
        message: testSet.INPUTS[0].MESSAGE + "tampered",
        ethAddress: testSet.ETH_ADDRESS,
      };

      const result = await verifyEthSignature({
        programData,
      });

      assert.strictEqual(
        result.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid signature error"
      );
    });

    it("should fail to validate Ethereum signature with invalid signature format", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const programData = {
        signature: "0x1234",
        message: testSet.INPUTS[0].MESSAGE,
        ethAddress: testSet.ETH_ADDRESS,
      };

      const error = await verifyEthSignature({
        programData,
      });

      assert.strictEqual(
        error.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid signature length error"
      );
    });

    it("should fail to validate Ethereum signature with invalid Ethereum address", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const programData = {
        signature: testSet.INPUTS[0].SIGNATURE,
        message: testSet.INPUTS[0].MESSAGE,
        ethAddress: "0x123",
      };

      const error = await verifyEthSignature({
        programData,
      });

      assert.strictEqual(
        error.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid address length error"
      );
    });

    it("should fail with address mismatch", async () => {
      const testSet = TEST_INPUTS.SET_1;
      const differentValidAddress = TEST_INPUTS.SET_2.ETH_ADDRESS;

      const programData = {
        signature: testSet.INPUTS[0].SIGNATURE,
        message: testSet.INPUTS[0].MESSAGE,
        ethAddress: differentValidAddress,
      };

      const result = await verifyEthSignature({
        programData,
      });

      assert.strictEqual(
        result.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid signature error due to address mismatch"
      );
    });
  });

  describe("Program errors", () => {
    it("should fail to validate Ethereum signature if there is no verification instruction", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const programData = {
        signature: testSet.INPUTS[0].SIGNATURE,
        message: testSet.INPUTS[0].MESSAGE,
        ethAddress: testSet.ETH_ADDRESS,
      };

      const result = await verifyEthSignature({
        programData,
        options: {
          skipPrecompileVerification: true,
        },
      });

      assert.include(
        result.error.error.errorMessage || "",
        "Missing secp256k1 verification instruction",
        "Should fail with missing verification instruction error"
      );
    });

    it("should fail when message in precompile differs from message in contract", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const programData = {
        signature: testSet.INPUTS[0].SIGNATURE,
        message: testSet.INPUTS[0].MESSAGE + " modified",
        ethAddress: testSet.ETH_ADDRESS,
      };

      const nativeProgramData = {
        message: testSet.INPUTS[0].MESSAGE,
      };

      const result = await verifyEthSignature({
        programData,
        nativeProgramData,
      });

      assert.include(
        result.error.error.errorMessage || "",
        "Message mismatch",
        "Should fail with message mismatch error in contract while precompile verification passes"
      );
    });

    it("should fail when ethereum address in precompile differs from address in contract", async () => {
      const testSet = TEST_INPUTS.SET_1;
      const testSet2 = TEST_INPUTS.SET_2;

      const programData = {
        signature: testSet.INPUTS[0].SIGNATURE,
        message: testSet.INPUTS[0].MESSAGE,
        ethAddress: testSet2.ETH_ADDRESS,
      };

      const nativeProgramData = {
        ethAddress: testSet.ETH_ADDRESS,
      };

      const result = await verifyEthSignature({
        programData,
        nativeProgramData,
      });

      assert.include(
        result.error.error.errorMessage || "",
        "Ethereum address mismatch",
        "Should fail with address mismatch error in contract while precompile verification passes"
      );
    });

    it("should fail when calling a different program instead of secp256k1", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const wrongProgramId = new PublicKey(
        "Secp256r1SigVerify1111111111111111111111111"
      );

      const fakeInstruction = new TransactionInstruction({
        keys: [],
        programId: wrongProgramId,
        data: Buffer.from(
          "01001000ffff5000ffff71004500fffff77969b7eaeaaed4b9a5cc5636b3755259d29d1406d8e852a8ce43dc74644da11453962702ea21a9efdd4a7077e39fcd754e3d01579493cf972f0151b6672f1f0220fb23e028391b72c517850b3cc83ba529ef4db766098a29bf3c8d06be95787849960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976319000000003c68c62d9fa1fb08819abcb3e7c184eff0fa41df9b9d29375768bbd03d76aa39",
          "hex"
        ),
      });

      const programData = {
        signature: testSet.INPUTS[0].SIGNATURE,
        message: testSet.INPUTS[0].MESSAGE,
        ethAddress: testSet.ETH_ADDRESS,
      };

      const result = await verifyEthSignature({
        programData,
        options: {
          skipPrecompileVerification: true,
          additionalInstructions: [fakeInstruction],
        },
      });

      assert.include(
        result.error.error.errorMessage || "",
        "Invalid verification instruction program ID",
        "Should fail with invalid verification instruction error when using wrong program ID"
      );
    });

    // TODO: I believe we don't need to check that the signature on our Program args is the same as the signature in the precompile, as we already know the message was signed by the address provided
    // it.only("should fail when signature in precompile differs from signature in contract", async () => {
    //   const testSet = TEST_INPUTS.SET_1;
    //   const testSet2 = TEST_INPUTS.SET_2;

    //   const programData = {
    //     signature: testSet2.INPUTS[0].SIGNATURE,
    //     message: testSet.INPUTS[0].MESSAGE,
    //     ethAddress: testSet.ETH_ADDRESS,
    //   };

    //   const nativeProgramData = {
    //     signature: testSet.INPUTS[0].SIGNATURE,
    //   };

    //   const result = await verifyEthSignature({
    //     programData,
    //     nativeProgramData,
    //   });

    //   console.log(result);

    //   assert.include(
    //     result.error.error.errorMessage || "",
    //     "Address mismatch",
    //     "Should fail with address mismatch error in contract while precompile verification passes"
    //   );
    // });
  });
});

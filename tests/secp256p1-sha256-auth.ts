import * as anchor from "@coral-xyz/anchor";
import { p256 } from "@noble/curves/p256";
import { createHash } from "crypto";
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
  SOLANA_MAX_COMPUTE_UNITS,
  SOLANA_PRE_COMPILED_ERRORS,
} from "../utils/constants";
import { toHex } from "viem";

const SECP256R1_PROGRAM_ID = new PublicKey(
  "Secp256r1SigVerify1111111111111111111111111"
);

const SIGNATURE_OFFSETS_SERIALIZED_SIZE = 14; // 7 fields * 2 bytes each
const DATA_START = 2; // 1 byte for number of signatures + 1 byte for padding
const HEADER_SIZE = DATA_START + SIGNATURE_OFFSETS_SERIALIZED_SIZE;
const INSTRUCTION_INDEX_NOT_USED = 0xffff;

/**
 * Creates a secp256r1 verification instruction for WebAuthn signatures
 */
function createSecp256r1VerificationInstruction(
  signature: Uint8Array,
  publicKey: Uint8Array,
  message: Uint8Array
): TransactionInstruction {
  const data = Buffer.alloc(
    HEADER_SIZE + signature.length + publicKey.length + message.length
  );

  data.writeUInt8(1, 0);
  data.writeUInt8(0, 1);

  const signatureOffset = HEADER_SIZE;
  const publicKeyOffset = signatureOffset + signature.length;
  const messageDataOffset = publicKeyOffset + publicKey.length;
  const messageDataSize = message.length;

  data.writeUInt16LE(signatureOffset, DATA_START);
  data.writeUInt16LE(INSTRUCTION_INDEX_NOT_USED, DATA_START + 2);
  data.writeUInt16LE(publicKeyOffset, DATA_START + 4);
  data.writeUInt16LE(INSTRUCTION_INDEX_NOT_USED, DATA_START + 6);
  data.writeUInt16LE(messageDataOffset, DATA_START + 8);
  data.writeUInt16LE(messageDataSize, DATA_START + 10);
  data.writeUInt16LE(INSTRUCTION_INDEX_NOT_USED, DATA_START + 12);

  Buffer.from(signature).copy(data, signatureOffset);
  Buffer.from(publicKey).copy(data, publicKeyOffset);
  Buffer.from(message).copy(data, messageDataOffset);

  return new TransactionInstruction({
    keys: [],
    programId: SECP256R1_PROGRAM_ID,
    data: data,
  });
}

/**
 * Prepares WebAuthn data for verification
 */
function prepareWebAuthnMessage(webauthnData: {
  signature: string;
  authenticatorData: string;
  clientData: string;
}) {
  const clientDataHash = createHash("sha256")
    .update(Buffer.from(webauthnData.clientData, "utf-8"))
    .digest();

  const authenticatorDataBuffer = Buffer.from(
    webauthnData.authenticatorData.slice(2),
    "hex"
  );
  const clientDataHashBuffer = Buffer.from(clientDataHash);

  const message = Buffer.concat([
    authenticatorDataBuffer,
    clientDataHashBuffer,
  ]);

  return message;
}

// Function to normalize an ECDSA signature by ensuring s is in the lower range
export function normalizeSignature(signature: string): string {
  const sigHex = signature.slice(2);
  let sigBuffer = Buffer.from(sigHex, "hex");

  const r = sigBuffer.slice(0, 32);
  const s = sigBuffer.slice(32, 64);

  // Check if s is in the upper range and normalize if needed
  const n = p256.CURVE.n;
  const sBigInt = BigInt("0x" + s.toString("hex"));

  // If s is in the upper range, compute n - s
  let normalizedS = sBigInt;
  if (sBigInt > n / BigInt(2)) {
    normalizedS = n - sBigInt;
  }

  const normalizedSBuffer = Buffer.from(
    normalizedS.toString(16).padStart(64, "0"),
    "hex"
  );

  const normalizedSig = Buffer.concat([r, normalizedSBuffer]);

  return toHex(normalizedSig);
}

/**
 * Helper function to verify WebAuthn signatures
 */
async function verifyWebauthnSignature({
  programData,
  nativeProgramData,
  options = {},
}: {
  programData: {
    signature: string;
    authenticatorData: string;
    clientData: string;
    compressedPublicKey: string;
  };
  nativeProgramData?: {
    signature?: string;
    authenticatorData?: string;
    clientData?: string;
    compressedPublicKey?: string;
  };
  options?: {
    addVerificationInstruction?: boolean;
    additionalInstructions?: TransactionInstruction[];
  };
}) {
  const { addVerificationInstruction = true, additionalInstructions = [] } =
    options;

  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  try {
    const message = prepareWebAuthnMessage(programData);

    const instructions = [...additionalInstructions];

    if (addVerificationInstruction) {
      const verificationSig =
        nativeProgramData?.signature || programData.signature;
      const verificationPubKey =
        nativeProgramData?.compressedPublicKey ||
        programData.compressedPublicKey;

      let verificationMessage = message;
      if (
        nativeProgramData?.authenticatorData ||
        nativeProgramData?.clientData
      ) {
        const nativeAuthData =
          nativeProgramData.authenticatorData || programData.authenticatorData;
        const nativeClientData =
          nativeProgramData.clientData || programData.clientData;

        const nativeWebAuthnDataObj = {
          signature: verificationSig,
          authenticatorData: nativeAuthData,
          clientData: nativeClientData,
        };

        verificationMessage = prepareWebAuthnMessage(nativeWebAuthnDataObj);
      }

      // Normalize the signature to ensure s is in the lower range
      const normalizedSignature = normalizeSignature(verificationSig);
      const signatureBytes = Buffer.from(normalizedSignature.slice(2), "hex");
      const publicKeyBytes = Buffer.from(verificationPubKey.slice(2), "hex");

      const verificationInstruction = createSecp256r1VerificationInstruction(
        signatureBytes,
        publicKeyBytes,
        verificationMessage
      );
      instructions.push(verificationInstruction);
    }

    const txSignature = await program.methods
      .verifyWebauthn(message, programData.compressedPublicKey)
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

describe("WebAuthn Authentication", () => {
  anchor.setProvider(anchor.AnchorProvider.env());

  const TEST_INPUTS = {
    SET_1: {
      COMPRESSED_PUBLIC_KEY:
        "0x020a34c8cfba4e32bdd93427cd30ddfe256adc6b101257282768f0f42af231b07f",
      INPUTS: [
        {
          CLIENT_DATA:
            '{"type":"webauthn.get","challenge":"arbU40dsETYiCh-EVZnhYr6LCwGXYEdMuT9TkPYIfkM","origin":"http://localhost:3000","crossOrigin":false}',
          AUTHENTICATOR_DATA:
            "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
          SIGNATURE:
            "0x54cdfd0dd30cf52e65345db8e151c0533c5fd51e894da5d93e6ad894643908032bacf1600319e6f22c3702c726c8734452f589ff1058f4cd53e5fc5d48876349",
        },
        {
          CLIENT_DATA:
            '{"type":"webauthn.get","challenge":"yJbTAOV9R_J-GVGsRDzquIWSjE4IervE7zjI5BX8UG4","origin":"http://localhost:3000","crossOrigin":false}',
          AUTHENTICATOR_DATA:
            "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
          SIGNATURE:
            "0x8549305067d642d5b7fd18f31b116752bf746cc283b0cc356beba35994e766893bce4c1c146cf0e247a865ded8e18db824bac0eef4e82acd4be8aafd17c203a0",
        },
        {
          CLIENT_DATA:
            '{"type":"webauthn.get","challenge":"s1BkcpB2a4MNysBrTKU3ruFP6N6AW5Nnf66UsQUebLQ","origin":"http://localhost:3000","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}',
          AUTHENTICATOR_DATA:
            "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
          SIGNATURE:
            "0xdbad2925d6958b4d17bb71bec492a680bc919db69e1577ff62ffe748f131220951e1aab36feae93baa75d7afaea9ad6730de031eeba309e0dfe9e5472199440d",
        },
      ],
    },
    SET_2: {
      COMPRESSED_PUBLIC_KEY:
        "0x031a08c5e977ab0a71d1ac3e5b8c435a431afb4c6d641b00a8b91496c5b085e6a3",
      INPUTS: [
        {
          CLIENT_DATA:
            '{"type":"webauthn.get","challenge":"DrZECYyV1n-dEUgWnwHu9_vun9jvTs6R_fIkDcwhwgA","origin":"http://localhost:3000","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}',
          AUTHENTICATOR_DATA:
            "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
          SIGNATURE:
            "0xd007d9c2850714db0addabe30b05fc3d1605cd9c4d848c794fd11fca184012c27262d46e06caff500847d800219fa16400ed751017146ae2bf7ddf8267fcda5b",
        },
        {
          CLIENT_DATA:
            '{"type":"webauthn.get","challenge":"7NEINnchZ-NH77mImg2kMibaTnOKjPyFn_-lYaD8Bh8","origin":"http://localhost:3000","crossOrigin":false}',
          AUTHENTICATOR_DATA:
            "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
          SIGNATURE:
            "0x7bcaded9357738fa21bca7cc6f4f37e7a366f03498678188fcf35cea66f2dbcd28455b66e1cc23b9b73a0238ec43160b2b63b305d1f1a4ab4651099ea46036ff",
        },
        {
          CLIENT_DATA:
            '{"type":"webauthn.get","challenge":"4SzZvQR_13EYvnAvUF0Qq78E07BiBSZKKNvvMVQbpyo","origin":"http://localhost:3000","crossOrigin":false}',
          AUTHENTICATOR_DATA:
            "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
          SIGNATURE:
            "0x23c70b2fa596b1c56ffc3f43567ccf86ddf910304ac32eb2d44ad59e0e4e3441c9f2c9c57cecb348e6ed6e5b2a242a477089b010f5bc62862c91d4ee4741c4c4",
        },
        {
          CLIENT_DATA:
            '{"type":"webauthn.get","challenge":"t104YSAE6yY189ZssLhescOSBvoDuZrLKY0or213EWA","origin":"http://localhost:3000","crossOrigin":false}',
          AUTHENTICATOR_DATA:
            "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
          SIGNATURE:
            "0xde8ea52c002f4adcfaf4d4e0d414156631363a1c09283b3fe21f775fb27be561bbddbaa8eda06979eb290326fda890a9a7ce0919aeb6b3b03999d63f8bb97155",
        },
      ],
    },
  };

  it("should validate WebAuthn signature correctly", async () => {
    const testPromises = [];

    for (const testSet of Object.values(TEST_INPUTS)) {
      const compressedPublicKey = testSet.COMPRESSED_PUBLIC_KEY;

      for (const input of testSet.INPUTS) {
        testPromises.push(
          (async () => {
            const result = await verifyWebauthnSignature({
              programData: {
                clientData: input.CLIENT_DATA,
                authenticatorData: input.AUTHENTICATOR_DATA,
                signature: input.SIGNATURE,
                compressedPublicKey,
              },
            });

            // logComputeUnitsUsed({
            //   txSignature: result.txSignature,
            // });

            assert.strictEqual(
              result.returnValue,
              1,
              `Should have a successful return value for public key ${compressedPublicKey}`
            );
          })()
        );
      }
    }

    await Promise.all(testPromises);
  });

  describe("Solana precompiled program errors", () => {
    it("should fail to validate WebAuthn signature with wrong public key", async () => {
      const testSet = TEST_INPUTS.SET_1;
      const wrongPublicKey =
        "0x031a08c5e977ab0a71d1ac3e5b8c435a431afb4c6d641b00a8b91496c5b085e6a4"; // Different last digit

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: wrongPublicKey,
        },
      });

      assert.strictEqual(
        result.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_PUBLIC_KEY}`,
        "Should fail with invalid signature error due to wrong public key"
      );
    });

    it("should fail to validate WebAuthn signature with tampered client data", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA + "tampered",
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: testSet.COMPRESSED_PUBLIC_KEY,
        },
      });

      assert.strictEqual(
        result.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid signature error due to tampered client data"
      );
    });

    it("should fail to validate WebAuthn signature with tampered authenticator data", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
          authenticatorData:
            "0x59960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000", // First byte changed
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: testSet.COMPRESSED_PUBLIC_KEY,
        },
      });

      assert.strictEqual(
        result.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid signature error due to tampered authenticator data"
      );
    });

    it("should fail to validate WebAuthn signature with invalid signature format", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
          signature:
            "0xde8ea52c002f4adcfaf4d4e0d414156631363a1c09283b3fe21f775fb27be561bbddbaa8eda06979eb290326fda890a9a7ce0919aeb6b3b03999d63f8bb97154", // Changed last hex
          compressedPublicKey: testSet.COMPRESSED_PUBLIC_KEY,
        },
      });

      assert.strictEqual(
        result.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid signature format error"
      );
    });

    it("should fail with public key mismatch", async () => {
      const testSet = TEST_INPUTS.SET_1;
      const differentValidPublicKey = TEST_INPUTS.SET_2.COMPRESSED_PUBLIC_KEY;

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: differentValidPublicKey,
        },
      });

      assert.strictEqual(
        result.error.transactionMessage,
        `Transaction simulation failed: Error processing Instruction 0: custom program error: ${SOLANA_PRE_COMPILED_ERRORS.INVALID_SIGNATURE}`,
        "Should fail with invalid signature error due to public key mismatch"
      );
    });
  });

  describe("Program errors", () => {
    it("should fail to validate WebAuthn signature if there is no verification instruction", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: testSet.COMPRESSED_PUBLIC_KEY,
        },
        options: { addVerificationInstruction: false },
      });

      assert.strictEqual(
        result.error.error.errorMessage,
        "Missing secp256r1 verification instruction",
        "Should fail with missing verification instruction error"
      );
    });

    it("should fail when client data in precompile differs from client data in contract", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA + " modified",
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: testSet.COMPRESSED_PUBLIC_KEY,
        },
        nativeProgramData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
        },
      });

      assert.strictEqual(
        result.error.error.errorMessage || "",
        "Signed data mismatch",
        "Should fail with message mismatch error in contract while precompile verification passes"
      );
    });

    it("should fail when authenticator data in precompile differs from authenticator data in contract", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
          authenticatorData:
            "0x59960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000", // Modified first byte
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: testSet.COMPRESSED_PUBLIC_KEY,
        },
        nativeProgramData: {
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
        },
      });

      assert.strictEqual(
        result.error.error.errorMessage || "",
        "Signed data mismatch",
        "Should fail with message mismatch error in contract while precompile verification passes"
      );
    });

    it("should fail when public key in precompile differs from public key in contract", async () => {
      const testSet = TEST_INPUTS.SET_1;
      const testSet2 = TEST_INPUTS.SET_2;
      const wrongCompressedPublicKey = testSet2.COMPRESSED_PUBLIC_KEY;

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: wrongCompressedPublicKey,
        },
        nativeProgramData: {
          compressedPublicKey: testSet.COMPRESSED_PUBLIC_KEY,
        },
      });

      assert.strictEqual(
        result.error.error.errorMessage || "",
        "Public key mismatch",
        "Should fail with public key mismatch error in contract while precompile verification passes"
      );
    });

    it("should fail when calling a different program instead of secp256r1", async () => {
      const testSet = TEST_INPUTS.SET_1;

      const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit(
        {
          units: SOLANA_MAX_COMPUTE_UNITS,
        }
      );

      const result = await verifyWebauthnSignature({
        programData: {
          clientData: testSet.INPUTS[0].CLIENT_DATA,
          authenticatorData: testSet.INPUTS[0].AUTHENTICATOR_DATA,
          signature: testSet.INPUTS[0].SIGNATURE,
          compressedPublicKey: testSet.COMPRESSED_PUBLIC_KEY,
        },
        options: {
          addVerificationInstruction: false,
          additionalInstructions: [computeBudgetInstruction],
        },
      });

      assert.strictEqual(
        result.error.error.errorMessage || "",
        "Invalid verification instruction program ID",
        "Should fail with invalid verification instruction error when using wrong program ID"
      );
    });
  });
});

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../utils/solana";
import { expect } from "chai";
import { createHash } from "crypto";
import { ComputeBudgetProgram } from "@solana/web3.js";

// Helper function to decode base64url
function base64urlDecode(input: string): Uint8Array {
  let padded = input;
  while (padded.length % 4 !== 0) {
    padded += "=";
  }
  const base64String = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64String, "base64");
}

// Helper function to process JWT token off-chain (production-ready implementation)
function processJwtToken(token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const [header, payload, signature] = parts;

  // Decode header to extract kid and algorithm
  const headerBytes = base64urlDecode(header);
  const headerData = JSON.parse(Buffer.from(headerBytes).toString("utf8"));

  const kid = headerData.kid;
  const alg = headerData.alg;

  // Decode payload to extract issuer
  const payloadBytes = base64urlDecode(payload);
  const payloadData = JSON.parse(Buffer.from(payloadBytes).toString("utf8"));
  const iss = payloadData.iss;

  // Verify algorithm is RS256 (only supported algorithm)
  if (alg !== "RS256") {
    throw new Error(`Unsupported algorithm: ${alg}. Only RS256 is supported.`);
  }

  // Map kid to key index (Google specific)
  let keyIndex: number;
  switch (kid) {
    case "89ce3598c473af1bda4bff95e6c8736450206fba":
      keyIndex = 0;
      break;
    case "dd125d5f462fbc6014aedab81ddf3bcedab70847":
      keyIndex = 1;
      break;
    default:
      throw new Error(`Unknown kid: ${kid}`);
  }

  // Map provider
  let provider: any;
  if (iss.includes("google")) {
    provider = { google: {} };
  } else {
    throw new Error(`Unsupported provider: ${iss}`);
  }

  // Create signing input (header.payload)
  const signingInput = `${header}.${payload}`;
  const signingInputBytes = Buffer.from(signingInput, "utf8");

  // Decode signature
  const signatureBytes = Buffer.from(base64urlDecode(signature));

  return {
    signingInput: signingInputBytes,
    signature: signatureBytes,
    provider,
    keyIndex,
  };
}

// Helper function to create optimized verification data
function createOptimizedVerificationData(token: string) {
  const baseData = processJwtToken(token);

  // Create SHA-256 hash of signing input instead of sending full input
  const signingInputHash = createHash("sha256")
    .update(baseData.signingInput)
    .digest();

  // Use hash instead of full signing input to reduce transaction size
  return {
    signingInputHash: Array.from(signingInputHash), // Convert to array for Borsh serialization
    signature: baseData.signature,
    provider: baseData.provider,
    keyIndex: baseData.keyIndex,
    // Add metadata for debugging
    _metadata: {
      originalSize: baseData.signingInput.length + baseData.signature.length,
      signingInputSize: baseData.signingInput.length,
      signatureSize: baseData.signature.length,
      signingInputHash: signingInputHash.toString("hex"),
      optimizedSize: 32 + baseData.signature.length, // hash + signature
    },
  };
}

describe("RSA OIDC Verification", () => {
  it.only("should verify Google OIDC token with optimized data transmission", async () => {
    // Process JWT token off-chain with optimizations
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);
    const verificationData = optimizedVerificationData;

    // Keep using Buffer as required by Anchor, but strip metadata before sending
    const optimizedData = {
      signingInputHash: verificationData.signingInputHash,
      signature: verificationData.signature,
      provider: verificationData.provider,
      keyIndex: verificationData.keyIndex,
    };

    try {
      // Call Solana program for RSA verification
      const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit(
        {
          units: 100_000, // NATIVE: Much lower CU requirement (~2K-5K vs 1.4M with BigUint)
        }
      );

      const txSignature = await program.methods
        .verifyOidcRsaNative(optimizedData) // Using NATIVE endpoint with Solana big_mod_exp syscall
        .accounts({
          signer: provider.wallet.publicKey,
        })
        .preInstructions([computeBudgetInstruction])
        .rpc({
          commitment: "confirmed",
        });

      await confirmTransaction(provider.connection, txSignature);

      // Get transaction info to check compute units used
      const txInfo = await getTxInfo({ txSignature });
      const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

      console.log(
        `💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`
      );

      // Get the return data
      const returnData = txInfo?.meta?.returnData?.data[0];
      if (!returnData) {
        throw new Error("No return data found");
      }

      const decodedData = Buffer.from(returnData, "base64");
      const result = decodedData.readUInt8(0) === 1;

      expect(result).to.be.true;
    } catch (error: any) {
      console.error("❌ Error details:", error);

      // Check if it's a transaction size error
      if (error.message && error.message.includes("overruns Buffer")) {
        console.error(
          "🚨 TRANSACTION SIZE ERROR - Data too large for Solana transaction"
        );
        console.error("💡 Possible solutions:");
        console.error("   1. Use account-based storage for large data");
        console.error("   2. Split data across multiple instructions");
        console.error(
          "   3. Use hash-based verification instead of full signature"
        );
      }

      throw error;
    }
  });

  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  // Real Google JWT token from the user
  const validToken =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg5Y2UzNTk4YzQ3M2FmMWJkYTRiZmY5NWU2Yzg3MzY0NTAyMDZmYmEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3Mzk5MTEwNjk3OTctaWRwMDYyODY2OTY0Z2JuZG82NjkzaDMydGdhNWN2bDEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3Mzk5MTEwNjk3OTctaWRwMDYyODY2OTY0Z2JuZG82NjkzaDMydGdhNWN2bDEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTc5MDI4NTUzNzMxNTc0MTAzMzAiLCJlbWFpbCI6ImZzLnBlc3NpbmFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoidGVzdF8xMjNfZmVsaXBlIiwibmJmIjoxNzM2NTIzMjM2LCJuYW1lIjoiRmVsaXBlIFBlc3NpbmEiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSktKYlV5QlZxQ0J2NHFWR09EU25WVGdMSFBLTjB0Vk9NSU1YVml1a2dyZC0wdGZlZFU9czk2LWMiLCJnaXZlbl9uYW1lIjoiRmVsaXBlIiwiZmFtaWx5X25hbWUiOiJQZXNzaW5hIiwiaWF0IjoxNzM2NTIzNTM2LCJleHAiOjE3MzY1MjcxMzYsImp0aSI6ImY3MjdlZjg1MGFhNzNmMDQ3ZmQwNjY5OWIwNjk3YTIwMDIzYWViYWMifQ.nlRKhlzBhHVpYejoSkH_S9ZOeAejlhvnL5u-94AzsREIhzuKroJbPp9jEHuvvki5dJozc-FzXx9lfpjT17X6PT0hJOM86QUE05RkmV9WkrVSr8trr1zbHY6dieii9tzj7c01pXsLJTa2FvTonmJAxDteVt_vsZFl7-pRWmyXKLMk4CFv9AZx20-uj5pDLuj-F5IkAk_cpXBuMJYh5PQeNBDk22d5svDTQkuwUAH5N9sssXRzDNdv92snGu4AykpmoPIJeSmc3EY-RW0TB5bAnwXH0E3keAjv84yrNYjnovYn2FRqKbTKxNxN4XUgWU_P0oRYCzckJznwz4tStaYZ2A";

  it.only("should successfully verify valid Google OIDC token", async () => {
    // Process JWT token off-chain
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);
    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    // Call Solana program for RSA verification
    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 100_000, // NATIVE: Much lower CU requirement (~2K-5K vs 1.4M with BigUint)
    });

    const txSignature = await program.methods
      .verifyOidcRsaNative(verificationData) // Using NATIVE endpoint with Solana big_mod_exp syscall
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    // Get transaction info to check compute units used
    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(`💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`);

    // Get the return data
    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1; // Boolean is serialized as 1 byte

    // This should succeed with the real Google token
    expect(result).to.be.true;
  });

  it.only("should fail verification with corrupted signature", async () => {
    // Process JWT token off-chain
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);

    // Corrupt the signature to make verification fail
    const corruptedSignature = Buffer.from(optimizedVerificationData.signature);
    corruptedSignature[0] = (corruptedSignature[0] + 1) % 256;

    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: corruptedSignature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    // Call Solana program for RSA verification
    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 100_000, // NATIVE: Much lower CU requirement
    });

    const txSignature = await program.methods
      .verifyOidcRsaNative(verificationData) // Using NATIVE endpoint with Solana big_mod_exp syscall
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    // Get transaction info to check compute units used
    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(`💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`);

    // Get the return data
    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1; // Boolean is serialized as 1 byte

    // This should fail with the corrupted signature
    expect(result).to.be.false;
  });

  it.only("should fail verification with wrong key index", async () => {
    // Process JWT token off-chain
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);

    // Use wrong key index to make verification fail
    const originalKeyIndex = optimizedVerificationData.keyIndex;
    const wrongKeyIndex = originalKeyIndex === 0 ? 1 : 0;

    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: wrongKeyIndex,
    };

    // Call Solana program for RSA verification
    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 100_000, // NATIVE: Much lower CU requirement
    });

    const txSignature = await program.methods
      .verifyOidcRsaNative(verificationData) // Using NATIVE endpoint with Solana big_mod_exp syscall
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    // Get transaction info to check compute units used
    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(`💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`);

    // Get the return data
    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1; // Boolean is serialized as 1 byte

    // This should fail with the wrong key
    expect(result).to.be.false;
  });
});

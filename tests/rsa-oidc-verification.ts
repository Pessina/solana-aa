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

  console.log("🔍 JWT Analysis:");
  console.log(`  - Algorithm: ${alg}`);
  console.log(`  - Key ID: ${kid}`);
  console.log(`  - Issuer: ${iss}`);
  console.log(`  - Subject: ${payloadData.sub}`);
  console.log(`  - Email: ${payloadData.email}`);

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

  // For large signing inputs, we can try several optimizations:

  // Option 1: Compress the signing input if it's text-based
  const signingInputStr = baseData.signingInput.toString("utf8");
  console.log(
    "📝 Original signing input preview:",
    signingInputStr.substring(0, 100) + "..."
  );

  // Option 2: Instead of sending full signing input, send its hash
  // (Note: This would require changing the Rust code to hash the input and compare)
  const signingInputHash = createHash("sha256")
    .update(baseData.signingInput)
    .digest();
  console.log(
    "🔐 SHA256 hash of signing input:",
    signingInputHash.toString("hex")
  );

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
    console.log("🧪 Testing RSA verification with optimized data");

    console.log("📝 Processing JWT token off-chain with optimizations...");
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);
    const verificationData = optimizedVerificationData;

    // Log detailed data analysis
    console.log("📊 Data Analysis:");
    console.log(
      `  - Signing Input: ${verificationData._metadata.signingInputSize} bytes`
    );
    console.log(
      `  - Signature: ${verificationData._metadata.signatureSize} bytes`
    );
    console.log(
      `  - Total core data: ${verificationData._metadata.originalSize} bytes`
    );
    console.log(
      `  - Signing Input Hash: ${verificationData._metadata.signingInputHash}`
    );

    // Calculate the actual Borsh serialization size with hash optimization
    const borshTestData = {
      signingInputHash: verificationData.signingInputHash,
      signature: Array.from(verificationData.signature),
      provider: verificationData.provider,
      keyIndex: verificationData.keyIndex,
    };

    // Estimate serialized size more accurately
    const jsonSize = JSON.stringify(borshTestData).length;
    const estimatedBorshSize = 32 + verificationData.signature.length + 50; // hash + signature + other fields

    console.log("📏 Size Estimates:");
    console.log(`  - JSON representation: ${jsonSize} bytes`);
    console.log(`  - Estimated Borsh size: ${estimatedBorshSize} bytes`);
    console.log(`  - Solana transaction limit: ~1232 bytes`);
    console.log(
      `  - Size reduction: ${
        verificationData._metadata.originalSize -
        verificationData._metadata.optimizedSize
      } bytes`
    );

    if (estimatedBorshSize > 1200) {
      console.warn(
        "⚠️  WARNING: Data size may exceed Solana transaction limits!"
      );
    } else {
      console.log(
        "✅ Optimized data should fit within Solana transaction limits!"
      );
    }

    // Keep using Buffer as required by Anchor, but strip metadata before sending
    const optimizedData = {
      signingInputHash: verificationData.signingInputHash,
      signature: verificationData.signature,
      provider: verificationData.provider,
      keyIndex: verificationData.keyIndex,
    };

    console.log("🔧 Final data structure ready for transmission:");

    console.log("🔧 Optimized data created, attempting transmission...");

    try {
      console.log("🔐 Calling Solana program for RSA verification...");
      const startTime = Date.now();

      // Create compute budget instruction to increase compute units for RSA verification
      const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit(
        {
          units: 1_600_000, // Increase to 1.6M for RSA operations (was consuming 1.399M)
        }
      );

      const txSignature = await program.methods
        .verifyOidcRsa(optimizedData)
        .accounts({
          signer: provider.wallet.publicKey,
        })
        .preInstructions([computeBudgetInstruction])
        .rpc({
          commitment: "confirmed",
        });

      await confirmTransaction(provider.connection, txSignature);
      const duration = Date.now() - startTime;

      // Get transaction info to check compute units used
      const txInfo = await getTxInfo({ txSignature });
      const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

      console.log(`⚡ Transaction completed in: ${duration}ms`);
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

      console.log(
        `🎯 Verification Result: ${result ? "SUCCESS ✅" : "FAILED ❌"}`
      );
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

  it("should successfully verify valid Google OIDC token", async () => {
    console.log("🧪 Testing RSA verification - SUCCESS case");

    console.log("📝 Processing JWT token off-chain...");
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);
    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    console.log("✅ Processed verification data:");
    console.log(`  - Provider: Google`);
    console.log(`  - Key Index: ${verificationData.keyIndex}`);
    console.log(`  - Signing Input Hash: 32 bytes`);
    console.log(
      `  - Signature Length: ${verificationData.signature.length} bytes`
    );

    console.log("🔐 Calling Solana program for RSA verification...");
    const startTime = Date.now();

    // Create compute budget instruction to increase compute units for RSA verification
    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000, // Increase from default 200k to 1.4M for RSA operations
    });

    const txSignature = await program.methods
      .verifyOidcRsa(verificationData)
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);
    const duration = Date.now() - startTime;

    // Get transaction info to check compute units used
    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(`⚡ Transaction completed in: ${duration}ms`);
    console.log(`💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`);

    // Get the return data
    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1; // Boolean is serialized as 1 byte

    console.log(
      `🎯 Verification Result: ${result ? "SUCCESS ✅" : "FAILED ❌"}`
    );

    // This should succeed with the real Google token
    expect(result).to.be.true;
  });

  it("should fail verification with corrupted signature", async () => {
    console.log("🧪 Testing RSA verification - FAILURE case");

    console.log("📝 Processing JWT token off-chain...");
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);

    // Corrupt the signature to make verification fail
    console.log("💥 Corrupting signature to force failure...");
    const corruptedSignature = Buffer.from(optimizedVerificationData.signature);
    corruptedSignature[0] = (corruptedSignature[0] + 1) % 256;

    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: corruptedSignature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    console.log("✅ Processed verification data (with corrupted signature):");
    console.log(`  - Provider: Google`);
    console.log(`  - Key Index: ${verificationData.keyIndex}`);
    console.log(`  - Signing Input Hash: 32 bytes`);
    console.log(
      `  - Signature Length: ${verificationData.signature.length} bytes`
    );

    console.log("🔐 Calling Solana program for RSA verification...");
    const startTime = Date.now();

    // Create compute budget instruction to increase compute units for RSA verification
    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000, // Increase from default 200k to 1.4M for RSA operations
    });

    const txSignature = await program.methods
      .verifyOidcRsa(verificationData)
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);
    const duration = Date.now() - startTime;

    // Get transaction info to check compute units used
    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(`⚡ Transaction completed in: ${duration}ms`);
    console.log(`💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`);

    // Get the return data
    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1; // Boolean is serialized as 1 byte

    console.log(
      `🎯 Verification Result: ${result ? "SUCCESS ✅" : "FAILED ❌"}`
    );

    // This should fail with the corrupted signature
    expect(result).to.be.false;
  });

  it("should fail verification with wrong key index", async () => {
    console.log("🧪 Testing RSA verification - WRONG KEY case");

    console.log("📝 Processing JWT token off-chain...");
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);

    // Use wrong key index to make verification fail
    console.log("🔑 Using wrong key index to force failure...");
    const originalKeyIndex = optimizedVerificationData.keyIndex;
    const wrongKeyIndex = originalKeyIndex === 0 ? 1 : 0;

    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: wrongKeyIndex,
    };

    console.log("✅ Processed verification data (with wrong key index):");
    console.log(`  - Provider: Google`);
    console.log(
      `  - Key Index: ${verificationData.keyIndex} (original: ${originalKeyIndex})`
    );
    console.log(`  - Signing Input Hash: 32 bytes`);
    console.log(
      `  - Signature Length: ${verificationData.signature.length} bytes`
    );

    console.log("🔐 Calling Solana program for RSA verification...");
    const startTime = Date.now();

    // Create compute budget instruction to increase compute units for RSA verification
    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000, // Increase from default 200k to 1.4M for RSA operations
    });

    const txSignature = await program.methods
      .verifyOidcRsa(verificationData)
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);
    const duration = Date.now() - startTime;

    // Get transaction info to check compute units used
    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(`⚡ Transaction completed in: ${duration}ms`);
    console.log(`💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`);

    // Get the return data
    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1; // Boolean is serialized as 1 byte

    console.log(
      `🎯 Verification Result: ${result ? "SUCCESS ✅" : "FAILED ❌"}`
    );

    // This should fail with the wrong key
    expect(result).to.be.false;
  });
});

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../utils/solana";
import { expect } from "chai";
import { createHash } from "crypto";
import { ComputeBudgetProgram, Keypair, PublicKey } from "@solana/web3.js";

function base64urlDecode(input: string): Uint8Array {
  let padded = input;
  while (padded.length % 4 !== 0) {
    padded += "=";
  }
  const base64String = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64String, "base64");
}

function processJwtToken(token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const [header, payload, signature] = parts;

  const headerBytes = base64urlDecode(header);
  const headerData = JSON.parse(Buffer.from(headerBytes).toString("utf8"));
  const kid = headerData.kid;
  const alg = headerData.alg;

  if (alg !== "RS256") {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  // Map kid to key index
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

  let provider: any;
  if (headerData.iss?.includes("google")) {
    provider = { google: {} };
  } else {
    throw new Error(`Unsupported provider`);
  }

  const signingInput = `${header}.${payload}`;
  const signingInputBytes = Buffer.from(signingInput, "utf8");
  const signatureBytes = Buffer.from(base64urlDecode(signature));

  return {
    signingInput: signingInputBytes,
    signature: signatureBytes,
    provider,
    keyIndex,
  };
}

function createOptimizedVerificationData(token: string) {
  const baseData = processJwtToken(token);
  const signingInputHash = createHash("sha256")
    .update(baseData.signingInput)
    .digest();

  return {
    signingInputHash: Array.from(signingInputHash),
    signature: baseData.signature,
    provider: baseData.provider,
    keyIndex: baseData.keyIndex,
  };
}

describe("RSA OIDC Verification - Simplified Implementation", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  const validToken =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg5Y2UzNTk4YzQ3M2FmMWJkYTRiZmY5NWU2Yzg3MzY0NTAyMDZmYmEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3Mzk5MTEwNjk3OTctaWRwMDYyODY2OTY0Z2JuZG82NjkzaDMydGdhNWN2bDEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3Mzk5MTEwNjk3OTctaWRwMDYyODY2OTY0Z2JuZG82NjkzaDMydGdhNWN2bDEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTc5MDI4NTUzNzMxNTc0MTAzMzAiLCJlbWFpbCI6ImZzLnBlc3NpbmFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoidGVzdF8xMjNfZmVsaXBlIiwibmJmIjoxNzM2NTIzMjM2LCJuYW1lIjoiRmVsaXBlIFBlc3NpbmEiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSktKYlV5QlZxQ0J2NHFWR09EU25WVGdMSFBLTjB0Vk9NSU1YVml1a2dyZC0wdGZlZFU9czk2LWMiLCJnaXZlbl9uYW1lIjoiRmVsaXBlIiwiZmFtaWx5X25hbWUiOiJQZXNzaW5hIiwiaWF0IjoxNzM2NTIzNTM2LCJleHAiOjE3MzY1MjcxMzYsImp0aSI6ImY3MjdlZjg1MGFhNzNmMDQ3ZmQwNjY5OWIwNjk3YTIwMDIzYWViYWMifQ.nlRKhlzBhHVpYejoSkH_S9ZOeAejlhvnL5u-94AzsREIhzuKroJbPp9jEHuvvki5dJozc-FzXx9lfpjT17X6PT0hJOM86QUE05RkmV9WkrVSr8trr1zbHY6dieii9tzj7c01pXsLJTa2FvTonmJAxDteVt_vsZFl7-pRWmyXKLMk4CFv9AZx20-uj5pDLuj-F5IkAk_cpXBuMJYh5PQeNBDk22d5svDTQkuwUAH5N9sssXRzDNdv92snGu4AykpmoPIJeSmc3EY-RW0TB5bAnwXH0E3keAjv84yrNYjnovYn2FRqKbTKxNxN4XUgWU_P0oRYCzckJznwz4tStaYZ2A";

  it("should process a few bits of RSA verification using zero-copy", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);
    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    // Generate a unique operation ID
    const operationId = Keypair.generate();

    console.log(`🔧 Operation ID: ${operationId.publicKey.toString()}`);

    // Step 1: Initialize the RSA verification
    console.log("🚀 Step 1: Initializing zero-copy RSA verification...");
    const initTxSignature = await program.methods
      .initRsaVerificationSimple(verificationData)
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, initTxSignature);

    const initTxInfo = await getTxInfo({ txSignature: initTxSignature });
    const initComputeUnitsUsed = initTxInfo?.meta?.computeUnitsConsumed || 0;
    console.log(
      `   💻 Init compute units used: ${initComputeUnitsUsed.toLocaleString()}`
    );

    // Step 2: Process a few bits to test the approach
    console.log("🔄 Step 2: Processing a few bits...");
    let continueTxCount = 0;
    const maxTestBits = 10; // Test more bits with zero-copy

    for (let i = 0; i < maxTestBits; i++) {
      const continueTxSignature = await program.methods
        .continueRsaVerificationSimple()
        .accounts({
          payer: provider.wallet.publicKey,
          operationId: operationId.publicKey,
        })
        .rpc();

      await confirmTransaction(provider.connection, continueTxSignature);

      const continueTxInfo = await getTxInfo({
        txSignature: continueTxSignature,
      });
      const continueComputeUnitsUsed =
        continueTxInfo?.meta?.computeUnitsConsumed || 0;
      continueTxCount++;

      console.log(
        `   🔄 Continue TX ${continueTxCount}: ${continueComputeUnitsUsed.toLocaleString()} compute units`
      );

      // Check if the operation is complete by looking at the return data
      const returnData = continueTxInfo?.meta?.returnData?.data[0];
      if (returnData) {
        const decodedData = Buffer.from(returnData, "base64");
        const isComplete = decodedData.readUInt8(0) === 1;
        if (isComplete) {
          console.log("   ✅ Modpow completed early!");
          break;
        }
      }
    }

    // Step 3: Clean up the state account
    console.log("🧹 Step 3: Cleaning up state account...");
    const cleanupTxSignature = await program.methods
      .cleanupRsaVerificationSimple()
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, cleanupTxSignature);

    console.log(
      `✅ Successfully processed ${continueTxCount} bits using zero-copy without memory issues!`
    );
  });
});

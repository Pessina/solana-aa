import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../../utils/solana";
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

  const payloadBytes = base64urlDecode(payload);
  const payloadData = JSON.parse(Buffer.from(payloadBytes).toString("utf8"));
  const iss = payloadData.iss;

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
  if (iss.includes("google")) {
    provider = { google: {} };
  } else {
    throw new Error(`Unsupported provider: ${iss}`);
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

function deriveModpowStatePda(
  programId: PublicKey,
  payer: PublicKey,
  operationId: PublicKey
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("rsa_modpow"), payer.toBuffer(), operationId.toBuffer()],
    programId
  );
  return pda;
}

describe.only("RSA OIDC Verification - Multi-Transaction", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  const validToken =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg5Y2UzNTk4YzQ3M2FmMWJkYTRiZmY5NWU2Yzg3MzY0NTAyMDZmYmEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3Mzk5MTEwNjk3OTctaWRwMDYyODY2OTY0Z2JuZG82NjkzaDMydGdhNWN2bDEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3Mzk5MTEwNjk3OTctaWRwMDYyODY2OTY0Z2JuZG82NjkzaDMydGdhNWN2bDEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTc5MDI4NTUzNzMxNTc0MTAzMzAiLCJlbWFpbCI6ImZzLnBlc3NpbmFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoidGVzdF8xMjNfZmVsaXBlIiwibmJmIjoxNzM2NTIzMjM2LCJuYW1lIjoiRmVsaXBlIFBlc3NpbmEiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSktKYlV5QlZxQ0J2NHFWR09EU25WVGdMSFBLTjB0Vk9NSU1YVml1a2dyZC0wdGZlZFU9czk2LWMiLCJnaXZlbl9uYW1lIjoiRmVsaXBlIiwiZmFtaWx5X25hbWUiOiJQZXNzaW5hIiwiaWF0IjoxNzM2NTIzNTM2LCJleHAiOjE3MzY1MjcxMzYsImp0aSI6ImY3MjdlZjg1MGFhNzNmMDQ3ZmQwNjY5OWIwNjk3YTIwMDIzYWViYWMifQ.nlRKhlzBhHVpYejoSkH_S9ZOeAejlhvnL5u-94AzsREIhzuKroJbPp9jEHuvvki5dJozc-FzXx9lfpjT17X6PT0hJOM86QUE05RkmV9WkrVSr8trr1zbHY6dieii9tzj7c01pXsLJTa2FvTonmJAxDteVt_vsZFl7-pRWmyXKLMk4CFv9AZx20-uj5pDLuj-F5IkAk_cpXBuMJYh5PQeNBDk22d5svDTQkuwUAH5N9sssXRzDNdv92snGu4AykpmoPIJeSmc3EY-RW0TB5bAnwXH0E3keAjv84yrNYjnovYn2FRqKbTKxNxN4XUgWU_P0oRYCzckJznwz4tStaYZ2A";

  it("should successfully verify valid Google OIDC token using multi-transaction approach", async () => {
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
    const modpowStatePda = deriveModpowStatePda(
      program.programId,
      provider.wallet.publicKey,
      operationId.publicKey
    );

    console.log(`🔧 Operation ID: ${operationId.publicKey.toString()}`);
    console.log(`📍 Modpow State PDA: ${modpowStatePda.toString()}`);

    // Step 1: Initialize the RSA verification
    console.log("🚀 Step 1: Initializing RSA verification...");
    const initComputeBudgetInstruction =
      ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });

    const initTxSignature = await program.methods
      .initRsaVerificationMultiTx(verificationData)
      .preInstructions([initComputeBudgetInstruction])
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

    // Step 2: Continue the RSA verification until complete
    console.log("🔄 Step 2: Continuing RSA verification...");
    let isComplete = false;
    let continueTxCount = 0;
    let totalContinueComputeUnits = 0;

    while (!isComplete) {
      const continueComputeBudgetInstruction =
        ComputeBudgetProgram.setComputeUnitLimit({
          units: 1_400_000,
        });

      const continueTxSignature = await program.methods
        .continueRsaVerificationMultiTx()
        .preInstructions([continueComputeBudgetInstruction])
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
      totalContinueComputeUnits += continueComputeUnitsUsed;
      continueTxCount++;

      console.log(
        `   🔄 Continue TX ${continueTxCount}: ${continueComputeUnitsUsed.toLocaleString()} compute units`
      );

      // Check if the operation is complete by looking at the return data
      const returnData = continueTxInfo?.meta?.returnData?.data[0];
      if (returnData) {
        const decodedData = Buffer.from(returnData, "base64");
        isComplete = decodedData.readUInt8(0) === 1;
      }

      // Safety check to prevent infinite loops
      if (continueTxCount > 100) {
        throw new Error(
          "Too many continue transactions - possible infinite loop"
        );
      }
    }

    console.log(
      `   ✅ Modpow completed after ${continueTxCount} continue transactions`
    );

    // Step 3: Finalize the RSA verification
    console.log("🏁 Step 3: Finalizing RSA verification...");
    const finalizeComputeBudgetInstruction =
      ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });

    const finalizeTxSignature = await program.methods
      .finalizeRsaVerificationMultiTx(verificationData)
      .preInstructions([finalizeComputeBudgetInstruction])
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, finalizeTxSignature);

    const finalizeTxInfo = await getTxInfo({
      txSignature: finalizeTxSignature,
    });
    const finalizeComputeUnitsUsed =
      finalizeTxInfo?.meta?.computeUnitsConsumed || 0;
    console.log(
      `   💻 Finalize compute units used: ${finalizeComputeUnitsUsed.toLocaleString()}`
    );

    const finalizeReturnData = finalizeTxInfo?.meta?.returnData?.data[0];
    if (!finalizeReturnData) {
      throw new Error("No return data found from finalize");
    }

    const finalizeDecodedData = Buffer.from(finalizeReturnData, "base64");
    const verificationResult = finalizeDecodedData.readUInt8(0) === 1;

    expect(verificationResult).to.be.true;

    // Step 4: Clean up the state account
    console.log("🧹 Step 4: Cleaning up state account...");
    const cleanupTxSignature = await program.methods
      .cleanupRsaVerificationMultiTx()
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, cleanupTxSignature);

    const cleanupTxInfo = await getTxInfo({ txSignature: cleanupTxSignature });
    const cleanupComputeUnitsUsed =
      cleanupTxInfo?.meta?.computeUnitsConsumed || 0;
    console.log(
      `   💻 Cleanup compute units used: ${cleanupComputeUnitsUsed.toLocaleString()}`
    );

    // Summary
    const totalComputeUnits =
      initComputeUnitsUsed +
      totalContinueComputeUnits +
      finalizeComputeUnitsUsed +
      cleanupComputeUnitsUsed;
    const totalTransactions = 1 + continueTxCount + 1 + 1; // init + continue + finalize + cleanup

    console.log(`\n📊 Multi-Transaction RSA Verification Summary:`);
    console.log(`   🔢 Total transactions: ${totalTransactions}`);
    console.log(
      `   💻 Total compute units: ${totalComputeUnits.toLocaleString()}`
    );
    console.log(
      `   📈 Average CU per transaction: ${Math.round(
        totalComputeUnits / totalTransactions
      ).toLocaleString()}`
    );
    console.log(
      `   ✅ Verification result: ${verificationResult ? "VALID" : "INVALID"}`
    );
  });

  it("should handle verification with wrong signature across multiple transactions", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);

    // Corrupt the signature
    const corruptedSignature = Buffer.from(optimizedVerificationData.signature);
    corruptedSignature[0] = (corruptedSignature[0] + 1) % 256;

    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: corruptedSignature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    // Generate a unique operation ID
    const operationId = Keypair.generate();

    console.log("🔧 Testing with corrupted signature...");

    // Step 1: Initialize
    const initTxSignature = await program.methods
      .initRsaVerificationMultiTx(verificationData)
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, initTxSignature);

    // Step 2: Continue until complete
    let isComplete = false;
    let continueTxCount = 0;

    while (!isComplete && continueTxCount < 100) {
      const continueTxSignature = await program.methods
        .continueRsaVerificationMultiTx()
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        ])
        .accounts({
          payer: provider.wallet.publicKey,
          operationId: operationId.publicKey,
        })
        .rpc();

      await confirmTransaction(provider.connection, continueTxSignature);

      const continueTxInfo = await getTxInfo({
        txSignature: continueTxSignature,
      });
      const returnData = continueTxInfo?.meta?.returnData?.data[0];
      if (returnData) {
        const decodedData = Buffer.from(returnData, "base64");
        isComplete = decodedData.readUInt8(0) === 1;
      }
      continueTxCount++;
    }

    // Step 3: Finalize
    const finalizeTxSignature = await program.methods
      .finalizeRsaVerificationMultiTx(verificationData)
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, finalizeTxSignature);

    const finalizeTxInfo = await getTxInfo({
      txSignature: finalizeTxSignature,
    });
    const finalizeReturnData = finalizeTxInfo?.meta?.returnData?.data[0];
    if (!finalizeReturnData) {
      throw new Error("No return data found from finalize");
    }

    const finalizeDecodedData = Buffer.from(finalizeReturnData, "base64");
    const verificationResult = finalizeDecodedData.readUInt8(0) === 1;

    expect(verificationResult).to.be.false;

    // Step 4: Clean up
    await program.methods
      .cleanupRsaVerificationMultiTx()
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    console.log(
      `   ✅ Corrupted signature correctly rejected after ${continueTxCount} continue transactions`
    );
  });

  it("should compare performance between single-tx and multi-tx approaches", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);
    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    // Test single-transaction native implementation
    console.log("🚀 Testing single-transaction native implementation...");
    const nativeComputeBudgetInstruction =
      ComputeBudgetProgram.setComputeUnitLimit({
        units: 100_000,
      });

    const nativeTxSignature = await program.methods
      .verifyOidcRsaNative(verificationData)
      .preInstructions([nativeComputeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, nativeTxSignature);

    const nativeTxInfo = await getTxInfo({ txSignature: nativeTxSignature });
    const nativeComputeUnitsUsed =
      nativeTxInfo?.meta?.computeUnitsConsumed || 0;

    // Test multi-transaction implementation
    console.log("🔄 Testing multi-transaction implementation...");
    const operationId = Keypair.generate();

    // Initialize
    const initTxSignature = await program.methods
      .initRsaVerificationMultiTx(verificationData)
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, initTxSignature);
    const initTxInfo = await getTxInfo({ txSignature: initTxSignature });
    const initComputeUnitsUsed = initTxInfo?.meta?.computeUnitsConsumed || 0;

    // Continue until complete
    let isComplete = false;
    let continueTxCount = 0;
    let totalContinueComputeUnits = 0;

    while (!isComplete && continueTxCount < 100) {
      const continueTxSignature = await program.methods
        .continueRsaVerificationMultiTx()
        .preInstructions([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        ])
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
      totalContinueComputeUnits += continueComputeUnitsUsed;

      const returnData = continueTxInfo?.meta?.returnData?.data[0];
      if (returnData) {
        const decodedData = Buffer.from(returnData, "base64");
        isComplete = decodedData.readUInt8(0) === 1;
      }
      continueTxCount++;
    }

    // Finalize
    const finalizeTxSignature = await program.methods
      .finalizeRsaVerificationMultiTx(verificationData)
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, finalizeTxSignature);
    const finalizeTxInfo = await getTxInfo({
      txSignature: finalizeTxSignature,
    });
    const finalizeComputeUnitsUsed =
      finalizeTxInfo?.meta?.computeUnitsConsumed || 0;

    // Clean up
    const cleanupTxSignature = await program.methods
      .cleanupRsaVerificationMultiTx()
      .accounts({
        payer: provider.wallet.publicKey,
        operationId: operationId.publicKey,
      })
      .rpc();

    await confirmTransaction(provider.connection, cleanupTxSignature);
    const cleanupTxInfo = await getTxInfo({ txSignature: cleanupTxSignature });
    const cleanupComputeUnitsUsed =
      cleanupTxInfo?.meta?.computeUnitsConsumed || 0;

    const multiTxTotalComputeUnits =
      initComputeUnitsUsed +
      totalContinueComputeUnits +
      finalizeComputeUnitsUsed +
      cleanupComputeUnitsUsed;
    const multiTxTotalTransactions = 1 + continueTxCount + 1 + 1;

    // Verify both return the same result
    const nativeReturnData = nativeTxInfo?.meta?.returnData?.data[0];
    const finalizeReturnData = finalizeTxInfo?.meta?.returnData?.data[0];

    if (!nativeReturnData || !finalizeReturnData) {
      throw new Error("No return data found");
    }

    const nativeResult =
      Buffer.from(nativeReturnData, "base64").readUInt8(0) === 1;
    const multiTxResult =
      Buffer.from(finalizeReturnData, "base64").readUInt8(0) === 1;

    expect(nativeResult).to.equal(multiTxResult);
    expect(nativeResult).to.be.true;

    // Performance comparison
    console.log(`\n📊 Performance Comparison:`);
    console.log(`   🚀 Native single-tx:`);
    console.log(
      `      💻 Compute units: ${nativeComputeUnitsUsed.toLocaleString()}`
    );
    console.log(`      🔢 Transactions: 1`);
    console.log(`   🔄 Multi-tx approach:`);
    console.log(
      `      💻 Total compute units: ${multiTxTotalComputeUnits.toLocaleString()}`
    );
    console.log(`      🔢 Total transactions: ${multiTxTotalTransactions}`);
    console.log(
      `      📈 Average CU per tx: ${Math.round(
        multiTxTotalComputeUnits / multiTxTotalTransactions
      ).toLocaleString()}`
    );
    console.log(`   📈 Overhead:`);
    console.log(
      `      💻 Extra compute units: ${(
        multiTxTotalComputeUnits - nativeComputeUnitsUsed
      ).toLocaleString()}`
    );
    console.log(
      `      📊 Overhead percentage: ${(
        (multiTxTotalComputeUnits / nativeComputeUnitsUsed - 1) *
        100
      ).toFixed(1)}%`
    );

    // The multi-tx approach should use more total compute units but stay within per-tx limits
    expect(multiTxTotalComputeUnits).to.be.greaterThan(nativeComputeUnitsUsed);
  });
});

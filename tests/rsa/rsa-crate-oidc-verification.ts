import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../../utils/solana";
import { expect } from "chai";
import { createHash } from "crypto";
import { ComputeBudgetProgram } from "@solana/web3.js";
import { createOptimizedVerificationData } from "./utils";
import { VALID_OIDC_TOKEN } from "./constants";

describe.skip("RSA Crate OIDC Verification", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  it("should successfully verify valid Google OIDC token using RSA crate", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(VALID_OIDC_TOKEN);
    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000, // Higher limit for RSA crate implementation
    });

    const txSignature = await program.methods
      .verifyOidcRsaCrate(verificationData)
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(
      `💻 RSA Crate - Compute units used: ${computeUnitsUsed.toLocaleString()}`
    );

    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1;

    expect(result).to.be.true;
  });

  it("should fail verification with corrupted signature using RSA crate", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(VALID_OIDC_TOKEN);

    const corruptedSignature = Buffer.from(optimizedVerificationData.signature);
    corruptedSignature[0] = (corruptedSignature[0] + 1) % 256;

    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: corruptedSignature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });

    try {
      await program.methods
        .verifyOidcRsaCrate(verificationData)
        .preInstructions([computeBudgetInstruction])
        .accounts({})
        .rpc();

      expect.fail(
        "Expected transaction to fail with InvalidSignatureFormat error"
      );
    } catch (error: any) {
      expect(error.toString()).to.include("InvalidSignatureFormat");
    }
  });

  it("should fail verification with wrong key index using RSA crate", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(VALID_OIDC_TOKEN);

    const originalKeyIndex = optimizedVerificationData.keyIndex;
    const wrongKeyIndex = originalKeyIndex === 0 ? 1 : 0;

    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: wrongKeyIndex,
    };

    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });

    try {
      await program.methods
        .verifyOidcRsaCrate(verificationData)
        .preInstructions([computeBudgetInstruction])
        .accounts({})
        .rpc();

      expect.fail(
        "Expected transaction to fail with InvalidSignatureFormat error"
      );
    } catch (error: any) {
      expect(error.toString()).to.include("InvalidSignatureFormat");
    }
  });

  it("should fail verification with wrong token using RSA crate", async () => {
    // Create a different token with different payload
    const wrongTokenHeader = {
      alg: "RS256",
      typ: "JWT",
      kid: "dd125d5f462fbc6014aedab81ddf3bcedab70847",
    };

    const wrongTokenPayload = {
      iss: "https://accounts.google.com",
      aud: "wrong-audience",
      sub: "wrong-subject",
      email: "wrong@example.com",
      email_verified: true,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const wrongTokenHeaderB64 = Buffer.from(
      JSON.stringify(wrongTokenHeader)
    ).toString("base64url");
    const wrongTokenPayloadB64 = Buffer.from(
      JSON.stringify(wrongTokenPayload)
    ).toString("base64url");
    const wrongSigningInput = `${wrongTokenHeaderB64}.${wrongTokenPayloadB64}`;

    // Use the signature from the valid token but with wrong signing input
    const validOptimizedData =
      createOptimizedVerificationData(VALID_OIDC_TOKEN);

    const wrongVerificationData = {
      signingInputHash: Array.from(
        createHash("sha256").update(wrongSigningInput).digest()
      ),
      signature: validOptimizedData.signature, // Valid signature but for different data
      provider: validOptimizedData.provider,
      keyIndex: validOptimizedData.keyIndex,
    };

    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 1_400_000,
    });

    const txSignature = await program.methods
      .verifyOidcRsaCrate(wrongVerificationData)
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(
      `💻 RSA Crate - Compute units used: ${computeUnitsUsed.toLocaleString()}`
    );

    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1;

    expect(result).to.be.false;
  });

  it("should compare performance between native and RSA crate implementations", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(VALID_OIDC_TOKEN);
    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    // Test native implementation
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

    // Test RSA crate implementation
    const crateComputeBudgetInstruction =
      ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
      });

    const crateTxSignature = await program.methods
      .verifyOidcRsaCrate(verificationData)
      .preInstructions([crateComputeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, crateTxSignature);

    const crateTxInfo = await getTxInfo({ txSignature: crateTxSignature });
    const crateComputeUnitsUsed = crateTxInfo?.meta?.computeUnitsConsumed || 0;

    // Verify both return the same result
    const nativeReturnData = nativeTxInfo?.meta?.returnData?.data[0];
    const crateReturnData = crateTxInfo?.meta?.returnData?.data[0];

    if (!nativeReturnData || !crateReturnData) {
      throw new Error("No return data found");
    }

    const nativeResult =
      Buffer.from(nativeReturnData, "base64").readUInt8(0) === 1;
    const crateResult =
      Buffer.from(crateReturnData, "base64").readUInt8(0) === 1;

    expect(nativeResult).to.equal(crateResult);
    expect(nativeResult).to.be.true;

    // Performance comparison
    console.log(`\n📊 Performance Comparison:`);
    console.log(
      `   Native syscall: ${nativeComputeUnitsUsed.toLocaleString()} compute units`
    );
    console.log(
      `   RSA crate:      ${crateComputeUnitsUsed.toLocaleString()} compute units`
    );
    console.log(
      `   Overhead:       ${(
        crateComputeUnitsUsed - nativeComputeUnitsUsed
      ).toLocaleString()} compute units (${(
        (crateComputeUnitsUsed / nativeComputeUnitsUsed - 1) *
        100
      ).toFixed(1)}% more)`
    );

    // Both should succeed, but RSA crate will use more compute units
    expect(crateComputeUnitsUsed).to.be.greaterThan(nativeComputeUnitsUsed);
  });
});

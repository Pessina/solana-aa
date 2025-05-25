import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../../utils/solana";
import { expect } from "chai";
import { createHash } from "crypto";
import { ComputeBudgetProgram } from "@solana/web3.js";
import { createOptimizedVerificationData } from "./utils";
import { VALID_OIDC_TOKEN } from "./constants";

describe("RSA Syscall OIDC Verification", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  it("should successfully verify valid Google OIDC token", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(VALID_OIDC_TOKEN);
    const verificationData = {
      signingInputHash: optimizedVerificationData.signingInputHash,
      signature: optimizedVerificationData.signature,
      provider: optimizedVerificationData.provider,
      keyIndex: optimizedVerificationData.keyIndex,
    };

    const computeBudgetInstruction = ComputeBudgetProgram.setComputeUnitLimit({
      units: 100_000,
    });

    const txSignature = await program.methods
      .verifyOidcRsaNative(verificationData)
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(`💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`);

    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1;

    expect(result).to.be.true;
  });

  it("should fail verification with corrupted signature", async () => {
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
      units: 100_000,
    });

    try {
      await program.methods
        .verifyOidcRsaNative(verificationData)
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

  it("should fail verification with wrong key index", async () => {
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
      units: 100_000,
    });

    try {
      await program.methods
        .verifyOidcRsaNative(verificationData)
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

  it("should fail verification with wrong token", async () => {
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
      units: 100_000,
    });

    const txSignature = await program.methods
      .verifyOidcRsaNative(wrongVerificationData)
      .preInstructions([computeBudgetInstruction])
      .accounts({})
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    const txInfo = await getTxInfo({ txSignature });
    const computeUnitsUsed = txInfo?.meta?.computeUnitsConsumed || 0;

    console.log(`💻 Compute units used: ${computeUnitsUsed.toLocaleString()}`);

    const returnData = txInfo?.meta?.returnData?.data[0];
    if (!returnData) {
      throw new Error("No return data found");
    }

    const decodedData = Buffer.from(returnData, "base64");
    const result = decodedData.readUInt8(0) === 1;

    expect(result).to.be.false;
  });
});

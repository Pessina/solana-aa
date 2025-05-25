import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../utils/solana";
import { expect } from "chai";
import { createHash } from "crypto";
import { ComputeBudgetProgram } from "@solana/web3.js";

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

describe.only("RSA OIDC Verification", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  const validToken =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg5Y2UzNTk4YzQ3M2FmMWJkYTRiZmY5NWU2Yzg3MzY0NTAyMDZmYmEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3Mzk5MTEwNjk3OTctaWRwMDYyODY2OTY0Z2JuZG82NjkzaDMydGdhNWN2bDEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3Mzk5MTEwNjk3OTctaWRwMDYyODY2OTY0Z2JuZG82NjkzaDMydGdhNWN2bDEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTc5MDI4NTUzNzMxNTc0MTAzMzAiLCJlbWFpbCI6ImZzLnBlc3NpbmFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoidGVzdF8xMjNfZmVsaXBlIiwibmJmIjoxNzM2NTIzMjM2LCJuYW1lIjoiRmVsaXBlIFBlc3NpbmEiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSktKYlV5QlZxQ0J2NHFWR09EU25WVGdMSFBLTjB0Vk9NSU1YVml1a2dyZC0wdGZlZFU9czk2LWMiLCJnaXZlbl9uYW1lIjoiRmVsaXBlIiwiZmFtaWx5X25hbWUiOiJQZXNzaW5hIiwiaWF0IjoxNzM2NTIzNTM2LCJleHAiOjE3MzY1MjcxMzYsImp0aSI6ImY3MjdlZjg1MGFhNzNmMDQ3ZmQwNjY5OWIwNjk3YTIwMDIzYWViYWMifQ.nlRKhlzBhHVpYejoSkH_S9ZOeAejlhvnL5u-94AzsREIhzuKroJbPp9jEHuvvki5dJozc-FzXx9lfpjT17X6PT0hJOM86QUE05RkmV9WkrVSr8trr1zbHY6dieii9tzj7c01pXsLJTa2FvTonmJAxDteVt_vsZFl7-pRWmyXKLMk4CFv9AZx20-uj5pDLuj-F5IkAk_cpXBuMJYh5PQeNBDk22d5svDTQkuwUAH5N9sssXRzDNdv92snGu4AykpmoPIJeSmc3EY-RW0TB5bAnwXH0E3keAjv84yrNYjnovYn2FRqKbTKxNxN4XUgWU_P0oRYCzckJznwz4tStaYZ2A";

  it("should successfully verify valid Google OIDC token", async () => {
    const optimizedVerificationData =
      createOptimizedVerificationData(validToken);
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
      createOptimizedVerificationData(validToken);

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
      createOptimizedVerificationData(validToken);

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
    const validOptimizedData = createOptimizedVerificationData(validToken);

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

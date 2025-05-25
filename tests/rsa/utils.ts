import { createHash } from "crypto";

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

export function createOptimizedVerificationData(token: string) {
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

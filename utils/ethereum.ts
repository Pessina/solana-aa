/**
 * Adds the Ethereum signed message prefix to a message
 * @param message - The original message
 * @returns The message with the Ethereum prefix
 */
export function addEthereumMessagePrefix(message: string): string {
  const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
  return prefix + message;
}

/**
 * Parses an Ethereum signature into its components
 * @param signature - The Ethereum signature (65 bytes with 0x prefix)
 * @returns The signature components (signature bytes and recovery ID)
 */
export function parseEthereumSignature(signature: string): {
  signature: Buffer;
  recoveryId: number;
} {
  const signatureHex = signature.slice(2); // Remove '0x'
  const signatureBytes = Buffer.from(signatureHex, "hex");

  const signaturePart = signatureBytes.slice(0, 64); // First 64 bytes
  const v = signatureBytes[64]; // Last byte is v
  const recoveryId = v - 27; // Convert Ethereum v (27 or 28) to recovery ID (0 or 1)

  return { signature: signaturePart, recoveryId };
}

/**
 * Validates an Ethereum address format
 * @param ethAddress - The Ethereum address to validate (with 0x prefix)
 * @returns The address bytes
 */
export function ethereumAddressToBytes(ethAddress: string): Buffer {
  const ethAddressBytes = Buffer.from(ethAddress.slice(2), "hex");

  return ethAddressBytes;
}

import { PublicKey, TransactionInstruction } from "@solana/web3.js";

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

export const SECP256K1_PROGRAM_ID = new PublicKey(
  "KeccakSecp256k11111111111111111111111111111"
);

export const SIGNATURE_OFFSETS_SERIALIZED_SIZE = 11;
export const DATA_START = SIGNATURE_OFFSETS_SERIALIZED_SIZE + 1;
export const SIGNATURE_SERIALIZED_SIZE = 64;
export const HASHED_PUBKEY_SERIALIZED_SIZE = 20;

/**
 * Creates a secp256k1 verification instruction for Ethereum signatures
 */
export function createSecp256k1VerificationInstruction(
  signature: Buffer,
  recoveryId: number,
  ethAddressBytes: Buffer,
  messageBytes: Buffer
): TransactionInstruction {
  const messageOffset =
    DATA_START + HASHED_PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE + 1;
  const messageSize = messageBytes.length;
  const instructionDataSize = messageOffset + messageSize;
  const instructionData = Buffer.alloc(instructionDataSize);

  instructionData.writeUInt8(1, 0);

  const ethAddressOffset = DATA_START;
  const signatureOffset = DATA_START + HASHED_PUBKEY_SERIALIZED_SIZE;
  const recoveryIdOffset =
    DATA_START + HASHED_PUBKEY_SERIALIZED_SIZE + SIGNATURE_SERIALIZED_SIZE;

  const offsetsBuffer = Buffer.alloc(SIGNATURE_OFFSETS_SERIALIZED_SIZE);
  offsetsBuffer.writeUInt16LE(signatureOffset, 0);
  offsetsBuffer.writeUInt8(0, 2);
  offsetsBuffer.writeUInt16LE(ethAddressOffset, 3);
  offsetsBuffer.writeUInt8(0, 5);
  offsetsBuffer.writeUInt16LE(messageOffset, 6);
  offsetsBuffer.writeUInt16LE(messageSize, 8);
  offsetsBuffer.writeUInt8(0, 10);
  offsetsBuffer.copy(instructionData, 1);

  ethAddressBytes.copy(instructionData, ethAddressOffset);
  signature.copy(instructionData, signatureOffset);
  instructionData.writeUInt8(recoveryId, recoveryIdOffset);
  messageBytes.copy(instructionData, messageOffset);

  return new TransactionInstruction({
    keys: [],
    programId: SECP256K1_PROGRAM_ID,
    data: instructionData,
  });
}

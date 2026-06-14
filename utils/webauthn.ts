import { PublicKey, TransactionInstruction } from "@solana/web3.js";

export const SECP256R1_PROGRAM_ID = new PublicKey(
  "Secp256r1SigVerify1111111111111111111111111"
);

const SIGNATURE_OFFSETS_SERIALIZED_SIZE = 14; // 7 fields * 2 bytes each
const DATA_START = 2; // 1 byte for number of signatures + 1 byte for padding
const HEADER_SIZE = DATA_START + SIGNATURE_OFFSETS_SERIALIZED_SIZE;
const INSTRUCTION_INDEX_NOT_USED = 0xffff;

/**
 * Builds a Solana secp256r1 precompile verification instruction for a WebAuthn
 * (P-256) signature over `message`, with the signature, public key, and message
 * all carried inline in this instruction's data.
 */
export function createSecp256r1VerificationInstruction(
  signature: Uint8Array,
  publicKey: Uint8Array,
  message: Uint8Array
): TransactionInstruction {
  const data = Buffer.alloc(
    HEADER_SIZE + signature.length + publicKey.length + message.length
  );

  data.writeUInt8(1, 0);
  data.writeUInt8(0, 1);

  const signatureOffset = HEADER_SIZE;
  const publicKeyOffset = signatureOffset + signature.length;
  const messageDataOffset = publicKeyOffset + publicKey.length;
  const messageDataSize = message.length;

  data.writeUInt16LE(signatureOffset, DATA_START);
  data.writeUInt16LE(INSTRUCTION_INDEX_NOT_USED, DATA_START + 2);
  data.writeUInt16LE(publicKeyOffset, DATA_START + 4);
  data.writeUInt16LE(INSTRUCTION_INDEX_NOT_USED, DATA_START + 6);
  data.writeUInt16LE(messageDataOffset, DATA_START + 8);
  data.writeUInt16LE(messageDataSize, DATA_START + 10);
  data.writeUInt16LE(INSTRUCTION_INDEX_NOT_USED, DATA_START + 12);

  Buffer.from(signature).copy(data, signatureOffset);
  Buffer.from(publicKey).copy(data, publicKeyOffset);
  Buffer.from(message).copy(data, messageDataOffset);

  return new TransactionInstruction({
    keys: [],
    programId: SECP256R1_PROGRAM_ID,
    data: data,
  });
}

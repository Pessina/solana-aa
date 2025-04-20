import { Connection, TransactionSignature } from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";

/**
 * Extracts the return value from a transaction
 * @param connection Solana connection
 * @param txSignature Transaction signature
 * @returns The return value or null if not available
 * @template T The type of the return value
 */
export async function getTransactionReturnValue<T>(
  connection: Connection,
  txSignature: string
): Promise<T | null> {
  const txInfo = (await connection.getTransaction(txSignature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  })) as unknown as {
    meta: {
      returnData: {
        data: string[];
      };
      logMessages: string[];
    };
  };

  return txInfo?.meta?.returnData?.data
    ? (Buffer.from(txInfo.meta.returnData.data[0], "base64") as unknown as T)
    : null;
}

/**
 * Confirms a transaction and waits for it to be processed
 * @param connection Solana connection
 * @param txSignature Transaction signature
 * @param commitment Commitment level to use, defaults to "confirmed"
 */
export async function confirmTransaction(
  connection: Connection,
  txSignature: TransactionSignature,
  commitment: "confirmed" | "finalized" = "confirmed"
): Promise<void> {
  const latestBlockhash = await connection.getLatestBlockhash();
  await connection.confirmTransaction(
    {
      signature: txSignature,
      blockhash: latestBlockhash.blockhash,
      lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
    },
    commitment
  );
}

/**
 * Logs the compute units used for a transaction
 * @param txSignature Transaction signature
 * @param compressedPublicKey Compressed public key
 */
export const logComputeUnitsUsed = async ({
  txSignature,
  compressedPublicKey,
}: {
  txSignature: string;
  compressedPublicKey: string;
}) => {
  if (txSignature) {
    const provider = anchor.getProvider() as anchor.AnchorProvider;
    const txInfo = await provider.connection.getTransaction(txSignature, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });

    if (txInfo && txInfo.meta) {
      console.log(
        `Compute units used for ${compressedPublicKey}: ${txInfo.meta.computeUnitsConsumed}`
      );
    }
  }
};

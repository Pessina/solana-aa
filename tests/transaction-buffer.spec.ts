import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import * as crypto from "crypto";
import * as borsh from "borsh";

const MAX_CHUNK_SIZE = 900;

class TestData {
  greeting: string;
  numbers: Uint8Array;

  constructor(props: { greeting: string; numbers: Uint8Array }) {
    this.greeting = props.greeting;
    this.numbers = props.numbers;
  }

  static schema = {
    struct: {
      greeting: "string",
      numbers: { array: { type: "u8" } },
    },
  };
}

describe("Transaction Buffer", () => {
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  /**
   * Generates a random data ID for storage
   */
  function generateDataId(): number[] {
    return Array.from(anchor.web3.Keypair.generate().secretKey.slice(0, 32));
  }

  /**
   * Calculates SHA-256 hash of data
   */
  function calculateHash(data: Buffer): number[] {
    return Array.from(crypto.createHash("sha256").update(data).digest());
  }

  /**
   * Splits data into chunks of specified size
   */
  function splitIntoChunks(data: Buffer, chunkSize: number): Buffer[] {
    const chunks: Buffer[] = [];
    for (let i = 0; i < data.length; i += chunkSize) {
      chunks.push(data.slice(i, Math.min(i + chunkSize, data.length)));
    }
    return chunks;
  }

  /**
   * Derives the storage PDA for a given data ID
   */
  function deriveStoragePda(dataId: number[]): PublicKey {
    const [storagePda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("unified_storage"),
        provider.wallet.publicKey.toBuffer(),
        Buffer.from(dataId),
      ],
      program.programId
    );
    return storagePda;
  }

  /**
   * Stores data chunks in the program
   */
  async function storeDataChunks(
    dataId: number[],
    dataHash: number[],
    chunks: Buffer[]
  ): Promise<void> {
    for (let i = 0; i < chunks.length; i++) {
      let txSignature: string;

      if (i === 0) {
        txSignature = await program.methods
          .initStorage(
            dataId,
            0,
            chunks.length,
            dataHash,
            Buffer.from(chunks[0])
          )
          .accounts({
            payer: provider.wallet.publicKey,
          })
          .rpc();
      } else {
        txSignature = await program.methods
          .storeChunk(
            dataId,
            i,
            chunks.length,
            dataHash,
            Buffer.from(chunks[i])
          )
          .accounts({
            payer: provider.wallet.publicKey,
          })
          .rpc();
      }

      console.log(
        `Stored chunk ${i + 1}/${chunks.length}, tx: ${txSignature.substring(
          0,
          10
        )}...`
      );
    }
  }

  /**
   * Retrieves and reassembles data from storage
   */
  async function retrieveAndReassembleData(
    storagePda: PublicKey,
    chunkCount: number
  ): Promise<Buffer> {
    let reassembledData = Buffer.alloc(0);

    for (let i = 0; i < chunkCount; i++) {
      try {
        const chunkData = await program.methods
          .retrieveChunk(i)
          .accounts({
            unifiedStorage: storagePda,
            payer: provider.wallet.publicKey,
          })
          .view();

        console.log(
          `Retrieved chunk ${i + 1}/${chunkCount}, size: ${
            chunkData.length
          } bytes`
        );

        reassembledData = Buffer.concat([
          reassembledData,
          Buffer.from(chunkData),
        ]);
      } catch (error) {
        console.error(`Error retrieving chunk ${i}:`, error);
        throw error;
      }
    }

    return reassembledData;
  }

  /**
   * Closes a storage account
   */
  async function closeStorageAccount(storagePda: PublicKey): Promise<void> {
    try {
      const txSignature = await program.methods
        .closeStorage()
        .accounts({
          unifiedStorage: storagePda,
          payer: provider.wallet.publicKey,
        })
        .rpc();

      console.log(
        `Closed storage account, tx: ${txSignature.substring(0, 10)}...`
      );
    } catch (error) {
      console.error(`Error closing storage account:`, error);
      throw error;
    }
  }

  it("Stores and retrieves Borsh-serialized data up to 32kb (solana single tx heap limit)", async () => {
    // Create large test data
    const largeGreeting =
      "Hello, Solana! This is a large test of oversized data handling with multiple chunks across multiple accounts. We'll use many different PDAs to store different parts of the data. This demonstrates our ability to handle data much larger than a single Solana account can store.";

    const largeNumbers = new Uint8Array(
      Array(24000)
        .fill(0)
        .map((_, i) => i % 256)
    );

    const largeTestData = new TestData({
      greeting: largeGreeting,
      numbers: largeNumbers,
    });
    const serializedData = borsh.serialize(
      TestData.schema,
      largeTestData
    ) as Buffer;

    console.log("Total serialized data size:", serializedData.length, "bytes");

    // Generate data ID and calculate hash
    const dataId = generateDataId();
    const dataHash = calculateHash(serializedData);

    // Split data into chunks and store them
    const chunks = splitIntoChunks(serializedData, MAX_CHUNK_SIZE);
    console.log(
      `Split data into ${chunks.length} chunks of max ${MAX_CHUNK_SIZE} bytes each`
    );

    await storeDataChunks(dataId, dataHash, chunks);

    // Get storage PDA and verify metadata
    const storagePda = deriveStoragePda(dataId);
    const metadata = await program.methods
      .getDataMetadata()
      .accounts({
        unifiedStorage: storagePda,
        payer: provider.wallet.publicKey,
      })
      .view();

    assert.equal(
      metadata.chunksStored,
      chunks.length,
      `Failed to store all chunks`
    );

    console.log(`Using ${chunks.length} storage accounts`);

    // Retrieve and reassemble data
    const reassembledData = await retrieveAndReassembleData(
      storagePda,
      chunks.length
    );

    // Verify data integrity
    const reassembledHash = calculateHash(reassembledData);
    const hashesMatch =
      JSON.stringify(reassembledHash) === JSON.stringify(dataHash);

    console.log(
      "Full data integrity verification (hash comparison):",
      hashesMatch
    );
    assert.isTrue(hashesMatch, "Data hash verification failed");

    // Deserialize and verify data
    const deserializedData = borsh.deserialize(
      TestData.schema,
      reassembledData
    ) as TestData;

    console.log("Deserialized data:", {
      greeting: deserializedData.greeting,
      numbersPreview:
        Array.from(deserializedData.numbers.slice(0, 10)).join(",") + "...",
    });

    assert.equal(deserializedData.greeting, largeGreeting);
    assert.equal(deserializedData.numbers.length, largeNumbers.length);
    assert.deepEqual(
      Array.from(deserializedData.numbers),
      Array.from(largeNumbers)
    );

    console.log(`Total chunks: ${chunks.length}`);
    console.log(`Original data size: ${serializedData.length} bytes`);
    console.log(`Reassembled data size: ${reassembledData.length} bytes`);

    // Clean up
    await closeStorageAccount(storagePda);
  });

  it("Tests storage with small data in single account", async () => {
    // Create small test data
    const smallTestData = new TestData({
      greeting: "Small data test",
      numbers: new Uint8Array(
        Array(50)
          .fill(0)
          .map((_, i) => i % 256)
      ),
    });

    const serializedData = borsh.serialize(
      TestData.schema,
      smallTestData
    ) as Buffer;
    const dataId = generateDataId();
    const dataHash = calculateHash(serializedData);

    console.log(
      `Storing small data (${serializedData.length} bytes) in a single account`
    );

    // Split and store data
    const chunks = splitIntoChunks(serializedData, MAX_CHUNK_SIZE);
    await storeDataChunks(dataId, dataHash, chunks);

    // Retrieve and verify data
    const storagePda = deriveStoragePda(dataId);
    const reassembledData = await retrieveAndReassembleData(
      storagePda,
      chunks.length
    );

    // Verify data integrity
    const reassembledHash = calculateHash(reassembledData);
    const dataIntegrityMatch =
      JSON.stringify(reassembledHash) === JSON.stringify(dataHash);

    console.log("Small data integrity verification:", dataIntegrityMatch);
    assert.isTrue(dataIntegrityMatch, "Small data integrity failed");

    // Clean up
    await closeStorageAccount(storagePda);

    console.log(
      "Test completed - successfully stored and retrieved data using multiple accounts"
    );
  });
});

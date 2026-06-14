import * as anchor from "@coral-xyz/anchor";
import { signWithEthereum } from "../utils/secp256k1-signer";
import { borshUtils, Transaction } from "../borsh";
import { confirmTransaction } from "../utils/solana";
import {
  parseEthereumSignature,
  ethereumAddressToBytes,
  createSecp256k1VerificationInstruction,
} from "../utils/ethereum";
import { Hex, keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { cleanUpProgramState, findAbstractAccountPDA } from "../utils/program";
import { buildEthereumIdentity } from "../utils/identity";
import { BN } from "bn.js";
import { PublicKey, Keypair } from "@solana/web3.js";
import { SolanaAa } from "../target/types/solana_aa";
import { MockChainSignatures } from "../target/types/mock_chain_signatures";
import { assert } from "chai";

const PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;

describe("Execute Sign (chain-signatures CPI)", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as anchor.Program<SolanaAa>;
  const mockProgram = anchor.workspace
    .mockChainSignatures as anchor.Program<MockChainSignatures>;
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;

  const mockProgramId = mockProgram.programId;
  // The mock does not validate these, but we derive the conventional
  // chain-signatures PDAs so the test documents the real account contract.
  const [mockProgramState] = PublicKey.findProgramAddressSync(
    [Buffer.from("program-state")],
    mockProgramId
  );
  const [mockEventAuthority] = PublicKey.findProgramAddressSync(
    [Buffer.from("__event_authority")],
    mockProgramId
  );

  // Sign remaining-account contract:
  // [program_state(w), event_authority, chain_signatures_program].
  const signRemainingAccounts = (
    chainSigProgram: PublicKey
  ): anchor.web3.AccountMeta[] => [
    { pubkey: mockProgramState, isSigner: false, isWritable: true },
    { pubkey: mockEventAuthority, isSigner: false, isWritable: false },
    { pubkey: chainSigProgram, isSigner: false, isWritable: false },
  ];

  beforeEach(async () => {
    // Point the deployment config at the local mock chain-signatures program.
    await cleanUpProgramState(program, connection, provider, mockProgramId);
  });

  async function executeSign({
    transaction,
    privateKey,
    accountId,
    remainingAccounts,
  }: {
    transaction: Transaction;
    privateKey: Hex;
    accountId: bigint;
    remainingAccounts: anchor.web3.AccountMeta[];
  }) {
    const serializedMessage = Buffer.from(
      borshUtils.serialize.transaction(transaction)
    );

    const ethSignature = await signWithEthereum({
      hash: keccak256(serializedMessage),
      privateKey,
    });

    const { signature, recoveryId } = parseEthereumSignature(
      ethSignature.signature
    );
    const addressBytes = ethereumAddressToBytes(ethSignature.address);

    const verificationInstruction = createSecp256k1VerificationInstruction(
      signature,
      recoveryId,
      addressBytes,
      serializedMessage
    );

    const txSignature = await program.methods
      .executeEk256(new BN(accountId.toString()))
      .preInstructions([verificationInstruction])
      .remainingAccounts(remainingAccounts)
      .rpc();

    await confirmTransaction(provider.connection, txSignature);
    return txSignature;
  }

  async function createAccount(accountId: bigint, privateKey: Hex) {
    const account = privateKeyToAccount(privateKey);
    const signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();
    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(
      new BN(accountId.toString()),
      program.programId
    );
    const info = await program.account.abstractAccount.fetch(accountPDA);
    return { accountPDA, nonce: BigInt(info.nonce.toString()) };
  }

  function buildSignTransaction(accountId: bigint, nonce: bigint): Transaction {
    return {
      account_id: accountId,
      nonce,
      action: {
        Sign: {
          payload: new Uint8Array(32).fill(7),
          key_version: 0,
          path: "m/44'/60'/0'/0/0",
          algo: "secp256k1",
          dest: "ethereum",
          params: "",
        },
      },
    };
  }

  it("executes a Sign action via CPI into the configured chain-signatures program", async () => {
    const accountId = 0n;
    const { accountPDA, nonce } = await createAccount(accountId, PRIVATE_KEY);

    await executeSign({
      transaction: buildSignTransaction(accountId, nonce),
      privateKey: PRIVATE_KEY,
      accountId,
      remainingAccounts: signRemainingAccounts(mockProgramId),
    });

    const info = await program.account.abstractAccount.fetch(accountPDA);
    assert.equal(
      info.nonce.toString(),
      "1",
      "Nonce should increment after a successful Sign"
    );
  });

  it("rejects a Sign whose chain-signatures program does not match config", async () => {
    const accountId = 0n;
    const { nonce } = await createAccount(accountId, PRIVATE_KEY);

    const wrongProgram = Keypair.generate().publicKey;
    try {
      await executeSign({
        transaction: buildSignTransaction(accountId, nonce),
        privateKey: PRIVATE_KEY,
        accountId,
        remainingAccounts: signRemainingAccounts(wrongProgram),
      });
      assert.fail("Should have rejected a mismatched chain-signatures program");
    } catch (error: any) {
      assert.equal(
        error.error.errorMessage,
        "Provided chain-signatures program does not match the configured deployment id"
      );
    }
  });

  it("rejects a Sign with the wrong number of chain-signatures accounts", async () => {
    const accountId = 0n;
    const { nonce } = await createAccount(accountId, PRIVATE_KEY);

    try {
      await executeSign({
        transaction: buildSignTransaction(accountId, nonce),
        privateKey: PRIVATE_KEY,
        accountId,
        remainingAccounts: signRemainingAccounts(mockProgramId).slice(0, 2),
      });
      assert.fail("Should have rejected the wrong remaining-account count");
    } catch (error: any) {
      assert.equal(
        error.error.errorMessage,
        "Sign action requires [program_state, event_authority, chain_signatures_program] as remaining accounts"
      );
    }
  });
});

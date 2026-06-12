import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import { ComputeBudgetProgram } from "@solana/web3.js";
import { assert } from "chai";
import { createHash } from "crypto";
import { toBytes } from "viem";
import { borshUtils, Transaction } from "../borsh";
import { SolanaAa } from "../target/types/solana_aa";
import { buildEthereumIdentity, buildOidcIdentity } from "../utils/identity";
import { cleanUpProgramState, findAbstractAccountPDA } from "../utils/program";
import { confirmTransaction } from "../utils/solana";
import { groth16ProofFromFixture, loadZkOidcFixture } from "../utils/zk-oidc";

const ETH_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

// On-chain Groth16 verification needs more than the default 200k CU budget.
const ZK_VERIFY_COMPUTE_UNITS = 500_000;

describe("Execute ZK OIDC", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as anchor.Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;

  const fixture = loadZkOidcFixture("zk-oidc-add-identity.json");
  const groth16Proof = groth16ProofFromFixture(fixture);
  const fixtureKeyEntry = {
    iss: fixture.iss,
    pkHash: Array.from(Buffer.from(fixture.pkHash, "hex")),
  };

  // The Borsh transaction the fixture proof is bound to (account 0, nonce 0,
  // AddIdentity of fixture.ethAddress with enable_act_as).
  const fixtureTransaction: Transaction = {
    account_id: BigInt(fixture.accountId),
    nonce: BigInt(fixture.accountNonce),
    action: {
      AddIdentity: {
        identity: {
          Wallet: {
            Ethereum: toBytes(fixture.ethAddress as `0x${string}`),
          },
        },
        permissions: {
          enable_act_as: true,
        },
      },
    },
  };

  // Same transaction in the Anchor instruction-argument format.
  const fixtureTransactionArg = {
    accountId: new BN(fixture.accountId),
    nonce: new BN(fixture.accountNonce),
    action: {
      addIdentity: {
        "0": {
          identity: {
            wallet: {
              "0": {
                ethereum: {
                  "0": Array.from(toBytes(fixture.ethAddress as `0x${string}`)),
                },
              },
            },
          },
          permissions: {
            enableActAs: true,
          },
        },
      },
    },
  };

  const oidcIdentity = buildOidcIdentity(
    {
      iss: fixture.iss,
      aud: fixture.aud,
      emailHash: Buffer.from(fixture.emailHash, "hex"),
    },
    null
  );

  const resetOidcRegistry = async () => {
    try {
      await program.methods
        .closeOidcRegistry()
        .accounts({ authority: provider.wallet.publicKey })
        .rpc();
    } catch {
      // Registry did not exist yet.
    }

    const initSignature = await program.methods.initOidcRegistry().rpc();
    await confirmTransaction(connection, initSignature);

    const addKeySignature = await program.methods
      .addOidcKey(fixtureKeyEntry)
      .rpc();
    await confirmTransaction(connection, addKeySignature);
  };

  const createOidcAccount = async () => {
    const signature = await program.methods.createAccount(oidcIdentity).rpc();
    await confirmTransaction(connection, signature);
  };

  const executeZkOidc = async (
    transactionArg: typeof fixtureTransactionArg
  ) => {
    const signature = await program.methods
      .executeZkOidc(transactionArg.accountId, transactionArg, groth16Proof)
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({
          units: ZK_VERIFY_COMPUTE_UNITS,
        }),
      ])
      .rpc();

    await confirmTransaction(connection, signature);
    return signature;
  };

  beforeEach(async () => {
    await cleanUpProgramState(program, connection, provider);
    await resetOidcRegistry();
  });

  it("matches the golden fixture across Rust and TypeScript Borsh", () => {
    const serialized = Buffer.from(
      borshUtils.serialize.transaction(fixtureTransaction)
    );

    assert.strictEqual(serialized.toString("hex"), fixture.transactionBorsh);

    const nonce = createHash("sha256").update(serialized).digest("hex");
    assert.strictEqual(nonce, fixture.nonce);
  });

  it("executes an AddIdentity transaction authorized by a ZK OIDC proof", async () => {
    await createOidcAccount();

    await executeZkOidc(fixtureTransactionArg);

    const [accountPDA] = findAbstractAccountPDA(new BN(0), program.programId);
    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(accountInfo.nonce.toString(), "1");
    assert.strictEqual(accountInfo.identities.length, 2);

    const addedIdentityBytes =
      accountInfo.identities[1].identity?.wallet?.[0].ethereum?.[0];
    assert.deepEqual(
      Array.from(addedIdentityBytes || []),
      Array.from(toBytes(fixture.ethAddress as `0x${string}`))
    );
  });

  it("rejects replaying the same proof after the account nonce moved", async () => {
    await createOidcAccount();
    await executeZkOidc(fixtureTransactionArg);

    try {
      await executeZkOidc(fixtureTransactionArg);
      assert.fail("Expected replay to be rejected");
    } catch (error: any) {
      assert.include(error.toString(), "NonceMismatch");
    }
  });

  it("rejects a transaction that differs from the one bound in the proof", async () => {
    await createOidcAccount();

    const tamperedTransaction = {
      ...fixtureTransactionArg,
      action: {
        addIdentity: {
          "0": {
            identity: {
              wallet: {
                "0": {
                  ethereum: {
                    "0": Array.from(toBytes(ETH_ADDRESS)),
                  },
                },
              },
            },
            permissions: {
              enableActAs: true,
            },
          },
        },
      },
    };

    try {
      await executeZkOidc(tamperedTransaction);
      assert.fail("Expected transaction binding mismatch");
    } catch (error: any) {
      assert.include(error.toString(), "TransactionBindingMismatch");
    }
  });

  it("rejects proofs signed by a key that is not in the registry", async () => {
    await createOidcAccount();

    const removeSignature = await program.methods
      .removeOidcKey(fixtureKeyEntry)
      .rpc();
    await confirmTransaction(connection, removeSignature);

    try {
      await executeZkOidc(fixtureTransactionArg);
      assert.fail("Expected unregistered key to be rejected");
    } catch (error: any) {
      assert.include(error.toString(), "OidcKeyNotRegistered");
    }
  });

  it("rejects a valid proof for an identity the account does not have", async () => {
    const signature = await program.methods
      .createAccount(buildEthereumIdentity(ETH_ADDRESS, null))
      .rpc();
    await confirmTransaction(connection, signature);

    try {
      await executeZkOidc(fixtureTransactionArg);
      assert.fail("Expected unknown identity to be rejected");
    } catch (error: any) {
      assert.include(error.toString(), "IdentityNotFound");
    }
  });
});

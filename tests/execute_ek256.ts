import * as anchor from "@coral-xyz/anchor";
import { signWithEthereum } from "../utils/secp256k1-signer";
import { borshUtils, Transaction } from "../borsh";
import { confirmTransaction } from "../utils/solana";
import {
  parseEthereumSignature,
  ethereumAddressToBytes,
  createSecp256k1VerificationInstruction,
} from "../utils/ethereum";
import { Hex, keccak256, toBytes } from "viem";
import _ from "lodash";
import {
  cleanUpProgramState,
  findAbstractAccountPDA,
  findAccountManagerPDA,
} from "../utils/program";
import { buildEthereumIdentity } from "../utils/identity";
import { privateKeyToAccount } from "viem/accounts";
import { BN } from "bn.js";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";

const PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const ETH_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

const PRIVATE_KEY_2 =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;
const ETH_ADDRESS_2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

const PRIVATE_KEY_3 =
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as const;
const ETH_ADDRESS_3 = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

describe("Execute Ek256", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as anchor.Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;

  beforeEach(async () => {
    await cleanUpProgramState(program, connection, provider);
  });

  async function executeEk256({
    transaction,
    privateKey,
    accountId,
  }: {
    transaction: Transaction;
    privateKey: Hex;
    accountId: bigint;
  }) {
    const serializedMessage = Buffer.from(
      borshUtils.serialize.transaction(transaction)
    );

    const ethSignature = await signWithEthereum({
      hash: keccak256(serializedMessage),
      privateKey: privateKey as Hex,
    });

    const {
      signature: precompileSignatureBuffer,
      recoveryId: precompileRecoveryId,
    } = parseEthereumSignature(ethSignature.signature);
    const precompileAddressBytes = ethereumAddressToBytes(ethSignature.address);

    const verificationInstruction = createSecp256k1VerificationInstruction(
      precompileSignatureBuffer,
      precompileRecoveryId,
      precompileAddressBytes,
      serializedMessage
    );

    const txSignature = await program.methods
      .executeEk256(new BN(accountId.toString()))
      .preInstructions([verificationInstruction])
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    return txSignature;
  }

  it("should create account and execute AddIdentity transaction", async () => {
    const accountId = new BN(0);
    const account = privateKeyToAccount(PRIVATE_KEY);
    const signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();

    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    const transaction: Transaction = {
      account_id: BigInt(accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS_2),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

    await executeEk256({
      transaction,
      privateKey: PRIVATE_KEY,
      accountId: BigInt(accountId.toString()),
    });

    const accountInfoUpdated = await program.account.abstractAccount.fetch(
      accountPDA
    );
    assert.equal(
      accountInfoUpdated.nonce.toString(),
      "1",
      "Nonce should be incremented"
    );
    assert.equal(
      accountInfoUpdated.identities.length,
      2,
      "Should have 2 identities"
    );

    const identity2Data = accountInfoUpdated.identities[1];
    const identity2Bytes = identity2Data.identity?.wallet?.[0].ethereum?.[0];
    assert.deepEqual(
      Array.from(identity2Bytes || []),
      Array.from(toBytes(ETH_ADDRESS_2)),
      "Second identity should match added identity"
    );
  });

  it("should execute RemoveIdentity transaction", async () => {
    const accountId = new BN(0);
    const account = privateKeyToAccount(PRIVATE_KEY);
    let signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();
    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
    let accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    let transaction: Transaction = {
      account_id: BigInt(accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS_2),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

    await executeEk256({
      transaction,
      privateKey: PRIVATE_KEY,
      accountId: BigInt(accountId.toString()),
    });

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    transaction = {
      account_id: BigInt(accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        RemoveIdentity: {
          Wallet: {
            Ethereum: toBytes(ETH_ADDRESS_2),
          },
        },
      },
    };

    await executeEk256({
      transaction,
      privateKey: PRIVATE_KEY,
      accountId: BigInt(accountId.toString()),
    });

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.equal(
      accountInfo.nonce.toString(),
      "2",
      "Nonce should be incremented to 2"
    );
    assert.equal(
      accountInfo.identities.length,
      1,
      "Should have 1 identity remaining"
    );
  });

  it("should add multiple identities and remove them one by one", async () => {
    const accountId = new BN(0);
    const account = privateKeyToAccount(PRIVATE_KEY);
    const signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();
    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
    let accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    const additionalAddresses = [ETH_ADDRESS_2, ETH_ADDRESS_3];

    for (let i = 0; i < additionalAddresses.length; i++) {
      accountInfo = await program.account.abstractAccount.fetch(accountPDA);
      const transaction: Transaction = {
        account_id: BigInt(accountId.toString()),
        nonce: BigInt(accountInfo.nonce.toString()),
        action: {
          AddIdentity: {
            identity: {
              Wallet: {
                Ethereum: toBytes(additionalAddresses[i]),
              },
            },
            permissions: {
              enable_act_as: i % 2 === 0,
            },
          },
        },
      };

      await executeEk256({
        transaction,
        privateKey: PRIVATE_KEY,
        accountId: BigInt(accountId.toString()),
      });
    }

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.equal(accountInfo.identities.length, 3, "Should have 3 identities");
    assert.equal(accountInfo.nonce.toString(), "2", "Nonce should be 2");

    for (let i = 0; i < additionalAddresses.length; i++) {
      accountInfo = await program.account.abstractAccount.fetch(accountPDA);
      const transaction: Transaction = {
        account_id: BigInt(accountId.toString()),
        nonce: BigInt(accountInfo.nonce.toString()),
        action: {
          RemoveIdentity: {
            Wallet: {
              Ethereum: toBytes(additionalAddresses[i]),
            },
          },
        },
      };

      await executeEk256({
        transaction,
        privateKey: PRIVATE_KEY,
        accountId: BigInt(accountId.toString()),
      });

      accountInfo = await program.account.abstractAccount.fetch(accountPDA);
      assert.equal(
        accountInfo.identities.length,
        3 - (i + 1),
        `Should have ${3 - (i + 1)} identities after removing ${i + 1}`
      );
    }

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.equal(accountInfo.identities.length, 1, "Should have 1 identity");
    assert.equal(accountInfo.nonce.toString(), "4", "Nonce should be 4");
  });

  it("should execute transaction from secondary identity after adding with act_as permission", async () => {
    const accountId = new BN(0);
    const primaryAccount = privateKeyToAccount(PRIVATE_KEY);
    const signature = await program.methods
      .createAccount(buildEthereumIdentity(primaryAccount.address, null))
      .rpc();
    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
    let accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    const transaction: Transaction = {
      account_id: BigInt(accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS_2),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

    await executeEk256({
      transaction,
      privateKey: PRIVATE_KEY,
      accountId: BigInt(accountId.toString()),
    });

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    const txFromSecondary: Transaction = {
      account_id: BigInt(accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS_3),
            },
          },
          permissions: {
            enable_act_as: false,
          },
        },
      },
    };

    await executeEk256({
      transaction: txFromSecondary,
      privateKey: PRIVATE_KEY_2,
      accountId: BigInt(accountId.toString()),
    });

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.equal(accountInfo.identities.length, 3, "Should have 3 identities");

    const thirdIdentity = accountInfo.identities[2];
    assert.isFalse(
      thirdIdentity.permissions?.enableActAs,
      "Third identity should have enable_act_as set to false"
    );
  });

  it("should execute RemoveAccount transaction", async () => {
    const accountId = new BN(0);
    const account = privateKeyToAccount(PRIVATE_KEY);
    const signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();
    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    const balanceBeforeRemove = await connection.getBalance(
      provider.wallet.publicKey
    );

    const transaction: Transaction = {
      account_id: BigInt(accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        RemoveAccount: {},
      },
    };

    await executeEk256({
      transaction,
      privateKey: PRIVATE_KEY,
      accountId: BigInt(accountId.toString()),
    });

    const balanceAfterRemove = await connection.getBalance(
      provider.wallet.publicKey
    );
    assert.isAbove(
      balanceAfterRemove,
      balanceBeforeRemove,
      "Signer balance should increase after removing account due to rent refund"
    );

    try {
      await program.account.abstractAccount.fetch(accountPDA);
      assert.fail("Account should have been deleted");
    } catch (error) {}
  });

  it("should create multiple accounts and verify they can be managed independently", async () => {
    const accounts = [
      { privateKey: PRIVATE_KEY, address: ETH_ADDRESS },
      { privateKey: PRIVATE_KEY_2, address: ETH_ADDRESS_2 },
      { privateKey: PRIVATE_KEY_3, address: ETH_ADDRESS_3 },
    ];

    for (let i = 0; i < accounts.length; i++) {
      const account = privateKeyToAccount(accounts[i].privateKey as any);
      const signature = await program.methods
        .createAccount(buildEthereumIdentity(account.address, null))
        .rpc();
      await confirmTransaction(provider.connection, signature);

      const [accountPDA] = findAbstractAccountPDA(new BN(i), program.programId);
      const accountInfo = await program.account.abstractAccount.fetch(
        accountPDA
      );
      assert.equal(accountInfo.identities.length, 1, "Should have 1 identity");
    }

    const [accountManagerPDA] = findAccountManagerPDA(program.programId);
    const accountManagerInfo = await program.account.accountManager.fetch(
      accountManagerPDA
    );
    assert.equal(
      accountManagerInfo.nextAccountId.toNumber(),
      accounts.length,
      `Next account ID should be ${accounts.length}`
    );

    for (let i = 0; i < accounts.length; i++) {
      const accountId = new BN(i);
      const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
      let accountInfo = await program.account.abstractAccount.fetch(accountPDA);

      const nextAddressIndex = (i + 1) % accounts.length;
      const transaction: Transaction = {
        account_id: BigInt(accountId.toString()),
        nonce: BigInt(accountInfo.nonce.toString()),
        action: {
          AddIdentity: {
            identity: {
              Wallet: {
                Ethereum: toBytes(accounts[nextAddressIndex].address),
              },
            },
            permissions: {
              enable_act_as: false,
            },
          },
        },
      };

      await executeEk256({
        transaction,
        privateKey: accounts[i].privateKey as any,
        accountId: BigInt(accountId.toString()),
      });

      accountInfo = await program.account.abstractAccount.fetch(accountPDA);
      assert.equal(
        accountInfo.identities.length,
        2,
        `Account ${i} should have 2 identities`
      );
    }
  });

  it("should fail when using incorrect nonce", async () => {
    const accountId = new BN(0);
    const account = privateKeyToAccount(PRIVATE_KEY);

    const signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();

    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    const transaction: Transaction = {
      account_id: BigInt(accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toNumber() + 1),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS_2),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

    try {
      await executeEk256({
        transaction,
        privateKey: PRIVATE_KEY,
        accountId: BigInt(accountId.toString()),
      });
      assert.fail("Transaction should have failed due to nonce mismatch");
    } catch (error: any) {
      assert.equal(
        error.error.errorMessage,
        "Nonce mismatch",
        "Error should be NonceMismatch"
      );
    }
  });

  it("should fail when using incorrect account_id", async () => {
    const accountId = new BN(0);
    const account = privateKeyToAccount(PRIVATE_KEY);

    const signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();

    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    const transaction: Transaction = {
      account_id: BigInt(999),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS_2),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

    try {
      await executeEk256({
        transaction,
        privateKey: PRIVATE_KEY,
        accountId: BigInt(accountId.toString()),
      });
      assert.fail("Transaction should have failed due to account ID mismatch");
    } catch (error: any) {
      assert.equal(
        error.error.errorMessage,
        "Account ID mismatch",
        "Error should be AccountIdMismatch"
      );
    }
  });

  it("should fail when using an identity not registered with the account", async () => {
    const accountId = new BN(0);
    const account = privateKeyToAccount(PRIVATE_KEY);

    const signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();

    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(accountId, program.programId);
    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    const transaction: Transaction = {
      account_id: BigInt(accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS_3),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

    try {
      await executeEk256({
        transaction,
        privateKey: PRIVATE_KEY_3,
        accountId: BigInt(accountId.toString()),
      });
      assert.fail("Transaction should have failed due to identity not found");
    } catch (error: any) {
      assert.equal(
        error.error.errorMessage,
        "Identity not found in account",
        "Error should be IdentityNotFound"
      );
    }
  });
});

import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import { confirmTransaction, logComputeUnitsUsed } from "../utils/solana";
import { Address, toBytes } from "viem";
import { PublicKey } from "@solana/web3.js";
import {
  ABSTRACT_ACCOUNT_SEED,
  ACCOUNT_MANAGER_SEED,
} from "../utils/constants";
import {
  cleanUpProgramState,
  findAbstractAccountPDA,
  findAccountManagerPDA,
} from "../utils/program";

const ETH_ADDRESS_KEY = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
const ETH_ADDRESS_KEY_2 = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
const ETH_ADDRESS_KEY_3 = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";
const ETH_ADDRESS_KEY_4 = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65";
const ETH_ADDRESS_KEY_5 = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc";
const ETH_ADDRESS_KEY_6 = "0x976EA74026E726554dB657fA54763abd0C3a0aa9";

type Permissions = {
  enableActAs: boolean;
} | null;

const buildEthereumIdentity = (address: Address, permissions: Permissions) => {
  return {
    identity: {
      wallet: {
        "0": {
          ethereum: {
            "0": Array.from(toBytes(address)),
          },
        },
      },
    },
    permissions,
  };
};

const ETHEREUM_IDENTITY_WITH_PERMISSIONS = buildEthereumIdentity(
  ETH_ADDRESS_KEY,
  null
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_2 = buildEthereumIdentity(
  ETH_ADDRESS_KEY_2,
  { enableActAs: true }
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_3 = buildEthereumIdentity(
  ETH_ADDRESS_KEY_3,
  { enableActAs: false }
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_4 = buildEthereumIdentity(
  ETH_ADDRESS_KEY_4,
  { enableActAs: false }
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_5 = buildEthereumIdentity(
  ETH_ADDRESS_KEY_5,
  { enableActAs: true }
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_6 = buildEthereumIdentity(
  ETH_ADDRESS_KEY_6,
  null
);

describe("Accounts", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  beforeEach(async () => {
    await cleanUpProgramState(program, connection, provider);
  });

  it("can create an account with Ethereum identity", async () => {
    const signature = await program.methods
      .createAccount(ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, signature);

    const [accountPDA] = findAbstractAccountPDA(new BN(0), program.programId);

    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(accountInfo.nonce.toString(), "0", "Nonce should be 0");
    assert.strictEqual(
      accountInfo.identities.length,
      1,
      "Should have 1 identity"
    );

    const identityWithPermissions = accountInfo.identities[0];
    assert.isDefined(
      identityWithPermissions.identity.wallet,
      "Identity should be a wallet type"
    );

    const wallet = identityWithPermissions.identity.wallet["0"];
    assert.isDefined(wallet.ethereum, "Wallet type should be ethereum");
    assert.deepEqual(
      wallet.ethereum[0],
      Array.from(toBytes(ETH_ADDRESS_KEY)),
      "Public key should match"
    );
  });

  it("can add an identity to an existing account", async () => {
    const createSignature = await program.methods
      .createAccount(ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, createSignature);

    const addSignature = await program.methods
      .addIdentity(new BN(0), ETHEREUM_IDENTITY_WITH_PERMISSIONS_2)
      .rpc();

    await confirmTransaction(connection, addSignature);

    const [accountPDA] = findAbstractAccountPDA(new BN(0), program.programId);

    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(
      accountInfo.identities.length,
      2,
      "Should have 2 identities"
    );

    const firstEthereumIdentity = accountInfo.identities.find(
      (id) =>
        id.identity.wallet &&
        Array.from(id.identity.wallet[0].ethereum[0]).toString() ===
          Array.from(toBytes(ETH_ADDRESS_KEY)).toString()
    );

    assert.isDefined(
      firstEthereumIdentity,
      "First Ethereum identity should exist"
    );
    assert.deepEqual(
      firstEthereumIdentity?.identity.wallet?.[0].ethereum?.[0],
      Array.from(toBytes(ETH_ADDRESS_KEY)),
      "First Ethereum public key should match"
    );

    const secondEthereumIdentity = accountInfo.identities.find(
      (id) =>
        id.identity.wallet &&
        Array.from(id.identity.wallet[0].ethereum[0]).toString() ===
          Array.from(toBytes(ETH_ADDRESS_KEY_2)).toString()
    );

    assert.isDefined(
      secondEthereumIdentity,
      "Second Ethereum identity should exist"
    );
    assert.deepEqual(
      secondEthereumIdentity?.identity.wallet?.[0].ethereum?.[0],
      Array.from(toBytes(ETH_ADDRESS_KEY_2)),
      "Second Ethereum public key should match"
    );
  });

  it("can remove an identity from an account", async () => {
    const createSignature = await program.methods
      .createAccount(ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, createSignature);

    const addSignature = await program.methods
      .addIdentity(new BN(0), ETHEREUM_IDENTITY_WITH_PERMISSIONS_2)
      .rpc();

    await confirmTransaction(connection, addSignature);

    const [accountPDA] = findAbstractAccountPDA(new BN(0), program.programId);

    let accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.strictEqual(
      accountInfo.identities.length,
      2,
      "Should have 2 identities before removal"
    );

    const removeSignature = await program.methods
      .removeIdentity(new BN(0), ETHEREUM_IDENTITY_WITH_PERMISSIONS.identity)
      .rpc();

    await confirmTransaction(connection, removeSignature);

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.strictEqual(
      accountInfo.identities.length,
      1,
      "Should have 1 identity after removal"
    );

    const remainingIdentityWithPermissions = accountInfo.identities[0];
    assert.isDefined(
      remainingIdentityWithPermissions.identity.wallet,
      "Remaining identity should be Ethereum wallet type"
    );
    assert.deepEqual(
      remainingIdentityWithPermissions.identity.wallet[0].ethereum[0],
      Array.from(toBytes(ETH_ADDRESS_KEY_2)),
      "Ethereum public key should match"
    );
  });

  it("can create accounts with different identities and check account manager state", async () => {
    const accounts = [
      ETHEREUM_IDENTITY_WITH_PERMISSIONS,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_2,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_3,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_4,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_5,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_6,
    ];

    for (let i = 0; i < accounts.length; i++) {
      const signature = await program.methods.createAccount(accounts[i]).rpc();

      await confirmTransaction(connection, signature);

      const [accountPDA] = findAbstractAccountPDA(new BN(i), program.programId);
      const accountInfo = await program.account.abstractAccount
        .fetch(accountPDA)
        .catch(() => {
          assert.fail(`Account ${i} should have been created`);
        });

      assert.strictEqual(
        accountInfo.nonce.toString(),
        "0",
        "Nonce should be 0"
      );
      assert.strictEqual(
        accountInfo.identities.length,
        1,
        "Should have 1 identity"
      );

      const storedIdentity = accountInfo.identities[0];
      assert.deepEqual(
        storedIdentity.identity,
        accounts[i].identity,
        `Identity ${i} should match what was provided`
      );

      const [accountManagerPDA] = findAccountManagerPDA(program.programId);
      const accountManagerInfo = await program.account.accountManager.fetch(
        accountManagerPDA
      );

      assert.strictEqual(
        accountManagerInfo.nextAccountId.toNumber(),
        i + 1,
        `Next account ID should be ${i + 1} after creating account ${i}`
      );
    }

    const [accountManagerPDA] = findAccountManagerPDA(program.programId);
    const accountManagerInfo = await program.account.accountManager.fetch(
      accountManagerPDA
    );

    assert.strictEqual(
      accountManagerInfo.nextAccountId.toNumber(),
      6,
      "Next account ID should be 6 after creating 6 accounts (0-indexed)"
    );

    for (let i = 0; i < accounts.length; i++) {
      const signature = await program.methods
        .deleteAccount(new BN(i))
        .accounts({
          signer: provider.wallet.publicKey,
        })
        .rpc();

      await confirmTransaction(connection, signature);

      const [accountPDA] = findAbstractAccountPDA(new BN(i), program.programId);

      const accountInfo = await program.account.abstractAccount
        .fetch(accountPDA)
        .catch(() => {});
      if (accountInfo) {
        assert.fail(`Account ${i} should have been deleted`);
      }
    }

    const finalAccountManagerInfo = await program.account.accountManager.fetch(
      accountManagerPDA
    );

    assert.strictEqual(
      finalAccountManagerInfo.nextAccountId.toNumber(),
      6,
      "Next account ID should still be 6 after deleting all accounts"
    );
  });
});

import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import { confirmTransaction, logComputeUnitsUsed } from "../utils/solana";
import { Address, Hex, toBytes } from "viem";
import {
  cleanUpProgramState,
  findAbstractAccountPDA,
  findAccountManagerPDA,
} from "../utils/program";

const ETH_ADDRESS: Hex = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
const ETH_ADDRESS_2: Hex = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
const ETH_ADDRESS_3: Hex = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";
const ETH_ADDRESS_4: Hex = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65";
const ETH_ADDRESS_5: Hex = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc";
const ETH_ADDRESS_6: Hex = "0x976EA74026E726554dB657fA54763abd0C3a0aa9";

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
  ETH_ADDRESS,
  null
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_2 = buildEthereumIdentity(
  ETH_ADDRESS_2,
  { enableActAs: true }
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_3 = buildEthereumIdentity(
  ETH_ADDRESS_3,
  { enableActAs: false }
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_4 = buildEthereumIdentity(
  ETH_ADDRESS_4,
  { enableActAs: false }
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_5 = buildEthereumIdentity(
  ETH_ADDRESS_5,
  { enableActAs: true }
);

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_6 = buildEthereumIdentity(
  ETH_ADDRESS_6,
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

  it("can create accounts with different identities and check account manager state", async () => {
    const accounts = [
      ETHEREUM_IDENTITY_WITH_PERMISSIONS,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_2,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_3,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_4,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_5,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_6,
    ];

    const initialSignerBalance = await connection.getBalance(
      provider.wallet.publicKey
    );

    for (let i = 0; i < accounts.length; i++) {
      const signerBalanceBefore = await connection.getBalance(
        provider.wallet.publicKey
      );

      const signature = await program.methods.createAccount(accounts[i]).rpc();

      await confirmTransaction(connection, signature);

      const signerBalanceAfter = await connection.getBalance(
        provider.wallet.publicKey
      );
      assert.isBelow(
        signerBalanceAfter,
        signerBalanceBefore,
        `Signer balance should decrease after creating account ${i}`
      );

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
      const signerBalanceBefore = await connection.getBalance(
        provider.wallet.publicKey
      );

      const signature = await program.methods
        .deleteAccount(new BN(i))
        .accounts({
          signer: provider.wallet.publicKey,
        })
        .rpc();

      await confirmTransaction(connection, signature);

      const signerBalanceAfter = await connection.getBalance(
        provider.wallet.publicKey
      );

      assert.isAbove(
        signerBalanceAfter,
        signerBalanceBefore,
        `Signer balance should increase after deleting account ${i} due to rent refund`
      );

      const [accountPDA] = findAbstractAccountPDA(new BN(i), program.programId);

      const accountInfo = await program.account.abstractAccount
        .fetch(accountPDA)
        .catch(() => {});
      if (accountInfo) {
        assert.fail(`Account ${i} should have been deleted`);
      }
    }

    const finalSignerBalance = await connection.getBalance(
      provider.wallet.publicKey
    );

    assert.isBelow(finalSignerBalance, initialSignerBalance);

    const finalAccountManagerInfo = await program.account.accountManager.fetch(
      accountManagerPDA
    );

    assert.strictEqual(
      finalAccountManagerInfo.nextAccountId.toNumber(),
      6,
      "Next account ID should still be 6 after deleting all accounts"
    );
  });

  it("can add multiple identities to one account and then remove them", async () => {
    const initialSignerBalance = await connection.getBalance(
      provider.wallet.publicKey
    );

    const createSignature = await program.methods
      .createAccount(ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, createSignature);

    const balanceAfterCreate = await connection.getBalance(
      provider.wallet.publicKey
    );
    assert.isBelow(
      balanceAfterCreate,
      initialSignerBalance,
      "Signer balance should decrease after creating account"
    );

    const identities = [
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_2,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_3,
      ETHEREUM_IDENTITY_WITH_PERMISSIONS_4,
    ];

    for (let i = 0; i < identities.length; i++) {
      const balanceBeforeAdd = await connection.getBalance(
        provider.wallet.publicKey
      );

      const addSignature = await program.methods
        .addIdentity(new BN(0), identities[i])
        .rpc();

      await confirmTransaction(connection, addSignature);

      const balanceAfterAdd = await connection.getBalance(
        provider.wallet.publicKey
      );
      assert.isBelow(
        balanceAfterAdd,
        balanceBeforeAdd,
        `Signer balance should decrease after adding identity ${
          i + 1
        } due to account reallocation`
      );
    }

    const [accountPDA] = findAbstractAccountPDA(new BN(0), program.programId);
    let accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(
      accountInfo.identities.length,
      4,
      "Should have 4 identities"
    );

    for (let i = 0; i < identities.length; i++) {
      const balanceBeforeRemove = await connection.getBalance(
        provider.wallet.publicKey
      );

      const removeSignature = await program.methods
        .removeIdentity(new BN(0), identities[i].identity)
        .rpc();

      await confirmTransaction(connection, removeSignature);

      const balanceAfterRemove = await connection.getBalance(
        provider.wallet.publicKey
      );
      assert.isAbove(
        balanceAfterRemove,
        balanceBeforeRemove,
        `Signer balance should increase after removing identity ${
          i + 1
        } due to account reallocation refund`
      );

      accountInfo = await program.account.abstractAccount.fetch(accountPDA);
      assert.strictEqual(
        accountInfo.identities.length,
        4 - (i + 1),
        `Should have ${4 - (i + 1)} identities after removing ${i + 1}`
      );
    }

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    const remainingIdentity = accountInfo.identities[0];
    assert.deepEqual(
      Array.from(remainingIdentity.identity?.wallet?.[0].ethereum?.[0] ?? []),
      Array.from(toBytes(ETH_ADDRESS)),
      "Only the original identity should remain"
    );

    const balanceBeforeDelete = await connection.getBalance(
      provider.wallet.publicKey
    );

    const deleteSignature = await program.methods
      .deleteAccount(new BN(0))
      .accounts({
        signer: provider.wallet.publicKey,
      })
      .rpc();

    await confirmTransaction(connection, deleteSignature);

    const balanceAfterDelete = await connection.getBalance(
      provider.wallet.publicKey
    );
    assert.isAbove(
      balanceAfterDelete,
      balanceBeforeDelete,
      "Signer balance should increase after deleting account due to rent refund"
    );

    const deletedAccountInfo = await program.account.abstractAccount
      .fetch(accountPDA)
      .catch(() => null);

    assert.isNull(deletedAccountInfo, "Account should have been deleted");
  });
});

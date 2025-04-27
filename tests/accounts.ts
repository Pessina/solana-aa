import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import { confirmTransaction, logComputeUnitsUsed } from "../utils/solana";
import { toBytes } from "viem";
import { PublicKey } from "@solana/web3.js";
import litesvm from "litesvm";

// Constants for comparison
const ETH_PUBLIC_KEY = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const WEBAUTHN_KEY_ID = "0x123456789abcdef";

const ETH_PUBLIC_KEY_2 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92264";

const ETHEREUM_IDENTITY_WITH_PERMISSIONS = {
  identity: {
    wallet: {
      "0": {
        ethereum: {
          0: Array.from(toBytes(ETH_PUBLIC_KEY)),
        },
      },
    },
  },
  permissions: {
    enableActAs: true,
  },
};

const ETHEREUM_IDENTITY_WITH_PERMISSIONS_2 = {
  identity: {
    wallet: {
      "0": {
        ethereum: {
          0: Array.from(toBytes(ETH_PUBLIC_KEY_2)),
        },
      },
    },
  },
  permissions: null,
};

const findAccountPDA = (accountId: BN, programId: PublicKey) => {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("account"), accountId.toArrayLike(Buffer, "le", 8)],
    programId
  );
};

describe.only("Accounts", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  before(async () => {
    const signature = await program.methods.initContract().rpc();

    await confirmTransaction(connection, signature);
  });

  beforeEach(async () => {
    // Reset the validator before each test to ensure a clean state
    try {
      await connection.requestAirdrop(provider.wallet.publicKey, 1000000000);
      await new Promise((resolve) => setTimeout(resolve, 500)); // Small delay to ensure airdrop completes

      // Reset the validator by clearing all accounts and transactions
      const resetCmd = require("child_process").spawnSync(
        "solana-test-validator",
        ["--reset"],
        {
          stdio: "ignore",
          shell: true,
        }
      );

      if (resetCmd.error) {
        console.error("Error resetting validator:", resetCmd.error);
      }

      // Wait a moment for the validator to restart
      await new Promise((resolve) => setTimeout(resolve, 1000));
    } catch (error: any) {
      console.error("Failed to reset validator:", error.message);
    }
    try {
      const [accountPDA] = findAccountPDA(new BN(0), program.programId);

      const accountInfo = await connection.getAccountInfo(accountPDA);

      if (accountInfo) {
        const signature = await program.methods
          .deleteAccount(new BN(0))
          .accounts({
            signer: provider.wallet.publicKey,
          })
          .rpc();

        await confirmTransaction(connection, signature);
      }
    } catch (error: any) {
      console.log(
        "Setup: No account to clean up or error occurred:",
        error.message
      );
    }
  });

  it("Can create an account with Ethereum identity", async () => {
    const signature = await program.methods
      .createAccount(ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, signature);

    const [accountPDA] = findAccountPDA(new BN(0), program.programId);

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
      Array.from(toBytes(ETH_PUBLIC_KEY)),
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

    const [accountPDA] = findAccountPDA(new BN(0), program.programId);

    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(
      accountInfo.identities.length,
      2,
      "Should have 2 identities"
    );

    const webAuthnIdentityWithPermissions = accountInfo.identities.find(
      (id) => id.identity.webAuthn
    );

    assert.isDefined(
      webAuthnIdentityWithPermissions,
      "WebAuthn identity should exist"
    );
    assert.strictEqual(
      webAuthnIdentityWithPermissions?.identity.webAuthn?.[0].keyId,
      WEBAUTHN_KEY_ID,
      "WebAuthn credential ID should match"
    );

    const ethereumIdentityWithPermissions = accountInfo.identities.find(
      (id) => id.identity.wallet
    );
    assert.isDefined(
      ethereumIdentityWithPermissions,
      "Ethereum identity should exist"
    );
    assert.strictEqual(
      ethereumIdentityWithPermissions?.identity.wallet?.[0].ethereum?.[0],
      Array.from(toBytes(ETH_PUBLIC_KEY_2)),
      "Ethereum public key should match"
    );
  });

  it("can remove an identity from an account", async () => {
    const createSignature = await program.methods
      .createAccount(ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, createSignature);

    const addSignature = await program.methods
      .addIdentity(new BN(0), ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, addSignature);

    const [accountPDA] = findAccountPDA(new BN(0), program.programId);

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
      remainingIdentityWithPermissions.identity.webAuthn,
      "Remaining identity should be WebAuthn type"
    );
    assert.strictEqual(
      remainingIdentityWithPermissions.identity.webAuthn[0].keyId,
      WEBAUTHN_KEY_ID,
      "WebAuthn credential ID should match"
    );
  });

  // it("Can handle multiple identities (stress test)", async () => {
  //   const identityWithPermissions = [
  //     ETHEREUM_IDENTITY_WITH_PERMISSIONS,
  //     ETHEREUM_IDENTITY_WITH_PERMISSIONS_2,
  //     {
  //       identity: createEthereumIdentity(ETH_PUBLIC_KEY_2),
  //       permissions: null,
  //     },
  //     {
  //       identity: createWebAuthnIdentity(
  //         WEBAUTHN_KEY_ID_2,
  //         WEBAUTHN_PUBLIC_KEY_2
  //       ),
  //       permissions: null,
  //     },
  //     {
  //       identity: createEthereumIdentity(ETH_PUBLIC_KEY_3),
  //       permissions: null,
  //     },
  //   ];

  //   const createSignature = await program.methods
  //     .createAccount(ACCOUNT_ID, identityWithPermissions[0])
  //     .rpc();

  //   await confirmTransaction(connection, createSignature);

  //   // await logComputeUnitsUsed({
  //   //   txSignature: createSignature,
  //   //   memo: "Create account with first identity",
  //   // });

  //   for (let i = 1; i < identityWithPermissions.length; i++) {
  //     const addSignature = await program.methods
  //       .addIdentity(ACCOUNT_ID, identityWithPermissions[i])
  //       .rpc();

  //     await confirmTransaction(connection, addSignature);

  //     // await logComputeUnitsUsed({
  //     //   txSignature: addSignature,
  //     //   memo: `Add identity ${i + 1}`,
  //     // });
  //   }

  //   const [accountPDA] = findAccountPDA(ACCOUNT_ID, program.programId);

  //   let accountInfo = await program.account.abstractAccount.fetch(accountPDA);
  //   assert.strictEqual(
  //     accountInfo.identities.length,
  //     5,
  //     "Should have 5 identities after adding all"
  //   );

  //   // const accountData = await connection.getAccountInfo(accountPDA);x

  //   // if (accountData) {
  //   //   console.log(`Account size: ${accountData.data.length} bytes`);
  //   //   console.log(
  //   //     `Account rent exemption: ${await connection.getMinimumBalanceForRentExemption(
  //   //       accountData.data.length
  //   //     )} lamports`
  //   //   );
  //   // } else {
  //   //   console.log("Account not found");
  //   // }

  //   for (let i = 0; i < identityWithPermissions.length; i++) {
  //     const removeSignature = await program.methods
  //       .removeIdentity(ACCOUNT_ID, identityWithPermissions[i].identity)
  //       .rpc();

  //     await confirmTransaction(connection, removeSignature);

  //     // await logComputeUnitsUsed({
  //     //   txSignature: removeSignature,
  //     //   memo: `Remove identity ${i + 1}`,
  //     // });

  //     accountInfo = await program.account.abstractAccount.fetch(accountPDA);
  //     assert.strictEqual(
  //       accountInfo.identities.length,
  //       4 - i,
  //       `Should have ${4 - i} identities after removing ${i + 1}`
  //     );
  //   }
  // });

  // it("Can create an account with identity permissions", async () => {
  //   const identityWithPermissions: IdentityWithPermissions = {
  //     identity: createEthereumIdentity(ETH_PUBLIC_KEY_3),
  //     permissions: createDefaultPermissions(),
  //   };

  //   const signature = await program.methods
  //     .createAccount(identityWithPermissions)
  //     .rpc();

  //   await confirmTransaction(connection, signature);

  //   const [accountPDA] = findAccountPDA(ACCOUNT_ID, program.programId);
  //   const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

  //   console.log(JSON.stringify(accountInfo, null, 2));

  //   assert.strictEqual(accountInfo.nonce.toString(), "0", "Nonce should be 0");
  //   assert.strictEqual(
  //     accountInfo.identities.length,
  //     1,
  //     "Should have 1 identity"
  //   );

  //   const storedIdentity = accountInfo.identities[0];
  //   assert.deepEqual(
  //     storedIdentity.identity,
  //     identityWithPermissions.identity,
  //     "Identity should match what was provided"
  //   );
  //   assert.isNotNull(
  //     storedIdentity.permissions,
  //     "Permissions should not be null"
  //   );
  //   assert.isTrue(
  //     storedIdentity.permissions.enableActAs,
  //     "enableActAs should be true"
  //   );
  // });
});

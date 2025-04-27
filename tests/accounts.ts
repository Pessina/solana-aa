import * as anchor from "@coral-xyz/anchor";
import { BN, Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import { confirmTransaction, logComputeUnitsUsed } from "../utils/solana";
import { toBytes } from "viem";
import { PublicKey } from "@solana/web3.js";

// Constants for comparison
const ETH_PUBLIC_KEY = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
const ETH_PUBLIC_KEY_2 = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

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

const findAccountManagerPDA = (programId: PublicKey) => {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("account_manager")],
    programId
  );
};

describe("Accounts", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  beforeEach(async () => {
    try {
      const [accountManagerPDA] = findAccountManagerPDA(program.programId);
      let accountManagerInfo;

      try {
        accountManagerInfo = await program.account.accountManager.fetch(
          accountManagerPDA
        );
      } catch (error) {
        console.log("Account manager doesn't exist yet");
      }

      if (accountManagerInfo) {
        const latestAccountId = accountManagerInfo.latestAccountId;

        for (let i = 0; i <= latestAccountId.toNumber(); i++) {
          const [accountPDA] = findAccountPDA(new BN(i), program.programId);

          try {
            const accountInfo = await connection.getAccountInfo(accountPDA);

            if (accountInfo) {
              const signature = await program.methods
                .deleteAccount(new BN(i))
                .accounts({
                  signer: provider.wallet.publicKey,
                })
                .rpc();

              await confirmTransaction(connection, signature);
            }
          } catch (error) {
            console.log(`No account with ID ${i} or error deleting it:`, error);
          }
        }

        const closeSignature = await program.methods
          .closeContract()
          .accounts({
            signer: provider.wallet.publicKey,
          })
          .rpc();

        await confirmTransaction(connection, closeSignature);
      }

      const initSignature = await program.methods.initContract().rpc();
      await confirmTransaction(connection, initSignature);
    } catch (error: any) {
      console.log("Setup error:", error.message);
    }
  });

  it("can create an account with Ethereum identity", async () => {
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

    // Find the first Ethereum identity (original one)
    const firstEthereumIdentity = accountInfo.identities.find(
      (id) =>
        id.identity.wallet &&
        Array.from(id.identity.wallet[0].ethereum[0]).toString() ===
          Array.from(toBytes(ETH_PUBLIC_KEY)).toString()
    );

    assert.isDefined(
      firstEthereumIdentity,
      "First Ethereum identity should exist"
    );
    assert.deepEqual(
      firstEthereumIdentity?.identity.wallet?.[0].ethereum?.[0],
      Array.from(toBytes(ETH_PUBLIC_KEY)),
      "First Ethereum public key should match"
    );

    // Find the second Ethereum identity
    const secondEthereumIdentity = accountInfo.identities.find(
      (id) =>
        id.identity.wallet &&
        Array.from(id.identity.wallet[0].ethereum[0]).toString() ===
          Array.from(toBytes(ETH_PUBLIC_KEY_2)).toString()
    );

    assert.isDefined(
      secondEthereumIdentity,
      "Second Ethereum identity should exist"
    );
    assert.deepEqual(
      secondEthereumIdentity?.identity.wallet?.[0].ethereum?.[0],
      Array.from(toBytes(ETH_PUBLIC_KEY_2)),
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
      remainingIdentityWithPermissions.identity.wallet,
      "Remaining identity should be Ethereum wallet type"
    );
    assert.deepEqual(
      remainingIdentityWithPermissions.identity.wallet[0].ethereum[0],
      Array.from(toBytes(ETH_PUBLIC_KEY_2)),
      "Ethereum public key should match"
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

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import { confirmTransaction, logComputeUnitsUsed } from "../utils/solana";
import {
  createEthereumIdentity,
  createWebAuthnIdentity,
  findAccountPDA,
  IdentityWithPermissions,
} from "../utils/account";

const ACCOUNT_ID = "my_account_id_1";

// Constants for comparison
const ETH_PUBLIC_KEY =
  "0x031a08c5e977ab0a71d1ac3e5b8c435a431afb4c6d641b00a8b91496c5b085e6aa";
const WEBAUTHN_KEY_ID = "0x123456789abcdef";
const WEBAUTHN_PUBLIC_KEY =
  "0x031a08c5e977ab0a71d1ac3e5b8c435a431afb4c6d641b00a8b91496c5b085e6ab";
const ETH_PUBLIC_KEY_2 =
  "0x031a08c5e977ab0a71d1ac3e5b8c435a431afb4c6d641b00a8b91496c5b085e6ac";
const WEBAUTHN_KEY_ID_2 = "0xabcdef123456789";
const WEBAUTHN_PUBLIC_KEY_2 =
  "0x031a08c5e977ab0a71d1ac3e5b8c435a431afb4c6d641b00a8b91496c5b085e6ad";
const ETH_PUBLIC_KEY_3 =
  "0x031a08c5e977ab0a71d1ac3e5b8c435a431afb4c6d641b00a8b91496c5b085e6ae";

const ETHEREUM_IDENTITY_WITH_PERMISSIONS: IdentityWithPermissions = {
  identity: createEthereumIdentity(ETH_PUBLIC_KEY),
  permissions: null,
};

const WEB_AUTHN_IDENTITY_WITH_PERMISSIONS: IdentityWithPermissions = {
  identity: createWebAuthnIdentity(WEBAUTHN_KEY_ID, WEBAUTHN_PUBLIC_KEY),
  permissions: null,
};

describe("Accounts", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  beforeEach(async () => {
    try {
      const [accountPDA] = findAccountPDA(ACCOUNT_ID, program.programId);

      const accountInfo = await connection.getAccountInfo(accountPDA);

      if (accountInfo) {
        const signature = await program.methods
          .deleteAccount(ACCOUNT_ID)
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
      .createAccount(ACCOUNT_ID, ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, signature);

    const [accountPDA] = findAccountPDA(ACCOUNT_ID, program.programId);

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
    assert.isDefined(
      wallet.walletType.ethereum,
      "Wallet type should be ethereum"
    );
    assert.strictEqual(
      wallet.compressedPublicKey,
      ETH_PUBLIC_KEY,
      "Public key should match"
    );
  });

  it("can create an account with WebAuthn identity", async () => {
    const signature = await program.methods
      .createAccount(ACCOUNT_ID, WEB_AUTHN_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, signature);

    const [accountPDA] = findAccountPDA(ACCOUNT_ID, program.programId);

    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(accountInfo.nonce.toString(), "0", "Nonce should be 0");
    assert.strictEqual(
      accountInfo.identities.length,
      1,
      "Should have 1 identity"
    );

    const identityWithPermissions = accountInfo.identities[0];
    assert.isDefined(
      identityWithPermissions.identity.webAuthn,
      "Identity should be a WebAuthn type"
    );

    const webAuthn = identityWithPermissions.identity.webAuthn["0"];
    assert.strictEqual(
      webAuthn.keyId,
      WEBAUTHN_KEY_ID,
      "Credential ID should match"
    );
    assert.strictEqual(
      webAuthn.compressedPublicKey,
      WEBAUTHN_PUBLIC_KEY,
      "Public key should match"
    );
  });

  it("can add an identity to an existing account", async () => {
    const createSignature = await program.methods
      .createAccount(ACCOUNT_ID, ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, createSignature);

    const addSignature = await program.methods
      .addIdentity(ACCOUNT_ID, WEB_AUTHN_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, addSignature);

    const [accountPDA] = findAccountPDA(ACCOUNT_ID, program.programId);

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
      ethereumIdentityWithPermissions?.identity.wallet?.[0].compressedPublicKey,
      ETH_PUBLIC_KEY,
      "Ethereum public key should match"
    );
  });

  it("can remove an identity from an account", async () => {
    const createSignature = await program.methods
      .createAccount(ACCOUNT_ID, WEB_AUTHN_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, createSignature);

    const addSignature = await program.methods
      .addIdentity(ACCOUNT_ID, ETHEREUM_IDENTITY_WITH_PERMISSIONS)
      .rpc();

    await confirmTransaction(connection, addSignature);

    const [accountPDA] = findAccountPDA(ACCOUNT_ID, program.programId);

    let accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.strictEqual(
      accountInfo.identities.length,
      2,
      "Should have 2 identities before removal"
    );

    const removeSignature = await program.methods
      .removeIdentity(ACCOUNT_ID, ETHEREUM_IDENTITY_WITH_PERMISSIONS.identity)
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

  it("Can handle multiple identities (stress test)", async () => {
    const identityWithPermissions: IdentityWithPermissions[] = [
      ETHEREUM_IDENTITY_WITH_PERMISSIONS,
      WEB_AUTHN_IDENTITY_WITH_PERMISSIONS,
      {
        identity: createEthereumIdentity(ETH_PUBLIC_KEY_2),
        permissions: null,
      },
      {
        identity: createWebAuthnIdentity(
          WEBAUTHN_KEY_ID_2,
          WEBAUTHN_PUBLIC_KEY_2
        ),
        permissions: null,
      },
      {
        identity: createEthereumIdentity(ETH_PUBLIC_KEY_3),
        permissions: null,
      },
    ];

    const createSignature = await program.methods
      .createAccount(ACCOUNT_ID, identityWithPermissions[0])
      .rpc();

    await confirmTransaction(connection, createSignature);

    // await logComputeUnitsUsed({
    //   txSignature: createSignature,
    //   memo: "Create account with first identity",
    // });

    for (let i = 1; i < identityWithPermissions.length; i++) {
      const addSignature = await program.methods
        .addIdentity(ACCOUNT_ID, identityWithPermissions[i])
        .rpc();

      await confirmTransaction(connection, addSignature);

      // await logComputeUnitsUsed({
      //   txSignature: addSignature,
      //   memo: `Add identity ${i + 1}`,
      // });
    }

    const [accountPDA] = findAccountPDA(ACCOUNT_ID, program.programId);

    let accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.strictEqual(
      accountInfo.identities.length,
      5,
      "Should have 5 identities after adding all"
    );

    // const accountData = await connection.getAccountInfo(accountPDA);x

    // if (accountData) {
    //   console.log(`Account size: ${accountData.data.length} bytes`);
    //   console.log(
    //     `Account rent exemption: ${await connection.getMinimumBalanceForRentExemption(
    //       accountData.data.length
    //     )} lamports`
    //   );
    // } else {
    //   console.log("Account not found");
    // }

    for (let i = 0; i < identityWithPermissions.length; i++) {
      const removeSignature = await program.methods
        .removeIdentity(ACCOUNT_ID, identityWithPermissions[i].identity)
        .rpc();

      await confirmTransaction(connection, removeSignature);

      // await logComputeUnitsUsed({
      //   txSignature: removeSignature,
      //   memo: `Remove identity ${i + 1}`,
      // });

      accountInfo = await program.account.abstractAccount.fetch(accountPDA);
      assert.strictEqual(
        accountInfo.identities.length,
        4 - i,
        `Should have ${4 - i} identities after removing ${i + 1}`
      );
    }
  });
});

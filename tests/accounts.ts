import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import { confirmTransaction, getTxInfo } from "../utils/solana";
const ACCOUNT_ID = "my_account_id_1";

const ETHEREUM_IDENTITY = {
  wallet: {
    "0": {
      walletType: {
        ethereum: {},
      },
      compressedPublicKey: "0x123456789abcdef",
    },
  },
};

const WEB_AUTHN_IDENTITY = {
  webAuthn: {
    "0": {
      keyId: "0x123456789abcdef",
      compressedPublicKey: "0x123456789abcdef",
    },
  },
};

describe.only("Accounts", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  beforeEach(async () => {
    try {
      const [accountPDA] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("account"), Buffer.from(ACCOUNT_ID)],
        program.programId
      );

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
      .createAccount(ACCOUNT_ID, ETHEREUM_IDENTITY)
      .rpc();

    await confirmTransaction(connection, signature);

    const [accountPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("account"), Buffer.from(ACCOUNT_ID)],
      program.programId
    );

    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(accountInfo.nonce.toString(), "0", "Nonce should be 0");
    assert.strictEqual(
      accountInfo.identities.length,
      1,
      "Should have 1 identity"
    );

    const identity = accountInfo.identities[0];
    assert.isDefined(identity.wallet, "Identity should be a wallet type");

    const wallet = identity.wallet["0"];
    assert.isDefined(
      wallet.walletType.ethereum,
      "Wallet type should be ethereum"
    );
    assert.strictEqual(
      wallet.compressedPublicKey,
      ETHEREUM_IDENTITY.wallet["0"].compressedPublicKey,
      "Public key should match"
    );
  });

  it("can create an account with WebAuthn identity", async () => {
    const signature = await program.methods
      .createAccount(ACCOUNT_ID, WEB_AUTHN_IDENTITY)
      .rpc();

    await confirmTransaction(connection, signature);

    const [accountPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("account"), Buffer.from(ACCOUNT_ID)],
      program.programId
    );

    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(accountInfo.nonce.toString(), "0", "Nonce should be 0");
    assert.strictEqual(
      accountInfo.identities.length,
      1,
      "Should have 1 identity"
    );

    const identity = accountInfo.identities[0];
    assert.isDefined(identity.webAuthn, "Identity should be a WebAuthn type");

    const webAuthn = identity.webAuthn["0"];
    assert.strictEqual(
      webAuthn.keyId,
      WEB_AUTHN_IDENTITY.webAuthn["0"].keyId,
      "Credential ID should match"
    );
    assert.strictEqual(
      webAuthn.compressedPublicKey,
      WEB_AUTHN_IDENTITY.webAuthn["0"].compressedPublicKey,
      "Public key should match"
    );
  });

  it("can add an identity to an existing account", async () => {
    const createSignature = await program.methods
      .createAccount(ACCOUNT_ID, ETHEREUM_IDENTITY)
      .rpc();

    await confirmTransaction(connection, createSignature);

    const addSignature = await program.methods
      .addIdentity(ACCOUNT_ID, WEB_AUTHN_IDENTITY)
      .rpc();

    await confirmTransaction(connection, addSignature);

    const [accountPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("account"), Buffer.from(ACCOUNT_ID)],
      program.programId
    );

    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    assert.strictEqual(
      accountInfo.identities.length,
      2,
      "Should have 2 identities"
    );

    const webAuthnIdentity = accountInfo.identities.find((id) => id.webAuthn);

    assert.isDefined(webAuthnIdentity, "WebAuthn identity should exist");
    assert.strictEqual(
      webAuthnIdentity?.webAuthn?.[0].keyId,
      WEB_AUTHN_IDENTITY.webAuthn[0].keyId,
      "WebAuthn credential ID should match"
    );

    const ethereumIdentity = accountInfo.identities.find((id) => id.wallet);
    assert.isDefined(ethereumIdentity, "Ethereum identity should exist");
    assert.strictEqual(
      ethereumIdentity?.wallet?.[0].compressedPublicKey,
      ETHEREUM_IDENTITY.wallet["0"].compressedPublicKey,
      "Ethereum public key should match"
    );
  });

  it("can remove an identity from an account", async () => {
    const createSignature = await program.methods
      .createAccount(ACCOUNT_ID, WEB_AUTHN_IDENTITY)
      .rpc();

    await confirmTransaction(connection, createSignature);

    const addSignature = await program.methods
      .addIdentity(ACCOUNT_ID, ETHEREUM_IDENTITY)
      .rpc();

    await confirmTransaction(connection, addSignature);

    const [accountPDA] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("account"), Buffer.from(ACCOUNT_ID)],
      program.programId
    );

    let accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.strictEqual(
      accountInfo.identities.length,
      2,
      "Should have 2 identities before removal"
    );

    const removeSignature = await program.methods
      .removeIdentity(ACCOUNT_ID, ETHEREUM_IDENTITY)
      .rpc();

    await confirmTransaction(connection, removeSignature);

    accountInfo = await program.account.abstractAccount.fetch(accountPDA);
    assert.strictEqual(
      accountInfo.identities.length,
      1,
      "Should have 1 identity after removal"
    );

    const remainingIdentity = accountInfo.identities[0];
    assert.isDefined(
      remainingIdentity.webAuthn,
      "Remaining identity should be WebAuthn type"
    );
    assert.strictEqual(
      remainingIdentity.webAuthn[0].keyId,
      WEB_AUTHN_IDENTITY.webAuthn[0].keyId,
      "WebAuthn credential ID should match"
    );
  });
});

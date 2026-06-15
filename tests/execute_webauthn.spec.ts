import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import { p256 } from "@noble/curves/p256";
import { createHash } from "crypto";
import { ComputeBudgetProgram, TransactionInstruction } from "@solana/web3.js";
import { toBytes } from "viem";
import { assert } from "chai";
import { borshUtils, Transaction } from "../borsh";
import { SolanaAa } from "../target/types/solana_aa";
import { buildWebauthnIdentity } from "../utils/identity";
import { cleanUpProgramState, findAbstractAccountPDA } from "../utils/program";
import { confirmTransaction } from "../utils/solana";
import { createSecp256r1VerificationInstruction } from "../utils/webauthn";

// Deterministic P-256 test credential.
const PRIV = new Uint8Array(32).fill(7);
const COMPRESSED_PUB =
  "0x" + Buffer.from(p256.getPublicKey(PRIV, true)).toString("hex");
const RP_ID = "example.com";
const ORIGIN = "https://example.com";
const ETH_ADDRESS_2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

// execute_webauthn parses clientDataJSON on-chain; give it CU headroom.
const WEBAUTHN_COMPUTE_UNITS = 400_000;

const sha256 = (data: Uint8Array): Buffer =>
  createHash("sha256").update(data).digest();

describe("Execute WebAuthn", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as anchor.Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;

  beforeEach(async () => {
    await cleanUpProgramState(program, connection, provider);
  });

  // authenticatorData = rpIdHash(32) || flags(1) || signCount(4).
  // Default flags 0x05 = UP (0x01) + UV (0x04); the program requires both.
  const authenticatorData = (flags = 0x05): Buffer =>
    Buffer.concat([
      createHash("sha256").update(RP_ID).digest(),
      Buffer.from([flags, 0, 0, 0, 0]),
    ]);

  // AddIdentity(ETH_ADDRESS_2) in Borsh form (for the challenge hash) and Anchor
  // instruction-argument form (camelCase, tuple fields under "0").
  const addIdentityTx = (accountId: bigint, nonce: bigint) => {
    const borsh: Transaction = {
      account_id: accountId,
      nonce,
      action: {
        AddIdentity: {
          identity: { Wallet: { Ethereum: toBytes(ETH_ADDRESS_2) } },
          permissions: { enable_act_as: false },
        },
      },
    };
    const arg: Parameters<typeof program.methods.executeWebauthn>[1] = {
      accountId: new BN(accountId.toString()),
      nonce: new BN(nonce.toString()),
      action: {
        addIdentity: {
          "0": {
            identity: {
              wallet: {
                "0": { ethereum: { "0": Array.from(toBytes(ETH_ADDRESS_2)) } },
              },
            },
            permissions: { enableActAs: false },
          },
        },
      },
    };
    return { borsh, arg };
  };

  // Produce clientDataJSON, authenticatorData, and the secp256r1 precompile
  // instruction that signs `authenticator_data || sha256(clientDataJSON)`.
  const signWebauthn = (
    borshTx: Transaction,
    opts: {
      origin?: string;
      flags?: number;
      challengeBytes?: Uint8Array;
      type?: string;
      authDataOverride?: Buffer;
    } = {}
  ) => {
    const origin = opts.origin ?? ORIGIN;
    const txHash = sha256(borshUtils.serialize.transaction(borshTx));
    const challenge = Buffer.from(opts.challengeBytes ?? txHash).toString(
      "base64url"
    );
    const clientData = JSON.stringify({
      type: opts.type ?? "webauthn.get",
      challenge,
      origin,
      crossOrigin: false,
    });
    const authData = opts.authDataOverride ?? authenticatorData(opts.flags);
    const message = Buffer.concat([
      authData,
      sha256(Buffer.from(clientData, "utf-8")),
    ]);
    // The secp256r1 precompile rejects high-S signatures as malleable, so force
    // the canonical low-S form (P-256 does not enforce it by default).
    const signature = p256
      .sign(sha256(message), PRIV, { lowS: true })
      .toCompactRawBytes();
    const verificationIx = createSecp256r1VerificationInstruction(
      signature,
      p256.getPublicKey(PRIV, true),
      message
    );
    return { clientData, authData, verificationIx };
  };

  const createWebauthnAccount = async () => {
    const signature = await program.methods
      .createAccount(
        buildWebauthnIdentity(
          { compressedPublicKey: COMPRESSED_PUB, rpId: RP_ID, origin: ORIGIN },
          null
        )
      )
      .rpc();
    await confirmTransaction(connection, signature);
    const [pda] = findAbstractAccountPDA(new BN(0), program.programId);
    const info = await program.account.abstractAccount.fetch(pda);
    return { pda, nonce: BigInt(info.nonce.toString()) };
  };

  const executeWebauthn = (
    accountId: bigint,
    arg: ReturnType<typeof addIdentityTx>["arg"],
    signed: {
      clientData: string;
      authData: Buffer;
      verificationIx: TransactionInstruction;
    }
  ) =>
    program.methods
      .executeWebauthn(new BN(accountId.toString()), arg, {
        clientData: signed.clientData,
        authenticatorData: signed.authData,
      })
      .preInstructions([
        ComputeBudgetProgram.setComputeUnitLimit({
          units: WEBAUTHN_COMPUTE_UNITS,
        }),
        signed.verificationIx,
      ])
      .rpc();

  it("executes an AddIdentity transaction authorized by a WebAuthn signature", async () => {
    const { pda, nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    const signed = signWebauthn(tx.borsh);

    const sig = await executeWebauthn(0n, tx.arg, signed);
    await confirmTransaction(connection, sig);

    const info = await program.account.abstractAccount.fetch(pda);
    assert.strictEqual(info.nonce.toString(), "1");
    assert.strictEqual(info.identities.length, 2);
  });

  it("rejects a challenge that does not match the transaction", async () => {
    const { nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    const signed = signWebauthn(tx.borsh, {
      challengeBytes: new Uint8Array(32).fill(9),
    });

    try {
      await executeWebauthn(0n, tx.arg, signed);
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "WebAuthnChallengeMismatch");
    }
  });

  it("rejects a signature whose origin is not the registered one", async () => {
    const { nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    const signed = signWebauthn(tx.borsh, { origin: "https://evil.com" });

    try {
      await executeWebauthn(0n, tx.arg, signed);
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "IdentityNotFound");
    }
  });

  it("rejects an assertion without the user-present flag", async () => {
    const { nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    const signed = signWebauthn(tx.borsh, { flags: 0x00 });

    try {
      await executeWebauthn(0n, tx.arg, signed);
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "WebAuthnUserNotPresent");
    }
  });

  it("rejects an assertion without the user-verified flag", async () => {
    const { nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    // UP set (0x01) but UV (0x04) absent — possession without verification.
    const signed = signWebauthn(tx.borsh, { flags: 0x01 });

    try {
      await executeWebauthn(0n, tx.arg, signed);
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "WebAuthnUserNotVerified");
    }
  });

  it("rejects replaying a transaction on a moved nonce", async () => {
    const { nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    const signed = signWebauthn(tx.borsh);
    const sig = await executeWebauthn(0n, tx.arg, signed);
    await confirmTransaction(connection, sig);

    const replay = addIdentityTx(0n, nonce);
    const replaySigned = signWebauthn(replay.borsh);
    try {
      await executeWebauthn(0n, replay.arg, replaySigned);
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "NonceMismatch");
    }
  });

  it("rejects auth data that does not match the verified signature", async () => {
    const { nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    const real = signWebauthn(tx.borsh);
    // The precompile verifies `real`, but the instruction passes a clientData
    // signed for a different origin, so the on-chain re-binding must fail.
    const decoy = signWebauthn(tx.borsh, { origin: "https://decoy.example" });

    try {
      await executeWebauthn(0n, tx.arg, {
        clientData: decoy.clientData,
        authData: decoy.authData,
        verificationIx: real.verificationIx,
      });
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "WebAuthnMessageMismatch");
    }
  });

  it("rejects a clientDataJSON whose type is not webauthn.get", async () => {
    const { nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    const signed = signWebauthn(tx.borsh, { type: "webauthn.create" });

    try {
      await executeWebauthn(0n, tx.arg, signed);
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "InvalidClientData");
    }
  });

  it("rejects authenticatorData shorter than 37 bytes", async () => {
    const { nonce } = await createWebauthnAccount();
    const tx = addIdentityTx(0n, nonce);
    // 32-byte rpIdHash + flags + only 3 counter bytes = 36 bytes (< 37).
    const shortAuthData = Buffer.concat([
      createHash("sha256").update(RP_ID).digest(),
      Buffer.from([0x05, 0, 0, 0]),
    ]);
    const signed = signWebauthn(tx.borsh, { authDataOverride: shortAuthData });

    try {
      await executeWebauthn(0n, tx.arg, signed);
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "InvalidAuthenticatorData");
    }
  });

  it("rejects a transaction whose account_id does not match the execution target", async () => {
    const { nonce } = await createWebauthnAccount();
    // Signed for account_id 1 but submitted against account 0's PDA. The
    // signature is valid and the identity/nonce line up, so only the account_id
    // binding stands between this and a cross-account transaction replay.
    const tx = addIdentityTx(1n, nonce);
    const signed = signWebauthn(tx.borsh);

    try {
      await executeWebauthn(0n, tx.arg, signed);
      assert.fail("executeWebauthn resolved but a rejection was expected");
    } catch (error: any) {
      assert.include(error.toString(), "AccountIdMismatch");
    }
  });
});

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { assert } from "chai";
import { confirmTransaction, getTxInfo } from "../utils/solana";

describe.only("Accounts", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;

  const program = anchor.workspace.solanaAa as Program<SolanaAa>;

  it("Is initialized!", async () => {
    const signature = await program.methods
      .createAccount("my_account_id_1", {
        // webAuthn: {
        //   0: {
        //     keyId: "0x123456789abcdef",
        //     compressedPublicKey: "0x123456789abcdef",
        //   },
        // },
        wallet: {
          0: {
            walletType: {
              ethereum: {},
            },
            compressedPublicKey: "0x123456789abcdef",
          },
        },
      })
      .rpc();

    await confirmTransaction(connection, signature);

    const signature2 = await program.methods
      .getAccount("my_account_id_1")
      .rpc();

    await confirmTransaction(connection, signature2);

    const txInfo = await getTxInfo({
      txSignature: signature2,
    });

    console.log({ txInfo: JSON.stringify(txInfo, null, 2) });

    assert.fail("Not implemented");
  });
});

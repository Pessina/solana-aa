import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import { SolanaAa } from "../target/types/solana_aa";
import { confirmTransaction } from "../utils/solana";
import { PublicKey } from "@solana/web3.js";
import {
  ABSTRACT_ACCOUNT_SEED,
  ACCOUNT_MANAGER_SEED,
} from "../utils/constants";

export const findAbstractAccountPDA = (accountId: BN, programId: PublicKey) => {
  return PublicKey.findProgramAddressSync(
    [ABSTRACT_ACCOUNT_SEED, accountId.toArrayLike(Buffer, "le", 8)],
    programId
  );
};

export const findAccountManagerPDA = (programId: PublicKey) => {
  return PublicKey.findProgramAddressSync([ACCOUNT_MANAGER_SEED], programId);
};

export const cleanUpProgramState = async (
  program: anchor.Program<SolanaAa>,
  connection: anchor.web3.Connection,
  provider: anchor.AnchorProvider
) => {
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
      const nextAccountId = accountManagerInfo.nextAccountId;

      for (let i = 0; i <= nextAccountId.toNumber(); i++) {
        const [accountPDA] = findAbstractAccountPDA(
          new BN(i),
          program.programId
        );

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
};

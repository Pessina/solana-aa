import * as anchor from "@coral-xyz/anchor";
import { signWithEthereum } from "../utils/secp256k1-signer";
import { borshUtils, Transaction } from "../borsh";
import { confirmTransaction } from "../utils/solana";
import {
  parseEthereumSignature,
  ethereumAddressToBytes,
  createSecp256k1VerificationInstruction,
} from "../utils/ethereum";
import { keccak256, toBytes } from "viem";
import _ from "lodash";
import { cleanUpProgramState, findAbstractAccountPDA } from "../utils/program";
import { buildEthereumIdentity } from "../utils/identity";
import { privateKeyToAccount } from "viem/accounts";
import { BN } from "bn.js";
import { SolanaAa } from "../target/types/solana_aa";

const PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const ETH_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

describe("Execute Ek256", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as anchor.Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());
  const connection = anchor.getProvider().connection;

  beforeEach(async () => {
    await cleanUpProgramState(program, connection, provider);
  });

  async function executeEk256(transaction: Transaction) {
    const serializedMessage = Buffer.from(
      borshUtils.serialize.transaction(transaction)
    );

    const ethSignature = await signWithEthereum({
      hash: keccak256(serializedMessage),
      privateKey: PRIVATE_KEY,
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
      .executeEk256(new BN(0))
      .preInstructions([verificationInstruction])
      .rpc();

    await confirmTransaction(provider.connection, txSignature);
  }

  it("should create account and execute Ek256 correctly", async () => {
    const account = privateKeyToAccount(PRIVATE_KEY);

    const signature = await program.methods
      .createAccount(buildEthereumIdentity(account.address, null))
      .rpc();

    await confirmTransaction(provider.connection, signature);

    const [accountPDA] = findAbstractAccountPDA(new BN(0), program.programId);
    const accountInfo = await program.account.abstractAccount.fetch(accountPDA);

    const transaction: Transaction = {
      account_id: BigInt(accountInfo.accountId.toString()),
      nonce: BigInt(accountInfo.nonce.toString()),
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: toBytes(ETH_ADDRESS),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

    await executeEk256(transaction);

    const accountInfoFinal = await program.account.abstractAccount.fetch(
      accountPDA
    );

    console.log({ accountInfoFinal });
  });
});

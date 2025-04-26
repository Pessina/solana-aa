import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { signWithEthereum } from "../utils/secp256k1-signer";
import { borshUtils, Transaction } from "../utils/borsh";
import { SolanaAa } from "../target/types/solana_aa";
import { confirmTransaction, getTxInfo } from "../utils/solana";
import {
  parseEthereumSignature,
  ethereumAddressToBytes,
  createSecp256k1VerificationInstruction,
} from "../utils/ethereum";
import { keccak256 } from "viem";
import { expect } from "chai";
import * as _ from "lodash";
import { normalize } from "../utils/utils";

const PRIVATE_KEY =
  "0x4646464646464646464646464646464646464646464646464646464646464646" as const;

describe.only("Ethereum Signature Verification", () => {
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.solanaAa as Program<SolanaAa>;
  anchor.setProvider(anchor.AnchorProvider.env());

  it("should validate Ethereum signature correctly", async () => {
    const transaction: Transaction = {
      account_id: 1n,
      nonce: 135n,
      action: {
        AddIdentity: {
          identity: {
            Wallet: {
              Ethereum: new Uint8Array([
                0x04, 0xab, 0x3c, 0xb2, 0x89, 0x73, 0x44, 0xaa, 0x3f, 0x6f,
                0xfa, 0xac, 0x94, 0xe4, 0x77, 0xae, 0xac, 0x17, 0x0b, 0x92,
              ]),
            },
          },
          permissions: {
            enable_act_as: true,
          },
        },
      },
    };

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
      .getEthData()
      .accounts({
        instructions_sysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .preInstructions([verificationInstruction])
      .rpc();

    await confirmTransaction(provider.connection, txSignature);

    const result = await getTxInfo({ txSignature });

    const returnData = result?.meta?.returnData?.data[0];
    const decodedData = Buffer.from(returnData, "base64");

    const ethAddressLength = decodedData.readUInt32LE(0);
    const ethAddressHex = decodedData.slice(4, 4 + ethAddressLength).toString();
    expect(ethAddressHex).to.equal(ethSignature.address.slice(2).toLowerCase());

    const transactionDataStart = 4 + ethAddressLength;
    const transactionData = decodedData.slice(transactionDataStart);

    const deserializedTransaction =
      borshUtils.deserialize.transaction(transactionData);

    const normalizedOriginal = normalize(transaction);
    const normalizedDeserialized = normalize(deserializedTransaction);

    expect(normalizedDeserialized).to.deep.equal(normalizedOriginal);
  });
});

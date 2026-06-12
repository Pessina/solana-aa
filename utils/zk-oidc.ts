import { PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";
import { OIDC_KEY_REGISTRY_SEED } from "./constants";

/**
 * Golden fixture produced by `cd zk/script && cargo run --release -- fixture`.
 * Contains a real SP1 Groth16 proof over a self-signed test JWT whose nonce is
 * the sha256 of the Borsh-serialized test transaction.
 */
export interface ZkOidcFixture {
  proof: string;
  publicValues: string;
  vkeyHash: string;
  emailHash: string;
  pkHash: string;
  iss: string;
  aud: string;
  nonce: string;
  accountId: string;
  accountNonce: string;
  ethAddress: string;
  transactionBorsh: string;
}

export const loadZkOidcFixture = (name: string): ZkOidcFixture => {
  const fixturePath = path.join(__dirname, "..", "tests", "fixtures", name);
  return JSON.parse(fs.readFileSync(fixturePath, "utf-8")) as ZkOidcFixture;
};

export const findOidcKeyRegistryPDA = (programId: PublicKey) => {
  return PublicKey.findProgramAddressSync([OIDC_KEY_REGISTRY_SEED], programId);
};

export const groth16ProofFromFixture = (fixture: ZkOidcFixture) => {
  return {
    proof: Buffer.from(fixture.proof, "hex"),
    publicValues: Buffer.from(fixture.publicValues, "hex"),
  };
};

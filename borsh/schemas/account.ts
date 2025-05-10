import { Schema } from "borsh";
import { identityWithPermissionsSchema } from "./identity";

export const abstractAccountSchema: Schema = {
  struct: {
    account_id: "u64",
    nonce: "u128",
    identities: { array: { type: identityWithPermissionsSchema } },
    bump: "u8",
  },
};

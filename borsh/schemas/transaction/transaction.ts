import { Schema } from "borsh";
import { identityWithPermissionsSchema, identitySchema } from "../identity";

export const actionSchema: Schema = {
  enum: [
    { struct: { RemoveAccount: { struct: {} } } },
    { struct: { AddIdentity: identityWithPermissionsSchema } },
    { struct: { RemoveIdentity: identitySchema } },
  ],
};

export const transactionSchema: Schema = {
  struct: {
    account_id: "u64",
    nonce: "u128",
    action: actionSchema,
  },
};

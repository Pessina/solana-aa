import { Schema } from "borsh";
import { identityWithPermissionsSchema, identitySchema } from "./identity";

// Action types
export const actionSchema: Schema = {
  enum: [
    { struct: { RemoveAccount: { struct: {} } } },
    { struct: { AddIdentity: identityWithPermissionsSchema } },
    { struct: { RemoveIdentity: identitySchema } },
  ],
};

// Transaction schema
export const transactionSchema: Schema = {
  struct: {
    account_id: "u64",
    nonce: "u128",
    action: actionSchema,
  },
};

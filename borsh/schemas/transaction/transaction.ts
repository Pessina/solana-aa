import { Schema } from "borsh";
import { identityWithPermissionsSchema, identitySchema } from "../identity";

export const signRequestSchema: Schema = {
  struct: {
    payload: { array: { type: "u8", len: 32 } },
    key_version: "u32",
    path: "string",
    algo: "string",
    dest: "string",
    params: "string",
  },
};

export const actionSchema: Schema = {
  enum: [
    { struct: { RemoveAccount: { struct: {} } } },
    { struct: { AddIdentity: identityWithPermissionsSchema } },
    { struct: { RemoveIdentity: identitySchema } },
    { struct: { Sign: signRequestSchema } },
  ],
};

export const transactionSchema: Schema = {
  struct: {
    account_id: "u64",
    nonce: "u128",
    action: actionSchema,
  },
};

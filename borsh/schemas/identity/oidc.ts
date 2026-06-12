import { Schema } from "borsh";

export const oidcIdentitySchema: Schema = {
  struct: {
    iss: "string",
    aud: "string",
    email_hash: { array: { type: "u8", len: 32 } },
  },
};

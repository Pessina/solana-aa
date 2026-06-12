import { Schema } from "borsh";

export const webAuthnAuthenticatorSchema: Schema = {
  struct: {
    key_id: "string",
    compressed_public_key: { option: "string" },
  },
};

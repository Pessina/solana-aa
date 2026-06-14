import { Schema } from "borsh";

export const webAuthnAuthenticatorSchema: Schema = {
  struct: {
    key_id: "string",
    compressed_public_key: { option: "string" },
    rp_id_hash: { array: { type: "u8", len: 32 } },
    origin: "string",
  },
};

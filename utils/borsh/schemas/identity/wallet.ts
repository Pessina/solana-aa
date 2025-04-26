import { Schema } from "borsh";

// Wallet types
export const walletTypeSchema: Schema = {
  enum: [{ struct: { Ethereum: { struct: {} } } }],
};

export const walletAuthenticatorSchema: Schema = {
  struct: {
    wallet_type: walletTypeSchema,
    compressed_public_key: { array: { type: "u8", len: 20 } },
  },
};

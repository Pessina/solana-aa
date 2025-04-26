import { Schema } from "borsh";

// Wallet types
export const walletTypeSchema: Schema = {
  enum: [{ struct: { Ethereum: { array: { type: "u8", len: 20 } } } }],
};

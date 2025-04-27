import { Schema } from "borsh";

export const walletTypeSchema: Schema = {
  enum: [{ struct: { Ethereum: { array: { type: "u8", len: 20 } } } }],
};

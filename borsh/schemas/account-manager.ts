import { Schema } from "borsh";

// Account Manager schema
export const accountManagerSchema: Schema = {
  struct: {
    next_account_id: "u64",
    max_nonce: "u128",
  },
};

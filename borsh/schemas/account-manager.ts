import { Schema } from "borsh";

export const accountManagerSchema: Schema = {
  struct: {
    next_account_id: "u64",
  },
};

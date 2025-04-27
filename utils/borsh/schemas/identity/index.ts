import { Schema } from "borsh";
import { walletTypeSchema } from "./wallet";

// Basic types
export const identityPermissionsSchema: Schema = {
  struct: {
    enable_act_as: "bool",
  },
};

// Identity types
export const identitySchema: Schema = {
  enum: [
    { struct: { Wallet: walletTypeSchema } },
    // Add WebAuthn when needed
  ],
};

export const identityWithPermissionsSchema: Schema = {
  struct: {
    identity: identitySchema,
    permissions: { option: identityPermissionsSchema },
  },
};

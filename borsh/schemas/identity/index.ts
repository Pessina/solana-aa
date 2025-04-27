import { Schema } from "borsh";
import { walletTypeSchema } from "./wallet";

export const identityPermissionsSchema: Schema = {
  struct: {
    enable_act_as: "bool",
  },
};

export const identitySchema: Schema = {
  enum: [{ struct: { Wallet: walletTypeSchema } }],
};

export const identityWithPermissionsSchema: Schema = {
  struct: {
    identity: identitySchema,
    permissions: { option: identityPermissionsSchema },
  },
};

export * from "./wallet";

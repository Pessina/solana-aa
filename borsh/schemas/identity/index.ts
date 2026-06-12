import { Schema } from "borsh";
import { walletTypeSchema } from "./wallet";
import { webAuthnAuthenticatorSchema } from "./webauthn";
import { oidcIdentitySchema } from "./oidc";

export const identityPermissionsSchema: Schema = {
  struct: {
    enable_act_as: "bool",
  },
};

// Variant order mirrors the Rust enum tags in
// programs/solana-aa/src/types/identity/mod.rs: Wallet=0, WebAuthn=1, Oidc=2.
export const identitySchema: Schema = {
  enum: [
    { struct: { Wallet: walletTypeSchema } },
    { struct: { WebAuthn: webAuthnAuthenticatorSchema } },
    { struct: { Oidc: oidcIdentitySchema } },
  ],
};

export const identityWithPermissionsSchema: Schema = {
  struct: {
    identity: identitySchema,
    permissions: { option: identityPermissionsSchema },
  },
};

export * from "./wallet";
export * from "./webauthn";
export * from "./oidc";

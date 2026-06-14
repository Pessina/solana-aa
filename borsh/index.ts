import * as borsh from "borsh";
import * as schemas from "./schemas";

export interface WalletType {
  Ethereum: Uint8Array;
}

export interface WebAuthnAuthenticator {
  key_id: string;
  compressed_public_key: string | null;
}

export interface OidcIdentity {
  iss: string;
  aud: string;
  email_hash: Uint8Array;
}

export type Identity =
  | { Wallet: WalletType }
  | { WebAuthn: WebAuthnAuthenticator }
  | { Oidc: OidcIdentity };

export interface IdentityPermissions {
  enable_act_as: boolean;
}

export interface IdentityWithPermissions {
  identity: Identity;
  permissions: IdentityPermissions | null;
}

export interface RemoveAccountAction {
  RemoveAccount: Record<string, never>;
}

export interface AddIdentityAction {
  AddIdentity: IdentityWithPermissions;
}

export interface RemoveIdentityAction {
  RemoveIdentity: Identity;
}

export interface SignRequest {
  payload: Uint8Array;
  key_version: number;
  path: string;
  algo: string;
  dest: string;
  params: string;
}

export interface SignAction {
  Sign: SignRequest;
}

export type Action =
  | RemoveAccountAction
  | AddIdentityAction
  | RemoveIdentityAction
  | SignAction;

export interface Transaction {
  account_id: bigint;
  nonce: bigint;
  action: Action;
}

export const borshUtils = {
  serialize: {
    walletType: (walletType: WalletType): Uint8Array => {
      return borsh.serialize(schemas.walletTypeSchema, walletType);
    },

    identityPermissions: (permissions: IdentityPermissions): Uint8Array => {
      return borsh.serialize(schemas.identityPermissionsSchema, permissions);
    },

    identity: (identity: Identity): Uint8Array => {
      return borsh.serialize(schemas.identitySchema, identity);
    },

    identityWithPermissions: (
      identityWithPermissions: IdentityWithPermissions
    ): Uint8Array => {
      return borsh.serialize(
        schemas.identityWithPermissionsSchema,
        identityWithPermissions
      );
    },

    transaction: (transaction: Transaction): Uint8Array => {
      return borsh.serialize(schemas.transactionSchema, transaction);
    },
  },

  deserialize: {
    walletType: (buffer: Uint8Array): WalletType => {
      return borsh.deserialize(schemas.walletTypeSchema, buffer) as WalletType;
    },

    identityPermissions: (buffer: Uint8Array): IdentityPermissions => {
      return borsh.deserialize(
        schemas.identityPermissionsSchema,
        buffer
      ) as IdentityPermissions;
    },

    identity: (buffer: Uint8Array): Identity => {
      return borsh.deserialize(schemas.identitySchema, buffer) as Identity;
    },

    identityWithPermissions: (buffer: Uint8Array): IdentityWithPermissions => {
      return borsh.deserialize(
        schemas.identityWithPermissionsSchema,
        buffer
      ) as IdentityWithPermissions;
    },

    transaction: (buffer: Uint8Array): Transaction => {
      return borsh.deserialize(
        schemas.transactionSchema,
        buffer
      ) as Transaction;
    },
  },
};

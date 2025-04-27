import * as borsh from "borsh";
import * as schemas from "./schemas";

export interface WalletType {
  Ethereum: Uint8Array;
}

export interface Identity {
  Wallet: WalletType;
}

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

export type Action =
  | RemoveAccountAction
  | AddIdentityAction
  | RemoveIdentityAction;

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

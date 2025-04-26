import * as borsh from "borsh";
import { transactionSchema } from "./schemas/transaction";
import {
  walletAuthenticatorSchema,
  walletTypeSchema,
} from "./schemas/identity/wallet";
import {
  identitySchema,
  identityWithPermissionsSchema,
  identityPermissionsSchema,
} from "./schemas/identity";

export interface WalletType {
  Ethereum: Record<string, never>;
}

export interface WalletAuthenticator {
  wallet_type: WalletType;
  compressed_public_key: Uint8Array;
}

export interface IdentityPermissions {
  enable_act_as: boolean;
}

export interface WalletIdentity {
  Wallet: WalletAuthenticator;
}

export interface IdentityWithPermissions {
  identity: WalletIdentity;
  permissions: IdentityPermissions | null;
}

export interface RemoveAccountAction {
  RemoveAccount: Record<string, never>;
}

export interface AddIdentityAction {
  AddIdentity: IdentityWithPermissions;
}

export interface RemoveIdentityAction {
  RemoveIdentity: WalletIdentity;
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

// Serialization and deserialization functions
export const borshUtils = {
  // Serialization functions
  serialize: {
    walletType: (walletType: WalletType): Uint8Array => {
      return borsh.serialize(walletTypeSchema, walletType);
    },

    walletAuthenticator: (authenticator: WalletAuthenticator): Uint8Array => {
      return borsh.serialize(walletAuthenticatorSchema, authenticator);
    },

    identityPermissions: (permissions: IdentityPermissions): Uint8Array => {
      return borsh.serialize(identityPermissionsSchema, permissions);
    },

    identity: (identity: WalletIdentity): Uint8Array => {
      return borsh.serialize(identitySchema, identity);
    },

    identityWithPermissions: (
      identityWithPermissions: IdentityWithPermissions
    ): Uint8Array => {
      return borsh.serialize(
        identityWithPermissionsSchema,
        identityWithPermissions
      );
    },

    transaction: (transaction: Transaction): Uint8Array => {
      return borsh.serialize(transactionSchema, transaction);
    },
  },

  // Deserialization functions
  deserialize: {
    walletType: (buffer: Uint8Array): WalletType => {
      return borsh.deserialize(walletTypeSchema, buffer) as WalletType;
    },

    walletAuthenticator: (buffer: Uint8Array): WalletAuthenticator => {
      return borsh.deserialize(
        walletAuthenticatorSchema,
        buffer
      ) as WalletAuthenticator;
    },

    identityPermissions: (buffer: Uint8Array): IdentityPermissions => {
      return borsh.deserialize(
        identityPermissionsSchema,
        buffer
      ) as IdentityPermissions;
    },

    identity: (buffer: Uint8Array): WalletIdentity => {
      return borsh.deserialize(identitySchema, buffer) as WalletIdentity;
    },

    identityWithPermissions: (buffer: Uint8Array): IdentityWithPermissions => {
      return borsh.deserialize(
        identityWithPermissionsSchema,
        buffer
      ) as IdentityWithPermissions;
    },

    transaction: (buffer: Uint8Array): Transaction => {
      return borsh.deserialize(transactionSchema, buffer) as Transaction;
    },
  },
};

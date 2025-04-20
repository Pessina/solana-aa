import * as anchor from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";

/**
 * Types for identity structures used in the Solana AA program
 */

// Wallet types
export type WalletType = {
  ethereum: Record<string, never>;
};

export type WalletAuthenticator = {
  walletType: WalletType;
  compressedPublicKey: string;
};

export type WalletIdentity = {
  wallet: {
    "0": WalletAuthenticator;
  };
};

// WebAuthn types
export type WebAuthnAuthenticator = {
  keyId: string;
  compressedPublicKey: string;
};

export type WebAuthnIdentity = {
  webAuthn: {
    "0": WebAuthnAuthenticator;
  };
};

// Permission types
export type EvmPermissions = Record<string, never>;
export type BtcPermissions = Record<string, never>;
export type CosmosPermissions = Record<string, never>;
export type SolanaPermissions = Record<string, never>;

export type IdentityPermissions = {
  enableActAs: boolean;
  evm: EvmPermissions | null;
  btc: BtcPermissions | null;
  cosmos: CosmosPermissions | null;
  solana: SolanaPermissions | null;
};

// Combined identity types
export type Identity = WalletIdentity | WebAuthnIdentity;

export type IdentityWithPermissions = {
  identity: Identity;
  permissions: IdentityPermissions | null;
};

/**
 * Helper functions to create identities
 */

export function createEthereumIdentity(compressedPublicKey: string): Identity {
  return {
    wallet: {
      "0": {
        walletType: {
          ethereum: {},
        },
        compressedPublicKey,
      },
    },
  };
}

export function createWebAuthnIdentity(
  keyId: string,
  compressedPublicKey: string
): Identity {
  return {
    webAuthn: {
      "0": {
        keyId,
        compressedPublicKey,
      },
    },
  };
}

export function createDefaultPermissions(): IdentityPermissions {
  return {
    enableActAs: true,
    evm: null,
    btc: null,
    cosmos: null,
    solana: null,
  };
}

/**
 * Helper functions for account operations
 */

export function findAccountPDA(
  accountId: string,
  programId: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("account"), Buffer.from(accountId)],
    programId
  );
}

import { createHash } from "crypto";

type Permissions = {
  enableActAs: boolean;
} | null;

/**
 * Builds a WebAuthn identity in the Anchor instruction format
 * (tuple enum variants nest their single field under "0"). `rpId` is hashed to
 * the rpIdHash the on-chain program reconstructs from authenticatorData.
 */
export const buildWebauthnIdentity = (
  {
    compressedPublicKey,
    rpId,
    origin,
    keyId = "",
  }: {
    compressedPublicKey: string;
    rpId: string;
    origin: string;
    keyId?: string;
  },
  permissions: Permissions
) => {
  const rpIdHash = Array.from(createHash("sha256").update(rpId).digest());
  return {
    identity: {
      webAuthn: {
        "0": {
          keyId,
          compressedPublicKey,
          rpIdHash,
          origin,
        },
      },
    },
    permissions,
  };
};

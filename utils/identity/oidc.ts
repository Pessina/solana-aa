type Permissions = {
  enableActAs: boolean;
} | null;

/**
 * Builds an OIDC identity in the Anchor instruction format
 * (tuple enum variants nest their single field under "0").
 */
export const buildOidcIdentity = (
  {
    iss,
    aud,
    emailHash,
  }: {
    iss: string;
    aud: string;
    emailHash: Uint8Array;
  },
  permissions: Permissions
) => {
  return {
    identity: {
      oidc: {
        "0": {
          iss,
          aud,
          emailHash: Array.from(emailHash),
        },
      },
    },
    permissions,
  };
};

import { Address, toBytes } from "viem";

type Permissions = {
  enableActAs: boolean;
} | null;

export const buildEthereumIdentity = (
  address: Address,
  permissions: Permissions
) => {
  return {
    identity: {
      wallet: {
        "0": {
          ethereum: {
            "0": Array.from(toBytes(address)),
          },
        },
      },
    },
    permissions,
  };
};

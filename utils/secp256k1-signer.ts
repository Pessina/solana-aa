import { privateKeyToAccount, signMessage } from "viem/accounts";
import { Hex } from "viem";

export async function signWithEthereum(
  hash: Hex,
  privateKey: Hex
): Promise<{
  signature: Hex;
  address: Hex;
  hash: Hex;
}> {
  const signature = await signMessage({
    message: { raw: hash },
    privateKey,
  });

  const address = privateKeyToAccount(privateKey);

  return {
    address: address.address,
    signature,
    hash,
  };
}

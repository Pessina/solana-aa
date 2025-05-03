import { privateKeyToAccount, sign, serializeSignature } from "viem/accounts";
import { Hex } from "viem";

export async function signWithEthereum({
  hash,
  privateKey,
}: {
  hash: Hex;
  privateKey: Hex;
}): Promise<{
  signature: Hex;
  address: Hex;
}> {
  const signature = await sign({
    hash,
    privateKey,
  });

  const address = privateKeyToAccount(privateKey);

  return {
    address: address.address,
    signature: serializeSignature(signature),
  };
}

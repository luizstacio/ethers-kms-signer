import { getBytes, JsonRpcProvider, Wallet } from "ethers";
import { KMSSigner } from ".";
import { OperationType, SafeTransaction, SafeTransactionDataPartial } from "@safe-global/safe-core-sdk-types";
import Safe, { SigningMethod } from "@safe-global/protocol-kit";
import SafeApiKit from '@safe-global/api-kit';
import { adjustVInSignature, EthSafeSignature } from "@safe-global/protocol-kit/dist/src/utils";


const config = {
  safeAddress: '...',
  rpcUrl: "....",
  chainId: BigInt(11155111)
}


async function getSafeSignature(kmsSigner: KMSSigner, safeTxHash: string) {
  const signerAddress = await kmsSigner.getAddress();
  const signature = await kmsSigner.signMessage(getBytes(safeTxHash));
  const signatureAjusted = await adjustVInSignature(SigningMethod.ETH_SIGN, signature, safeTxHash, signerAddress);
  return new EthSafeSignature(signerAddress, signatureAjusted, false);
}

async function main() {
  const provider = new JsonRpcProvider(config.rpcUrl);
  const kmsSigner = new KMSSigner(process.env.KMS_ID, provider);
  const signerAddress = await kmsSigner.getAddress();

  const safe = await Safe.init({
    provider: config.rpcUrl,
    safeAddress: config.safeAddress
  });
  const apiKit = new SafeApiKit({
    chainId: config.chainId,
  });

  const safeTransactionData: SafeTransactionDataPartial = {
    to: config.safeAddress,
    value: '100', // 0.001 ether
    data: '0x',
    operation: OperationType.Call,
    nonce: 18
  }

  let safeTransaction: SafeTransaction;
  try {
    safeTransaction = await safe.createTransaction({ transactions: [safeTransactionData] })
  } catch (err) {
    console.log('`createTransaction` failed:')
    console.log(err)
    return
  }

  const safeTxHash = await safe.getTransactionHash(safeTransaction);
  const sign = await getSafeSignature(kmsSigner, safeTxHash);

  const result = await apiKit.proposeTransaction({
    safeAddress: config.safeAddress,
    safeTransactionData: safeTransaction.data,
    safeTxHash,
    senderAddress: signerAddress,
    senderSignature: sign.data,
  });
  console.log('Created the Safe transaction.', result);
}

main().catch(console.error);

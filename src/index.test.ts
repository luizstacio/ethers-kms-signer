import { expect, test } from "bun:test";
import { KMSSigner } from "./index";
import { verifyMessage, verifyTypedData, TypedDataDomain, TypedDataField } from "ethers";

const KMS_ID = process.env.KMS_ID || "";

test("KMSSigner signs a message with valid recovery", async () => {
  const signer = new KMSSigner(KMS_ID);
  const address = await signer.getAddress();
  const message = "Hello World";
  const signature = await signer.signMessage(message);
  const recoveredAddress = await verifyMessage(message, signature);  
  expect(recoveredAddress.toLowerCase()).toBe(address.toLowerCase());
});

test("KMSSigner returns correct address", async () => {
  const signer = new KMSSigner(KMS_ID);
  const returnedAddress = await signer.getAddress();
  expect(returnedAddress.startsWith('0x')).toBe(true);
});

test("KMSSigner signs typed data with valid recovery", async () => {
  const signer = new KMSSigner(KMS_ID);
  const address = await signer.getAddress();

  const domain: TypedDataDomain = {
    name: 'Test Protocol',
    version: '1',
    chainId: 1,
    verifyingContract: '0x0000000000000000000000000000000000000000'
  };

  const types: Record<string, Array<TypedDataField>> = {
    Person: [
      { name: 'name', type: 'string' },
      { name: 'wallet', type: 'address' }
    ]
  };

  const value = {
    name: 'Bob',
    wallet: address
  };
  const signature = await signer.signTypedData(domain, types, value);
  const recoveredAddress = await verifyTypedData(domain, types, value, signature);
  expect(recoveredAddress.toLowerCase()).toBe(address.toLowerCase());
});

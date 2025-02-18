import { 
  TypedDataDomain,
  TypedDataField,
  AbstractSigner,
  Provider,
  TransactionRequest,
  hashMessage,
  TypedDataEncoder,
  getBytes,
  hexlify,
  concat,
  Transaction,
  recoverAddress,
  getAddress
} from 'ethers';
import { KMS, SignCommand, SignCommandInput, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { keccak256 } from 'ethers';
import { fromBER } from 'asn1js';

export class KMSSigner extends AbstractSigner {
  private kms: KMS;
  private keyId: string;
  private _address: string | null = null;

  constructor(keyId: string, provider?: Provider, region: string = 'us-east-1') {
    super(provider);
    this.kms = new KMS({ region });
    this.keyId = keyId;
  }

  async getAddress(): Promise<string> {
    if (!this._address) {
      this._address = await this.getPublicKey();
    }
    return getAddress(this._address);
  }

  async signMessage(message: string | Uint8Array): Promise<string> {
    const messageHash = hashMessage(message);
    const signature = await this.signDigest(messageHash);
    return signature;
  }

  async signTransaction(tx: TransactionRequest): Promise<string> {
    const populated = await this.populateTransaction(tx);
    const serialized = Transaction.from(populated);
    const signature = await this.signDigest(serialized.unsignedHash);
    
    return Transaction.from(populated).serialized;
  }

  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    value: Record<string, any>
  ): Promise<string> {
    const messageHash = TypedDataEncoder.hash(domain, types, value);
    const signature = await this.signDigest(messageHash);
    return signature;
  }

  connect(provider: Provider): KMSSigner {
    return new KMSSigner(this.keyId, provider);
  }

  async signDigest(digestHex: string): Promise<string> {
    const digest = getBytes(digestHex);
    const address = await this.getAddress();
    
    const params: SignCommandInput = {
      KeyId: this.keyId,
      Message: digest,
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256'
    };

    const command = new SignCommand(params);
    const response = await this.kms.send(command);
    
    if (!response.Signature) {
      throw new Error('KMS signing failed');
    }

    const asn1 = fromBER(Buffer.from(response.Signature).buffer);
    const rBytes = new Uint8Array(32).fill(0);
    const sBytes = new Uint8Array(32).fill(0);

    const r = new Uint8Array((asn1.result.valueBlock as any).value[0].valueBlock.valueHex);
    let s = new Uint8Array((asn1.result.valueBlock as any).value[1].valueBlock.valueHex);
    
    rBytes.set(r.slice(-32));
    sBytes.set(s.slice(-32));

    // ccording to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
    // if s > secp256k1n/2, then s = secp256k1n - s
    const secp256k1n = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    const secp256k1n_2 = secp256k1n / BigInt(2);
    
    let sBigInt = BigInt("0x" + Buffer.from(sBytes).toString('hex'));
    if (sBigInt > secp256k1n_2) {
      sBigInt = secp256k1n - sBigInt;
      const newSBytes = Buffer.from(sBigInt.toString(16).padStart(64, '0'), 'hex');
      sBytes.set(new Uint8Array(newSBytes));
    }
    
    // Try both v values
    for (const v of [27, 28]) {
      const sig = concat([rBytes, sBytes, new Uint8Array([v])]);
      const recoveredAddress = await recoverAddress(digestHex, sig);
      
      if (recoveredAddress.toLowerCase() === address.toLowerCase()) {
        return hexlify(sig);
      }
    }

    throw new Error('Failed to recover matching address');
  }

  async getPublicKey(): Promise<string> {
    const response = await this.kms.send(new GetPublicKeyCommand({
      KeyId: this.keyId
    }));
    
    if (!response.PublicKey) {
      throw new Error('Failed to get public key from KMS');
    }

    const asn1 = fromBER(Buffer.from(response.PublicKey).buffer);
    const pubKeyBytes = new Uint8Array((asn1.result.valueBlock as any).value[1].valueBlock.valueHex);

    const address = '0x' + keccak256(pubKeyBytes.subarray(1)).slice(26);
    return address.toLowerCase();
  }
}

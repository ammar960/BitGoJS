import { randomBytes } from 'crypto';
import { bip32 } from '@bitgo/utxo-lib';
import { pubkeyToAddress } from '@cosmjs/amino';
import { toBase64 } from '@cosmjs/encoding';
import {
  DefaultKeys,
  isPrivateKey,
  isPublicKey,
  isSeed,
  KeyPairOptions,
  Secp256k1ExtendedKeyPair,
} from '@bitgo/sdk-core';
import { DEFAULT_SEED_SIZE_BYTES } from './constants';

/**
 * Cosmos keys and address management.
 */
export class KeyPair extends Secp256k1ExtendedKeyPair {
  /**
   * Public constructor. By default, creates a key pair with a random master seed.
   *
   * @param { KeyPairOptions } source Either a master seed, a private key (extended or raw), or a public key
   *     (extended, compressed, or uncompressed)
   */
  constructor(source?: KeyPairOptions) {
    super(source);
    if (!source) {
      const seed = randomBytes(DEFAULT_SEED_SIZE_BYTES);
      this.hdNode = bip32.fromSeed(seed);
    } else if (isSeed(source)) {
      this.hdNode = bip32.fromSeed(source.seed);
    } else if (isPrivateKey(source)) {
      this.recordKeysFromPrivateKey(source.prv);
    } else if (isPublicKey(source)) {
      this.recordKeysFromPublicKey(source.pub);
    } else {
      throw new Error('Invalid key pair options');
    }

    if (this.hdNode) {
      this.keyPair = Secp256k1ExtendedKeyPair.toKeyPair(this.hdNode);
    }
  }

  /**
   * Cosmos default keys format: raw private and compressed public key
   *
   * @returns { DefaultKeys } The keys in the protocol default key format
   */
  getKeys(): DefaultKeys {
    return {
      pub: this.getPublicKey({ compressed: true }).toString('hex'),
      prv: this.getPrivateKey()?.toString('hex'),
    };
  }

  /** @inheritdoc */
  getAddress(): string {
    const PUBLIC_KEY_SIZE = 32;
    const tmp = new Uint8Array(PUBLIC_KEY_SIZE + 1);
    const pubBuf = Buffer.from(this.getKeys().pub.slice(0, 64), 'hex');
    tmp.set(pubBuf, 1);
    // convert to base64
    const base64String = toBase64(tmp);
    return pubkeyToAddress(
      {
        type: 'tendermint/PubKeySecp256k1',
        value: base64String,
      },
      'cosmos'
    );
  }
}

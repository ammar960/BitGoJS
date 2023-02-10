import * as createHash from 'create-hash';
import * as necc from '@noble/secp256k1';
import { MuSigFactory, MuSig } from '@brandonblack/musig';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore base_crypto is exported as a subPath export, ignoring since compiler complains about importing like this
import * as base_crypto from '@brandonblack/musig/base_crypto';

function toBigInt(b: Uint8Array | Buffer): bigint {
  return Buffer.from(b).readBigUint64BE();
}

const crypto = {
  ...base_crypto,
  pointMultiplyUnsafe: (p: Uint8Array, a: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      const product = necc.Point.fromHex(p).multiplyAndAddUnsafe(necc.Point.ZERO, toBigInt(a), BigInt(1));
      if (!product) return null;
      return product.toRawBytes(compress);
    } catch {
      return null;
    }
  },
  pointMultiplyAndAddUnsafe: (p1: Uint8Array, a: Uint8Array, p2: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      const p2p = necc.Point.fromHex(p2);
      const p = necc.Point.fromHex(p1).multiplyAndAddUnsafe(p2p, toBigInt(a), BigInt(1));
      if (!p) return null;
      return p.toRawBytes(compress);
    } catch {
      return null;
    }
  },
  pointAdd: (a: Uint8Array, b: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return necc.Point.fromHex(a).add(necc.Point.fromHex(b)).toRawBytes(compress);
    } catch {
      return null;
    }
  },
  pointAddTweak: (p: Uint8Array, tweak: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      const P = necc.Point.fromHex(p);
      const t = base_crypto.readSecret(tweak);
      const Q = necc.Point.BASE.multiplyAndAddUnsafe(P, t, BigInt(1));
      if (!Q) throw new Error('Tweaked point at infinity');
      return Q.toRawBytes(compress);
    } catch {
      return null;
    }
  },
  pointCompress: (p: Uint8Array, compress = true): Uint8Array => necc.Point.fromHex(p).toRawBytes(compress),
  liftX: (p: Uint8Array): Uint8Array | null => {
    try {
      return necc.Point.fromHex(p).toRawBytes(false);
    } catch {
      return null;
    }
  },
  getPublicKey: (s: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return necc.getPublicKey(s, compress);
    } catch {
      return null;
    }
  },
  taggedHash: necc.utils.taggedHashSync,
  sha256: (...messages: Uint8Array[]): Uint8Array => {
    const sha256 = createHash('sha256');
    for (const message of messages) sha256.update(message);
    return sha256.digest();
  },
};

const musig: MuSig = MuSigFactory(crypto);

export { musig, MuSig };

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';

/** An Ed25519 identity. Keys are stored as base64url raw 32-byte values (JWK `x` and `d`). */
export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  const pub = publicKey.export({ format: 'jwk' });
  if (!jwk.d || !pub.x) throw new Error('failed to export Ed25519 key');
  return { publicKey: pub.x, privateKey: jwk.d };
}

function privateKeyObject(kp: KeyPair): KeyObject {
  return createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x: kp.publicKey, d: kp.privateKey }, format: 'jwk' });
}

function publicKeyObject(publicKey: string): KeyObject {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' });
}

export function signBytes(kp: KeyPair, message: string): string {
  return sign(null, Buffer.from(message, 'utf8'), privateKeyObject(kp)).toString('base64url');
}

export function verifyBytes(publicKey: string, message: string, signature: string): boolean {
  if (!isPublicKey(publicKey) || typeof signature !== 'string' || !/^[A-Za-z0-9_-]+$/.test(signature)) return false;
  try {
    return verify(null, Buffer.from(message, 'utf8'), publicKeyObject(publicKey), Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

export function isPublicKey(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
}

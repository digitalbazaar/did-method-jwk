/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1';
const JSON_WEB_KEY_V1_URL = 'https://w3id.org/security/jwk/v1';
const JSON_WEB_KEY_2020_URL = 'https://w3id.org/security/suites/jws-2020/v1';

export const ALG_TO_CRVS = new Map([
  ['EdDSA', ['Ed25519']],
  ['ES256', ['P-256']],
  ['ES256K', ['P-256K', 'secp256k1']],
  ['ES384', 'P-384'],
  ['ES521', 'P-521']
]);

export const DEFAULT_JWK_USE = new Map([
  ['Bls12381G2', 'sig'],
  ['Ed25519', 'sig'],
  ['X25519', 'enc'],
  ['P-256', 'sig'],
  ['P-256K', 'sig'],
  ['P-384', 'sig'],
  ['P-521', 'sig']
]);

export const DID_DOC_CONTEXTS_BY_VM_TYPE = new Map([
  ['JsonWebKey', [DID_CONTEXT_URL, JSON_WEB_KEY_V1_URL]],
  ['JsonWebKey2020', [DID_CONTEXT_URL, JSON_WEB_KEY_2020_URL]]
]);

export const VM_CONTEXTS_BY_VM_TYPE = new Map([
  ['JsonWebKey', JSON_WEB_KEY_V1_URL],
  ['JsonWebKey2020', JSON_WEB_KEY_2020_URL]
]);

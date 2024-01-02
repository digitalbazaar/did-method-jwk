/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  X25519KeyAgreementKey2019
} from '@digitalbazaar/x25519-key-agreement-key-2019';
import {
  X25519KeyAgreementKey2020
} from '@digitalbazaar/x25519-key-agreement-key-2020';

const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1';
const ED25519_KEY_2018_CONTEXT_URL =
  'https://w3id.org/security/suites/ed25519-2018/v1';
const ED25519_KEY_2020_CONTEXT_URL =
  'https://w3id.org/security/suites/ed25519-2020/v1';
const JSON_WEB_KEY_2020 = 'https://w3id.org/security/suites/jws-2020/v1';
const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';

export const KEY_PAIR_CONTEXTS_BY_SUITE = new Map([
  ['JsonWebKey2020', JSON_WEB_KEY_2020],
  ['Ed25519VerificationKey2020', ED25519_KEY_2020_CONTEXT_URL],
  ['Ed25519VerificationKey2018', ED25519_KEY_2018_CONTEXT_URL],
  ['Multikey', MULTIKEY_CONTEXT_V1_URL],
  [X25519KeyAgreementKey2020.suite, X25519KeyAgreementKey2020.SUITE_CONTEXT],
  [X25519KeyAgreementKey2019.suite, X25519KeyAgreementKey2019.SUITE_CONTEXT]
]);

export const DID_DOC_CONTEXTS_BY_SUITE = new Map([
  ['JsonWebKey2020', [DID_CONTEXT_URL, JSON_WEB_KEY_2020]],
  ['Ed25519VerificationKey2020', [
    DID_CONTEXT_URL, ED25519_KEY_2020_CONTEXT_URL
  ]],
  ['Ed25519VerificationKey2018', [
    DID_CONTEXT_URL, ED25519_KEY_2018_CONTEXT_URL
  ]],
  ['Multikey', [DID_CONTEXT_URL, MULTIKEY_CONTEXT_V1_URL]],
  [X25519KeyAgreementKey2020.suite, [
    DID_CONTEXT_URL, X25519KeyAgreementKey2020.SUITE_CONTEXT
  ]],
  [X25519KeyAgreementKey2019.suite, [
    DID_CONTEXT_URL, X25519KeyAgreementKey2019.SUITE_CONTEXT
  ]]
]);

/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import DidJwk from '@or13/did-jwk';
import {DID_DOC_CONTEXTS_BY_SUITE} from './constants.js';

export async function getKeyPair({
  key, handler
} = {}) {
  if(!key && key.type !== 'JsonWebKey2020') {
    throw new TypeError('"key" must be a JsonWebKey2020 object.');
  }
  if(!handler && typeof handler !== 'function') {
    throw new TypeError('"handler" must be a function.');
  }
  const keyPair = await handler(key);
  const {type} = keyPair;
  let keyAgreementKeyPair;
  if(type === 'X25519KeyAgreementKey2020' ||
    type === 'X25519KeyAgreementKey2019') {
    keyAgreementKeyPair = keyPair;
    keyPair = null;
  }
  return {keyPair, keyAgreementKeyPair};
}

export async function getDidDoc({
  did, doc, handler
} = {}) {
  if(!doc) {
    if(!did) {
      throw new TypeError('Either "did" of "doc" must be defined.');
    }
    doc = DidJwk.resolve(did);
  }
  if(!handler && typeof handler !== 'function') {
    throw new TypeError('"handler" must be a function.');
  }
  const [key] = doc.verificationMethod;
  const keyPair = await handler(key);
  return {
    ...doc,
    '@context': DID_DOC_CONTEXTS_BY_SUITE.get(keyPair.type),
    verificationMethod: [keyPair]
  };
}

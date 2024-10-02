/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {
  ALG_TO_CRVS,
  DEFAULT_JWK_USE,
  DID_DOC_CONTEXTS_BY_VM_TYPE,
  VM_CONTEXTS_BY_VM_TYPE
} from './constants.js';

// Note: did:jwk spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md

export class DidJwkDriver {
  constructor() {
    // used by did-io to register drivers
    this.method = 'jwk';
    this._allowedKeyTypes = new Map();
  }

  /**
   * Registers a key handler for an algorithm (a JWK "alg" or "crv" value). If
   * no algorithms (or curves) are registered with a driver, then no key
   * validation is performed when resolving a `did:jwk` DID.
   *
   * @param {object} options - Options hashmap.
   * @param {string} options.algorithm - The JWK "alg" or "crv" value to
   *   register a handler with.
   * @param {Function} options.handler - A function that converts a
   *  `{publicKeyJwk}` value into a key pair interface.
   */
  use({algorithm, handler} = {}) {
    if(typeof algorithm !== 'string') {
      throw new TypeError('"algorithm" must be a string.');
    }
    if(typeof handler !== 'function') {
      throw new TypeError('"handler" must be a function.');
    }
    this._allowedKeyTypes.set(algorithm, handler);
    // support curves associated with algorithms
    const crvs = ALG_TO_CRVS.get(algorithm);
    if(crvs) {
      for(const crv of crvs) {
        if(!this._allowedKeyTypes.has(crv)) {
          this._allowedKeyTypes.set(crv, handler);
        }
      }
    }
  }

  /**
   * Generates a DID `jwk` (`did:jwk`) method DID Document from a JWK. If
   * handlers have been registered for the JWK's "alg" or "crv" value,
   * then `keyPairs` will also be returned for use.
   *
   * @param {object} options - Options hashmap.
   * @param {object} [options.jwk] - The JWK.
   * @param {string} [options.verificationMethodType='JsonWebKey'] - The
   *   verification method type to use in the DID document: 'JsonWebKey', or
   *   'JsonWebKey2020'.
   *
   * @returns {Promise<{didDocument: object, keyPairs: Map,
  *   methodFor: Function}>} Resolves with the generated DID Document, along
  *   with the corresponding key pairs used to generate it (for storage in a
  *   KMS).
  */
  async fromJwk({jwk, verificationMethodType = 'JsonWebKey'} = {}) {
    const {didDocument, keyPairs} = await this._jwkToDidDocument({
      jwk, verificationMethodType
    });

    // convenience function that returns the public/private key pair instance
    // for a given purpose (authentication, assertionMethod, keyAgreement, etc).
    const methodFor = ({purpose}) => {
      const {id: methodId} = this.publicMethodFor({didDocument, purpose});
      return keyPairs.get(methodId);
    };
    return {didDocument, keyPairs, methodFor};
  }

  /**
   * Returns the public key (verification method) object for a given DID
   * Document and purpose. Useful in conjunction with a `.get()` call.
   *
   * @example
   * const didDocument = await didKeyDriver.get({did});
   * const verificationMethod = didDriver.publicMethodFor({
   *   didDocument, purpose: 'authentication'
   * });
   * someKeyLibrary.from(verificationMethod);
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.didDocument - DID Document (retrieved via a
   *   `.get()` or from some other source).
   * @param {string} options.purpose - Verification method purpose, such as
   *   'authentication', 'assertionMethod', 'keyAgreement' and so on.
   *
   * @returns {object} Returns the public key object (obtained from the DID
   *   Document), without a `@context`.
   */
  publicMethodFor({didDocument, purpose} = {}) {
    if(!didDocument) {
      throw new TypeError('The "didDocument" parameter is required.');
    }
    if(!purpose) {
      throw new TypeError('The "purpose" parameter is required.');
    }
    // try to get method based on `purpose`
    let [method] = didDocument[purpose] ?? [];
    if(typeof method === 'string' &&
      method === didDocument.verificationMethod?.[0]?.id) {
      // dereference method
      method = didDocument.verificationMethod[0];
    }
    if(method && method !== 'string') {
      throw new Error(`No verification method found for purpose "${purpose}".`);
    }

    const contexts = VM_CONTEXTS_BY_VM_TYPE.get(method.type);
    if(!contexts) {
      throw new Error(`Unknown verification method type "${method.type}".`);
    }

    // resolve an individual key
    return {'@context': contexts, ...method};
  }

  /**
   * Returns a `did:jwk` method DID Document for a given DID, or a key document
   * for a given DID URL (key id).
   * Either a `did` or `url` param is required.
   *
   * @example
   * await resolver.get({did}); // -> did document
   * await resolver.get({url: keyId}); // -> public key node
   *
   * @param {object} options - Options hashmap.
   * @param {string} [options.did] - DID URL or a key id.
   * @param {string} [options.url] - Alias for the `did` url param, supported
   *   for better readability of invoking code.
   * @param {string} [options.verificationMethodType='JsonWebKey'] - The
   *   verification method type to use in the DID document: 'JsonWebKey', or
   *   'JsonWebKey2020'.
   *
   * @returns {Promise<object>} Resolves to a DID Document or a
   *   public key node with context.
   */
  async get({did, url, verificationMethodType = 'JsonWebKey'} = {}) {
    url = did || url;
    if(!(url && typeof url === 'string')) {
      throw new TypeError('"did" or "url" must be a string.');
    }
    const contexts = VM_CONTEXTS_BY_VM_TYPE.get(verificationMethodType);
    if(!contexts) {
      const keys = [...VM_CONTEXTS_BY_VM_TYPE.keys()];
      throw new TypeError(
        `"verificationMethodType" must be one of: ${keys.join(', ')}.`);
    }

    const [didAuthority, keyIdFragment] = url.split('#');
    if(!didAuthority.startsWith('did:jwk:')) {
      throw new Error(
        `Invalid "did:jwk" URL "${url}"; the prefix "did:jwk:" is required.`);
    }
    if(keyIdFragment !== undefined && keyIdFragment !== '0') {
      throw new Error(
        `Invalid "did:jwk" URL "${url}"; if present, fragment MUST be "#0".`);
    }

    // parse base64url-encoded JWK
    const encodedJwk = didAuthority.slice('did:jwk:'.length);
    let jwkJson;
    let jwk;
    try {
      jwkJson = new TextDecoder().decode(base64url.decode(encodedJwk));
    } catch(e) {
      const error = new Error(
        `Could not decode base64url-encoded JWK from "${encodedJwk}".`);
      error.cause = e;
      throw error;
    }
    try {
      jwk = JSON.parse(jwkJson);
    } catch(e) {
      const error = new Error(`Could not parse JWK "${jwkJson}".`);
      error.cause = e;
      throw error;
    }

    const {didDocument} = await this._jwkToDidDocument({
      did: didAuthority, jwk, verificationMethodType
    });

    if(keyIdFragment) {
      // resolve an individual key
      return {
        '@context': contexts,
        ...didDocument.verificationMethod[0]
      };
    }
    // resolve the full DID Document
    return didDocument;
  }

  /**
   * Converts a JWK object to a `did:jwk` method DID Document.
   *
   * @param {object} options - Options hashmap.
   * @param {string} [options.did] - The `did` to use.
   * @param {object} options.jwk - The JWK object.
   * @param {string} [options.verificationMethodType='JsonWebKey'] - The
   *   verification method type to use in the DID document: 'JsonWebKey', or
   *   'JsonWebKey2020'.
   *
   * @returns {Promise<{didDocument: object, keyPairs: Map}>}
   *   Resolves with the generated DID Document, along with the corresponding
   *   key pairs.
   */
  async _jwkToDidDocument({
    did, jwk, verificationMethodType = 'JsonWebKey'
  } = {}) {
    if(did === undefined) {
      const encoded = base64url.encode(
        new TextEncoder().encode(JSON.stringify(jwk)));
      did = `did:jwk:${encoded}`;
    } else if(typeof did !== 'string') {
      throw new TypeError('"did" must be a string.');
    }
    if(!(jwk && typeof jwk === 'object')) {
      throw new TypeError('"jwk" must be an object.');
    }

    const verificationMethod = {
      id: `${did}#0`,
      type: verificationMethodType,
      controller: did,
      publicKeyJwk: jwk
    };

    const keyPairs = new Map();

    // try to import JWK if `allowedKeyTypes` has any values
    if(this._allowedKeyTypes.size > 0) {
      // get "algorithms" for JWK.alg / JWK.crv
      const algorithms = [];
      if(jwk.alg !== undefined) {
        algorithms.push(jwk.alg);
      }
      if(jwk.crv !== undefined) {
        algorithms.push(jwk.crv);
      }
      let handler;
      for(const algorithm of algorithms) {
        handler = this._allowedKeyTypes.get(algorithm);
        if(handler) {
          break;
        }
      }
      if(!handler) {
        throw new Error(`JWK alg/crv values not allowed: "${algorithms}".`);
      }
      keyPairs.set(verificationMethod.id, await handler(verificationMethod));
    }

    // start constructing DID document
    const didDocument = {
      '@context': DID_DOC_CONTEXTS_BY_VM_TYPE.get(verificationMethodType),
      id: did,
      verificationMethod: [verificationMethod]
    };

    // determine `use` from the curve, if available
    let {use} = jwk;
    if(use === undefined) {
      if(jwk.alg?.startsWith?.('ECDH')) {
        use = 'enc';
      } else {
        /* Spec note: The JWK should have the appropriate use value set to
        match the capabilities of the specified crv. For example, the curve
        ed25519 is only valid for "sig" use and X25519 is only valid for "enc"
        (see RFC 8037 and the second example below). */
        use = DEFAULT_JWK_USE.get(jwk.crv);
      }
    }

    /* Spec note: If the JWK contains a use property with the value "sig" then
    the `keyAgreement` property is not included in the DID Document. If the use
    value is "enc" then only the keyAgreement property is included in the DID
    Document. */
    if(use === 'sig') {
      didDocument.assertionMethod = [verificationMethod.id];
      didDocument.authentication = [verificationMethod.id];
      didDocument.capabilityInvocation = [verificationMethod.id];
      didDocument.capabilityDelegation = [verificationMethod.id];
    }
    if(use === 'enc') {
      didDocument.keyAgreement = [verificationMethod.id];
    }

    return {didDocument, keyPairs};
  }
}

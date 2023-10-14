/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as didIo from '@digitalbazaar/did-io';
import DidJwk from '@or13/did-jwk';
import {CONTEXTS_BY_SUITE} from './constants.js';
import {getKeyPair} from './helpers.js';

export class DidJwkDriver {
  constructor() {
    // used by did-io to register drivers
    this.method = 'jwk';
    this._registeredKeyTypes = new Map();
    this._registeredAlgorithms = new Set();
  }

  /**
   * Registers a multibase-multikey header and a multibase-multikey
   * deserializer that is allowed to handle data using that header.
   *
   * @param {object} options - Options hashmap.
   *
   * @param {string} options.algorithm - The algorithm to calculate the key.
   *   header to register.
   * @param {Function} options.fromJsonWebKey2020 - A function that converts a
   *  JsonWebKey2020 object into a key pair interface.
   */
  use({algorithm, fromJsonWebKey2020} = {}) {
    if(!algorithm) {
      throw new TypeError(`Missing algorithm: "algorithm" must be either a valid signature value (${DidJwk.signatureAlgorithms.join(', ')}) 
or a valid encryption value (${DidJwk.encryptionAlgorithms.join(', ')}) .`);
    }
    if(!DidJwk.algorithms.includes(algorithm)) {
      throw new TypeError(`Invalid algorithm: "algorithm" must be either a valid signature value (${DidJwk.signatureAlgorithms.join(', ')}) 
or a valid encryption value (${DidJwk.encryptionAlgorithms.join(', ')}) .`);
    }
    if(typeof fromJsonWebKey2020 !== 'function') {
      throw new TypeError('"fromJsonWebKey2020" must be a function.');
    }

    this._registeredKeyTypes.set(algorithm, fromJsonWebKey2020);
    this._registeredAlgorithms.add(algorithm);
  }

  /**
   * Generates a DID `jwk` (`did:jwk`) method DID Document from a KeyPair.
   *
   * @param {object} options - Options hashmap.
   *
   * @param {string} options.algorithm - The algorithm to calculate the key.
   *
   * @returns {Promise<{didDocument: object, keyPairs: Map, methodFor: Function}>}
   *   Resolves with the generated DID Document, along with the corresponding
   *   key pairs used to generate it (for storage in a KMS).
   */
  async generate({algorithm} = {}) {
    if(!algorithm) {
      throw new TypeError(`Missing algorithm: "algorithm" must be either a valid signature value (${DidJwk.signatureAlgorithms.join(', ')}) 
or a valid encryption value (${DidJwk.encryptionAlgorithms.join(', ')}) .`);
    }
    if(!DidJwk.algorithms.includes(algorithm)) {
      throw new TypeError(`Invalid algorithm: "algorithm" must be either a valid signature value (${DidJwk.signatureAlgorithms.join(', ')}) 
or a valid encryption value (${DidJwk.encryptionAlgorithms.join(', ')}) .`);
    }
    if(!this._registeredAlgorithms.has(algorithm)) {
      throw new TypeError(`Unregistered algorithm: "algorithm" ("${algorithm}") must be registered with the "use" method`);
    }

    const {publicKeyJwk} = await DidJwk.generateKeyPair(algorithm);
    const didDocument = DidJwk.toDidDocument(publicKeyJwk);
    const jsonWebKey2020 = didDocument.verificationMethod[0];
    const fromJsonWebKey2020 = this._registeredKeyTypes.get(algorithm);
    const {keyPair} = await getKeyPair({
      fromJsonWebKey2020, jsonWebKey2020
    });

    const keyIdAbridged = keyPair.id;
    const keyIdFull = this.computeId({keyPair});
    const keyPairs = new Map([
      [keyIdAbridged, keyPair],
      [keyIdFull, keyPair]
    ]);

    // convenience function that returns the public/private key pair instance
    // for a given purpose (authentication, assertionMethod, keyAgreement, etc).
    const methodFor = ({purpose}) => {
      const {id: methodId} = this.publicMethodFor({
        didDocument, purpose
      });
      return keyPairs.get(methodId);
    };
    return {didDocument, keyPairs, methodFor};
  }

  /**
   * Returns the public key (verification method) object for a given DID
   * Document and purpose. Useful in conjunction with a `.get()` call.
   *
   * @example
   * const didDocument = await didJwkDriver.get({did});
   * const authKeyData = didDriver.publicMethodFor({
   *   didDocument, purpose: 'authentication'
   * });
   * // You can then create a suite instance object to verify signatures etc.
   * const authPublicKey = await cryptoLd.from(authKeyData);
   * const {verify} = authPublicKey.verifier();
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

    const method = didIo.findVerificationMethod({doc: didDocument, purpose});
    if(!method) {
      throw new Error(`No verification method found for purpose "${purpose}"`);
    }
    return method;
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
   * @param {string} [options.did] - DID URL or a key id (either an ed25519 key
   *   or an x25519 key-agreement key id).
   * @param {string} [options.url] - Alias for the `did` url param, registered
   *   for better readability of invoking code.
   *
   * @returns {Promise<object>} Resolves to a DID Document or a
   *   public key node with context.
   */
  async get({did, url} = {}) {
    did = did || url;
    if(!did) {
      throw new TypeError('"did" must be a string.');
    }

    const [didAuthority, keyIdFragment] = did.split('#');
    const didDocument = DidJwk.resolve(didAuthority);
    if(keyIdFragment) {
      // resolve an individual key
      const jsonWebKey2020 = didDocument.verificationMethod[0];
      const algorithm = jsonWebKey2020.publicKeyJwk.alg;
      const fromJsonWebKey2020 = this._registeredKeyTypes.get(algorithm);
      const {keyPair} = await getKeyPair({
        fromJsonWebKey2020, jsonWebKey2020
      });
      return {
        '@context': CONTEXTS_BY_SUITE.get(keyPair.type),
        ...DidJwk.dereference(did)
      };
    }
    return didDocument;
  }

  /**
   * Converts a public key object to a `did:jwk` method DID Document.
   * Note that unlike `generate()`, a `keyPairs` map is not returned.
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.publicKeyJwk - Public key object
   *   used to generate the DID document.
   *
   * @returns {Promise<object>} Resolves with the generated DID Document.
   */
  async publicKeyToDidDoc({publicKeyJwk} = {}) {
    return DidJwk.toDidDocument(publicKeyJwk);
  }

  /**
   * Computes and returns the id of a given key pair. Used by `did-io` drivers.
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.keyPair - The key pair used when computing the
   *   identifier.
   *
   * @returns {string} Returns the key's id.
   */
  async computeId({keyPair}) {
    return `${keyPair.controller}#0`;
  }
}

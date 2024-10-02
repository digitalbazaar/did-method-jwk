/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import chai from 'chai';
import {driver} from '../lib/index.js';

chai.should();
const {expect} = chai;
const didJwkDriver = driver();
// intentionally use a mix of "alg" and "crv" here:
didJwkDriver.use({
  algorithm: 'EdDSA',
  handler: Ed25519Multikey.from
});
didJwkDriver.use({
  algorithm: 'P-256',
  handler: EcdsaMultikey.from
});
didJwkDriver.use({
  algorithm: 'ES384',
  handler: EcdsaMultikey.from
});
didJwkDriver.use({
  algorithm: 'Bls12381G2',
  handler: Bls12381Multikey.from
});

describe('did:jwk method driver', () => {
  describe('get', () => {
    it('should get the DID Document w/o any handlers set', async () => {
      const handlerLessDriver = driver();

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYb\
HdJIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaE\
FZS3FJUEs5cm5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await handlerLessDriver.get({did});

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/jwk/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      expect(publicKey).to.eql({
        id: keyId,
        type: 'JsonWebKey',
        controller: did,
        publicKeyJwk: {
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:kirAYu_5chPBalBK4Y\
7u2aLkOS4KauP6AVB185tXlwI`,
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          x: 'iPhAYKqIPK9rng_uedhpXzIC2vOMn8VtGoohdnAVlrA'
        }
      });
    });

    it('should get the DID Document for an EdDSA did:jwk DID', async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'EdDSA',
        handler: Ed25519Multikey.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYb\
HdJIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaE\
FZS3FJUEs5cm5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({did});

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/jwk/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      expect(publicKey).to.eql({
        id: keyId,
        type: 'JsonWebKey',
        controller: did,
        publicKeyJwk: {
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:kirAYu_5chPBalBK4Y\
7u2aLkOS4KauP6AVB185tXlwI`,
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          x: 'iPhAYKqIPK9rng_uedhpXzIC2vOMn8VtGoohdnAVlrA'
        }
      });
    });

    it('should get the DID Document for an Ed25519 did:jwk DID', async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'Ed25519',
        handler: Ed25519Multikey.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYb\
HdJIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaE\
FZS3FJUEs5cm5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({did});

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/jwk/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      expect(publicKey).to.eql({
        id: keyId,
        type: 'JsonWebKey',
        controller: did,
        publicKeyJwk: {
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:kirAYu_5chPBalBK4Y\
7u2aLkOS4KauP6AVB185tXlwI`,
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          x: 'iPhAYKqIPK9rng_uedhpXzIC2vOMn8VtGoohdnAVlrA'
        }
      });
    });

    it(`should use EdDSA handler to get the DID Document for an EdDSA did:jwk \
DID`, async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'EdDSA',
        handler: Ed25519Multikey.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYbHdJIiw\
ia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaEFZS3FJUEs5cm\
5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({did});

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/jwk/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      // convert to multibase
      const keypair = await Ed25519Multikey.from(publicKey);
      const mk = await keypair.export({public: true});
      expect(mk.id).not.to.be.undefined;
      expect(mk.type).not.to.be.undefined;
      expect(mk.controller).not.to.be.undefined;
      expect(mk.id).to.equal(keyId);
      expect(mk.type).to.equal('Multikey');
      expect(mk.controller).to.equal(did);
      expect(mk.publicKeyMultibase).to
        .equal('z6Mkofw3hAMb2bbRt6FJ5dUTZwK2z63ySprKQwoosFC8nPMy');
    });

    it('should get the DID Document for an ES256 did:jwk DID', async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'ES256',
        handler: EcdsaMultikey.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpSWGFWZUxpTEltelVxS2pWUExaT1ZrdlUxdGh3YnoyYXZybXkzeVBfTTJnIiw\
ia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2IiwieCI6InF2LW9VSTdKVU5jMkNMY3\
F6RHB5V3lUby1nbGdHV1RfMUtkZEwzd0ViVWsiLCJ5IjoiZmhMdmtPTWVNQ0lSQmZlYmpIdnZHampne\
mRjRFpHQ2tueUJQSVNKVThfcyJ9`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({did});

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/jwk/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      expect(publicKey).to.eql({
        id: keyId,
        type: 'JsonWebKey',
        controller: did,
        publicKeyJwk: {
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:RXaVeLiLImzUqKjVPL\
ZOVkvU1thwbz2avrmy3yP_M2g`,
          kty: 'EC',
          crv: 'P-256',
          alg: 'ES256',
          x: 'qv-oUI7JUNc2CLcqzDpyWyTo-glgGWT_1KddL3wEbUk',
          y: 'fhLvkOMeMCIRBfebjHvvGjjgzdcDZGCknyBPISJU8_s'
        }
      });
    });

    it('should get the DID Document for a P-256 did:jwk DID', async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'P-256',
        handler: EcdsaMultikey.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpSWGFWZUxpTEltelVxS2pWUExaT1ZrdlUxdGh3YnoyYXZybXkzeVBfTTJnIiw\
ia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2IiwieCI6InF2LW9VSTdKVU5jMkNMY3\
F6RHB5V3lUby1nbGdHV1RfMUtkZEwzd0ViVWsiLCJ5IjoiZmhMdmtPTWVNQ0lSQmZlYmpIdnZHampne\
mRjRFpHQ2tueUJQSVNKVThfcyJ9`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({did});

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/jwk/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      expect(publicKey).to.eql({
        id: keyId,
        type: 'JsonWebKey',
        controller: did,
        publicKeyJwk: {
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:RXaVeLiLImzUqKjVPL\
ZOVkvU1thwbz2avrmy3yP_M2g`,
          kty: 'EC',
          crv: 'P-256',
          alg: 'ES256',
          x: 'qv-oUI7JUNc2CLcqzDpyWyTo-glgGWT_1KddL3wEbUk',
          y: 'fhLvkOMeMCIRBfebjHvvGjjgzdcDZGCknyBPISJU8_s'
        }
      });
    });

    it('should NOT get the DID Document for a disallowed key', async () => {
      const didJwkDriver = driver();
      // note: only `EdDSA` is supported, NOT P-256 which is what we try to
      // load below and expect to fail
      didJwkDriver.use({
        algorithm: 'EdDSA',
        handler: Ed25519Multikey.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpSWGFWZUxpTEltelVxS2pWUExaT1ZrdlUxdGh3YnoyYXZybXkzeVBfTTJnIiw\
ia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2IiwieCI6InF2LW9VSTdKVU5jMkNMY3\
F6RHB5V3lUby1nbGdHV1RfMUtkZEwzd0ViVWsiLCJ5IjoiZmhMdmtPTWVNQ0lSQmZlYmpIdnZHampne\
mRjRFpHQ2tueUJQSVNKVThfcyJ9`;
      let err;
      let didDocument;
      try {
        didDocument = await didJwkDriver.get({did});
      } catch(e) {
        err = e;
      }
      expect(didDocument).to.be.undefined;
      expect(err).to.not.be.undefined;
    });

    it(`should use BLS handler to get the DID Document for a BLS did:jwk \
      DID`, async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'Bls12381G2',
        handler: Bls12381Multikey.from
      });

      const did = `did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJCbHMxMjM4MUcyIiwieCI6InJN\
dlhqX0xpYk1lUnJOaDJzcW1rQnFCSDR4S2VPV21BWUs4aW5WTVgxODM5eTZYZW9sbmJUNnZ4bnhVMlB\
tVjlGWEotcnRjejZUeGU3djJpajFkRnpNSHVCVDFUeUJydEVaV3RDU09NVElCWHBuVnNPTU1TZGhzVE\
IxaVVTOW8xIn0`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({did});

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/jwk/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      expect(publicKey.id).not.to.be.undefined;
      expect(publicKey.type).not.to.be.undefined;
      expect(publicKey.controller).not.to.be.undefined;
      expect(publicKey.id).to.equal(keyId);
      expect(publicKey.type).to.equal('JsonWebKey');
      expect(publicKey.controller).to.equal(did);
      expect(publicKey.publicKeyJwk).to.deep.equal({
        kty: 'OKP',
        crv: 'Bls12381G2',
        x: `rMvXj_LibMeRrNh2sqmkBqBH4xKeOWmAYK8inVMX1839y6XeolnbT6vxnxU2PmV9FXJ\
-rtcz6Txe7v2ij1dFzMHuBT1TyBrtEZWtCSOMTIBXpnVsOMMSdhsTB1iUS9o1`
      });
    });

    it('should get the DID Document for an ECDH did:jwk DID with key agreement',
      async () => {
        const didJwkDriver = driver();

        const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW\
1icHJpbnQ6c2hhLTI1NjpOaXpuNmpvRi1UMXQ5X0xtaHdLWDFnbTM1dVRYT2Vac3ZhcFROT3d5SlQ4I\
iwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwieCI6Ii1lY1hy\
aU5BQTJqM0FCTVRqVnJ2TlU4eUNOQXNiTkdZenRRUExtTldjREEiLCJ5IjoiVS1JcEg5ZFFBbFFwcVV\
FX1VVRWtUOHhIS1FhTlduNTBhTFBhNEY2U0d4TSJ9`;
        const keyIdFragment = '#0';
        const keyId = `${did}${keyIdFragment}`;
        const keyIdCandidates = [keyId, keyIdFragment];
        const didDocument = await didJwkDriver.get({did});

        expect(didDocument.id).to.equal(did);
        expect(didDocument['@context']).to.eql([
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/jwk/v1'
        ]);
        expect(keyIdCandidates).to.include.members(didDocument.keyAgreement);

        const [publicKey] = didDocument.verificationMethod;
        expect(publicKey).to.eql({
          id: keyId,
          type: 'JsonWebKey',
          controller: did,
          publicKeyJwk: {
            kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:Nizn6joF-T1t9_Lm\
hwKX1gm35uTXOeZsvapTNOwyJT8`,
            kty: 'EC',
            crv: 'P-256',
            alg: 'ECDH-ES+A256KW',
            x: '-ecXriNAA2j3ABMTjVrvNU8yCNAsbNGYztQPLmNWcDA',
            y: 'U-IpH9dQAlQpqUE_UUEkT8xHKQaNWn50aLPa4F6SGxM'
          }
        });
      });

    it('should resolve an individual EdDSA key within the DID Document',
      async () => {
        const didJwkDriver = driver();

        const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW\
1icHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYbHdJI\
iwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaEFZS3FJUEs5\
cm5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
        const keyIdFragment = '#0';
        const keyId = `${did}${keyIdFragment}`;
        const key = await didJwkDriver.get({url: keyId});

        expect(key).to.eql({
          '@context': 'https://w3id.org/security/jwk/v1',
          id: keyId,
          type: 'JsonWebKey',
          controller: did,
          publicKeyJwk: {
            alg: 'EdDSA',
            crv: 'Ed25519',
            kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:kirAYu_5chPBalBK\
4Y7u2aLkOS4KauP6AVB185tXlwI`,
            kty: 'OKP',
            x: 'iPhAYKqIPK9rng_uedhpXzIC2vOMn8VtGoohdnAVlrA'
          }
        });
      });

    it('should use EdDSA handler to resolve an individual EdDSA key within the \
DID Document', async () => {
      const didJwkDriver = driver();

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW\
1icHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYbHdJI\
iwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaEFZS3FJUEs5\
cm5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const key = await didJwkDriver.get({url: keyId});

      expect(key).to.eql({
        '@context': 'https://w3id.org/security/jwk/v1',
        id: keyId,
        type: 'JsonWebKey',
        controller: did,
        publicKeyJwk: {
          alg: 'EdDSA',
          crv: 'Ed25519',
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:kirAYu_5chPBalBK\
4Y7u2aLkOS4KauP6AVB185tXlwI`,
          kty: 'OKP',
          x: 'iPhAYKqIPK9rng_uedhpXzIC2vOMn8VtGoohdnAVlrA'
        }
      });

      // convert to multibase
      const keypair = await Ed25519Multikey.from(key);
      const mk = await keypair.export({public: true});
      expect(mk.id).not.to.be.undefined;
      expect(mk.type).not.to.be.undefined;
      expect(mk.controller).not.to.be.undefined;
      expect(mk.id).to.equal(keyId);
      expect(mk.type).to.equal('Multikey');
      expect(mk.controller).to.equal(did);
      expect(mk.publicKeyMultibase).to
        .equal('z6Mkofw3hAMb2bbRt6FJ5dUTZwK2z63ySprKQwoosFC8nPMy');
    });

    it('should resolve an individual ES256 key within the DID Document',
      async () => {
        const didJwkDriver = driver();

        const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRod\
W1icHJpbnQ6c2hhLTI1NjpSWGFWZUxpTEltelVxS2pWUExaT1ZrdlUxdGh3YnoyYXZybXkzeVBfTTJ\
nIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2IiwieCI6InF2LW9VSTdKVU5jM\
kNMY3F6RHB5V3lUby1nbGdHV1RfMUtkZEwzd0ViVWsiLCJ5IjoiZmhMdmtPTWVNQ0lSQmZlYmpIdnZ\
HampnemRjRFpHQ2tueUJQSVNKVThfcyJ9`;
        const keyIdFragment = '#0';
        const keyId = `${did}${keyIdFragment}`;
        const key = await didJwkDriver.get({url: keyId});

        expect(key).to.eql({
          '@context': 'https://w3id.org/security/jwk/v1',
          id: keyId,
          type: 'JsonWebKey',
          controller: did,
          publicKeyJwk: {
            kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:RXaVeLiLImzUqKjV\
PLZOVkvU1thwbz2avrmy3yP_M2g`,
            kty: 'EC',
            crv: 'P-256',
            alg: 'ES256',
            x: 'qv-oUI7JUNc2CLcqzDpyWyTo-glgGWT_1KddL3wEbUk',
            y: 'fhLvkOMeMCIRBfebjHvvGjjgzdcDZGCknyBPISJU8_s'
          }
        });
      });

    it('should resolve an individual ECDH key agreement key', async () => {
      const didJwkDriver = driver();

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpOaXpuNmpvRi1UMXQ5X0xtaHdLWDFnbTM1dVRYT2Vac3ZhcFROT3d5SlQ4Iiw\
ia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwieCI6Ii1lY1hyaU\
5BQTJqM0FCTVRqVnJ2TlU4eUNOQXNiTkdZenRRUExtTldjREEiLCJ5IjoiVS1JcEg5ZFFBbFFwcVVFX\
1VVRWtUOHhIS1FhTlduNTBhTFBhNEY2U0d4TSJ9`;
      const keyIdFragment = '#0';
      const kakKeyId = `${did}${keyIdFragment}`;
      const key = await didJwkDriver.get({url: kakKeyId});

      expect(key).to.eql({
        '@context': 'https://w3id.org/security/jwk/v1',
        id: kakKeyId,
        type: 'JsonWebKey',
        controller: did,
        publicKeyJwk: {
          alg: 'ECDH-ES+A256KW',
          crv: 'P-256',
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:Nizn6joF-T1t9_Lmhw\
KX1gm35uTXOeZsvapTNOwyJT8`,
          kty: 'EC',
          x: '-ecXriNAA2j3ABMTjVrvNU8yCNAsbNGYztQPLmNWcDA',
          y: 'U-IpH9dQAlQpqUE_UUEkT8xHKQaNWn50aLPa4F6SGxM'
        }
      });
    });
  });

  describe('get w/verificationMethodType=JsonWebKey2020', () => {
    it('should get the DID Document for an EdDSA did:jwk DID', async () => {
      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYb\
HdJIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaE\
FZS3FJUEs5cm5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({
        did, verificationMethodType: 'JsonWebKey2020'
      });

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      expect(publicKey).to.eql({
        id: keyId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:kirAYu_5chPBalBK4Y\
7u2aLkOS4KauP6AVB185tXlwI`,
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          x: 'iPhAYKqIPK9rng_uedhpXzIC2vOMn8VtGoohdnAVlrA'
        }
      });
    });

    it(`should use EdDSA handler to get the DID Document for an EdDSA did:jwk \
DID`, async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'EdDSA',
        handler: Ed25519Multikey.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYbHdJIiw\
ia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaEFZS3FJUEs5cm\
5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({
        did, verificationMethodType: 'JsonWebKey2020'
      });

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      // convert to multibase
      const keypair = await Ed25519Multikey.from(publicKey);
      const mk = await keypair.export({public: true});
      expect(mk.id).not.to.be.undefined;
      expect(mk.type).not.to.be.undefined;
      expect(mk.controller).not.to.be.undefined;
      expect(mk.id).to.equal(keyId);
      expect(mk.type).to.equal('Multikey');
      expect(mk.controller).to.equal(did);
      expect(mk.publicKeyMultibase).to
        .equal('z6Mkofw3hAMb2bbRt6FJ5dUTZwK2z63ySprKQwoosFC8nPMy');
    });

    it('should get the DID Document for an ES256 did:jwk DID', async () => {
      const didJwkDriver = driver();

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpSWGFWZUxpTEltelVxS2pWUExaT1ZrdlUxdGh3YnoyYXZybXkzeVBfTTJnIiw\
ia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2IiwieCI6InF2LW9VSTdKVU5jMkNMY3\
F6RHB5V3lUby1nbGdHV1RfMUtkZEwzd0ViVWsiLCJ5IjoiZmhMdmtPTWVNQ0lSQmZlYmpIdnZHampne\
mRjRFpHQ2tueUJQSVNKVThfcyJ9`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const keyIdCandidates = [keyId, keyIdFragment];
      const didDocument = await didJwkDriver.get({
        did, verificationMethodType: 'JsonWebKey2020'
      });

      expect(didDocument.id).to.equal(did);
      expect(didDocument['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1'
      ]);
      expect(keyIdCandidates).to.include.members(didDocument.authentication);
      expect(keyIdCandidates).to.include.members(didDocument.assertionMethod);
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityDelegation
      );
      expect(keyIdCandidates).to.include.members(
        didDocument.capabilityInvocation
      );

      const [publicKey] = didDocument.verificationMethod;
      expect(publicKey).to.eql({
        id: keyId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:RXaVeLiLImzUqKjVPL\
ZOVkvU1thwbz2avrmy3yP_M2g`,
          kty: 'EC',
          crv: 'P-256',
          alg: 'ES256',
          x: 'qv-oUI7JUNc2CLcqzDpyWyTo-glgGWT_1KddL3wEbUk',
          y: 'fhLvkOMeMCIRBfebjHvvGjjgzdcDZGCknyBPISJU8_s'
        }
      });
    });

    it('should get the DID Document for an ECDH did:jwk DID with key agreement',
      async () => {
        const didJwkDriver = driver();

        const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW\
1icHJpbnQ6c2hhLTI1NjpOaXpuNmpvRi1UMXQ5X0xtaHdLWDFnbTM1dVRYT2Vac3ZhcFROT3d5SlQ4I\
iwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwieCI6Ii1lY1hy\
aU5BQTJqM0FCTVRqVnJ2TlU4eUNOQXNiTkdZenRRUExtTldjREEiLCJ5IjoiVS1JcEg5ZFFBbFFwcVV\
FX1VVRWtUOHhIS1FhTlduNTBhTFBhNEY2U0d4TSJ9`;
        const keyIdFragment = '#0';
        const keyId = `${did}${keyIdFragment}`;
        const keyIdCandidates = [keyId, keyIdFragment];
        const didDocument = await didJwkDriver.get({
          did, verificationMethodType: 'JsonWebKey2020'
        });

        expect(didDocument.id).to.equal(did);
        expect(didDocument['@context']).to.eql([
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1'
        ]);
        expect(keyIdCandidates).to.include.members(didDocument.keyAgreement);

        const [publicKey] = didDocument.verificationMethod;
        expect(publicKey).to.eql({
          id: keyId,
          type: 'JsonWebKey2020',
          controller: did,
          publicKeyJwk: {
            kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:Nizn6joF-T1t9_Lm\
hwKX1gm35uTXOeZsvapTNOwyJT8`,
            kty: 'EC',
            crv: 'P-256',
            alg: 'ECDH-ES+A256KW',
            x: '-ecXriNAA2j3ABMTjVrvNU8yCNAsbNGYztQPLmNWcDA',
            y: 'U-IpH9dQAlQpqUE_UUEkT8xHKQaNWn50aLPa4F6SGxM'
          }
        });
      });

    it('should resolve an individual EdDSA key within the DID Document',
      async () => {
        const didJwkDriver = driver();

        const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW\
1icHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYbHdJI\
iwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaEFZS3FJUEs5\
cm5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
        const keyIdFragment = '#0';
        const keyId = `${did}${keyIdFragment}`;
        const key = await didJwkDriver.get({
          url: keyId, verificationMethodType: 'JsonWebKey2020'
        });

        expect(key).to.eql({
          '@context': 'https://w3id.org/security/suites/jws-2020/v1',
          id: keyId,
          type: 'JsonWebKey2020',
          controller: did,
          publicKeyJwk: {
            alg: 'EdDSA',
            crv: 'Ed25519',
            kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:kirAYu_5chPBalBK\
4Y7u2aLkOS4KauP6AVB185tXlwI`,
            kty: 'OKP',
            x: 'iPhAYKqIPK9rng_uedhpXzIC2vOMn8VtGoohdnAVlrA'
          }
        });
      });

    it('should use EdDSA handler to resolve an individual EdDSA key within the \
DID Document', async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'EdDSA',
        handler: Ed25519Multikey.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYbHdJIiw\
ia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaEFZS3FJUEs5cm\
5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const key = await didJwkDriver.get({
        url: keyId, verificationMethodType: 'JsonWebKey2020'
      });

      // convert to multibase
      const keypair = await Ed25519Multikey.from(key);
      const mk = await keypair.export({public: true});
      expect(mk.id).not.to.be.undefined;
      expect(mk.type).not.to.be.undefined;
      expect(mk.controller).not.to.be.undefined;
      expect(mk.id).to.equal(keyId);
      expect(mk.type).to.equal('Multikey');
      expect(mk.controller).to.equal(did);
      expect(mk.publicKeyMultibase).to
        .equal('z6Mkofw3hAMb2bbRt6FJ5dUTZwK2z63ySprKQwoosFC8nPMy');
    });

    it('should resolve an individual ES256 key within the DID Document',
      async () => {
        const didJwkDriver = driver();

        const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRod\
W1icHJpbnQ6c2hhLTI1NjpSWGFWZUxpTEltelVxS2pWUExaT1ZrdlUxdGh3YnoyYXZybXkzeVBfTTJ\
nIiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2IiwieCI6InF2LW9VSTdKVU5jM\
kNMY3F6RHB5V3lUby1nbGdHV1RfMUtkZEwzd0ViVWsiLCJ5IjoiZmhMdmtPTWVNQ0lSQmZlYmpIdnZ\
HampnemRjRFpHQ2tueUJQSVNKVThfcyJ9`;
        const keyIdFragment = '#0';
        const keyId = `${did}${keyIdFragment}`;
        const key = await didJwkDriver.get({
          url: keyId, verificationMethodType: 'JsonWebKey2020'
        });

        expect(key).to.eql({
          '@context': 'https://w3id.org/security/suites/jws-2020/v1',
          id: keyId,
          type: 'JsonWebKey2020',
          controller: did,
          publicKeyJwk: {
            kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:RXaVeLiLImzUqKjV\
PLZOVkvU1thwbz2avrmy3yP_M2g`,
            kty: 'EC',
            crv: 'P-256',
            alg: 'ES256',
            x: 'qv-oUI7JUNc2CLcqzDpyWyTo-glgGWT_1KddL3wEbUk',
            y: 'fhLvkOMeMCIRBfebjHvvGjjgzdcDZGCknyBPISJU8_s'
          }
        });
      });

    it('should resolve an individual ECDH key agreement key', async () => {
      const didJwkDriver = driver();

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpOaXpuNmpvRi1UMXQ5X0xtaHdLWDFnbTM1dVRYT2Vac3ZhcFROT3d5SlQ4Iiw\
ia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwieCI6Ii1lY1hyaU\
5BQTJqM0FCTVRqVnJ2TlU4eUNOQXNiTkdZenRRUExtTldjREEiLCJ5IjoiVS1JcEg5ZFFBbFFwcVVFX\
1VVRWtUOHhIS1FhTlduNTBhTFBhNEY2U0d4TSJ9`;
      const keyIdFragment = '#0';
      const kakKeyId = `${did}${keyIdFragment}`;
      const key = await didJwkDriver.get({
        url: kakKeyId, verificationMethodType: 'JsonWebKey2020'
      });

      expect(key).to.eql({
        '@context': 'https://w3id.org/security/suites/jws-2020/v1',
        id: kakKeyId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: {
          alg: 'ECDH-ES+A256KW',
          crv: 'P-256',
          kid: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:Nizn6joF-T1t9_Lmhw\
KX1gm35uTXOeZsvapTNOwyJT8`,
          kty: 'EC',
          x: '-ecXriNAA2j3ABMTjVrvNU8yCNAsbNGYztQPLmNWcDA',
          y: 'U-IpH9dQAlQpqUE_UUEkT8xHKQaNWn50aLPa4F6SGxM'
        }
      });
    });
  });

  describe('method', () => {
    it('should return did method id', async () => {
      const didJwkDriver = driver();

      expect(didJwkDriver.method).to.equal('jwk');
    });
  });
});

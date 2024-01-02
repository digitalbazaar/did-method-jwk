/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import {driver} from '../lib/index.js';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';

chai.should();
const {expect} = chai;

describe('did:jwk method driver', () => {
  describe('get', () => {
    it('should get the DID Document for a EdDSA did:jwk DID', async () => {
      const didJwkDriver = driver();

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
        id: keyIdFragment,
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

    it(`should use EdDSA handler to get the DID Document for a EdDSA did:jwk \
DID`, async () => {
      const didJwkDriver = driver();
      didJwkDriver.use({
        algorithm: 'EdDSA',
        handler: Ed25519VerificationKey2020.from
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
        'https://w3id.org/security/suites/ed25519-2020/v1'
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
      expect(publicKey.id).to.equal(keyIdFragment);
      expect(publicKey.type).to.equal('Ed25519VerificationKey2020');
      expect(publicKey.controller).to.equal(did);
      expect(publicKey.publicKeyMultibase).to
        .equal('z6Mkofw3hAMb2bbRt6FJ5dUTZwK2z63ySprKQwoosFC8nPMy');
    });

    it('should get the DID Document for a ES256 did:jwk DID', async () => {
      const didJwkDriver = driver();

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
        id: keyIdFragment,
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

    it('should get the DID Document for a ECDH did:jwk DID with key agreement',
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
          'https://w3id.org/security/suites/jws-2020/v1'
        ]);
        expect(keyIdCandidates).to.include.members(didDocument.keyAgreement);

        const [publicKey] = didDocument.verificationMethod;
        expect(publicKey).to.eql({
          id: keyIdFragment,
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
        const key = await didJwkDriver.get({did: keyId});

        expect(key).to.eql({
          '@context': 'https://w3id.org/security/suites/jws-2020/v1',
          id: keyIdFragment,
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
        handler: Ed25519VerificationKey2020.from
      });

      const did = `did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i\
cHJpbnQ6c2hhLTI1NjpraXJBWXVfNWNoUEJhbEJLNFk3dTJhTGtPUzRLYXVQNkFWQjE4NXRYbHdJIiw\
ia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6ImlQaEFZS3FJUEs5cm\
5nX3VlZGhwWHpJQzJ2T01uOFZ0R29vaGRuQVZsckEifQ`;
      const keyIdFragment = '#0';
      const keyId = `${did}${keyIdFragment}`;
      const key = await didJwkDriver.get({did: keyId});

      expect(key.id).not.to.be.undefined;
      expect(key.type).not.to.be.undefined;
      expect(key.controller).not.to.be.undefined;
      expect(key.id).to.equal(keyIdFragment);
      expect(key.type).to.equal('Ed25519VerificationKey2020');
      expect(key.controller).to.equal(did);
      expect(key.publicKeyMultibase).to
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
        const key = await didJwkDriver.get({did: keyId});

        expect(key).to.eql({
          '@context': 'https://w3id.org/security/suites/jws-2020/v1',
          id: keyIdFragment,
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
      const key = await didJwkDriver.get({did: kakKeyId});

      expect(key).to.eql({
        '@context': 'https://w3id.org/security/suites/jws-2020/v1',
        id: keyIdFragment,
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

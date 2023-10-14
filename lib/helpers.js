/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
export async function getKeyPair({
  fromJsonWebKey2020, jsonWebKey2020
} = {}) {
  const keyPair = await fromJsonWebKey2020(jsonWebKey2020);
  let keyAgreementKeyPair;
  if(type === 'X25519KeyAgreementKey2020' ||
    type === 'X25519KeyAgreementKey2019') {
    keyAgreementKeyPair = keyPair;
    keyPair = null;
  }
  return {keyPair, keyAgreementKeyPair};
}

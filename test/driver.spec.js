/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import {/*FIXME,*/ driver} from '../lib/index.js';

chai.should();
const {expect} = chai;
const didJwkDriver = driver();

describe('did:jwk method driver', () => {
  // FIXME: copy from did-method-key test

  describe('method', () => {
    it('should return did method id', async () => {
      expect(didJwkDriver.method).to.equal('jwk');
    });
  });
});

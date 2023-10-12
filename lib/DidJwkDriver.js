/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
//import * as didIo from '@digitalbazaar/did-io';

//const DID_CONTEXT_URL = 'https://www.w3.org/ns/did/v1';

export class DidJwkDriver {
  constructor() {
    // used by did-io to register drivers
    this.method = 'jwk';
  }
}

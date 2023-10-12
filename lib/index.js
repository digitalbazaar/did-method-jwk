/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {DidJwkDriver} from './DidJwkDriver.js';

/**
 * Helper method to match the `.driver()` API of other `did-io` plugins.
 *
 * @returns {DidJwkDriver} Returns an instance of a did:jwk resolver driver.
 */
function driver() {
  return new DidJwkDriver();
}

export {driver, DidJwkDriver};

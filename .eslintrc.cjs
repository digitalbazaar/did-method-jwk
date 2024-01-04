/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
module.exports = {
  root: true,
  env: {
    node: true,
    browser: true
  },
  extends: [
    'digitalbazaar',
    'digitalbazaar/jsdoc',
    'digitalbazaar/module'
  ],
  ignorePatterns: ['node_modules/']
};

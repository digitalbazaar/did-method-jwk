# did-method-jwk ChangeLog

## 2.0.0 - 2024-10-02

### Added
- Add support for using newer `JsonWebKey` verification method
  type in resolved DID documents by default. To use the older
  `JsonWebKey2020` type, pass that value as a string using the
  `verificationMethodType` parameter in `.get()`.

### Changed
- **BREAKING**: Simplify exported functions to only include `driver`
  and `DidJwkDriver`. The `DidJwkDriver` instances will only load
  JWKs that can be parsed by registered handlers via `.use()` unless
  no handlers are loaded. In that case, any JSON-parsable JWK will
  be loaded without any attempt to parse the key.
- Only 

### Removed
- The `DidJwkDriver` class has been simplified to only include
  handler registration (`.use()`), resolution (`.get()`), and
  conversion from a JWK (`.fromJwk()`). To generate a new DID
  document from a JWK, call `.fromJwk()` after generating that
  JWK using whatever external tools are desirable.
- Support for non-conformant key relative IDs. Only absolute
  key IDs are used now.
- Support for non-jwk verification method types in the returned
  DID document; now only `JsonWebKey` and `JsonWebKey2020` can
  be used with the expectation that key libraries will be able
  to perform the conversions necessary (if any) from JWK-formatted
  keys to, for example, multikey-formatted keys.
- All dependencies except for `base64url-universal`.

## 1.0.1 - 2024-01-18

### Changed
- Removed patch.

## 1.0.0 - 2024-01-17

### Changed
- Initial release.

- See git history for changes previous to this release.

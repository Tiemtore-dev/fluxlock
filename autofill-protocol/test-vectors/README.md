# Public NIST test fixtures — never production keys

The binary seeds here are deliberately public, deterministic **test data**.
They are never read by production code and must never be used as real keys.

Source: NIST ACVP-Server, commit
`65370b861b96efd30dfe0daae607bde26a78a5c8`, internal projection files:

- [ML-KEM-keyGen-FIPS203](https://github.com/usnistgov/ACVP-Server/blob/65370b861b96efd30dfe0daae607bde26a78a5c8/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json): parameter set ML-KEM-768, `tgId=2`, `tcId=26`. Seed is `d || z` (64 bytes), public key is `ek` (1184 bytes).
- [ML-DSA-keyGen-FIPS204](https://github.com/usnistgov/ACVP-Server/blob/65370b861b96efd30dfe0daae607bde26a78a5c8/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json): parameter set ML-DSA-65, `tgId=2`, `tcId=26`. Seed is `seed` (32 bytes), public key is `pk` (1952 bytes).

Native tests compare the public keys byte for byte. The Node/WASM test also
checks the identity pin against the published ML-DSA key, independently of the
native interoperability peer. These selected vectors are not FIPS certification
or an exhaustive ACVP test campaign.

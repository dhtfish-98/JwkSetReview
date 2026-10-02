# JwkSetReview

Full public-only JWK set structural, semantic, key-material, algorithm and distinct-identity audit for RSA, NIST EC and Ed25519.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. Cryptographic primitives use cryptography; no upstream application is called.

## Contract

Run `jwk-set-review request.json` or pipe JSON to `jwk-set-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- No token claims or trust decision; symmetric/private JWKs, x5c/x5u/jku and additional algorithm families rejected explicitly.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required `jwks.keys` contains only public RSA, NIST EC P-256/P-384/P-521, or OKP Ed25519 keys with distinct nonempty `kid` and declared compatible `alg`. Optional `use` is `sig`; optional `key_ops` must be exactly `verify`. Private/symmetric fields and certificate or remote-key indirection fail closed. RSA strength/exponent policy, canonical base64url integers, native EC on-curve validation, and libsodium Ed25519 canonical prime-subgroup point validation are enforced. PASS describes this key-material profile; `verified=false` means there was no signature, token, ownership, or trust validation.

All accepted Ed25519 public keys are canonical nonidentity points in the main subgroup, checked through libsodium. Ed25519 signature R points must also be canonical nonidentity main-subgroup points and S must be below the group order. Certificates and CRLs require exactly matching inner/outer AlgorithmIdentifiers; the strict profile permits only RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and Ed25519 with absent parameters. OCSP permits the same explicit algorithm encodings and key-family/hash binding.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
jwk-set-review examples/valid.json
```

See [ORIGIN.md](ORIGIN.md), [VALIDATION.md](VALIDATION.md), [LICENSE](LICENSE) and [UPSTREAM_LICENSE](UPSTREAM_LICENSE) for scope, evidence and attribution.

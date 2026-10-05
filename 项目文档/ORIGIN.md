# Origin and implementation scope

The new independent implementation is authored by **dhtfish98** (package version **0.1.4**). Upstream works retain their original attribution and license notices in this document and `UPSTREAM_LICENSE`.

JwkSetReview independently implements this selected scope: Full public-only JWK set structural, semantic, key-material, algorithm and distinct-identity audit for RSA, NIST EC and Ed25519.

The research source is [latchset/jwcrypto](https://github.com/latchset/jwcrypto) at fixed commit `14b32e7cbea50d32551a9490009bf946cec61d38`. Source archive SHA-256: `e8cf7e87217ed6a14f1dcb701739c9f466f2555b075c06c94b93bc6c26cf1e28`. Its license is LGPL-3.0-or-later; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [jwcrypto/jwk.py](https://github.com/latchset/jwcrypto/blob/14b32e7cbea50d32551a9490009bf946cec61d38/jwcrypto/jwk.py) — SHA-256 `2988d909b16245c10e1ae429613a0584180a12a097805fefd950553c79d76d06`.
- [jwcrypto/jwa.py](https://github.com/latchset/jwcrypto/blob/14b32e7cbea50d32551a9490009bf946cec61d38/jwcrypto/jwa.py) — SHA-256 `04329d0cb7b5ae42f8a02e3a94eace0621aa84c9b44b5c139f8f789a4cc7d214`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on JWK public key representation and algorithm registry, public-material fingerprint and EC import behavior. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required `jwks.keys` contains only public RSA, NIST EC P-256/P-384/P-521, or OKP Ed25519 keys with distinct nonempty `kid` and declared compatible `alg`. Optional `use` is `sig`; optional `key_ops` must be exactly `verify`. Private/symmetric fields and certificate or remote-key indirection fail closed. RSA strength/exponent policy, canonical base64url integers, native EC on-curve validation, and libsodium Ed25519 canonical prime-subgroup point validation are enforced. PASS describes this key-material profile; `verified=false` means there was no signature, token, ownership, or trust validation.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.

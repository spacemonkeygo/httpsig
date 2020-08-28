# HTTPSIG for Go

This library implements HTTP request signature generation and verification based on
the RFC draft specification https://tools.ietf.org/html/draft-cavage-http-signatures-06.

The library strives be compatible with the popular python library of the same
name: https://github.com/ahknight/httpsig

## Installing

```
go get gopkg.in/spacemonkeygo/httpsig.v0
```

## Signing Requests

Signing requests is done by constructing a new `Signer`. The key id, key,
algorithm, and what headers to sign are required.

For example to construct a `Signer` with key id `"foo"`, using an RSA private
key, for the hs2019 algorithm and RSA key (PSS), with the default header set, you can do:

```
var key *rsa.PrivateKey = ...
signer := httpsig.NewSigner("foo", key, httpsig.HS1029_PSS, nil)
```

There are helper functions for specific algorithms that are less verbose and
provide more type safety (the key paramater need not be of type `interface{}`
because the type required for the algorithm is known).

```
var key *rsa.PrivateKey = ...
signer := httpsig.NewHS2019PSSSigner("foo", key, nil, rsa.PSSSaltLengthEqualsHash)
```

By default, if no headers are passed to `NewSigner` (or the helpers), the
`(request-target)` pseudo-header and `Date` header are signed.

To sign requests, call the `Sign()` method. The method signs the request and
adds an `Authorization` header containing the signature parameters.

```
err = signer.Sign(req)
if err != nil {
    ...
}
fmt.Println("AUTHORIZATION:", req.Header.Get('Authorization'))

...

AUTHORIZATION: Signature: keyId="foo",algorithm="hs2019",signature="..."

```

## Verifying Requests

Verifying requests is done by constructing a new `Verifier`. The verifier
requires a KeyGetter implementation to look up keys based on `keyId`'s
retrieved from signature parameters.

```
var getter httpsig.KeyGetter = ....
verifier := httpsig.NewVerifier(getter)
```

A request can be verified by calling the `Verify()` method:

```
err = verifier.Verify(req)
```

By default, the verifier only requires the `Date` header to be included
in the signature. The set of required headers be changed using the
`SetRequiredHeaders()` method to enforce stricter requirements.

```
verifier.SetRequiredHeaders([]string{"(request-target)", "host", "date"})
```

Requests that don't include the full set of required headers in the `headers`
signature parameter (either implicity or explicity) will fail verification.

**Note that required headers are simply a specification for which headers must
be included in the signature, and does not enforce header presence in requests.
It is up to callers to validate header contents (or the lack thereof).**

A simple in-memory key store is provided by the library and can be constructed
with the `NewMemoryKeyStore()` function. Keys can be added using the SetKey
method:
```
keystore := NewMemoryKeyStore()

var rsa_key *rsa.PublicKey = ...
keystore.SetKey("foo", rsa_key)

var hmac_key []byte = ...
keystore.SetKey("foo", hmac_key)
```

In order to support hs2019 the keystore also includes a store for the key 
algorithm. Key algorithms can be added using the SetKeyAlgorithm method:
```
keystore.SetKeyAlgorithm("foo", NewHS2019_PSS(rsa.PSSSaltLengthEqualHash))
``` 

## Handler

A convenience function is provided that wraps an `http.Handler` and verifies
incoming request signatures before passing them down to the wrapped handler.

If requires a verifier and optionally a realm (for constructing the
`WWW-Authenticate` header).

```
var handler http.Handler = ...
var verifier *httpsig.Verifier = ...
wrapped := httpsig.RequireSignature(handler, verifier, "example.com")
```

If signature validation fails, a `401` is returned along with a
`WWW-Authenticate` header containing  a `Signature` challenge with optional
`realm` and `headers` parameters.

## Supported algorithms

- hs2019 (using PSS)

### Deprecated algorithms
- rsa-sha1 (using PKCS1v15)
- rsa-sha256 (using PKCS1v15)
- hmac-sha256

### License

Copyright (C) 2017 Space Monkey, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

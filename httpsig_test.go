// Copyright (C) 2017 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The following tests are meant to assert conformance to results in
// Appendix C of the specification are are not exhaustive. Finer grained tests
// can be found elsewhere in the package.

package httpsig

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"
)

var (
	privKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`
)

func TestDate(t *testing.T) {
	test := NewTest(t)

	signer := NewRSASHA256Signer("Test", test.PrivateKey, []string{"date"})
	verifier := NewVerifier(test)

	req := test.NewRequest()
	test.AssertNoError(signer.Sign(req))

	// headers should not be present in the signature params since we specified
	// nil in the constructor. ["Date"] is default header list.
	params := getParamsFromAuthHeader(req)
	test.AssertNotNil(params)
	test.AssertStringsEqual(params.Headers, []string{})

	// Modify the request host, method, and path, and drop all headers but the date
	// and authorization header and assert it still verifies.
	req.Method = "FOO"
	req.Host = "BAR"
	req.URL.Path = "BAZ"
	req.Header = trimHeader(req.Header, "Authorization", "Date")
	test.AssertNoError(verifier.Verify(req))

	// Now modify the date and assert verification fails
	req.Header.Set("Date", "stuff")
	test.AssertAnyError(verifier.Verify(req))
}

func TestRequestTargetAndHost(t *testing.T) {
	test := NewTest(t)

	headers := []string{"(request-target)", "host", "date"}
	signer := NewRSASHA256Signer("Test", test.PrivateKey, headers)
	verifier := NewVerifier(test)

	req := test.NewRequest()
	test.AssertNoError(signer.Sign(req))

	// Make sure the right params exist
	params := getParamsFromAuthHeader(req)
	test.AssertNotNil(params)
	test.AssertStringsEqual(params.Headers, headers)

	// Drop all headers but Date and Authorization
	req.Header = trimHeader(req.Header, "Authorization", "Date")

	// Make sure it verifies.
	test.AssertNoError(verifier.Verify(req))

	// swap the method and see it fail
	orig_method := req.Method
	req.Method = "blah"
	test.AssertAnyError(verifier.Verify(req))
	req.Method = orig_method

	// swap the path and see it fail
	orig_path := req.URL.Path
	req.URL.Path = "blah"
	test.AssertAnyError(verifier.Verify(req))
	req.URL.Path = orig_path

	// swap the host and see it fail
	orig_host := req.Host
	req.Host = "blah"
	test.AssertAnyError(verifier.Verify(req))
	req.Host = orig_host
}

/////////////////////////////////////////////////////////////////////////////
// Helpers
/////////////////////////////////////////////////////////////////////////////

func trimHeader(header http.Header, keepers ...string) http.Header {
	keeper_set := map[string]bool{}
	for _, keeper := range keepers {
		keeper_set[http.CanonicalHeaderKey(keeper)] = true
	}
	for key := range header {
		if keeper_set[http.CanonicalHeaderKey(key)] {
			continue
		}
		delete(header, key)
	}
	return header
}

type Test struct {
	tb testing.TB
	KeyGetter
	PrivateKey *rsa.PrivateKey
}

func NewTest(tb testing.TB) *Test {
	block, _ := pem.Decode([]byte(privKey))
	if block == nil {
		tb.Fatalf("test setup failure: malformed PEM on private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		tb.Fatal(err)
	}

	keystore := NewMemoryKeyStore()
	keystore.SetKey("Test", key)

	return &Test{
		tb:         tb,
		KeyGetter:  keystore,
		PrivateKey: key,
	}
}

func (t *Test) NewRequest() *http.Request {
	req, err := http.NewRequest("POST", "http://example.com/foo",
		strings.NewReader(`{"hello": "world"}`))
	t.AssertNoError(err)
	req.Header.Set("Date", "Thu, 05 Jan 2014 21:31:40 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Digest",
		"SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
	return req
}

func (t *Test) Fatal(msg interface{}) {
	t.tb.Fatalf("\nFATAL:\n%v\nSTACK:\n%s", []interface{}{msg, string(debug.Stack())}...)
}

func (t *Test) Fatalf(format string, args ...interface{}) {
	t.Fatal(fmt.Sprintf(format, args...))
}

func (t *Test) AssertNotNil(v interface{}) {
	if v == nil {
		t.Fatalf("expected nil; got %+v", v)
	}
}

func (t *Test) AssertIntEqual(a, b int) {
	if a != b {
		t.Fatalf("expected %d == %d, but nope", a, b)
	}
}

func (t *Test) AssertStringEqual(a, b string) {
	if a != b {
		t.Fatalf("expected %q == %q, but nope", a, b)
	}
}

func (t *Test) AssertStringsEqual(a, b []string) {
	if a == nil {
		a = []string{}
	}
	if b == nil {
		b = []string{}
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("expected %q == %q, but nope", a, b)
	}
}

func (t *Test) AssertNoError(err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func (t *Test) AssertAnyError(err error) {
	if err == nil {
		t.Fatal("expected error")
	}
}

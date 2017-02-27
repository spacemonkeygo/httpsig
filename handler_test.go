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

package httpsig

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerNoRealm(t *testing.T) {
	test := NewTest(t)

	v := NewVerifier(test)

	counter := new(ServeCounter)

	server := httptest.NewServer(RequireSignature(counter, v, ""))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	test.AssertNoError(err)

	resp, err := http.DefaultClient.Do(req)
	test.AssertNoError(err)
	defer resp.Body.Close()

	test.AssertIntEqual(resp.StatusCode, http.StatusUnauthorized)
	test.AssertStringEqual(resp.Header.Get("WWW-Authenticate"),
		`Signature headers="date"`)
	test.AssertIntEqual(counter.Count, 0)
}

func TestHandlerWithRealm(t *testing.T) {
	test := NewTest(t)

	v := NewVerifier(test)

	counter := new(ServeCounter)

	server := httptest.NewServer(RequireSignature(counter, v, "example.com"))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	test.AssertNoError(err)

	resp, err := http.DefaultClient.Do(req)
	test.AssertNoError(err)
	defer resp.Body.Close()

	test.AssertIntEqual(resp.StatusCode, http.StatusUnauthorized)
	test.AssertStringEqual(resp.Header.Get("WWW-Authenticate"),
		`Signature realm="example.com", headers="date"`)
	test.AssertIntEqual(counter.Count, 0)
}

func TestHandlerRejectsRequestWithoutRequiredHeadersInSignature(t *testing.T) {
	test := NewTest(t)

	v := NewVerifier(test)
	v.SetRequiredHeaders([]string{"(request-target)", "date"})

	counter := new(ServeCounter)

	server := httptest.NewServer(RequireSignature(counter, v, ""))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	test.AssertNoError(err)

	s := NewRSASHA256Signer("Test", test.PrivateKey, []string{"date"})
	test.AssertNoError(s.Sign(req))

	resp, err := http.DefaultClient.Do(req)
	test.AssertNoError(err)
	defer resp.Body.Close()

	test.AssertIntEqual(resp.StatusCode, http.StatusUnauthorized)
	test.AssertStringEqual(resp.Header.Get("WWW-Authenticate"),
		`Signature headers="(request-target) date"`)
	test.AssertIntEqual(counter.Count, 0)
}

func TestHandlerRejectsModifiedRequest(t *testing.T) {
	test := NewTest(t)

	v := NewVerifier(test)
	v.SetRequiredHeaders([]string{"(request-target)", "date"})

	counter := new(ServeCounter)

	server := httptest.NewServer(RequireSignature(counter, v, ""))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	test.AssertNoError(err)

	s := NewRSASHA256Signer("Test", test.PrivateKey, v.RequiredHeaders())
	test.AssertNoError(s.Sign(req))

	req.URL.Path = "/foo"

	resp, err := http.DefaultClient.Do(req)
	test.AssertNoError(err)
	defer resp.Body.Close()

	test.AssertIntEqual(resp.StatusCode, http.StatusUnauthorized)
	test.AssertStringEqual(resp.Header.Get("WWW-Authenticate"),
		`Signature headers="(request-target) date"`)
	test.AssertIntEqual(counter.Count, 0)
}

func TestHandlerAcceptsSignedRequest(t *testing.T) {
	test := NewTest(t)

	v := NewVerifier(test)
	v.SetRequiredHeaders([]string{"(request-target)", "date"})

	counter := new(ServeCounter)

	server := httptest.NewServer(RequireSignature(counter, v, ""))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	test.AssertNoError(err)

	s := NewRSASHA256Signer("Test", test.PrivateKey, v.RequiredHeaders())
	test.AssertNoError(s.Sign(req))

	resp, err := http.DefaultClient.Do(req)
	test.AssertNoError(err)
	defer resp.Body.Close()

	test.AssertIntEqual(resp.StatusCode, http.StatusOK)
	test.AssertStringEqual(resp.Header.Get("WWW-Authenticate"), "")
	test.AssertIntEqual(counter.Count, 1)
}

/////////////////////////////////////////////////////////////////////////////
// Helpers
/////////////////////////////////////////////////////////////////////////////

type ServeCounter struct {
	Count int
}

func (h *ServeCounter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.Count++
}

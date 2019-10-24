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
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"math/big"
)

type ecdsa_signature struct {
	R *big.Int
	S *big.Int
}

// ECDSASHA256 implements ECDSA PKCS1v15 signatures over a SHA256 digest
var ECDSASHA256 Algorithm = ecdsa_sha256{}

type ecdsa_sha256 struct{}

func (ecdsa_sha256) Name() string {
	return "ecdsa-sha256"
}

func (a ecdsa_sha256) Sign(key interface{}, data []byte) ([]byte, error) {
	k := toECDSAPrivateKey(key)
	if k == nil {
		return nil, unsupportedAlgorithm(a)
	}
	return ECDSASign(k, crypto.SHA256, data)
}

func (a ecdsa_sha256) Verify(key interface{}, data, sig []byte) error {
	k := toECDSAPublicKey(key)
	if k == nil {
		return unsupportedAlgorithm(a)
	}
	return ECDSAVerify(k, crypto.SHA256, data, sig)
}

// ECDSASign signs a digest of the data hashed using the provided hash
func ECDSASign(key *ecdsa.PrivateKey, hash crypto.Hash, data []byte) (
	signature []byte, err error) {

	var sig ecdsa_signature

	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}

	sig.R, sig.S, err = ecdsa.Sign(Rand, key, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(sig)
}

// ECDSAVerify verifies a signed digest of the data hashed using the provided hash
func ECDSAVerify(key *ecdsa.PublicKey, hash crypto.Hash, data, sig []byte) (
	err error) {

	var signature ecdsa_signature

	if _, err := asn1.Unmarshal(sig, &signature); err != nil {
		return err
	}

	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	if !ecdsa.Verify(key, h.Sum(nil), signature.R, signature.S) {
		return fmt.Errorf("ecdsa: invalid signature")
	}
	return nil
}

package httpsig

import (
	"crypto"
	"crypto/rsa"
)


// HS2019 implements PSS signatures over a SHA512 digest
var HS2019_PSS Algorithm = hs2019_pss{}

type hs2019_pss struct{}

func (hs2019_pss) Name() string {
	return "hs2019_pss"
}

func (a hs2019_pss) Sign(key interface{}, data []byte) ([]byte, error) {
	k := toRSAPrivateKey(key)
	if k == nil {
		return nil, unsupportedAlgorithm(a)
	}
	return RSASignPSS(k, crypto.SHA512, data)
}

func (a hs2019_pss) Verify(key interface{}, data, sig []byte) error {
	k := toRSAPublicKey(key)
	if k == nil {
		return unsupportedAlgorithm(a)
	}
	return RSAVerifyPSS(k, crypto.SHA512, data, sig)
}

// RSASignPSS signs a digest of the data hashed using the provided hash
func RSASignPSS(key *rsa.PrivateKey, hash crypto.Hash, data []byte) (
	signature []byte, err error) {

	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return rsa.SignPSS(Rand, key, hash, h.Sum(nil), nil)
}

// RSAVerifyPSS verifies a signed digest of the data hashed using the provided hash
func RSAVerifyPSS(key *rsa.PublicKey, hash crypto.Hash, data, sig []byte) (
	err error) {

	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	return rsa.VerifyPSS(key, hash, h.Sum(nil), sig, nil)
}
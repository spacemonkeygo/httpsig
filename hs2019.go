package httpsig

import (
	"crypto"
	"crypto/rsa"
)

// HS2019 implements PSS signatures over a SHA512 digest
var HS2019_PSS Algorithm = hs2019_pss{}

type hs2019_pss struct {
	saltLength int
	hash       crypto.Hash
}

func (hs2019_pss) HS2019_PSS(saltLenght int) *hs2019_pss {
	return &hs2019_pss{
		saltLength: saltLenght,
		hash:       crypto.SHA512,
	}
}

func (hs2019_pss) Name() string {
	return "hs2019"
}

func (a hs2019_pss) Sign(key interface{}, data []byte) ([]byte, error) {
	k := toRSAPrivateKey(key)
	if k == nil {
		return nil, unsupportedAlgorithm(a)
	}

	h := a.hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	opt := &rsa.PSSOptions{SaltLength: a.saltLength}
	return rsa.SignPSS(Rand, k, a.hash, h.Sum(nil), opt)
}

func (a hs2019_pss) Verify(key interface{}, data, sig []byte) error {
	k := toRSAPublicKey(key)
	if k == nil {
		return unsupportedAlgorithm(a)
	}

	h := a.hash.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	opt := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.VerifyPSS(k, a.hash, h.Sum(nil), sig, opt)
}

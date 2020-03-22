package httpsig

import (
	ed "crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEd25519(t *testing.T) {
	pk, sk, err := ed.GenerateKey(nil)
	require.NoError(t, err)

	msg := make([]byte, 4006)
	_, err = io.ReadFull(rand.Reader, msg)
	require.NoError(t, err)

	signature, err := Ed25519Sign(sk, msg)
	require.NoError(t, err)

	err = Ed25519Verify(pk, msg, signature)
	assert.NoError(t, err)
}

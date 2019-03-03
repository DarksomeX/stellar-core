package keys

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stellar/go/xdr"
)

func TestPubKeysEq(t *testing.T) {
	key1 := xdr.Uint256(sha256.Sum256([]byte("HOHOHAHA")))
	key2 := xdr.Uint256(sha256.Sum256([]byte("HOHOHAHA")))

	a := xdr.PublicKey{
		Ed25519: &key1,
	}

	b := xdr.PublicKey{
		Ed25519: &key2,
	}

	assert.True(t, PubKeysEq(a, b))
}

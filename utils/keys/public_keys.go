package keys

import (
	"github.com/stellar/go/xdr"
)

type Slice []xdr.PublicKey

func Eq(a, b xdr.PublicKey) bool {
	return *a.Ed25519 == *b.Ed25519
}

func In(k xdr.PublicKey, keys []xdr.PublicKey) bool {
	for _, key := range keys {
		if Eq(key, k) {
			return true
		}
	}

	return false
}

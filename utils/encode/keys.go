package encode

import (
	"github.com/stellar/go/strkey"
	"github.com/stellar/go/xdr"
)

func AccountID(key xdr.PublicKey) string {
	bytes := [32]byte(*key.Ed25519)
	return strkey.MustEncode(strkey.VersionByteAccountID, bytes[:])
}

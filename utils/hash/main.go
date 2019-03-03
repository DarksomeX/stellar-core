package hash

import (
	"crypto/sha256"

	"github.com/pkg/errors"
	"github.com/stellar/go/xdr"
)

func QuorumSet(qSet *xdr.ScpQuorumSet) [32]byte {
	bytes, err := qSet.MarshalBinary()
	if err != nil {
		panic(errors.Wrap(err, "failed to marshal qSet"))
	}

	return sha256.Sum256(bytes)
}

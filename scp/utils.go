package scp

import (
	"bytes"

	"github.com/stellar/go/xdr"
)

func EnvelopeEq(e1 *xdr.ScpEnvelope, e2 *xdr.ScpEnvelope) bool {
	b1, err := e1.MarshalBinary()
	if err != nil {
		panic("failed to marshal envelope")
	}

	b2, err := e2.MarshalBinary()
	if err != nil {
		panic("failed to marshal envelope")
	}

	return bytes.Compare(b1, b2) == 0
}

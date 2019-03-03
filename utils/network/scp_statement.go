package network

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
	"github.com/stellar/go/hash"
	"github.com/stellar/go/xdr"
)

func HashScpStatement(tx *xdr.ScpStatement, passphraseHash [32]byte) ([32]byte, error) {
	var txBytes bytes.Buffer

	_, err := fmt.Fprintf(&txBytes, "%s", passphraseHash)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "fprint network id failed")
	}

	_, err = xdr.Marshal(&txBytes, xdr.EnvelopeTypeEnvelopeTypeScp)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal type failed")
	}

	_, err = xdr.Marshal(&txBytes, tx)
	if err != nil {
		return [32]byte{}, errors.Wrap(err, "marshal tx failed")
	}

	return hash.Hash(txBytes.Bytes()), nil
}

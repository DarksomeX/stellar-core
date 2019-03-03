package transactions

import "github.com/stellar/go/xdr"

type TransactionFrame struct {
	envelope *xdr.TransactionEnvelope
}

func (t *TransactionFrame) GetEnvelope() *xdr.TransactionEnvelope {
	return t.envelope
}

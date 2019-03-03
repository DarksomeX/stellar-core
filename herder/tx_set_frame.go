package herder

import (
	"github.com/darksomex/stellar-core/transactions"
	"github.com/stellar/go/xdr"
)

type TxSetFrame struct {
	hashIsValid        bool
	hash               xdr.Hash
	previousLedgerHash xdr.Hash

	transactions []*transactions.TransactionFrame
}

func (t *TxSetFrame) ToXDR() *xdr.TransactionSet {
	res := new(xdr.TransactionSet)

	for _, tx := range t.transactions {
		res.Txs = append(res.Txs, *tx.GetEnvelope())
	}

	res.PreviousLedgerHash = t.previousLedgerHash

	return res
}

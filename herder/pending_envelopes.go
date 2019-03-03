package herder

import "github.com/stellar/go/xdr"

type PendingEnvelopes struct {

	// all the txsets we have learned about per ledger#
	TxSetCache map[xdr.Hash]*TxSetFrame
	// all the quorum sets we have learned about
	QSetCache map[xdr.Hash]*xdr.ScpQuorumSet
}

func (pe *PendingEnvelopes) getTxSet(hash *xdr.Hash) *TxSetFrame {
	if frame, ok := pe.TxSetCache[*hash]; ok {
		return frame
	}

	return nil
}

func (pe *PendingEnvelopes) getQSet(hash *xdr.Hash) *xdr.ScpQuorumSet {
	if set, ok := pe.QSetCache[*hash]; ok {
		return set
	}

	return nil
}

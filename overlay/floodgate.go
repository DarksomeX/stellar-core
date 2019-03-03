package overlay

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"github.com/stellar/go/xdr"
)

// FloodGate keeps track of which peers have sent us which broadcast messages,
// in order to ensure that for each broadcast message M and for each peer P, we
// either send M to P once (and only once), or receive M _from_ P (thereby
// inhibit sending M to P at all).
// The broadcast message types are TRANSACTION and SCP_MESSAGE.
// All messages are marked with the ledger sequence number to which they
// relate, and all flood-management information for a given ledger number
// is purged from the FloodGate when the ledger closes.
type FloodGate struct {
	manager *Manager

	shuttingDown bool

	//TODO make this global pointer
	currentLedgerSeq uint32

	floodMap map[xdr.Hash]*floodRecord

	log *logrus.Entry
}

type floodRecord struct {
	ledgerSeq      uint32
	stellarMessage *xdr.StellarMessage
	peersTold      map[*Peer]struct{}
}

func FloodRecord(ledgerseq uint32, msg *xdr.StellarMessage, peer *Peer) *floodRecord {
	rec := &floodRecord{
		ledgerSeq:      ledgerseq,
		stellarMessage: msg,
		peersTold:      make(map[*Peer]struct{}),
	}

	if peer != nil {
		rec.peersTold[peer] = struct{}{}
	}

	return rec
}

func (f *FloodGate) broadcast(msg *xdr.StellarMessage, force bool) {
	if f.shuttingDown {
		return
	}

	bytes, err := msg.MarshalBinary()
	if err != nil {
		panic(errors.Wrap(err, "failed to unmarshal stellar message"))
	}

	hash := sha256.Sum256(bytes)
	f.log.Tracef("broadcasting %s", hex.EncodeToString(hash[:]))

	result, ok := f.floodMap[hash]
	if !ok || force { // no one has sent us this message
		record := FloodRecord(f.currentLedgerSeq, msg, nil)
		f.floodMap[hash] = record
		//f.floodMapSize.SetCount(len(f.floodMap)) //metric

		result = record
	}

	// send it to people that haven't sent it to us
	peersTold := result.peersTold

	// make a copy, in case peers gets modified
	peers := f.manager.authenticatedPeers

	for _, peer := range peers {
		if peer.PeerState != PeerStateGotAuth {
			panic("unathentificated peer!")
		}

		if _, ok := peersTold[peer]; !ok {
			// f.SendFromBroadcast.Mark()
			peer.sendMessage(msg)
			peersTold[peer] = struct{}{}
		}
	}

	f.log.Tracef("broadcast %s told %d", hex.EncodeToString(hash[:]), len(peersTold))
}

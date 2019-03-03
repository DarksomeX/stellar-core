package herder

import (
	"time"

	"github.com/darksomex/stellar-core/db"
	"github.com/darksomex/stellar-core/metrics"
	"github.com/darksomex/stellar-core/overlay"
	"github.com/darksomex/stellar-core/scp"
	"github.com/sirupsen/logrus"
	"github.com/stellar/go/xdr"
)

type Herder struct {
	*SCPDriver

	scp *scp.SCP
	log *logrus.Entry

	// last slot that was persisted into the database
	// only keep track of the most recent slot
	lastSavedSlot uint64

	db *db.DB

	pendingEnvelopes *PendingEnvelopes

	overlayManager *overlay.Manager
}

type SCPState struct {
	envelopes       []*xdr.ScpEnvelope
	transactionSets []*xdr.TransactionSet
	qourumSets      []*xdr.ScpQuorumSet
}

const (
	// ExpectedLedgerTimespan is expected time between two ledger close.
	ExpectedLedgerTimespan = 5 * time.Second
	// MaxSCPTimeout is maximum timeout for SCP consensus.
	MaxSCPTimeout = 240 * time.Second
	// ConsensusStuckTimeout is timeout before considering the node out of sync
	ConsensusStuckTimeout = 35 * time.Second
	//MaxTimeSlip is maximum time slip between nodes.
	MaxTimeSlip = 60 * time.Second
	//NodeExpiration shows how many seconds of inactivity before evicting a node.
	NodeExpiration = 240 * time.Second
	// LedgerValidityBracket should be in the order of
	// how many ledgers can close ahead given ConsensusStuckTimeout
	LedgerValidityBracket = 100
	// MaxSlotsToRemember = 12 give us about a minute to reconnect
	MaxSlotsToRemember = 12
)

type envelopeStatus int

const (
	// EnvelopeStatusDiscarded : for some reason this envelope was discarded - either is was invalid,
	// used unsane qset or was coming from node that is not in quorum
	EnvelopeStatusDiscarded envelopeStatus = iota + 1
	// EnvelopeStatusFetching : envelope data is currently being fetched
	EnvelopeStatusFetching
	// EnvelopeStatusReady : current call to recvSCPEnvelope() was the first when the envelope
	// was fully fetched so it is ready for processing
	EnvelopeStatusReady
	// EnvelopeStatusProcessed : envelope was already processed
	EnvelopeStatusProcessed
)

type State int

const (
	StateSyncing State = iota + 1
	StateTracking
	StateNum
)

type transactionStatus int

const (
	TransactionStatusPending transactionStatus = iota
	TransactionStatusDuplicate
	TransactionStatusError
	TransactionStatusCount
)

type Metrics struct {
	Statements   metrics.Counter
	EnvelopeSign metrics.Meter
}

func (h *Herder) syncMetrics() {
	m := new(Metrics)
	m.Statements.Set(uint64(h.scp.StetementsCount()))
}

func (h *Herder) bootstrap() {
	h.log.Info("force joining SCP with local state")
	if !h.scp.IsValidator {
		h.log.Panic("node is not validator")
	}

}

func (h *Herder) persistSCPState(slotIdx uint64) {
	if slotIdx < h.lastSavedSlot {
		return
	}

	// saves SCP messages and related data (transaction sets, quorum sets)
	latestEnvs := make([]*xdr.ScpEnvelope, 0)
	txSets := make(map[xdr.Hash]*TxSetFrame, 0)
	qourumSets := make(map[xdr.Hash]*xdr.ScpQuorumSet, 0)

	for _, env := range h.SCP.GetLatestMessagesSend(slotIdx) {
		latestEnvs = append(latestEnvs, env)

		// saves transaction sets referred by the statement
		for _, hash := range getTxSetHashes(env) {
			txSet := h.pendingEnvelopes.getTxSet(hash)
			if txSet != nil {
				txSets[*hash] = txSet
			}
		}

		qsHash := scp.GetCompanionQourumSetHashFromStatement(&env.Statement)
		qSet := h.pendingEnvelopes.getQSet(qsHash)
		if qSet != nil {
			qourumSets[*qsHash] = qSet
		}
	}

	latestTxSets := make([]*xdr.TransactionSet, 0, len(txSets))
	for _, set := range txSets {
		latestTxSets = append(latestTxSets, set.ToXDR())
	}

	latestQSets := make([]*xdr.ScpQuorumSet, 0, len(qourumSets))
	for _, q := range qourumSets {
		latestQSets = append(latestQSets, q)
	}

	scpState, err := xdr.MarshalBase64(SCPState{
		latestEnvs,
		latestTxSets,
		latestQSets,
	})
	if err != nil {
		panic("failed to marhal scp state")
	}

	h.db.SetState(db.LastSCPData, scpState)
}

func (h *Herder) emitEnvelope(env *xdr.ScpEnvelope) {
	slotIndex := env.Statement.SlotIndex

	h.log.WithFields(logrus.Fields{
		"statementType": env.Statement.Pledges.Type.String(),
		"slotIndex":     slotIndex,
		//"appState" :
	}).Debug("emitting envelope")

	h.persistSCPState(uint64(slotIndex))
}

func (h *Herder) broadcast(env *xdr.ScpEnvelope) {
	//if !config.ManualClose

	m := new(xdr.StellarMessage)
	m.Type = xdr.MessageTypeScpMessage
	m.Envelope = env

	h.log.WithFields(logrus.Fields{
		"statementType": env.Statement.Pledges.Type.String(),
		"slotIndex":     env.Statement.SlotIndex,
	}).Debug("broadcast")

	//h.metrics.EnvelopeEmit.Mark()
	h.overlayManager.BroadcastMessage(m, true)
}

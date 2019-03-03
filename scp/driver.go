package scp

import (
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
	"github.com/stellar/go/xdr"
)

type ValidationLevel int

const (
	ValidationLevelInvalid ValidationLevel = iota + 1
	ValidationLevelValid
	ValidationLevelMaybe
)

type Driver interface {
	// Envelope signature/verification
	SignEnvelope(*xdr.ScpEnvelope)
	VerifyEnvelope(*xdr.ScpEnvelope) bool

	// Retrieves a quorum set from its hash
	//
	// All SCP statement (see `SCPNomination` and `SCPStatement`) include
	// a quorum set hash.
	// SCP does not define how quorum sets are exchanged between nodes,
	// hence their retrieval is delegated to the user of SCP.
	// The return value is not cached by SCP, as quorum sets are transient.
	//
	// `nil` is a valid return value which cause the statement to be
	// considered invalid.
	GetQSet(xdr.Hash) *xdr.ScpQuorumSet

	// Users of the SCP library should inherit from SCPDriver and implement the
	// virtual methods which are called by the SCP implementation to
	// abstract the transport layer used from the implementation of the SCP
	// protocol.

	// Delegates the emission of an SCPEnvelope to the user of SCP. Envelopes
	// should be flooded to the network.
	EmitEnvelope(*xdr.ScpEnvelope)

	// methods to hand over the validation and ordering of values and ballots.

	// `validateValue` is called on each message received before any processing
	// is done. It should be used to filter out values that are not compatible
	// with the current state of that node. Unvalidated values can never
	// externalize.
	// If the value cannot be validated (node is missing some context) but
	// passes
	// the validity checks, kMaybeValidValue can be returned. This will cause
	// the current slot to be marked as a non validating slot: the local node
	// will abstain from emiting its position.
	// validation can be *more* restrictive during nomination as needed
	ValidateValue(slotIdx uint64, v xdr.Value, nomination bool) ValidationLevel

	// `extractValidValue` transforms the value, if possible to a different
	// value that the local node would agree to (fully validated).
	// This is used during nomination when encountering an invalid value (ie
	// validateValue did not return `kFullyValidatedValue` for this value).
	// returning Value() means no valid value could be extracted
	ExtractValidValue(slotIdx uint64, v xdr.Value) xdr.Value

	// `getValueString` is used for debugging
	// default implementation is the hash of the value
	GetValueString(xdr.Value) string

	// `toShortString` converts to the common name of a key if found
	ToShortString(xdr.PublicKey) string

	// `computeHashNode` is used by the nomination protocol to
	// randomize the order of messages between nodes.
	ComputeHashNode(slotIdx uint64, prev xdr.Value, isPriority bool, roundNum int32, nodeID xdr.PublicKey) uint64

	// `computeValueHash` is used by the nomination protocol to
	// randomize the relative order between values.
	ComputeValueHash(slotIdx uint64, prev xdr.Value, roundNum int32, value xdr.Value) uint64

	// `combineCandidates` computes the composite value based off a list
	// of candidate values.
	CombineCandidates(slotIdx uint64, candidates XDRValueSet) xdr.Value

	// `setupTimer`: requests to trigger 'cb' after timeout
	// if cb is nullptr, the timer is cancelled
	SetupTimer(slotIdx uint64, timerID TimerID, timeout time.Duration, cb func())

	// `computeTimeout` computes a timeout given a round number
	// it should be sufficiently large such that nodes in a
	// quorum can exchange 4 messages
	ComputeTimeout(roundNum uint32) time.Duration

	// Inform about events happening within the consensus algorithm.

	// `valueExternalized` is called at most once per slot when the slot
	// externalize its value.
	ValueExternalized(slotIdx uint64, v xdr.Value)

	// ``nominatingValue`` is called every time the local instance nominates
	// a new value.
	NominatingValue(slotIdx uint64, v xdr.Value)

	// the following methods are used for monitoring of the SCP subsystem
	// most implementation don't really need to do anything with these

	// `updatedCandidateValue` is called every time a new candidate value
	// is included in the candidate set, the value passed in is
	// a composite value
	UpdateCandidateValue(slotIdx uint64, v xdr.Value)

	// `startedBallotProtocol` is called when the ballot protocol is started
	// (ie attempts to prepare a new ballot)
	StartedBallotProtocol(slotIdx uint64, b *xdr.ScpBallot)

	// `acceptedBallotPrepared` every time a ballot is accepted as prepared
	AcceptedBallotPrepared(slotIdx uint64, b *xdr.ScpBallot)

	// `confirmedBallotPrepared` every time a ballot is confirmed prepared
	ConfirmedBallotPrepared(slotIdx uint64, b *xdr.ScpBallot)

	// `acceptedCommit` every time a ballot is accepted commit
	AcceptedCommit(slotIdx uint64, b *xdr.ScpBallot)

	// `ballotDidHearFromQuorum` is called when we received messages related to
	// the current `mBallot` from a set of node that is a transitive quorum for
	// the local node.
	BallotDidHearFromQuorum(slotIdx uint64, b *xdr.ScpBallot)
}

func (s *SCP) StetementsCount() (c int) {
	for _, slot := range s.knownSlots {
		c += slot.StatementsCount()
	}
	return c
}

func getValueString(v xdr.Value) (string, error) {
	bin, err := v.MarshalBinary()
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal xdr value")
	}

	return hex.EncodeToString(bin), nil
}

func toShortString(pub xdr.PublicKey) {

}

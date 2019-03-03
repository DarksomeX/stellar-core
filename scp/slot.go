package scp

import (
	"time"

	"github.com/stellar/go/support/log"
	"github.com/stellar/go/xdr"
)

type TimerID int

const (
	NominationTimer TimerID = iota
	BallotTimer
)

// Slot is in charge of maintaining the state of the SCP protocol
// for a given slot index.
type Slot struct {
	scp *SCP

	index             uint64
	statementsHistory []*HistoricalStatement

	// true if the Slot was fully validated
	fullyValidated bool

	nominationProtocol *NominationProtocol
	ballotProtocol     *BallotProtocol
}

func (s *Slot) LocalNode() *LocalNode {
	return s.scp.LocalNode()
}

func (s *Slot) SetFullyValidated(b bool) {
	s.fullyValidated = b
}

func (s *Slot) FullyValidated() bool {
	return s.fullyValidated
}

func (s *Slot) StopNomination() {
	s.nominationProtocol.StopNomination()
}

// ProcessEnvelope process a newly received envelope for this slot and update the state of
// the slot accordingly.
// self: set to true when node wants to record its own messages (potentially
// triggering more transitions)
func (s *Slot) ProcessEnvelope(env *xdr.ScpEnvelope, self bool) EnvelopeState {
	if uint64(env.Statement.SlotIndex) != s.index {
		panic("statement slot idx doesnt eq to actual")
	}

	log.WithFields(log.F{
		"slotIdx": s.index,
		"env":     EnvelopeToString(env),
	})

	// TODO handle error here
	/*
			auto info = getJsonInfo();
		        CLOG(ERROR, "SCP") << "Exception in processEnvelope "
		                           << "state: " << info.toStyledString()
		                           << " processing envelope: "
		                           << mSCP.envToStr(envelope);

		        throw;
	*/
	if env.Statement.Pledges.Type == xdr.ScpStatementTypeScpStNominate {
		return s.nominationProtocol.ProcessEnvelope(env)
	}

	return s.ballotProtocol.ProcessEnvelope(env, self)
}

func (s *Slot) CreateEnvelope(st *xdr.ScpStatement) *xdr.ScpEnvelope {
	st.NodeId = xdr.NodeId(s.scp.LocalNodeID())
	st.SlotIndex = xdr.Uint64(s.index)

	env := &xdr.ScpEnvelope{
		Statement: *st,
	}

	s.scp.Driver().SignEnvelope(env)

	return env
}

func (s *Slot) SCP() *SCP {
	return s.scp
}

func (s *Slot) Index() uint64 {
	return s.index
}

func (s *Slot) SCPDriver() Driver {
	return s.SCP().Driver()
}

func (s *Slot) BallotProtocol() *BallotProtocol {
	return s.ballotProtocol
}

func (s *Slot) LatestCompositeCandidate() xdr.Value {
	return s.nominationProtocol.LatestCompositeCandidate()
}

func NewSlot(idx uint64, scp *SCP) *Slot {
	slot := &Slot{
		index: idx,
		scp:   scp,
	}

	slot.ballotProtocol = NewBallotProtocol(slot)
	slot.nominationProtocol = NewNominationProtocol(slot)
	slot.fullyValidated = scp.LocalNode().isValidator

	return slot
}

// HistoricalStatement keeps track of all statements seen so far for this slot.
// it is used for debugging purpose
type HistoricalStatement struct {
	time      *time.Time
	statement *xdr.ScpStatement
	validated bool
}

func (s *Slot) StatementsCount() int {
	return len(s.statementsHistory)
}

func (s *Slot) getLatestMessagesSend() (res []*xdr.ScpEnvelope) {
	if s.fullyValidated {
		npm := s.nominationProtocol.getLatestMessageSend()
		if npm != nil {
			res = append(res, npm)
		}

		bpm := s.ballotProtocol.getLatestMessageSend()
		if bpm != nil {
			res = append(res, bpm)
		}
	}
	return res
}

func GetStatementValues(st *xdr.ScpStatement) (res []*xdr.Value) {
	switch st.Pledges.Type {
	case xdr.ScpStatementTypeScpStNominate:
		for _, v := range st.Pledges.Nominate.Votes {
			res = append(res, &v)
		}
		for _, v := range st.Pledges.Nominate.Accepted {
			res = append(res, &v)
		}
	case xdr.ScpStatementTypeScpStPrepare:
		res = append(res, &st.Pledges.Prepare.Ballot.Value)
	case xdr.ScpStatementTypeScpStConfirm:
		res = append(res, &st.Pledges.Confirm.Ballot.Value)
	case xdr.ScpStatementTypeScpStExternalize:
		res = append(res, &st.Pledges.Externalize.Commit.Value)
	default:
		panic("unknown scp statement type")
	}

	return
}

func GetCompanionQourumSetHashFromStatement(st *xdr.ScpStatement) *xdr.Hash {
	switch st.Pledges.Type {
	case xdr.ScpStatementTypeScpStNominate:
		return &st.Pledges.Nominate.QuorumSetHash
	case xdr.ScpStatementTypeScpStPrepare:
		return &st.Pledges.Prepare.QuorumSetHash
	case xdr.ScpStatementTypeScpStConfirm:
		return &st.Pledges.Confirm.QuorumSetHash
	case xdr.ScpStatementTypeScpStExternalize:
		return &st.Pledges.Externalize.CommitQuorumSetHash
	}

	panic("unknown scp statement type")
}

func (s *Slot) BumpState(value xdr.Value, force bool) bool {
	return s.ballotProtocol.BumpState(value, force)
}

func (s *Slot) GetQuorumSetFromStatement(st *xdr.ScpStatement) *xdr.ScpQuorumSet {
	switch st.Pledges.Type {
	case xdr.ScpStatementTypeScpStExternalize:
		return buildSingletonQSet(xdr.PublicKey(st.NodeId))
	case xdr.ScpStatementTypeScpStPrepare:
		h := st.Pledges.Prepare.QuorumSetHash
		return s.SCPDriver().GetQSet(h)
	case xdr.ScpStatementTypeScpStConfirm:
		h := st.Pledges.Confirm.QuorumSetHash
		return s.SCPDriver().GetQSet(h)
	case xdr.ScpStatementTypeScpStNominate:
		h := st.Pledges.Nominate.QuorumSetHash
		return s.SCPDriver().GetQSet(h)
	default:
		panic("unknown scp statement type")
	}
}

func (s *Slot) RecordStatement(st *xdr.ScpStatement) {
	s.statementsHistory = append(s.statementsHistory,
		&HistoricalStatement{
			statement: st,
			validated: s.fullyValidated,
		},
	)
}

func (s *Slot) FederatedAccept(voted, accepted StatementPredicate, env EnvelopeMap) bool {
	// Checks if the nodes that claimed to accept the statement form a
	// v-blocking set
	if isVBlockingF(s.LocalNode().QuorumSet(), env, accepted) {
		return true
	}

	// Checks if the set of nodes that accepted or voted for it form a quorum
	ratifyFilter := func(st *xdr.ScpStatement) bool {
		return accepted(st) || voted(st)
	}

	if IsQuorum(
		s.LocalNode().QuorumSet(), env,
		s.GetQuorumSetFromStatement, ratifyFilter,
	) {
		return true
	}

	return false
}

func (s *Slot) FederatedRatify(voted StatementPredicate, envs EnvelopeMap) bool {
	return IsQuorum(
		s.LocalNode().QuorumSet(), envs,
		s.GetQuorumSetFromStatement, voted,
	)
}

func (s *Slot) getCurrentState() []*xdr.ScpEnvelope {
	return append(
		s.nominationProtocol.getCurrentState(),
		s.ballotProtocol.getCurrentState()...,
	)
}

func (s *Slot) getEntireCurrentState() []*xdr.ScpEnvelope {
	old := s.fullyValidated
	// fake fully validated to force returning all envelopes
	s.fullyValidated = true
	r := s.getCurrentState()
	s.fullyValidated = old
	return r
}

func (s *Slot) SetStateFromEnvelope(e *xdr.ScpEnvelope) {
	if *e.Statement.NodeId.Ed25519 == *s.scp.LocalNodeID().Ed25519 &&
		uint64(e.Statement.SlotIndex) == s.index {
		if e.Statement.Pledges.Type == xdr.ScpStatementTypeScpStNominate {
			s.nominationProtocol.SetStatementFromEnvelope(e)
		} else {
			s.ballotProtocol.SetStatementFromEnvelope(e)
		}
	} else {
		log.Debug("Slot.SetStateFromEnvelope invalid envelope")
	}
}

func (s *Slot) Nominate(value, previousValue xdr.Value, timeout bool) bool {
	return s.nominationProtocol.Nominate(value, previousValue, timeout)
}

func (s *Slot) getLatestCompositeCandidate() xdr.Value {
	return s.nominationProtocol.getLatestCompositeCandidate()
}

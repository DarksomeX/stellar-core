package scp

import (
	"github.com/stellar/go/support/log"
	"github.com/stellar/go/xdr"
)

type EnvelopeState int

const (
	EnvelopeStateInvalid = iota
	EnvelopeStateValid
)

type SCP struct {
	driver Driver

	localNode *LocalNode

	ID          xdr.PublicKey
	IsValidator bool
	knownSlots  map[uint64]*Slot
}

func (s *SCP) Driver() Driver {
	return s.driver
}

func (s *SCP) LocalNode() *LocalNode {
	return s.localNode
}
func (s *SCP) LocalNodeID() xdr.PublicKey {
	return s.localNode.ID()
}

func NewSCP(d Driver, nodeID xdr.PublicKey, isValidator bool, qSetLocal *xdr.ScpQuorumSet) *SCP {
	scp := &SCP{
		driver:     d,
		knownSlots: make(map[uint64]*Slot),
	}

	scp.localNode = NewLocalNode(nodeID, isValidator, qSetLocal, scp)

	return scp
}

func (s *SCP) GetLatestMessagesSend(slotIdx uint64) []*xdr.ScpEnvelope {
	slot := s.getSlot(slotIdx, false)
	if slot != nil {
		slot.getLatestMessagesSend()
	}

	return nil
}

func (s *SCP) getSlot(slotIdx uint64, create bool) *Slot {
	slot, ok := s.knownSlots[slotIdx]
	if ok {
		return slot
	}

	if create {
		slot = NewSlot(slotIdx, s)
		s.knownSlots[slotIdx] = slot
	}

	return slot
}

func (s *SCP) ReceiveEnvelope(env *xdr.ScpEnvelope) EnvelopeState {
	if !s.driver.VerifyEnvelope(env) {
		log.Debug("SCP::receiveEnvelope invalid")
		return EnvelopeStateInvalid
	}

	slotIdx := env.Statement.SlotIndex
	return s.getSlot(uint64(slotIdx), true).ProcessEnvelope(env, false)
}

func (s *SCP) SetStateFromEnvelope(slotIndex uint64, e *xdr.ScpEnvelope) {
	if s.driver.VerifyEnvelope(e) {
		slot := s.getSlot(slotIndex, true)
		slot.SetStateFromEnvelope(e)
	}
}

func EnvelopeToString(env *xdr.ScpEnvelope) string {
	return StatementToString(&env.Statement)
}

func StatementToString(st *xdr.ScpStatement) string {
	//TODO implement
	return ""
}

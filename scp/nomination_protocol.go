package scp

import (
	"bytes"
	"math"
	"sort"

	"github.com/stellar/go/support/log"
	"github.com/stellar/go/xdr"
)

type XDRValueSet []xdr.Value

func (s *XDRValueSet) Put(v xdr.Value) bool {
	for _, value := range []xdr.Value(*s) {
		if bytes.Compare(value, v) == 0 {
			return false
		}
	}

	*s = append([]xdr.Value(*s), v)
	return true
}

func (s *XDRValueSet) Contains(v xdr.Value) bool {
	for _, value := range []xdr.Value(*s) {
		if bytes.Compare(value, v) == 0 {
			return true
		}
	}

	return false
}

type PublicKeySet map[[32]byte]struct{}

func (m *PublicKeySet) Get(key xdr.PublicKey) bool {
	_, ok := map[[32]byte]struct{}(*m)[*key.Ed25519]
	return ok
}

func (m *PublicKeySet) Set(key xdr.PublicKey) bool {
	_, ok := map[[32]byte]struct{}(*m)[*key.Ed25519]
	if ok {
		return false
	}

	map[[32]byte]struct{}(*m)[*key.Ed25519] = struct{}{}
	return true
}

type NominationProtocol struct {
	slot *Slot

	roundNumber       int32
	votes             XDRValueSet // X
	accepted          XDRValueSet // Y
	candidates        XDRValueSet // Z
	latestNominations EnvelopeMap // N

	lastEnvelope *xdr.ScpEnvelope // last envelope emitted by this node

	// nodes from quorum set that have the highest priority this round
	roundLeaders PublicKeySet

	// true if 'nominate' was called
	nominationStarted bool

	// the latest (if any) candidate value
	latestCompositeCandidate xdr.Value

	// the value from the previous slot
	previousValue xdr.Value
}

func NewNominationProtocol(slot *Slot) *NominationProtocol {
	return &NominationProtocol{
		slot:              slot,
		roundNumber:       0,
		nominationStarted: false,
		roundLeaders:      make(PublicKeySet),
	}
}

func (n *NominationProtocol) LatestCompositeCandidate() xdr.Value {
	return n.latestCompositeCandidate
}

func (n *NominationProtocol) IsNewerStatement(nodeID xdr.PublicKey, st *xdr.ScpNomination) bool {
	oldp := n.latestNominations.Get(nodeID)

	if oldp == nil {
		return true
	}

	return n.IsNewerStatementD(oldp.Statement.Pledges.Nominate, st)
}

func (n *NominationProtocol) IsNewerStatementD(oldst *xdr.ScpNomination, st *xdr.ScpNomination) bool {
	g := false
	if !n.IsSubsetHelper(oldst.Votes, st.Votes, &g) {
		return false
	}

	grows := g
	if !n.IsSubsetHelper(oldst.Accepted, st.Accepted, &g) {
		return false
	}

	return grows || g // true only if one of the sets grew
}

func (n *NominationProtocol) IsSubsetHelper(p []xdr.Value, v []xdr.Value, notEq *bool) bool {
	if len(p) > len(v) {
		*notEq = true
		return false
	}

	sort.Slice(p, func(i, j int) bool {
		return bytes.Compare(p[i], p[j]) < 0
	})
	sort.Slice(v, func(i, j int) bool {
		return bytes.Compare(v[i], v[j]) < 0
	})

	find := func(val xdr.Value) bool {
		for _, vv := range v {
			if bytes.Equal(vv, val) {
				return true
			}
		}
		return false
	}

	for i := range p {
		if !find(p[i]) {
			*notEq = true
			return false
		}
	}

	*notEq = len(p) != len(v)
	return true
}

func (n *NominationProtocol) IsSane(st *xdr.ScpStatement) bool {
	nom := st.Pledges.Nominate
	if len(nom.Votes)+len(nom.Accepted) == 0 {
		return false
	}

	for i := 0; i < len(nom.Votes)-1; i++ {
		if len(nom.Votes[i]) >= len(nom.Votes[i+1]) {
			return false
		}
	}

	for i := 0; i < len(nom.Accepted)-1; i++ {
		if len(nom.Accepted[i]) >= len(nom.Accepted[i+1]) {
			return false
		}
	}

	return true
}

// RecordEnvelope only called after a call to isNewerStatement so safe to replace the
// mLatestNomination
func (n *NominationProtocol) RecordEnvelope(env *xdr.ScpEnvelope) {
	n.latestNominations.Put(xdr.PublicKey(env.Statement.NodeId), env)

	/*st := env.Statement
	oldp := n.latestNominations.Get(xdr.PublicKey(st.NodeId))
	if oldp == nil {
		n.latestNominations.Put(xdr.PublicKey(st.NodeId), env)
	} else {
		*oldp = *env
	}*/

	n.slot.RecordStatement(&env.Statement)
}

func (n *NominationProtocol) AcceptPredicate(v xdr.Value, st *xdr.ScpStatement) bool {
	for _, value := range st.Pledges.Nominate.Accepted {
		if bytes.Compare(value, v) == 0 {
			return true
		}
	}

	return false
}

func (n *NominationProtocol) ValidateValue(v xdr.Value) ValidationLevel {
	return n.slot.SCPDriver().ValidateValue(n.slot.Index(), v, true)
}

func (n *NominationProtocol) ExtractValidValue(v xdr.Value) xdr.Value {
	return n.slot.SCPDriver().ExtractValidValue(n.slot.Index(), v)
}

func (n *NominationProtocol) HashValue(v xdr.Value) uint64 {
	return n.slot.SCPDriver().ComputeValueHash(
		n.slot.Index(), n.previousValue, n.roundNumber, v,
	)
}

func (n *NominationProtocol) NewValueFromNomination(nom *xdr.ScpNomination) xdr.Value {
	newVote := xdr.Value(nil)
	var newHash uint64

	// pick the highest value we don't have from the leader
	// sorted using hashValue.
	n.ApplyAll(
		nom,
		func(v xdr.Value) {
			var valueToNominate xdr.Value
			if n.ValidateValue(v) == ValidationLevelValid {
				valueToNominate = v
			} else {
				valueToNominate = n.ExtractValidValue(v)
			}

			if valueToNominate == nil {
				return
			}

			if n.votes.Contains(valueToNominate) {
				return
			}

			curHash := n.HashValue(v)
			if curHash >= newHash {
				newHash = curHash
				newVote = valueToNominate
			}

		},
	)

	return newVote
}

func (n *NominationProtocol) ApplyAll(nom *xdr.ScpNomination, processor func(xdr.Value)) {
	for _, v := range nom.Votes {
		processor(v)
	}
	for _, a := range nom.Accepted {
		processor(a)
	}
}

func (n *NominationProtocol) EmitNomination() {
	st := xdr.ScpStatement{
		NodeId: xdr.NodeId(n.slot.LocalNode().ID()),
		Pledges: xdr.ScpStatementPledges{
			Type: xdr.ScpStatementTypeScpStNominate,
			Nominate: &xdr.ScpNomination{
				QuorumSetHash: n.slot.LocalNode().QuorumSetHash(),
			},
		},
	}

	for _, v := range n.votes {
		st.Pledges.Nominate.Votes = append(
			st.Pledges.Nominate.Votes, v,
		)
	}

	for _, a := range n.accepted {
		st.Pledges.Nominate.Accepted = append(
			st.Pledges.Nominate.Accepted, a,
		)
	}

	env := n.slot.CreateEnvelope(&st)
	if n.slot.ProcessEnvelope(env, true) != EnvelopeStateValid {
		// there is a bug in the application if it queued up
		// a statement for itself that it considers invalid
		panic("moved to a bad state (nomination)")
	}

	if n.lastEnvelope == nil || n.IsNewerStatementD(
		n.lastEnvelope.Statement.Pledges.Nominate,
		st.Pledges.Nominate,
	) {
		n.lastEnvelope = env
		if n.slot.FullyValidated() {
			n.slot.SCPDriver().EmitEnvelope(env)
		}
	}
}

func (n *NominationProtocol) ProcessEnvelope(env *xdr.ScpEnvelope) EnvelopeState {
	st := env.Statement
	nom := st.Pledges.Nominate

	if !n.IsNewerStatement(xdr.PublicKey(st.NodeId), nom) {
		return EnvelopeStateInvalid
	}

	if !n.IsSane(&st) {
		log.Debug("NominationProtocol: message didn't pass sanity check")
	}

	n.RecordEnvelope(env)

	if !n.nominationStarted {
		return EnvelopeStateValid
	}

	modified := false // tracks if we should emit a new nomination message
	newCandidates := false

	// attempts to promote some of the votes to accepted

votes:
	for _, v := range nom.Votes {
		for _, a := range n.accepted {
			if bytes.Equal(a, v) {
				continue votes // v is already accepted
			}
		}

		if n.slot.FederatedAccept(
			func(st *xdr.ScpStatement) bool {
				nom := st.Pledges.Nominate
				for _, vote := range nom.Votes {
					if bytes.Equal(v, vote) {
						return true
					}
				}
				return false
			},
			func(st *xdr.ScpStatement) bool {
				return n.AcceptPredicate(v, st)
			},
			n.latestNominations,
		) {
			vl := n.ValidateValue(v)
			if vl == ValidationLevelValid {
				n.accepted.Put(v)
				n.votes.Put(v)
				modified = true
			} else {
				// the value made it pretty far:
				// see if we can vote for a variation that
				// we consider valid
				toVote := n.ExtractValidValue(v)
				if toVote != nil {
					if ok := n.votes.Put(toVote); ok {
						modified = true
					}
				}

			}
		}
	}

	// attempts to promote accepted values to candidates
	for _, a := range n.accepted {
		if n.candidates.Contains(a) {
			continue
		}

		if n.slot.FederatedRatify(
			func(st *xdr.ScpStatement) bool {
				return n.AcceptPredicate(a, st)
			},
			n.latestNominations,
		) {
			n.candidates.Put(a)
			newCandidates = true
		}
	}

	// only take round leader votes if we're still looking for
	// candidates
	if len(n.candidates) == 0 && n.roundLeaders.Get(xdr.PublicKey(st.NodeId)) {
		newVote := n.NewValueFromNomination(nom)
		if newVote != nil {
			n.votes.Put(newVote)
			modified = true
			n.slot.SCPDriver().NominatingValue(
				n.slot.Index(), newVote,
			)
		}
	}

	if modified {
		n.EmitNomination()
	}

	if newCandidates {
		n.latestCompositeCandidate = n.slot.SCPDriver().CombineCandidates(
			n.slot.Index(), n.candidates,
		)

		n.slot.SCPDriver().UpdateCandidateValue(
			n.slot.Index(), n.latestCompositeCandidate,
		)

		n.slot.BumpState(n.latestCompositeCandidate, false)
	}

	return EnvelopeStateValid
}

func (n *NominationProtocol) getLatestMessageSend() *xdr.ScpEnvelope {
	return n.lastEnvelope
}

func (n *NominationProtocol) StopNomination() {
	n.nominationStarted = false
}

func (n *NominationProtocol) getCurrentState() (res []*xdr.ScpEnvelope) {
	for _, e := range n.latestNominations {
		// only return messages for self if the slot is fully validated
		if !(*e.Statement.NodeId.Ed25519 == *n.slot.scp.LocalNodeID().Ed25519) ||
			n.slot.fullyValidated {
			res = append(res, e)
		}
	}
	return res
}

func (n *NominationProtocol) SetStatementFromEnvelope(e *xdr.ScpEnvelope) {
	if n.nominationStarted {
		panic("Cannot set state after nomination is started")
	}

	n.RecordEnvelope(e)
	nom := e.Statement.Pledges.MustNominate()
	for _, v := range nom.Accepted {
		n.accepted.Put(v)
	}
	for _, v := range nom.Votes {
		n.votes.Put(v)
	}

	n.lastEnvelope = e
}

func (n *NominationProtocol) hashNode(isPriority bool, nodeID xdr.NodeId) uint64 {
	return n.slot.SCPDriver().ComputeHashNode(
		n.slot.Index(), n.previousValue, isPriority, n.roundNumber, xdr.PublicKey(nodeID),
	)
}

func (n *NominationProtocol) getNodePriority(nodeID xdr.NodeId, qSet *xdr.ScpQuorumSet) uint64 {
	var res, w uint64

	if *nodeID.Ed25519 == *n.slot.LocalNode().ID().Ed25519 {
		// local node is in all quorum sets
		w = math.MaxUint64
	} else {
		w = getNodeWeight(nodeID, qSet)
	}

	if n.hashNode(false, nodeID) < w {
		res = n.hashNode(true, nodeID)
	} else {
		res = 0
	}

	return res
}

func (n *NominationProtocol) updateRoundLeaders() {
	QSet := n.slot.LocalNode().QuorumSet()
	copyQSet := xdr.ScpQuorumSet{
		Threshold:  QSet.Threshold,
		Validators: append([]xdr.PublicKey{}, QSet.Validators...),
		InnerSets:  append([]xdr.ScpQuorumSet{}, QSet.InnerSets...),
	}

	// initialize priority with value derived from self
	n.roundLeaders = make(PublicKeySet)
	localID := xdr.NodeId(n.slot.LocalNode().id)
	normalizeQSet(&copyQSet, &localID)

	n.roundLeaders.Set(xdr.PublicKey(localID))
	topPriority := n.getNodePriority(localID, &copyQSet)

	forAllNodes(&copyQSet, func(cur xdr.NodeId) {
		w := n.getNodePriority(cur, &copyQSet)
		if w > topPriority {
			topPriority = w
			n.roundLeaders = make(PublicKeySet)
		}
		if w == topPriority && w > 0 {
			n.roundLeaders.Set(xdr.PublicKey(cur))
		}
	})

	//log.Debug("updateRoundLeaders")
}

func (n *NominationProtocol) getNewValueFromNomination(nom *xdr.ScpNomination) xdr.Value {
	// pick the highest value we don't have from the leader
	// sorted using hashValue.
	var newVote xdr.Value
	newHash := uint64(0)

	n.ApplyAll(nom, func(value xdr.Value) {
		var valueToNominate xdr.Value
		vl := n.ValidateValue(value)
		if vl == ValidationLevelValid {
			valueToNominate = value
		} else {
			valueToNominate = n.ExtractValidValue(value)
		}

		if valueToNominate != nil {
			if !n.votes.Contains(valueToNominate) {
				curHash := n.HashValue(valueToNominate)
				if curHash >= newHash {
					newHash = curHash
					newVote = valueToNominate
				}
			}
		}
	})

	return newVote
}

// attempts to nominate a value for consensus
func (n *NominationProtocol) Nominate(value, previousValue xdr.Value, timedout bool) bool {
	updated := false

	if timedout && !n.nominationStarted {
		log.Debug("nominate: timed out")
		return false
	}

	n.nominationStarted = true
	n.previousValue = previousValue

	n.roundNumber++
	n.updateRoundLeaders()

	var nominatingValue xdr.Value

	if n.roundLeaders.Get(n.slot.LocalNode().ID()) {
		if n.votes.Put(value) {
			updated = true
		}
		nominatingValue = value
	} else {
		for leader := range n.roundLeaders {
			uint256 := xdr.Uint256(leader)
			pk := xdr.PublicKey{
				Ed25519: &uint256,
			}
			if l := n.latestNominations.Get(pk); l != nil {
				nominatingValue = n.getNewValueFromNomination(l.Statement.Pledges.Nominate)
				if nominatingValue != nil {
					n.votes.Put(nominatingValue)
					updated = true
				}
			}
		}
	}

	timeout := n.slot.SCPDriver().ComputeTimeout(uint32(n.roundNumber))
	n.slot.SCPDriver().NominatingValue(n.slot.Index(), nominatingValue)

	slot := n.slot
	n.slot.SCPDriver().SetupTimer(
		n.slot.Index(), NominationTimer, timeout,
		func() {
			slot.Nominate(value, previousValue, true)
		},
	)

	if updated {
		n.EmitNomination()
	} else {
		log.Debug("nominate: skipped")
	}

	return updated
}

func (n *NominationProtocol) getLatestCompositeCandidate() xdr.Value {
	return n.latestCompositeCandidate
}

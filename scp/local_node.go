package scp

import (
	"encoding/hex"
	"math"
	"sort"

	"github.com/darksomex/stellar-core/utils/encode"
	"github.com/darksomex/stellar-core/utils/hash"
	"github.com/darksomex/stellar-core/utils/keys"
	"github.com/sirupsen/logrus"

	"github.com/stellar/go/support/log"
	"github.com/stellar/go/xdr"
)

// LocalNode This is one Node in the stellar network
type LocalNode struct {
	id          xdr.PublicKey
	isValidator bool
	qSet        *xdr.ScpQuorumSet
	qSetHash    xdr.Hash

	// alternative qset used during externalize {{mNodeID}}
	singleQSetHash xdr.Hash          // hash of the singleton qset
	singleQSet     *xdr.ScpQuorumSet // {{mNodeID}}

	scp *SCP
}

func (l *LocalNode) ID() xdr.PublicKey {
	return l.id
}

func (l *LocalNode) QuorumSetHash() xdr.Hash {
	return l.qSetHash
}

func NewLocalNode(nodeID xdr.PublicKey, isValidator bool, qSet *xdr.ScpQuorumSet, scp *SCP) *LocalNode {
	normalizeQSet(qSet, nil)
	qSetHash := hash.QuorumSet(qSet)

	log.WithFields(log.F{
		"localNode": encode.AccountID(nodeID),
		"qSet":      hex.EncodeToString(qSetHash[:]),
	})

	singleQSet := buildSingletonQSet(nodeID)
	return &LocalNode{
		id:             nodeID,
		isValidator:    isValidator,
		qSet:           qSet,
		qSetHash:       qSetHash,
		singleQSet:     singleQSet,
		singleQSetHash: hash.QuorumSet(singleQSet),
	}
}

// if a validator is repeated multiple times its weight is only the
// weight of the first occurrence
func getNodeWeight(nodeID xdr.NodeId, qSet *xdr.ScpQuorumSet) uint64 {
	n := uint64(qSet.Threshold)
	d := uint64(len(qSet.InnerSets) + len(qSet.Validators))
	nodePublic := xdr.PublicKey(nodeID)
	max := uint64(math.MaxUint64)

	for _, qSetNode := range qSet.Validators {
		if nodePublic == qSetNode {
			return max/d*n + (d-1)/d
		}
	}

	for _, q := range qSet.InnerSets {
		leafW := getNodeWeight(nodeID, &q)
		if leafW != 0 {
			return leafW/d*n + (d-1)/d
		}
	}

	return 0
}

func isQourumSlice(qSet *xdr.ScpQuorumSet, nodeSet []xdr.PublicKey) bool {
	logrus.Tracef("isQourumSlice: len(nodeSet): %d", len(nodeSet))
	return isQourumSliceInternal(qSet, nodeSet)
}

func isQourumSliceInternal(qSet *xdr.ScpQuorumSet, nodeSet []xdr.PublicKey) bool {
	thresholdLeft := qSet.Threshold
	for _, validator := range qSet.Validators {
		if keys.In(validator, nodeSet) {
			thresholdLeft--
			if thresholdLeft <= 0 {
				return true
			}
		}
	}

	for _, inner := range qSet.InnerSets {
		if isQourumSliceInternal(&inner, nodeSet) {
			thresholdLeft--
			if thresholdLeft <= 0 {
				return true
			}
		}
	}

	return false
}

func isVBlocking(qSet *xdr.ScpQuorumSet, nodeSet []xdr.PublicKey) bool {
	logrus.Tracef("isVBlocking: len(nodeSet): %d", len(nodeSet))
	return isVBlockingInternal(qSet, nodeSet)
}

func isVBlockingF(qSet *xdr.ScpQuorumSet, m EnvelopeMap, filter StatementPredicate) bool {
	nodes := make([]xdr.PublicKey, 0)
	for _, env := range m {
		if filter(&env.Statement) {
			nodes = append(nodes,
				xdr.PublicKey(env.Statement.NodeId),
			)
		}
	}

	return isVBlocking(qSet, nodes)
}

func isVBlockingInternal(qSet *xdr.ScpQuorumSet, nodeSet []xdr.PublicKey) bool {
	// There is no v-blocking set for {\empty}
	if qSet.Threshold == 0 {
		return false
	}

	leftTillBlock := 1 + len(qSet.Validators) + len(qSet.InnerSets) - int(qSet.Threshold)

	for _, validator := range qSet.Validators {
		if keys.In(validator, nodeSet) {
			leftTillBlock--
			if leftTillBlock <= 0 {
				return true
			}
		}
	}

	for _, inner := range qSet.InnerSets {
		if isVBlockingInternal(&inner, nodeSet) {
			leftTillBlock--
			if leftTillBlock <= 0 {
				return true
			}
		}
	}

	return false
}

func findClosestVBlocking(qSet *xdr.ScpQuorumSet, nodes []xdr.PublicKey, excluded *xdr.PublicKey) []xdr.PublicKey {
	leftTillBlock := 1 + len(qSet.Validators) + len(qSet.InnerSets) - int(qSet.Threshold)

	res := make([]xdr.PublicKey, 0)

	// first, compute how many top level items need to be blocked
	for _, validator := range qSet.Validators {
		if excluded == nil || !keys.Eq(validator, *excluded) {
			if !keys.In(validator, nodes) {
				leftTillBlock--
				if leftTillBlock == 0 {
					// already blocked
					return nil
				}
			}
			// save this for later
			res = append(res, validator)
		}
	}

	var resInternals [][]xdr.PublicKey

	for _, inner := range qSet.InnerSets {
		v := findClosestVBlocking(&inner, nodes, excluded)
		if len(v) == 0 {
			leftTillBlock--
			if leftTillBlock == 0 {
				//already blocked
				return nil
			}
		} else {
			resInternals = append(resInternals, v)
		}

	}

	// use the top level validators to get closer
	if len(res) > leftTillBlock {
		res = res[:leftTillBlock]
	}
	leftTillBlock -= len(res)

	sort.Slice(resInternals, func(i int, j int) bool {
		return len(resInternals[i]) < len(resInternals[j])
	})

	// use subsets to get closer, using the smallest ones first
	for _, r := range resInternals {
		if leftTillBlock == 0 {
			break
		}

		res = append(res, r...)
		leftTillBlock--
	}

	return res
}

func buildSingletonQSet(nodeID xdr.PublicKey) *xdr.ScpQuorumSet {
	return &xdr.ScpQuorumSet{
		Threshold:  1,
		Validators: []xdr.PublicKey{nodeID},
	}
}

func (l *LocalNode) QuorumSet() *xdr.ScpQuorumSet {
	return l.qSet
}

func IsQuorum(qSet *xdr.ScpQuorumSet, m EnvelopeMap,
	qfun func(*xdr.ScpStatement) *xdr.ScpQuorumSet, filter func(*xdr.ScpStatement) bool) bool {

	nodes := make([]xdr.PublicKey, 0)
	for _, env := range m {
		if filter(&env.Statement) {
			nodes = append(nodes,
				xdr.PublicKey(env.Statement.NodeId),
			)
		}
	}

	count := 0
	for {
		count = len(nodes)
		fnodes := make([]xdr.PublicKey, 0, count)
		quorumFilter := func(nodeID xdr.PublicKey) bool {
			qSet := qfun(&m.Get(nodeID).Statement)
			if qSet == nil {
				return false
			}
			return isQourumSlice(qSet, nodes)
		}

		for _, node := range nodes {
			if quorumFilter(node) {
				fnodes = append(fnodes, node)
			}
		}

		nodes = fnodes

		if count == len(nodes) {
			break
		}
	}

	return isQourumSlice(qSet, nodes)
}

func forAllNodesInternal(qSet *xdr.ScpQuorumSet, proc func(xdr.NodeId)) {
	for _, n := range qSet.Validators {
		proc(xdr.NodeId(n))
	}
	for _, q := range qSet.InnerSets {
		forAllNodesInternal(&q, proc)
	}
}

func forAllNodes(qSet *xdr.ScpQuorumSet, proc func(xdr.NodeId)) {
	done := make(map[xdr.Uint256]struct{})
	forAllNodesInternal(qSet, func(n xdr.NodeId) {
		_, ok := done[*n.Ed25519]
		if !ok {
			proc(n)
			done[*n.Ed25519] = struct{}{}
		}
	})
}

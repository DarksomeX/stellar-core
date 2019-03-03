package scp

import (
	"github.com/stellar/go/xdr"
)

type qourumSetSanityChecker struct {
	extraChecks bool
	knownNodes  PublicKeySet
	isSane      bool
	count       int
}

func QourumSetSanityChecker(qSet *xdr.ScpQuorumSet, extraChecks bool) *qourumSetSanityChecker {
	checker := new(qourumSetSanityChecker)
	checker.knownNodes = make(PublicKeySet)

	checker.isSane = checker.checkSanity(qSet, 0) &&
		checker.count >= 1 &&
		checker.count <= 1000

	return checker
}

func isQuorumSetSane(qSet *xdr.ScpQuorumSet, extraChecks bool) bool {
	checker := QourumSetSanityChecker(qSet, extraChecks)
	return checker.isSane
}

func (q *qourumSetSanityChecker) checkSanity(qSet *xdr.ScpQuorumSet, depth int) bool {
	if depth > 2 {
		return false
	}

	if qSet.Threshold < 1 {
		return false
	}

	v := qSet.Validators
	i := qSet.InnerSets

	totalEntries := len(v) + len(i)
	blockingSize := totalEntries - int(qSet.Threshold) + 1

	q.count += len(v)

	if int(qSet.Threshold) > totalEntries {
		return false
	}

	// threshold is within the proper range
	if q.extraChecks && int(qSet.Threshold) < blockingSize {
		return false
	}

	for _, validator := range v {
		ok := q.knownNodes.Get(xdr.PublicKey(validator))
		if ok {
			// n was already present
			return false
		}

		q.knownNodes.Set(xdr.PublicKey(validator))
	}

	for _, innerSet := range i {
		if !q.checkSanity(&innerSet, depth+1) {
			return false
		}
	}

	return true
}

// helper function that:
//  * removes nodeID
//      { t: n, v: { ...BEFORE... , nodeID, ...AFTER... }, ...}
//      { t: n-1, v: { ...BEFORE..., ...AFTER...} , ... }
//  * simplifies singleton inner set into outerset
//      { t: n, v: { ... }, { t: 1, X }, ... }
//        into
//      { t: n, v: { ..., X }, .... }
//  * simplifies singleton innersets
//      { t:1, { innerSet } } into innerSet
func normalizeQSet(qSet *xdr.ScpQuorumSet, idToRemove *xdr.NodeId) {
	if idToRemove != nil {
		remove := xdr.PublicKey(*idToRemove)

		var found bool
		var index int
		for i, pub := range qSet.Validators {
			if pub == remove {
				found = true
				index = i
			}
		}

		if found {
			qSet.Validators = append(qSet.Validators[:index], qSet.Validators[index+1:]...)
		}
	}

	var cleaned []xdr.ScpQuorumSet
	for i, innerSet := range qSet.InnerSets {
		normalizeQSet(&qSet.InnerSets[i], idToRemove)

		// merge singleton inner sets into validator list
		if innerSet.Threshold == 1 && len(innerSet.Validators) == 1 && len(innerSet.InnerSets) == 0 {
			qSet.Validators = append(qSet.Validators, innerSet.Validators...)
			continue
		}

		cleaned = append(cleaned, qSet.InnerSets[i])
	}
	qSet.InnerSets = cleaned

	// simplify quorum set if needed
	if qSet.Threshold == 1 && len(qSet.Validators) == 0 && len(qSet.InnerSets) == 1 {
		*qSet = qSet.InnerSets[0]
	}
}

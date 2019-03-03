package scp

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/darksomex/stellar-core/utils/hash"
	"github.com/stellar/go/xdr"
	"github.com/stretchr/testify/require"
)

var (
	xValueHash = sha256.Sum256([]byte("SEED_VALUE_HASH_x"))
	xValue     = xdr.Value(xValueHash[:])

	yValueHash = sha256.Sum256([]byte("SEED_VALUE_HASH_y"))
	yValue     = xdr.Value(yValueHash[:])

	zValueHash = sha256.Sum256([]byte("SEED_VALUE_HASH_z"))
	zValue     = xdr.Value(zValueHash[:])
)

type genEnvelope func(sk [64]byte) *xdr.ScpEnvelope

type testValue struct {
	hash  xdr.Hash
	value xdr.Value
}

type timerData struct {
	absoluteTimeout time.Duration
	callback        func()
}

type testSCP struct {
	*testing.T

	scp            *SCP
	priorityLookup func(xdr.PublicKey) uint64

	envs               []*xdr.ScpEnvelope
	qourumSets         map[xdr.Hash]*xdr.ScpQuorumSet
	externalizedValues map[uint64]xdr.Value
	heardFromQuorums   map[uint64][]*xdr.ScpBallot

	timers map[int]timerData

	HashValueCalculator func(xdr.Value) uint64
	expectedCandidates  XDRValueSet
	compositeValue      xdr.Value

	currentTimerOffset time.Duration
}

func newTestSCP(nodeID xdr.PublicKey, qSetLocal *xdr.ScpQuorumSet, isValidator bool) *testSCP {

	testSCP := &testSCP{
		qourumSets:         make(map[xdr.Hash]*xdr.ScpQuorumSet),
		timers:             make(map[int]timerData),
		heardFromQuorums:   make(map[uint64][]*xdr.ScpBallot),
		externalizedValues: make(map[uint64]xdr.Value),
	}

	testSCP.scp = NewSCP(testSCP, nodeID, isValidator, qSetLocal)
	testSCP.priorityLookup = func(n xdr.PublicKey) uint64 {
		if *n.Ed25519 == *testSCP.scp.LocalNodeID().Ed25519 {
			return 1000
		}
		return 1
	}

	testSCP.StoreQuorumSet(testSCP.scp.LocalNode().QuorumSet())

	return testSCP
}

func (t *testSCP) getEntireState(index uint64) []*xdr.ScpEnvelope {
	return t.scp.getSlot(index, false).getEntireCurrentState()
}

func (t *testSCP) getCurrentEnvelope(index uint64, id xdr.NodeId) *xdr.ScpEnvelope {
	r := t.getEntireState(index)
	for _, e := range r {
		if *e.Statement.NodeId.Ed25519 == *id.Ed25519 {
			return e
		}
	}

	panic("current envelope not found")
}

func (t *testSCP) nominate(slotIndex uint64, value xdr.Value, timedout bool) bool {
	return t.scp.getSlot(slotIndex, true).Nominate(value, value, timedout)
}

func (t *testSCP) AcceptedBallotPrepared(slotIdx uint64, b *xdr.ScpBallot) {}
func (t *testSCP) AcceptedCommit(slotIdx uint64, b *xdr.ScpBallot)         {}
func (t *testSCP) BallotDidHearFromQuorum(slotIdx uint64, b *xdr.ScpBallot) {
	t.heardFromQuorums[slotIdx] = append(t.heardFromQuorums[slotIdx], b)
}

// only used by nomination protocol
func (t *testSCP) CombineCandidates(slotIdx uint64, candidates XDRValueSet) xdr.Value {
	for i := range candidates {
		require.True(t, bytes.Compare(t.expectedCandidates[i], candidates[i]) == 0)
	}
	require.NotNil(t, t.compositeValue)

	return t.compositeValue
}

func (t *testSCP) getLatestCompositeCandidate(slotIndex uint64) xdr.Value {
	return t.scp.getSlot(slotIndex, true).getLatestCompositeCandidate()
}

// override the internal hashing scheme in order to make tests
// more predictable.
func (t *testSCP) ComputeHashNode(slotIdx uint64, prev xdr.Value, isPriority bool,
	roundNum int32, nodeID xdr.PublicKey) uint64 {
	var res uint64
	if isPriority {
		res = t.priorityLookup(nodeID)
	} else {
		res = 0
	}

	return res
}

const MaxTimeOutSeconds = 30 * 60

func (t *testSCP) ComputeTimeout(roundNum uint32) time.Duration {
	// straight linear timeout
	// starting at 1 second and capping at MAX_TIMEOUT_SECONDS

	if roundNum > MaxTimeOutSeconds {
		return MaxTimeOutSeconds * time.Second
	}

	return time.Duration(roundNum) * time.Second

}

// override the value hashing, to make tests more predictable.
func (t *testSCP) ComputeValueHash(slotIdx uint64, prev xdr.Value, roundNum int32, value xdr.Value) uint64 {
	return t.HashValueCalculator(value)
}
func (t *testSCP) ConfirmedBallotPrepared(slotIdx uint64, b *xdr.ScpBallot) {}
func (t *testSCP) GetValueString(xdr.Value) string                          { return "" }
func (t *testSCP) NominatingValue(slotIdx uint64, v xdr.Value)              {}

func (t *testSCP) receiveEnvelope(env *xdr.ScpEnvelope) {
	t.scp.ReceiveEnvelope(env)
}
func (t *testSCP) ExtractValidValue(slotIdx uint64, v xdr.Value) xdr.Value { return v }

func (t *testSCP) SignEnvelope(*xdr.ScpEnvelope) {}
func (t *testSCP) VerifyEnvelope(*xdr.ScpEnvelope) bool {
	return true
}
func (t *testSCP) SetupTimer(slotIdx uint64, timerID TimerID, timeout time.Duration, cb func()) {
	if cb == nil {
		timeout = 0
	}

	t.timers[int(timerID)] = timerData{
		absoluteTimeout: t.currentTimerOffset + timeout,
		callback:        cb,
	}
}
func (t *testSCP) StartedBallotProtocol(slotIdx uint64, b *xdr.ScpBallot) {}

func (t *testSCP) StoreQuorumSet(qSet *xdr.ScpQuorumSet) {
	t.qourumSets[hash.QuorumSet(qSet)] = qSet
}
func (t *testSCP) ToShortString(xdr.PublicKey) string { return "" }

func (t *testSCP) bumpTimerOffset() time.Duration {
	t.currentTimerOffset += time.Hour * 5
	return t.currentTimerOffset
}
func (t *testSCP) UpdateCandidateValue(slotIdx uint64, v xdr.Value) {}

func (t *testSCP) ValidateValue(uint64, xdr.Value, bool) ValidationLevel {
	return ValidationLevelValid
}

func (t *testSCP) BallotDidHeadFromQuorum(slotIdx uint64, ballot *xdr.ScpBallot) {
	t.heardFromQuorums[slotIdx] = append(
		t.heardFromQuorums[slotIdx],
		ballot,
	)
}

func (t *testSCP) ValueExternalized(slotIdx uint64, value xdr.Value) {
	if _, ok := t.externalizedValues[slotIdx]; ok {
		panic("Value already externalized")
	}

	t.externalizedValues[slotIdx] = value
}

func (t *testSCP) GetQSet(qSetHash xdr.Hash) *xdr.ScpQuorumSet {
	return t.qourumSets[qSetHash]
}

func (t *testSCP) EmitEnvelope(env *xdr.ScpEnvelope) {
	t.envs = append(t.envs, env)
}

func (t *testSCP) BumpState(slotIdx uint64, v xdr.Value) bool {
	return t.scp.getSlot(slotIdx, true).BumpState(v, true)
}

func (t *testSCP) getBallotProtocolTimer() timerData {
	data, ok := t.timers[int(BallotTimer)]
	if !ok {
		t.timers[int(BallotTimer)] = data
	}

	return data
}

// returns true if a ballot protocol timer exists (in the past or future)
func (t *testSCP) hasBallotProtocolTimer() bool {
	return t.getBallotProtocolTimer().callback != nil
}

// returns true if the ballot protocol timer is scheduled in the future
// false if scheduled in the past
// this method is mostly used to verify that the timer *would* have fired
func (t *testSCP) hasBallotTimerUpcoming() bool {
	// timer must be scheduled in the past or future
	require.True(t, t.hasBallotProtocolTimer())
	return t.currentTimerOffset < t.getBallotProtocolTimer().absoluteTimeout
}

func makeEnvelope(secretKey [64]byte, slotIdx uint64, statement *xdr.ScpStatement) *xdr.ScpEnvelope {
	key := xdr.Uint256{}
	copy(key[:], secretKey[32:])

	statement.NodeId = xdr.NodeId{
		Ed25519: &key,
	}
	statement.SlotIndex = xdr.Uint64(slotIdx)

	envelope := xdr.ScpEnvelope{
		Statement: *statement,
	}

	return &envelope
}

func makePrepareGen(qSetHash xdr.Hash, ballot *xdr.ScpBallot) genEnvelope {
	return func(secretKey [64]byte) *xdr.ScpEnvelope {
		return makePrepareD(secretKey, qSetHash, 0, ballot)
	}
}

func makePrepareD(secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64, ballot *xdr.ScpBallot) *xdr.ScpEnvelope {
	return makePrepare(secretKey, qSetHash, slotIdx, ballot, nil, nil, 0, 0)
}

func (t *testSCP) verifyPrepareD(actual *xdr.ScpEnvelope, secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64,
	ballot *xdr.ScpBallot) {
	t.verifyPrepare(actual, secretKey, qSetHash, slotIdx, ballot, nil, nil, 0, 0)
}

func (t *testSCP) verifyPrepare(actual *xdr.ScpEnvelope, secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64,
	ballot, prepared, preparedPrime *xdr.ScpBallot, nC, nH uint32) {
	exp := makePrepare(secretKey, qSetHash, slotIdx, ballot, prepared, preparedPrime, nC, nH)
	require.True(t, reflect.DeepEqual(actual.Statement, exp.Statement))
}

func (t *testSCP) makeConfirm(secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64,
	preparedCounter uint32, b *xdr.ScpBallot, nC uint32, nH uint32) *xdr.ScpEnvelope {
	st := xdr.ScpStatement{}
	st.Pledges.Type = xdr.ScpStatementTypeScpStConfirm
	st.Pledges.Confirm = &xdr.ScpStatementConfirm{
		Ballot:        *b,
		NPrepared:     xdr.Uint32(preparedCounter),
		NCommit:       xdr.Uint32(nC),
		NH:            xdr.Uint32(nH),
		QuorumSetHash: qSetHash,
	}

	return makeEnvelope(secretKey, slotIdx, &st)
}

func (t *testSCP) verifyConfirm(actual *xdr.ScpEnvelope, secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64,
	prepared uint32, b *xdr.ScpBallot, nC uint32, nH uint32) {
	exp := t.makeConfirm(secretKey, qSetHash, slotIdx, prepared, b, nC, nH)
	require.Equal(t, exp.Statement, actual.Statement)
}

func makeNominate(secretKey [64]byte, qSetHash xdr.Hash, slotIndex uint64, votes, accepted []xdr.Value) *xdr.ScpEnvelope {
	sort.SliceStable(accepted, func(i, j int) bool {
		return bytes.Compare(accepted[i], accepted[j]) < 0
	})
	sort.SliceStable(votes, func(i, j int) bool {
		return bytes.Compare(votes[i], votes[j]) < 0
	})

	st := xdr.ScpStatement{}
	st.Pledges.Type = xdr.ScpStatementTypeScpStNominate
	st.Pledges.Nominate = new(xdr.ScpNomination)
	nom := st.Pledges.Nominate
	nom.QuorumSetHash = qSetHash
	for _, v := range votes {
		nom.Votes = append(nom.Votes, v)
	}
	for _, a := range accepted {
		nom.Accepted = append(nom.Accepted, a)
	}

	return makeEnvelope(secretKey, slotIndex, &st)
}

func (t *testSCP) verifyNominate(actual *xdr.ScpEnvelope, secretKey [64]byte, qSetHash xdr.Hash, slotIndex uint64,
	votes, accepted []xdr.Value) {
	exp := makeNominate(secretKey, qSetHash, slotIndex, votes, accepted)
	require.Equal(t, exp.Statement, actual.Statement)
}

func makeExternalize(secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64,
	commit *xdr.ScpBallot, nH uint32) *xdr.ScpEnvelope {
	st := xdr.ScpStatement{}
	st.Pledges.Type = xdr.ScpStatementTypeScpStExternalize
	st.Pledges.Externalize = &xdr.ScpStatementExternalize{
		Commit:              *commit,
		NH:                  xdr.Uint32(nH),
		CommitQuorumSetHash: qSetHash,
	}

	return makeEnvelope(secretKey, slotIdx, &st)
}

func (t *testSCP) verifyExternalize(actual *xdr.ScpEnvelope, secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64,
	commit *xdr.ScpBallot, nH uint32) {
	exp := makeExternalize(secretKey, qSetHash, slotIdx, commit, nH)
	require.Equal(t, exp.Statement, actual.Statement)
}

func makePrepare(secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64,
	ballot, prepared, preparedPrime *xdr.ScpBallot,
	nC, nH uint32) *xdr.ScpEnvelope {
	st := xdr.ScpStatement{
		Pledges: xdr.ScpStatementPledges{
			Type: xdr.ScpStatementTypeScpStPrepare,
			Prepare: &xdr.ScpStatementPrepare{
				Ballot:        *ballot,
				QuorumSetHash: qSetHash,
				Prepared:      prepared,
				NC:            xdr.Uint32(nC),
				NH:            xdr.Uint32(nH),
				PreparedPrime: preparedPrime,
			},
		},
	}

	return makeEnvelope(secretKey, slotIdx, &st)
}

func createTestValue(s string) *testValue {
	hash := xdr.Hash(sha256.Sum256([]byte("SEED_VALUE_HASH_" + s)))
	value, err := hash.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return &testValue{
		hash:  hash,
		value: value,
	}
}

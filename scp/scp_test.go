package scp

import (
	"bytes"
	"crypto/sha256"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stellar/go/xdr"
)

type prepareGen struct {
	qSetHash      xdr.Hash
	ballot        *xdr.ScpBallot
	prepared      *xdr.ScpBallot
	slotIdx       uint64
	nC            uint32
	nH            uint32
	preparedPrime *xdr.ScpBallot
}

func (g prepareGen) make() genEnvelope {
	return func(sd [64]byte) *xdr.ScpEnvelope {
		return makePrepare(sd, g.qSetHash, g.slotIdx, g.ballot,
			g.prepared, g.preparedPrime, g.nC, g.nH)
	}
}

func makeConfirm(secretKey [64]byte, qSetHash xdr.Hash, slotIdx uint64, prepareCounter uint32,
	b *xdr.ScpBallot, nC uint32, nH uint32) *xdr.ScpEnvelope {

	st := xdr.ScpStatement{}
	st.Pledges.Type = xdr.ScpStatementTypeScpStConfirm
	st.Pledges.Confirm = &xdr.ScpStatementConfirm{
		Ballot:        *b,
		NPrepared:     xdr.Uint32(prepareCounter),
		NCommit:       xdr.Uint32(nC),
		NH:            xdr.Uint32(nH),
		QuorumSetHash: qSetHash,
	}

	return makeEnvelope(secretKey, slotIdx, &st)
}

type confirmGen struct {
	qSetHash       xdr.Hash
	prepareCounter uint32
	ballot         *xdr.ScpBallot
	nC             uint32
	nH             uint32
}

func (g confirmGen) make() genEnvelope {
	return func(sd [64]byte) *xdr.ScpEnvelope {
		return makeConfirm(sd, g.qSetHash, 0, g.prepareCounter,
			g.ballot, g.nC, g.nH)
	}
}

type externalizeGen struct {
	qSetHash xdr.Hash
	slotIdx  uint64
	commit   *xdr.ScpBallot
	nH       uint32
}

func (g externalizeGen) make() genEnvelope {
	return func(sd [64]byte) *xdr.ScpEnvelope {
		return makeExternalize(sd, g.qSetHash, g.slotIdx, g.commit, g.nH)
	}
}

type testState struct {
	*testing.T
	v         [5]simulationNode
	A         [6]xdr.ScpBallot
	B         [4]xdr.ScpBallot
	AInf      xdr.ScpBallot
	BInf      xdr.ScpBallot
	scp       *testSCP
	qSet      xdr.ScpQuorumSet
	qSetHash  xdr.Hash
	qSetHash0 xdr.Hash
	votes     []xdr.Value
	accepted  []xdr.Value
	votes2    []xdr.Value
	acc       [5]*xdr.ScpEnvelope
	nom       [5]*xdr.ScpEnvelope
	myVotes   []xdr.Value
	acceptedY []xdr.Value
}

func (t *testState) recvVBlockingChecks(gen genEnvelope, withChecks bool) {
	e1 := gen(t.v[1].secretKey)
	e2 := gen(t.v[2].secretKey)

	t.scp.bumpTimerOffset()

	// nothing should happen with first message
	i := len(t.scp.envs)
	t.scp.receiveEnvelope(e1)
	if withChecks {
		require.True(t, len(t.scp.envs) == i)
	}
	i++
	t.scp.receiveEnvelope(e2)
	if withChecks {
		require.True(t, len(t.scp.envs) == i)
	}
}

func (t *testState) recvVBlocking(gen genEnvelope) {
	t.recvVBlockingChecks(gen, true)
}

func (t *testState) recvQuorumChecksEx(gen genEnvelope, withChecks, delayedQuorum, checkUpcoming bool) {
	e1 := gen(t.v[1].secretKey)
	e2 := gen(t.v[2].secretKey)
	e3 := gen(t.v[3].secretKey)
	e4 := gen(t.v[4].secretKey)

	t.scp.bumpTimerOffset()

	t.scp.receiveEnvelope(e1)
	t.scp.receiveEnvelope(e2)
	i := len(t.scp.envs) + 1
	t.scp.receiveEnvelope(e3)
	if withChecks && !delayedQuorum {
		require.True(t, len(t.scp.envs) == i)
	}
	if checkUpcoming && !delayedQuorum {
		require.True(t, t.scp.hasBallotTimerUpcoming())
	}
	// nothing happens with an extra vote (unless we're in delayedQuorum)
	t.scp.receiveEnvelope(e4)
	if withChecks && delayedQuorum {
		require.True(t, len(t.scp.envs) == i)
	}
	if checkUpcoming && delayedQuorum {
		require.True(t, t.scp.hasBallotTimerUpcoming())
	}
}

func (t *testState) nodesAllPledgeToCommit() {
	b := &xdr.ScpBallot{
		Counter: 1,
		Value:   xValue,
	}

	prepare1 := makePrepareD(t.v[1].secretKey, t.qSetHash, 0, b)
	prepare2 := makePrepareD(t.v[2].secretKey, t.qSetHash, 0, b)
	prepare3 := makePrepareD(t.v[3].secretKey, t.qSetHash, 0, b)
	prepare4 := makePrepareD(t.v[4].secretKey, t.qSetHash, 0, b)

	require.True(t, t.scp.BumpState(0, xValue))
	require.True(t, len(t.scp.envs) == 1)

	t.scp.verifyPrepareD(t.scp.envs[0], t.v[0].secretKey, t.qSetHash, 0, b)

	t.scp.receiveEnvelope(prepare1)
	require.True(t, len(t.scp.envs) == 1)
	require.True(t, len(t.scp.heardFromQuorums[0]) == 0)

	t.scp.receiveEnvelope(prepare2)
	require.True(t, len(t.scp.envs) == 1)
	require.True(t, len(t.scp.heardFromQuorums[0]) == 0)

	t.scp.receiveEnvelope(prepare3)
	require.True(t, len(t.scp.envs) == 2)
	require.True(t, len(t.scp.heardFromQuorums[0]) == 1)
	require.True(t, compareBallots(t.scp.heardFromQuorums[0][0], b) == 0)

	// We have a quorum including us
	t.scp.verifyPrepare(t.scp.envs[1], t.v[0].secretKey, t.qSetHash, 0, b, b, nil, 0, 0)

	t.scp.receiveEnvelope(prepare4)
	require.True(t, len(t.scp.envs) == 2)

	prepare1 = makePrepare(t.v[1].secretKey, t.qSetHash, 0, b, b, nil, 0, 0)
	prepare2 = makePrepare(t.v[2].secretKey, t.qSetHash, 0, b, b, nil, 0, 0)
	prepare3 = makePrepare(t.v[3].secretKey, t.qSetHash, 0, b, b, nil, 0, 0)
	prepare4 = makePrepare(t.v[4].secretKey, t.qSetHash, 0, b, b, nil, 0, 0)

	t.scp.receiveEnvelope(prepare4)
	t.scp.receiveEnvelope(prepare3)
	require.True(t, len(t.scp.envs) == 2)

	t.scp.receiveEnvelope(prepare2)
	require.True(t, len(t.scp.envs) == 3)

	// confirms prepared
	t.scp.verifyPrepare(t.scp.envs[2], t.v[0].secretKey, t.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32(b.Counter))

	// extra statement doesn't do anything
	t.scp.receiveEnvelope(prepare1)
	require.True(t, len(t.scp.envs) == 3)
}

// doesn't check timers
func (t *testState) recvQuorumChecks(gen genEnvelope, withChecks, delayedQuorum bool) {
	t.recvQuorumChecksEx(gen, withChecks, delayedQuorum, false)
}

// checks enabled, no delayed quorum
func (t *testState) recvQuorumEx(gen genEnvelope, checkUpcoming bool) {
	t.recvQuorumChecksEx(gen, true, false, checkUpcoming)
}

// checks enabled, no delayed quorum, no check timers
func (t *testState) recvQuorum(gen genEnvelope) {
	t.recvQuorumEx(gen, false)
}

func TestSCP(t *testing.T) {
	t.Run("vblocking and quorum (scp)", func(t *testing.T) {

		node0 := newSimulation(0)
		node1 := newSimulation(1)
		node2 := newSimulation(2)
		node3 := newSimulation(3)

		qSet := xdr.ScpQuorumSet{
			Threshold: 3,
			Validators: []xdr.PublicKey{
				node0.publicKey,
				node1.publicKey,
				node2.publicKey,
				node3.publicKey,
			},
		}

		nodeSet := []xdr.PublicKey{node0.publicKey}

		require.False(t, isQourumSlice(&qSet, nodeSet))
		require.False(t, isVBlocking(&qSet, nodeSet))

		nodeSet = append(nodeSet, node2.publicKey)

		require.False(t, isQourumSlice(&qSet, nodeSet))
		require.True(t, isVBlocking(&qSet, nodeSet))

		nodeSet = append(nodeSet, node3.publicKey)

		require.True(t, isQourumSlice(&qSet, nodeSet))
		require.True(t, isVBlocking(&qSet, nodeSet))

		nodeSet = append(nodeSet, node1.publicKey)

		require.True(t, isQourumSlice(&qSet, nodeSet))
		require.True(t, isVBlocking(&qSet, nodeSet))
	})

	t.Run("v blocking distance (scp)", func(t *testing.T) {
		node0 := newSimulation(0)
		node1 := newSimulation(1)
		node2 := newSimulation(2)
		node3 := newSimulation(3)
		node4 := newSimulation(4)
		node5 := newSimulation(5)
		node6 := newSimulation(6)
		node7 := newSimulation(7)

		qSet := xdr.ScpQuorumSet{
			Threshold: 2,
			Validators: []xdr.PublicKey{
				node0.publicKey,
				node1.publicKey,
				node2.publicKey,
			},
		}

		check := func(qSetCheck *xdr.ScpQuorumSet, s []xdr.PublicKey, expected int) {
			r := findClosestVBlocking(qSetCheck, s, nil)
			require.Equal(t, expected, len(r))
		}

		good := []xdr.PublicKey{node0.publicKey}

		// already v-blocking
		check(&qSet, good, 0)

		good = append(good, node1.publicKey)
		// either v0 or v1
		check(&qSet, good, 1)

		good = append(good, node2.publicKey)
		// any 2 of v0..v2
		check(&qSet, good, 2)

		qSubSet1 := xdr.ScpQuorumSet{
			Threshold: 1,
			Validators: []xdr.PublicKey{
				node3.publicKey,
				node4.publicKey,
				node5.publicKey,
			},
		}
		qSet.InnerSets = append(qSet.InnerSets, qSubSet1)

		good = append(good, node3.publicKey)
		// any 3 of v0..v3
		check(&qSet, good, 3)

		good = append(good, node4.publicKey)
		// v0..v2
		check(&qSet, good, 3)

		qSet.Threshold = 1
		// v0..v4
		check(&qSet, good, 5)

		good = append(good, node5.publicKey)
		// v0..v5
		check(&qSet, good, 6)

		qSubSet2 := xdr.ScpQuorumSet{
			Threshold: 2,
			Validators: []xdr.PublicKey{
				node6.publicKey,
				node7.publicKey,
			},
		}

		qSet.InnerSets = append(qSet.InnerSets, qSubSet2)
		// v0..v5
		check(&qSet, good, 6)

		good = append(good, node6.publicKey)
		// v0..v5
		check(&qSet, good, 6)

		good = append(good, node7.publicKey)
		// v0..v5 and one of 6,7
		check(&qSet, good, 7)

		qSet.Threshold = 4
		// v6, v7
		check(&qSet, good, 2)

		qSet.Threshold = 3
		// v0..v2
		check(&qSet, good, 3)

		qSet.Threshold = 2
		// v0..v2 and one of v6,v7
		check(&qSet, good, 4)
	})

	t.Run("ballot protocol core5 (scp)", func(t *testing.T) {
		init := func(t *testing.T) *testState {
			ts := testState{
				T: t,
			}

			ts.v[0] = *newSimulation(0)
			ts.v[1] = *newSimulation(1)
			ts.v[2] = *newSimulation(2)
			ts.v[3] = *newSimulation(3)
			ts.v[4] = *newSimulation(4)

			// we need 5 nodes to avoid sharing various thresholds:
			// v-blocking set size: 2
			// threshold: 4 = 3 + self or 4 others

			qSet := xdr.ScpQuorumSet{
				Threshold: 4,
				Validators: []xdr.PublicKey{
					ts.v[0].publicKey,
					ts.v[1].publicKey,
					ts.v[2].publicKey,
					ts.v[3].publicKey,
					ts.v[4].publicKey,
				},
			}
			ts.qSet = qSet

			b, err := qSet.MarshalBinary()
			if err != nil {
				panic(err)
			}

			ts.qSetHash = sha256.Sum256(b)

			ts.scp = newTestSCP(ts.v[0].publicKey, &qSet, true)
			ts.scp.StoreQuorumSet(&qSet)
			ts.qSetHash0 = ts.scp.scp.localNode.QuorumSetHash()
			ts.scp.T = t

			require.True(t, bytes.Compare(xValue[:], yValue[:]) < 0)

			return &ts
		}

		t.Run("bumpState x", func(t *testing.T) {
			ts := init(t)

			require.True(t, ts.scp.BumpState(0, xValue))
			require.True(t, len(ts.scp.envs) == 1)

			expectedBallot := xdr.ScpBallot{
				Counter: 1,
				Value:   xValue,
			}

			ts.scp.verifyPrepareD(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash, 0, &expectedBallot)
		})

		t.Run("start <1,x>", func(t *testing.T) {
			aValue := xValue
			bValue := yValue

			init := func(t *testing.T) *testState {
				ts := init(t)

				// no timer is set
				require.False(t, ts.scp.hasBallotProtocolTimer())

				ts.A[1] = xdr.ScpBallot{
					Counter: 1,
					Value:   aValue,
				}

				ts.B[1] = xdr.ScpBallot{
					Counter: 1,
					Value:   bValue,
				}

				ts.A[2] = ts.A[1]
				ts.A[2].Counter++

				ts.A[3] = ts.A[2]
				ts.A[3].Counter++

				ts.A[4] = ts.A[3]
				ts.A[4].Counter++

				ts.A[5] = ts.A[4]
				ts.A[5].Counter++

				ts.AInf = xdr.ScpBallot{
					Counter: math.MaxUint32,
					Value:   aValue,
				}

				ts.BInf = xdr.ScpBallot{
					Counter: math.MaxUint32,
					Value:   bValue,
				}

				ts.B[2] = ts.B[1]
				ts.B[2].Counter++

				ts.B[3] = ts.B[2]
				ts.B[3].Counter++

				require.True(t, ts.scp.BumpState(0, aValue))
				require.Equal(t, len(ts.scp.envs), 1)
				require.False(t, ts.scp.hasBallotProtocolTimer())

				return ts
			}

			t.Run("prepared A1", func(t *testing.T) {
				init := func(t *testing.T) *testState {
					ts := init(t)

					ts.recvQuorumEx(makePrepareGen(ts.qSetHash, &ts.A[1]), true)
					require.Equal(t, len(ts.scp.envs), 2)
					ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash,
						0, &ts.A[1], &ts.A[1], nil, 0, 0)

					return ts
				}

				t.Run("bump prepared A2", func(t *testing.T) {
					init := func(t *testing.T) *testState {
						ts := init(t)

						// bump to (2,a)
						ts.scp.bumpTimerOffset()
						require.True(t, ts.scp.BumpState(0, aValue))
						require.Equal(t, 3, len(ts.scp.envs))
						ts.scp.verifyPrepare(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash,
							0, &ts.A[2], &ts.A[1], nil, 0, 0)

						require.False(t, ts.scp.hasBallotProtocolTimer())

						ts.recvQuorumEx(makePrepareGen(ts.qSetHash, &ts.A[2]), true)
						require.Equal(t, 4, len(ts.scp.envs))
						ts.scp.verifyPrepare(ts.scp.envs[3], ts.v[0].secretKey, ts.qSetHash,
							0, &ts.A[2], &ts.A[2], nil, 0, 0)

						return ts
					}

					t.Run("Confirm prepared A2", func(t *testing.T) {
						init := func(t *testing.T) *testState {
							ts := init(t)

							ts.recvQuorum(prepareGen{
								qSetHash: ts.qSetHash,
								ballot:   &ts.A[2],
								prepared: &ts.A[2],
							}.make())
							require.Equal(t, 5, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[4], ts.v[0].secretKey, ts.qSetHash,
								0, &ts.A[2], &ts.A[2], nil, 2, 2)

							require.False(t, ts.scp.hasBallotTimerUpcoming())

							return ts
						}

						t.Run("Accept commit", func(t *testing.T) {
							t.Run("Quorum A2", func(t *testing.T) {
								init := func(t *testing.T) *testState {
									ts := init(t)

									ts.recvQuorum(prepareGen{
										qSetHash: ts.qSetHash,
										ballot:   &ts.A[2],
										prepared: &ts.A[2],
										nC:       2,
										nH:       2,
									}.make())
									require.Equal(t, 6, len(ts.scp.envs))
									ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash,
										0, 2, &ts.A[2], 2, 2)

									require.False(t, ts.scp.hasBallotTimerUpcoming())

									return ts
								}

								t.Run("Quorum prepared A3", func(t *testing.T) {
									init := func(t *testing.T) *testState {
										ts := init(t)

										ts.recvVBlocking(prepareGen{
											qSetHash: ts.qSetHash,
											ballot:   &ts.A[3],
											prepared: &ts.A[2],
											nC:       2,
											nH:       2,
										}.make())
										require.Equal(t, 7, len(ts.scp.envs))

										ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 2,
											&ts.A[3], 2, 2)

										require.False(t, ts.scp.hasBallotProtocolTimer())

										ts.recvQuorumEx(prepareGen{
											qSetHash: ts.qSetHash,
											ballot:   &ts.A[3],
											prepared: &ts.A[2],
											nC:       2,
											nH:       2,
										}.make(), true)
										require.Equal(t, 8, len(ts.scp.envs))

										ts.scp.verifyConfirm(ts.scp.envs[7], ts.v[0].secretKey, ts.qSetHash, 0, 3,
											&ts.A[3], 2, 2)

										return ts
									}

									t.Run("Accept more commit A3", func(t *testing.T) {
										init := func(t *testing.T) *testState {
											ts := init(t)

											ts.recvQuorum(prepareGen{
												qSetHash: ts.qSetHash,
												ballot:   &ts.A[3],
												prepared: &ts.A[3],
												nC:       2,
												nH:       3,
											}.make())
											require.Equal(t, 9, len(ts.scp.envs))

											ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0, 3,
												&ts.A[3], 2, 3)
											require.False(t, ts.scp.hasBallotTimerUpcoming())

											require.Len(t, ts.scp.externalizedValues, 0)
											return ts
										}

										t.Run("Quorum externalize A3", func(t *testing.T) {
											ts := init(t)

											ts.recvQuorum(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.A[3],
												nC:             2,
												nH:             3,
											}.make())
											require.Equal(t, 10, len(ts.scp.envs))

											ts.scp.verifyExternalize(ts.scp.envs[9], ts.v[0].secretKey, ts.qSetHash, 0,
												&ts.A[2], 3)

											require.False(t, ts.scp.hasBallotProtocolTimer())
											require.Len(t, ts.scp.externalizedValues, 1)
											require.Equal(t, ts.scp.externalizedValues[0], aValue)
										})
									})

									t.Run("v-blocking accept more A3", func(t *testing.T) {
										t.Run("Confirm A3", func(t *testing.T) {
											ts := init(t)

											ts.recvVBlocking(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.A[3],
												nC:             2,
												nH:             3,
											}.make())
											require.Equal(t, 9, len(ts.scp.envs))
											ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0, 3,
												&ts.A[3], 2, 3)
											require.False(t, ts.scp.hasBallotTimerUpcoming())
										})

										t.Run("Externalize A3", func(t *testing.T) {
											ts := init(t)

											ts.recvVBlocking(externalizeGen{
												qSetHash: ts.qSetHash,
												commit:   &ts.A[2],
												nH:       3,
											}.make())
											require.Equal(t, 9, len(ts.scp.envs))
											ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0,
												math.MaxUint32, &ts.AInf, 2, math.MaxUint32)

											require.False(t, ts.scp.hasBallotProtocolTimer())
										})

										t.Run("other nodes moved to c=A4 h=A5", func(t *testing.T) {
											t.Run("Confirm A4..5", func(t *testing.T) {
												ts := init(t)

												ts.recvVBlocking(confirmGen{
													qSetHash:       ts.qSetHash,
													prepareCounter: 3,
													ballot:         &ts.A[5],
													nC:             4,
													nH:             5,
												}.make())
												require.Equal(t, 9, len(ts.scp.envs))
												ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0,
													3, &ts.A[5], 4, 5)
												require.False(t, ts.scp.hasBallotProtocolTimer())
											})

											t.Run("Externalize A4..5", func(t *testing.T) {
												ts := init(t)

												ts.recvVBlocking(externalizeGen{
													qSetHash: ts.qSetHash,
													commit:   &ts.A[4],
													nH:       5,
												}.make())
												require.Equal(t, 9, len(ts.scp.envs))
												ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0,
													math.MaxUint32, &ts.AInf, 4, math.MaxUint32)
												require.False(t, ts.scp.hasBallotProtocolTimer())
											})
										})
									})
								})

								t.Run("v-blocking prepared A3", func(t *testing.T) {
									ts := init(t)

									ts.recvVBlocking(prepareGen{
										qSetHash: ts.qSetHash,
										ballot:   &ts.A[3],
										prepared: &ts.A[3],
										nC:       2,
										nH:       2,
									}.make())
									require.Equal(t, 7, len(ts.scp.envs))

									ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 3,
										&ts.A[3], 2, 2)

									require.False(t, ts.scp.hasBallotProtocolTimer())
								})

								t.Run("v-blocking prepared A3+B3", func(t *testing.T) {
									ts := init(t)

									ts.recvVBlocking(prepareGen{
										qSetHash:      ts.qSetHash,
										ballot:        &ts.A[3],
										prepared:      &ts.B[3],
										nC:            2,
										nH:            2,
										preparedPrime: &ts.A[3],
									}.make())
									require.Equal(t, 7, len(ts.scp.envs))
									ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 3,
										&ts.A[3], 2, 2)
									require.False(t, ts.scp.hasBallotProtocolTimer())
								})

								t.Run("v-blocking confirm A3", func(t *testing.T) {
									ts := init(t)

									ts.recvVBlocking(confirmGen{
										qSetHash:       ts.qSetHash,
										prepareCounter: 3,
										ballot:         &ts.A[3],
										nC:             2,
										nH:             2,
									}.make())
									require.Equal(t, 7, len(ts.scp.envs))
									ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 3,
										&ts.A[3], 2, 2)
									require.False(t, ts.scp.hasBallotProtocolTimer())
								})

								t.Run("Hang - does not switch to B in CONFIRM", func(t *testing.T) {
									t.Run("Network EXTERNALIZE", func(t *testing.T) {
										ts := init(t)
										// externalize messages have a counter at
										// infinite
										ts.recvVBlocking(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.B[2],
											nH:       3,
										}.make())
										require.Equal(t, 7, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 2,
											&ts.AInf, 2, 2)

										// stuck
										ts.recvQuorumChecks(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.B[2],
											nH:       3,
										}.make(), false, false)
										require.Equal(t, 7, len(ts.scp.envs))
										require.Len(t, ts.scp.externalizedValues, 0)

										// timer scheduled as there is a quorum
										// with (2, *)
										require.True(t, ts.scp.hasBallotTimerUpcoming())
									})

									t.Run("Network CONFIRMS other ballot", func(t *testing.T) {
										t.Run("at same counter", func(t *testing.T) {
											ts := init(t)
											// nothing should happen here, in
											// particular, node should not attempt
											// to switch 'p'
											ts.recvQuorumChecks(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.B[2],
												nC:             3,
												nH:             3,
											}.make(), false, false)
											require.Equal(t, 6, len(ts.scp.envs))
											require.Len(t, ts.scp.externalizedValues, 0)
											require.False(t, ts.scp.hasBallotTimerUpcoming())
										})

										t.Run("at a different counter", func(t *testing.T) {
											ts := init(t)

											ts.recvVBlocking(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.B[3],
												nC:             3,
												nH:             3,
											}.make())
											require.Equal(t, 7, len(ts.scp.envs))

											ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 2,
												&ts.A[3], 2, 2)
											require.False(t, ts.scp.hasBallotProtocolTimer())

											ts.recvQuorumChecks(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.B[3],
												nC:             3,
												nH:             3,
											}.make(), false, false)
											require.Equal(t, 7, len(ts.scp.envs))

											require.Len(t, ts.scp.externalizedValues, 0)
											// timer scheduled as there is a quorum
											// with (3, *)
											require.True(t, ts.scp.hasBallotTimerUpcoming())
										})
									})
								})
							})

							t.Run("v-blocking", func(t *testing.T) {
								t.Run("CONFIRM", func(t *testing.T) {
									t.Run("CONFIRM A2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 2,
											ballot:         &ts.A[2],
											nC:             2,
											nH:             2,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0, 2,
											&ts.A[2], 2, 2)

										require.False(t, ts.scp.hasBallotTimerUpcoming())
									})

									t.Run("CONFIRM A3..4", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 4,
											ballot:         &ts.A[4],
											nC:             3,
											nH:             4,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))

										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0, 4,
											&ts.A[4], 3, 4)

										require.False(t, ts.scp.hasBallotProtocolTimer())
									})

									t.Run("CONFIRM B2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 2,
											ballot:         &ts.B[2],
											nC:             2,
											nH:             2,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0,
											2, &ts.B[2], 2, 2)

										require.False(t, ts.scp.hasBallotTimerUpcoming())
									})
								})

								t.Run("EXTERNALIZE", func(t *testing.T) {
									t.Run("EXTERNALIZE A2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.A[2],
											nH:       2,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0,
											math.MaxUint32, &ts.AInf, 2, math.MaxUint32)

										require.False(t, ts.scp.hasBallotProtocolTimer())
									})

									t.Run("EXTERNALIZE B2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.B[2],
											nH:       2,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0,
											math.MaxUint32, &ts.BInf, 2, math.MaxUint32)

										require.False(t, ts.scp.hasBallotProtocolTimer())
									})
								})
							})
						})

						t.Run("get conflicting prepared B", func(t *testing.T) {
							t.Run("same counter", func(t *testing.T) {
								ts := init(t)

								ts.recvVBlocking(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.B[2],
									prepared: &ts.B[2],
								}.make())
								require.Equal(t, 6, len(ts.scp.envs))
								ts.scp.verifyPrepare(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash0,
									0, &ts.A[2], &ts.B[2], &ts.A[2], 0, 2)

								require.False(t, ts.scp.hasBallotTimerUpcoming())

								ts.recvQuorum(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.B[2],
									prepared: &ts.B[2],
									nC:       2,
									nH:       2,
								}.make())
								require.Equal(t, 7, len(ts.scp.envs))

								ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash0, 0,
									2, &ts.B[2], 2, 2)

								require.False(t, ts.scp.hasBallotTimerUpcoming())
							})

							t.Run("higher counter", func(t *testing.T) {
								ts := init(t)

								ts.recvVBlocking(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.B[3],
									prepared: &ts.B[2],
									nC:       2,
									nH:       2,
								}.make())
								require.Equal(t, 6, len(ts.scp.envs))
								ts.scp.verifyPrepare(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash0,
									0, &ts.A[3], &ts.B[2], &ts.A[2], 0, 2)

								ts.recvQuorumChecksEx(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.B[3],
									prepared: &ts.B[2],
									nC:       2,
									nH:       2,
								}.make(), true, true, true)
								require.Equal(t, 7, len(ts.scp.envs))

								ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash0, 0,
									3, &ts.B[3], 2, 2)
							})

						})
					})

					t.Run("Confirm prepared mixed", func(t *testing.T) {
						init := func(t *testing.T) *testState {
							// a few nodes prepared B2
							ts := init(t)

							ts.recvVBlocking(prepareGen{
								qSetHash:      ts.qSetHash,
								ballot:        &ts.B[2],
								prepared:      &ts.B[2],
								nC:            0,
								nH:            0,
								preparedPrime: &ts.A[2],
							}.make())
							require.Equal(t, 5, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[4], ts.v[0].secretKey, ts.qSetHash0,
								0, &ts.A[2], &ts.B[2], &ts.A[2], 0, 0)

							require.False(t, ts.scp.hasBallotTimerUpcoming())

							return ts
						}

						t.Run("mixed A2", func(t *testing.T) {
							ts := init(t)
							// causes h=A2
							// but c = 0, as p >!~ h
							ts.scp.bumpTimerOffset()
							ts.scp.receiveEnvelope(makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, &ts.A[2], &ts.A[2], nil, 0, 0))

							require.Equal(t, 6, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash0,
								0, &ts.A[2], &ts.B[2], &ts.A[2], 0, 2)

							require.False(t, ts.scp.hasBallotTimerUpcoming())

							ts.scp.bumpTimerOffset()
							ts.scp.receiveEnvelope(makePrepare(ts.v[4].secretKey, ts.qSetHash, 0, &ts.A[2], &ts.A[2], nil, 0, 0))

							require.Equal(t, 6, len(ts.scp.envs))
							require.False(t, ts.scp.hasBallotTimerUpcoming())
						})

						t.Run("mixed B2", func(t *testing.T) {
							ts := init(t)
							// causes h=B2, c=B2
							ts.scp.bumpTimerOffset()
							ts.scp.receiveEnvelope(makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, &ts.B[2], &ts.B[2], nil, 0, 0))

							require.Equal(t, 6, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash0,
								0, &ts.B[2], &ts.B[2], &ts.A[2], 2, 2)

							require.False(t, ts.scp.hasBallotTimerUpcoming())

							ts.scp.bumpTimerOffset()
							ts.scp.receiveEnvelope(makePrepare(ts.v[4].secretKey, ts.qSetHash, 0, &ts.B[2], &ts.B[2], nil, 0, 0))

							require.Equal(t, 6, len(ts.scp.envs))
							require.False(t, ts.scp.hasBallotTimerUpcoming())
						})
					})
				})

				t.Run("switch prepared B1", func(t *testing.T) {
					ts := init(t)

					ts.recvVBlocking(prepareGen{
						qSetHash: ts.qSetHash,
						ballot:   &ts.B[1],
						prepared: &ts.B[1],
					}.make())
					require.Equal(t, 3, len(ts.scp.envs))

					ts.scp.verifyPrepare(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash0,
						0, &ts.A[1], &ts.B[1], &ts.A[1], 0, 0)
					require.False(t, ts.scp.hasBallotTimerUpcoming())
				})

				t.Run("switch prepared B1", func(t *testing.T) {
					ts := init(t)

					ts.recvQuorumChecks(prepareGen{
						qSetHash: ts.qSetHash,
						ballot:   &ts.B[1],
					}.make(), true, true)
					require.Equal(t, 3, len(ts.scp.envs))

					ts.scp.verifyPrepare(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash0,
						0, &ts.A[1], &ts.B[1], &ts.A[1], 0, 0)
					require.False(t, ts.scp.hasBallotTimerUpcoming())
				})
			})

			t.Run("prepared B (v-blocking)", func(t *testing.T) {
				ts := init(t)

				ts.recvVBlocking(prepareGen{
					qSetHash: ts.qSetHash,
					ballot:   &ts.B[1],
					prepared: &ts.B[1],
				}.make())
				require.Equal(t, 2, len(ts.scp.envs))

				ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0,
					0, &ts.A[1], &ts.B[1], nil, 0, 0)
				require.False(t, ts.scp.hasBallotProtocolTimer())
			})

			t.Run("prepare B (quorum)", func(t *testing.T) {
				ts := init(t)

				ts.recvQuorumChecksEx(prepareGen{
					qSetHash: ts.qSetHash,
					ballot:   &ts.B[1],
				}.make(), true, true, true)
				require.Equal(t, 2, len(ts.scp.envs))

				ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0,
					0, &ts.A[1], &ts.B[1], nil, 0, 0)
			})

			t.Run("confirm (v-blocking)", func(t *testing.T) {
				t.Run("via CONFIRM", func(t *testing.T) {
					ts := init(t)

					ts.scp.bumpTimerOffset()
					ts.scp.receiveEnvelope(makeConfirm(ts.v[1].secretKey, ts.qSetHash, 0, 3, &ts.A[3], 3, 3))
					ts.scp.receiveEnvelope(makeConfirm(ts.v[2].secretKey, ts.qSetHash, 0, 4, &ts.A[4], 2, 4))
					require.Equal(t, 2, len(ts.scp.envs))

					ts.scp.verifyConfirm(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0,
						0, 3, &ts.A[3], 3, 3)

					require.False(t, ts.scp.hasBallotProtocolTimer())
				})

				t.Run("via EXTERNALIZE", func(t *testing.T) {
					ts := init(t)

					ts.scp.receiveEnvelope(makeExternalize(ts.v[1].secretKey, ts.qSetHash, 0, &ts.A[2], 4))
					ts.scp.receiveEnvelope(makeExternalize(ts.v[2].secretKey, ts.qSetHash, 0, &ts.A[3], 5))
					require.Equal(t, 2, len(ts.scp.envs))

					ts.scp.verifyConfirm(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0,
						0, math.MaxUint32, &ts.AInf, 3, math.MaxUint32)
					require.False(t, ts.scp.hasBallotProtocolTimer())
				})
			})
		})

		// this is the same test suite than "start <1,x>" with the exception that
		// some transitions are not possible as x < y - so instead we verify that
		// nothing happens
		t.Run("start <1,y>", func(t *testing.T) {
			aValue := yValue
			bValue := xValue

			init := func(t *testing.T) *testState {
				ts := init(t)

				// no timer is set
				require.False(t, ts.scp.hasBallotProtocolTimer())

				ts.A[1] = xdr.ScpBallot{
					Counter: 1,
					Value:   aValue,
				}

				ts.B[1] = xdr.ScpBallot{
					Counter: 1,
					Value:   bValue,
				}

				ts.A[2] = ts.A[1]
				ts.A[2].Counter++

				ts.A[3] = ts.A[2]
				ts.A[3].Counter++

				ts.A[4] = ts.A[3]
				ts.A[4].Counter++

				ts.A[5] = ts.A[4]
				ts.A[5].Counter++

				ts.AInf = xdr.ScpBallot{
					Counter: math.MaxUint32,
					Value:   aValue,
				}

				ts.BInf = xdr.ScpBallot{
					Counter: math.MaxUint32,
					Value:   bValue,
				}

				ts.B[2] = ts.B[1]
				ts.B[2].Counter++

				ts.B[3] = ts.B[2]
				ts.B[3].Counter++

				require.True(t, ts.scp.BumpState(0, aValue))
				require.Equal(t, len(ts.scp.envs), 1)
				require.False(t, ts.scp.hasBallotProtocolTimer())

				return ts
			}

			t.Run("prepared A1", func(t *testing.T) {
				init := func(t *testing.T) *testState {
					ts := init(t)

					ts.recvQuorumEx(makePrepareGen(ts.qSetHash, &ts.A[1]), true)
					require.Equal(t, len(ts.scp.envs), 2)
					ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash,
						0, &ts.A[1], &ts.A[1], nil, 0, 0)

					return ts
				}

				t.Run("bump prepared A2", func(t *testing.T) {
					init := func(t *testing.T) *testState {
						ts := init(t)

						// bump to (2,a)
						ts.scp.bumpTimerOffset()
						require.True(t, ts.scp.BumpState(0, aValue))
						require.Equal(t, 3, len(ts.scp.envs))
						ts.scp.verifyPrepare(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash,
							0, &ts.A[2], &ts.A[1], nil, 0, 0)

						require.False(t, ts.scp.hasBallotProtocolTimer())

						ts.recvQuorumEx(makePrepareGen(ts.qSetHash, &ts.A[2]), true)
						require.Equal(t, 4, len(ts.scp.envs))
						ts.scp.verifyPrepare(ts.scp.envs[3], ts.v[0].secretKey, ts.qSetHash,
							0, &ts.A[2], &ts.A[2], nil, 0, 0)

						return ts
					}

					t.Run("Confirm prepared A2", func(t *testing.T) {
						init := func(t *testing.T) *testState {
							ts := init(t)

							ts.recvQuorum(prepareGen{
								qSetHash: ts.qSetHash,
								ballot:   &ts.A[2],
								prepared: &ts.A[2],
							}.make())
							require.Equal(t, 5, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[4], ts.v[0].secretKey, ts.qSetHash,
								0, &ts.A[2], &ts.A[2], nil, 2, 2)

							require.False(t, ts.scp.hasBallotTimerUpcoming())

							return ts
						}

						t.Run("Accept commit", func(t *testing.T) {
							t.Run("Quorum A2", func(t *testing.T) {
								init := func(t *testing.T) *testState {
									ts := init(t)

									ts.recvQuorum(prepareGen{
										qSetHash: ts.qSetHash,
										ballot:   &ts.A[2],
										prepared: &ts.A[2],
										nC:       2,
										nH:       2,
									}.make())
									require.Equal(t, 6, len(ts.scp.envs))
									ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash,
										0, 2, &ts.A[2], 2, 2)

									require.False(t, ts.scp.hasBallotTimerUpcoming())

									return ts
								}

								t.Run("Quorum prepared A3", func(t *testing.T) {
									init := func(t *testing.T) *testState {
										ts := init(t)

										ts.recvVBlocking(prepareGen{
											qSetHash: ts.qSetHash,
											ballot:   &ts.A[3],
											prepared: &ts.A[2],
											nC:       2,
											nH:       2,
										}.make())
										require.Equal(t, 7, len(ts.scp.envs))

										ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 2,
											&ts.A[3], 2, 2)

										require.False(t, ts.scp.hasBallotProtocolTimer())

										ts.recvQuorumEx(prepareGen{
											qSetHash: ts.qSetHash,
											ballot:   &ts.A[3],
											prepared: &ts.A[2],
											nC:       2,
											nH:       2,
										}.make(), true)
										require.Equal(t, 8, len(ts.scp.envs))

										ts.scp.verifyConfirm(ts.scp.envs[7], ts.v[0].secretKey, ts.qSetHash, 0, 3,
											&ts.A[3], 2, 2)

										return ts
									}

									t.Run("Accept more commit A3", func(t *testing.T) {
										init := func(t *testing.T) *testState {
											ts := init(t)

											ts.recvQuorum(prepareGen{
												qSetHash: ts.qSetHash,
												ballot:   &ts.A[3],
												prepared: &ts.A[3],
												nC:       2,
												nH:       3,
											}.make())
											require.Equal(t, 9, len(ts.scp.envs))

											ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0, 3,
												&ts.A[3], 2, 3)
											require.False(t, ts.scp.hasBallotTimerUpcoming())

											require.Len(t, ts.scp.externalizedValues, 0)
											return ts
										}

										t.Run("Quorum externalize A3", func(t *testing.T) {
											ts := init(t)

											ts.recvQuorum(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.A[3],
												nC:             2,
												nH:             3,
											}.make())
											require.Equal(t, 10, len(ts.scp.envs))

											ts.scp.verifyExternalize(ts.scp.envs[9], ts.v[0].secretKey, ts.qSetHash, 0,
												&ts.A[2], 3)

											require.False(t, ts.scp.hasBallotProtocolTimer())
											require.Len(t, ts.scp.externalizedValues, 1)
											require.Equal(t, ts.scp.externalizedValues[0], aValue)
										})
									})

									t.Run("v-blocking accept more A3", func(t *testing.T) {
										t.Run("Confirm A3", func(t *testing.T) {
											ts := init(t)

											ts.recvVBlocking(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.A[3],
												nC:             2,
												nH:             3,
											}.make())
											require.Equal(t, 9, len(ts.scp.envs))
											ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0, 3,
												&ts.A[3], 2, 3)
											require.False(t, ts.scp.hasBallotTimerUpcoming())
										})

										t.Run("Externalize A3", func(t *testing.T) {
											ts := init(t)

											ts.recvVBlocking(externalizeGen{
												qSetHash: ts.qSetHash,
												commit:   &ts.A[2],
												nH:       3,
											}.make())
											require.Equal(t, 9, len(ts.scp.envs))
											ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0,
												math.MaxUint32, &ts.AInf, 2, math.MaxUint32)

											require.False(t, ts.scp.hasBallotProtocolTimer())
										})

										t.Run("other nodes moved to c=A4 h=A5", func(t *testing.T) {
											t.Run("Confirm A4..5", func(t *testing.T) {
												ts := init(t)

												ts.recvVBlocking(confirmGen{
													qSetHash:       ts.qSetHash,
													prepareCounter: 3,
													ballot:         &ts.A[5],
													nC:             4,
													nH:             5,
												}.make())
												require.Equal(t, 9, len(ts.scp.envs))
												ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0,
													3, &ts.A[5], 4, 5)
												require.False(t, ts.scp.hasBallotProtocolTimer())
											})

											t.Run("Externalize A4..5", func(t *testing.T) {
												ts := init(t)

												ts.recvVBlocking(externalizeGen{
													qSetHash: ts.qSetHash,
													commit:   &ts.A[4],
													nH:       5,
												}.make())
												require.Equal(t, 9, len(ts.scp.envs))
												ts.scp.verifyConfirm(ts.scp.envs[8], ts.v[0].secretKey, ts.qSetHash, 0,
													math.MaxUint32, &ts.AInf, 4, math.MaxUint32)
												require.False(t, ts.scp.hasBallotProtocolTimer())
											})
										})
									})
								})

								t.Run("v-blocking prepared A3", func(t *testing.T) {
									ts := init(t)

									ts.recvVBlocking(prepareGen{
										qSetHash: ts.qSetHash,
										ballot:   &ts.A[3],
										prepared: &ts.A[3],
										nC:       2,
										nH:       2,
									}.make())
									require.Equal(t, 7, len(ts.scp.envs))

									ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 3,
										&ts.A[3], 2, 2)

									require.False(t, ts.scp.hasBallotProtocolTimer())
								})

								t.Run("v-blocking prepared A3+B3", func(t *testing.T) {
									ts := init(t)

									ts.recvVBlocking(prepareGen{
										qSetHash:      ts.qSetHash,
										ballot:        &ts.A[3],
										prepared:      &ts.A[3],
										nC:            2,
										nH:            2,
										preparedPrime: &ts.B[3],
									}.make())
									require.Equal(t, 7, len(ts.scp.envs))
									ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 3,
										&ts.A[3], 2, 2)
									require.False(t, ts.scp.hasBallotProtocolTimer())
								})

								t.Run("v-blocking confirm A3", func(t *testing.T) {
									ts := init(t)

									ts.recvVBlocking(confirmGen{
										qSetHash:       ts.qSetHash,
										prepareCounter: 3,
										ballot:         &ts.A[3],
										nC:             2,
										nH:             2,
									}.make())
									require.Equal(t, 7, len(ts.scp.envs))
									ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 3,
										&ts.A[3], 2, 2)
									require.False(t, ts.scp.hasBallotProtocolTimer())
								})

								t.Run("Hang - does not switch to B in CONFIRM", func(t *testing.T) {
									t.Run("Network EXTERNALIZE", func(t *testing.T) {
										ts := init(t)
										// externalize messages have a counter at
										// infinite
										ts.recvVBlocking(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.B[2],
											nH:       3,
										}.make())
										require.Equal(t, 7, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 2,
											&ts.AInf, 2, 2)

										// stuck
										ts.recvQuorumChecks(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.B[2],
											nH:       3,
										}.make(), false, false)
										require.Equal(t, 7, len(ts.scp.envs))
										require.Len(t, ts.scp.externalizedValues, 0)

										// timer scheduled as there is a quorum
										// with (inf, *)
										require.True(t, ts.scp.hasBallotTimerUpcoming())
									})

									t.Run("Network CONFIRMS other ballot", func(t *testing.T) {
										t.Run("at same counter", func(t *testing.T) {
											ts := init(t)
											// nothing should happen here, in
											// particular, node should not attempt
											// to switch 'p'
											ts.recvQuorumChecks(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.B[2],
												nC:             3,
												nH:             3,
											}.make(), false, false)
											require.Equal(t, 6, len(ts.scp.envs))
											require.Len(t, ts.scp.externalizedValues, 0)
											require.False(t, ts.scp.hasBallotTimerUpcoming())
										})

										t.Run("at a different counter", func(t *testing.T) {
											ts := init(t)

											ts.recvVBlocking(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.B[3],
												nC:             3,
												nH:             3,
											}.make())
											require.Equal(t, 7, len(ts.scp.envs))

											ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash, 0, 2,
												&ts.A[3], 2, 2)
											require.False(t, ts.scp.hasBallotProtocolTimer())

											ts.recvQuorumChecks(confirmGen{
												qSetHash:       ts.qSetHash,
												prepareCounter: 3,
												ballot:         &ts.B[3],
												nC:             3,
												nH:             3,
											}.make(), false, false)
											require.Equal(t, 7, len(ts.scp.envs))

											require.Len(t, ts.scp.externalizedValues, 0)
											// timer scheduled as there is a quorum
											// with (3, *)
											require.True(t, ts.scp.hasBallotTimerUpcoming())
										})
									})
								})
							})

							t.Run("v-blocking", func(t *testing.T) {
								t.Run("CONFIRM", func(t *testing.T) {
									t.Run("CONFIRM A2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 2,
											ballot:         &ts.A[2],
											nC:             2,
											nH:             2,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0, 2,
											&ts.A[2], 2, 2)

										require.False(t, ts.scp.hasBallotTimerUpcoming())
									})

									t.Run("CONFIRM A3..4", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 4,
											ballot:         &ts.A[4],
											nC:             3,
											nH:             4,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))

										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0, 4,
											&ts.A[4], 3, 4)

										require.False(t, ts.scp.hasBallotProtocolTimer())
									})

									t.Run("CONFIRM B2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 2,
											ballot:         &ts.B[2],
											nC:             2,
											nH:             2,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0,
											2, &ts.B[2], 2, 2)

										require.False(t, ts.scp.hasBallotTimerUpcoming())
									})
								})

								t.Run("EXTERNALIZE", func(t *testing.T) {
									t.Run("EXTERNALIZE A2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.A[2],
											nH:       2,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0,
											math.MaxUint32, &ts.AInf, 2, math.MaxUint32)

										require.False(t, ts.scp.hasBallotProtocolTimer())
									})

									t.Run("EXTERNALIZE B2", func(t *testing.T) {
										ts := init(t)
										// can switch to B2 with externalize (higher counter)
										ts.recvVBlocking(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.B[2],
											nH:       2,
										}.make())
										require.Equal(t, 6, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0,
											math.MaxUint32, &ts.BInf, 2, math.MaxUint32)

										require.False(t, ts.scp.hasBallotProtocolTimer())
									})
								})
							})
						})

						t.Run("get conflicting prepared B", func(t *testing.T) {
							t.Run("same counter", func(t *testing.T) {
								ts := init(t)

								ts.recvQuorumChecks(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.B[2],
									prepared: &ts.B[2],
									nC:       2,
									nH:       2,
								}.make(), false, false)
								require.Equal(t, 5, len(ts.scp.envs))

								require.False(t, ts.scp.hasBallotTimerUpcoming())
							})

							t.Run("higher counter", func(t *testing.T) {
								ts := init(t)

								ts.recvVBlocking(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.B[3],
									prepared: &ts.B[2],
									nC:       2,
									nH:       2,
								}.make())
								require.Equal(t, 6, len(ts.scp.envs))
								// A2 > B2 -> p = A2, p'=B2
								ts.scp.verifyPrepare(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash0,
									0, &ts.A[3], &ts.A[2], &ts.B[2], 2, 2)

								// node is trying to commit A2=<2,y> but rest
								// of its quorum is trying to commit B2
								// we end up with a delayed quorum
								ts.recvQuorumChecksEx(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.B[3],
									prepared: &ts.B[2],
									nC:       2,
									nH:       2,
								}.make(), true, true, true)
								require.Equal(t, 7, len(ts.scp.envs))

								ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash0, 0,
									3, &ts.B[3], 2, 2)
							})

						})
					})

					t.Run("Confirm prepared mixed", func(t *testing.T) {
						init := func(t *testing.T) *testState {
							// a few nodes prepared B2
							ts := init(t)

							ts.recvVBlocking(prepareGen{
								qSetHash:      ts.qSetHash,
								ballot:        &ts.A[2],
								prepared:      &ts.A[2],
								nC:            0,
								nH:            0,
								preparedPrime: &ts.B[2],
							}.make())
							require.Equal(t, 5, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[4], ts.v[0].secretKey, ts.qSetHash0,
								0, &ts.A[2], &ts.A[2], &ts.B[2], 0, 0)

							require.False(t, ts.scp.hasBallotTimerUpcoming())

							return ts
						}

						t.Run("mixed A2", func(t *testing.T) {
							ts := init(t)
							// causes h=A2, c=A2
							ts.scp.bumpTimerOffset()
							ts.scp.receiveEnvelope(makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, &ts.A[2], &ts.A[2], nil, 0, 0))

							require.Equal(t, 6, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash0,
								0, &ts.A[2], &ts.A[2], &ts.B[2], 2, 2)

							require.False(t, ts.scp.hasBallotTimerUpcoming())

							ts.scp.bumpTimerOffset()
							ts.scp.receiveEnvelope(makePrepare(ts.v[4].secretKey, ts.qSetHash, 0, &ts.A[2], &ts.A[2], nil, 0, 0))

							require.Equal(t, 6, len(ts.scp.envs))
							require.False(t, ts.scp.hasBallotTimerUpcoming())
						})

						t.Run("mixed B2", func(t *testing.T) {
							ts := init(t)
							// causes computed_h=B2 ~ not set as h ~!= b -> noop
							ts.scp.bumpTimerOffset()
							ts.scp.receiveEnvelope(makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, &ts.A[2], &ts.B[2], nil, 0, 0))

							require.Equal(t, 5, len(ts.scp.envs))

							require.False(t, ts.scp.hasBallotTimerUpcoming())

							ts.scp.bumpTimerOffset()
							ts.scp.receiveEnvelope(makePrepare(ts.v[4].secretKey, ts.qSetHash, 0, &ts.B[2], &ts.B[2], nil, 0, 0))

							require.Equal(t, 5, len(ts.scp.envs))
							require.False(t, ts.scp.hasBallotTimerUpcoming())
						})
					})
				})

				t.Run("switch prepared B1", func(t *testing.T) {
					ts := init(t)
					// can't switch to B1
					ts.recvQuorumChecks(prepareGen{
						qSetHash: ts.qSetHash,
						ballot:   &ts.B[1],
						prepared: &ts.B[1],
					}.make(), false, false)
					require.Equal(t, 2, len(ts.scp.envs))

					require.False(t, ts.scp.hasBallotTimerUpcoming())
				})
			})

			t.Run("prepared B (v-blocking)", func(t *testing.T) {
				ts := init(t)

				ts.recvVBlocking(prepareGen{
					qSetHash: ts.qSetHash,
					ballot:   &ts.B[1],
					prepared: &ts.B[1],
				}.make())
				require.Equal(t, 2, len(ts.scp.envs))

				ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0,
					0, &ts.A[1], &ts.B[1], nil, 0, 0)
				require.False(t, ts.scp.hasBallotProtocolTimer())
			})

			t.Run("prepare B (quorum)", func(t *testing.T) {
				ts := init(t)

				ts.recvQuorumChecksEx(prepareGen{
					qSetHash: ts.qSetHash,
					ballot:   &ts.B[1],
				}.make(), true, true, true)
				require.Equal(t, 2, len(ts.scp.envs))

				ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0,
					0, &ts.A[1], &ts.B[1], nil, 0, 0)
			})

			t.Run("confirm (v-blocking)", func(t *testing.T) {
				t.Run("via CONFIRM", func(t *testing.T) {
					ts := init(t)

					ts.scp.bumpTimerOffset()
					ts.scp.receiveEnvelope(makeConfirm(ts.v[1].secretKey, ts.qSetHash, 0, 3, &ts.A[3], 3, 3))
					ts.scp.receiveEnvelope(makeConfirm(ts.v[2].secretKey, ts.qSetHash, 0, 4, &ts.A[4], 2, 4))
					require.Equal(t, 2, len(ts.scp.envs))

					ts.scp.verifyConfirm(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0,
						0, 3, &ts.A[3], 3, 3)

					require.False(t, ts.scp.hasBallotProtocolTimer())
				})

				t.Run("via EXTERNALIZE", func(t *testing.T) {
					ts := init(t)

					ts.scp.receiveEnvelope(makeExternalize(ts.v[1].secretKey, ts.qSetHash, 0, &ts.A[2], 4))
					ts.scp.receiveEnvelope(makeExternalize(ts.v[2].secretKey, ts.qSetHash, 0, &ts.A[3], 5))
					require.Equal(t, 2, len(ts.scp.envs))

					ts.scp.verifyConfirm(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0,
						0, math.MaxUint32, &ts.AInf, 3, math.MaxUint32)
					require.False(t, ts.scp.hasBallotProtocolTimer())
				})
			})
		})

		// this is the same test suite than "start <1,x>" but only keeping
		// the transitions that are observable when starting from empty
		t.Run("start from pristine", func(t *testing.T) {
			aValue := xValue
			bValue := yValue

			init := func(t *testing.T) *testState {
				ts := init(t)

				// no timer is set
				require.False(t, ts.scp.hasBallotProtocolTimer())

				ts.A[1] = xdr.ScpBallot{
					Counter: 1,
					Value:   aValue,
				}

				ts.B[1] = xdr.ScpBallot{
					Counter: 1,
					Value:   bValue,
				}

				ts.A[2] = ts.A[1]
				ts.A[2].Counter++

				ts.A[3] = ts.A[2]
				ts.A[3].Counter++

				ts.A[4] = ts.A[3]
				ts.A[4].Counter++

				ts.A[5] = ts.A[4]
				ts.A[5].Counter++

				ts.AInf = xdr.ScpBallot{
					Counter: math.MaxUint32,
					Value:   aValue,
				}

				ts.BInf = xdr.ScpBallot{
					Counter: math.MaxUint32,
					Value:   bValue,
				}

				ts.B[2] = ts.B[1]
				ts.B[2].Counter++

				ts.B[3] = ts.B[2]
				ts.B[3].Counter++

				require.Equal(t, len(ts.scp.envs), 0)

				return ts
			}

			t.Run("prepared A1", func(t *testing.T) {
				init := func(t *testing.T) *testState {
					ts := init(t)

					ts.recvQuorumChecks(makePrepareGen(ts.qSetHash, &ts.A[1]), false, false)
					require.Equal(t, len(ts.scp.envs), 0)

					return ts
				}

				t.Run("bump prepared A2", func(t *testing.T) {

					t.Run("Confirm prepared A2", func(t *testing.T) {
						init := func(t *testing.T) *testState {
							ts := init(t)

							ts.recvVBlockingChecks(prepareGen{
								qSetHash: ts.qSetHash,
								ballot:   &ts.A[2],
								prepared: &ts.A[2],
							}.make(), false)
							require.Equal(t, 0, len(ts.scp.envs))

							return ts
						}

						t.Run("Quorum A2", func(t *testing.T) {
							ts := init(t)
							ts.recvVBlockingChecks(prepareGen{
								qSetHash: ts.qSetHash,
								ballot:   &ts.A[2],
								prepared: &ts.A[2],
							}.make(), false)
							require.Equal(t, 0, len(ts.scp.envs))
							ts.recvQuorum(prepareGen{
								qSetHash: ts.qSetHash,
								ballot:   &ts.A[2],
								prepared: &ts.A[2],
							}.make())
							require.Equal(t, 1, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, &ts.A[2], &ts.A[2],
								nil, 1, 2)
						})

						t.Run("Quorum B2", func(t *testing.T) {
							ts := init(t)
							ts.recvVBlockingChecks(prepareGen{
								qSetHash: ts.qSetHash,
								ballot:   &ts.B[2],
								prepared: &ts.B[2],
							}.make(), false)
							require.Equal(t, 0, len(ts.scp.envs))
							ts.recvQuorum(prepareGen{
								qSetHash: ts.qSetHash,
								ballot:   &ts.B[2],
								prepared: &ts.B[2],
							}.make())
							require.Equal(t, 1, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, &ts.B[2], &ts.B[2],
								&ts.A[2], 2, 2)
						})

						t.Run("Accept commit", func(t *testing.T) {
							t.Run("Quorum A2", func(t *testing.T) {
								ts := init(t)

								ts.recvQuorum(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.A[2],
									prepared: &ts.A[2],
									nC:       2,
									nH:       2,
								}.make())
								require.Equal(t, 1, len(ts.scp.envs))
								ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0,
									0, 2, &ts.A[2], 2, 2)
							})

							t.Run("Quorum B2", func(t *testing.T) {
								ts := init(t)

								ts.recvQuorum(prepareGen{
									qSetHash: ts.qSetHash,
									ballot:   &ts.B[2],
									prepared: &ts.B[2],
									nC:       2,
									nH:       2,
								}.make())
								require.Equal(t, 1, len(ts.scp.envs))
								ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0,
									0, 2, &ts.B[2], 2, 2)
							})

							t.Run("v-blocking", func(t *testing.T) {
								t.Run("CONFIRM", func(t *testing.T) {
									t.Run("CONFIRM A2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 2,
											ballot:         &ts.A[2],
											nC:             2,
											nH:             2,
										}.make())
										require.Equal(t, 1, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash, 0, 2,
											&ts.A[2], 2, 2)
									})

									t.Run("CONFIRM A3..4", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 4,
											ballot:         &ts.A[4],
											nC:             3,
											nH:             4,
										}.make())
										require.Equal(t, 1, len(ts.scp.envs))

										ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash, 0, 4,
											&ts.A[4], 3, 4)
									})

									t.Run("CONFIRM B2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(confirmGen{
											qSetHash:       ts.qSetHash,
											prepareCounter: 2,
											ballot:         &ts.B[2],
											nC:             2,
											nH:             2,
										}.make())
										require.Equal(t, 1, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash, 0,
											2, &ts.B[2], 2, 2)
									})
								})

								t.Run("EXTERNALIZE", func(t *testing.T) {
									t.Run("EXTERNALIZE A2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.A[2],
											nH:       2,
										}.make())
										require.Equal(t, 1, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash, 0,
											math.MaxUint32, &ts.AInf, 2, math.MaxUint32)
									})

									t.Run("EXTERNALIZE B2", func(t *testing.T) {
										ts := init(t)

										ts.recvVBlocking(externalizeGen{
											qSetHash: ts.qSetHash,
											commit:   &ts.B[2],
											nH:       2,
										}.make())
										require.Equal(t, 1, len(ts.scp.envs))
										ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash, 0,
											math.MaxUint32, &ts.BInf, 2, math.MaxUint32)
									})
								})
							})
						})
					})

					t.Run("Confirm prepared mixed", func(t *testing.T) {
						init := func(t *testing.T) *testState {
							ts := init(t)

							// a few nodes prepared A2
							// causes p=A2

							ts.recvVBlockingChecks(prepareGen{
								qSetHash: ts.qSetHash,
								ballot:   &ts.A[2],
								prepared: &ts.A[2],
							}.make(), false)
							require.Equal(t, 0, len(ts.scp.envs))

							// a few nodes prepared B2
							// causes p=B2, p'=A2

							ts.recvVBlockingChecks(prepareGen{
								qSetHash:      ts.qSetHash,
								ballot:        &ts.A[2],
								prepared:      &ts.B[2],
								preparedPrime: &ts.A[2],
							}.make(), false)
							require.Equal(t, 0, len(ts.scp.envs))

							return ts
						}

						t.Run("mixed A2", func(t *testing.T) {
							ts := init(t)
							// causes h=A2
							// but c = 0, as p >!~ h
							ts.scp.receiveEnvelope(makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, &ts.A[2], &ts.A[2], nil, 0, 0))

							require.Equal(t, 1, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0,
								0, &ts.A[2], &ts.B[2], &ts.A[2], 0, 2)

							ts.scp.receiveEnvelope(makePrepare(ts.v[4].secretKey, ts.qSetHash, 0, &ts.A[2], &ts.A[2], nil, 0, 0))

							require.Equal(t, 1, len(ts.scp.envs))
						})

						t.Run("mixed B2", func(t *testing.T) {
							ts := init(t)
							// causes h=B2, c=B2
							ts.scp.receiveEnvelope(makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, &ts.B[2], &ts.B[2], nil, 0, 0))

							require.Equal(t, 1, len(ts.scp.envs))
							ts.scp.verifyPrepare(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0,
								0, &ts.B[2], &ts.B[2], &ts.A[2], 2, 2)

							ts.scp.receiveEnvelope(makePrepare(ts.v[4].secretKey, ts.qSetHash, 0, &ts.B[2], &ts.B[2], nil, 0, 0))

							require.Equal(t, 1, len(ts.scp.envs))
						})
					})
				})

				t.Run("switch prepared B1", func(t *testing.T) {
					ts := init(t)

					ts.recvVBlockingChecks(prepareGen{
						qSetHash: ts.qSetHash,
						ballot:   &ts.B[1],
						prepared: &ts.B[1],
					}.make(), false)
					require.Equal(t, 0, len(ts.scp.envs))
				})
			})

			t.Run("prepared B (v-blocking)", func(t *testing.T) {
				ts := init(t)

				ts.recvVBlockingChecks(prepareGen{
					qSetHash: ts.qSetHash,
					ballot:   &ts.B[1],
					prepared: &ts.B[1],
				}.make(), false)
				require.Equal(t, 0, len(ts.scp.envs))
			})

			t.Run("confirm (v-blocking)", func(t *testing.T) {
				t.Run("via CONFIRM", func(t *testing.T) {
					ts := init(t)

					ts.scp.receiveEnvelope(makeConfirm(ts.v[1].secretKey, ts.qSetHash, 0, 3, &ts.A[3], 3, 3))
					ts.scp.receiveEnvelope(makeConfirm(ts.v[2].secretKey, ts.qSetHash, 0, 4, &ts.A[4], 2, 4))
					require.Equal(t, 1, len(ts.scp.envs))

					ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0,
						0, 3, &ts.A[3], 3, 3)

				})

				t.Run("via EXTERNALIZE", func(t *testing.T) {
					ts := init(t)

					ts.scp.receiveEnvelope(makeExternalize(ts.v[1].secretKey, ts.qSetHash, 0, &ts.A[2], 4))
					ts.scp.receiveEnvelope(makeExternalize(ts.v[2].secretKey, ts.qSetHash, 0, &ts.A[3], 5))
					require.Equal(t, 1, len(ts.scp.envs))

					ts.scp.verifyConfirm(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0,
						0, math.MaxUint32, &ts.AInf, 3, math.MaxUint32)
				})
			})
		})

		t.Run("normal round (1,x)", func(t *testing.T) {
			init := func(t *testing.T) *testState {
				ts := init(t)

				ts.nodesAllPledgeToCommit()
				require.Equal(t, 3, len(ts.scp.envs))

				b := &xdr.ScpBallot{
					Counter: 1,
					Value:   xValue,
				}

				// bunch of prepare messages with "commit b"
				prepareC1 := makePrepare(ts.v[1].secretKey, ts.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32(b.Counter))
				prepareC2 := makePrepare(ts.v[2].secretKey, ts.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32(b.Counter))
				prepareC3 := makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32(b.Counter))
				//prepareC4 := makePrepare(ts.v[4].secretKey, ts.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32(b.Counter))

				// those should not trigger anything just yet
				ts.scp.receiveEnvelope(prepareC1)
				ts.scp.receiveEnvelope(prepareC2)
				require.Equal(t, 3, len(ts.scp.envs))

				// this should cause the node to accept 'commit b' (quorum)
				// and therefore send a "CONFIRM" message
				ts.scp.receiveEnvelope(prepareC3)
				require.Equal(t, 4, len(ts.scp.envs))

				ts.scp.verifyConfirm(ts.scp.envs[3], ts.v[0].secretKey, ts.qSetHash0, 0, 1, b,
					uint32(b.Counter), uint32(b.Counter))

				// bunch of confirm messages
				comfirm1 := makeConfirm(ts.v[1].secretKey, ts.qSetHash, 0, uint32(b.Counter), b, uint32(b.Counter),
					uint32(b.Counter))
				comfirm2 := makeConfirm(ts.v[2].secretKey, ts.qSetHash, 0, uint32(b.Counter), b, uint32(b.Counter),
					uint32(b.Counter))
				comfirm3 := makeConfirm(ts.v[3].secretKey, ts.qSetHash, 0, uint32(b.Counter), b, uint32(b.Counter),
					uint32(b.Counter))
				comfirm4 := makeConfirm(ts.v[4].secretKey, ts.qSetHash, 0, uint32(b.Counter), b, uint32(b.Counter),
					uint32(b.Counter))

				// those should not trigger anything just yet
				ts.scp.receiveEnvelope(comfirm1)
				ts.scp.receiveEnvelope(comfirm2)
				require.Equal(t, 4, len(ts.scp.envs))

				ts.scp.receiveEnvelope(comfirm3)
				// this causes our node to
				// externalize (confirm commit c)
				require.Equal(t, 5, len(ts.scp.envs))

				// The slot should have externalized the value
				require.Len(t, ts.scp.externalizedValues, 1)
				require.True(t, bytes.Compare(ts.scp.externalizedValues[0], xValue) == 0)

				ts.scp.verifyExternalize(ts.scp.envs[4], ts.v[0].secretKey, ts.qSetHash, 0, b, uint32(b.Counter))

				// extra vote should not do anything
				ts.scp.receiveEnvelope(comfirm4)
				require.Equal(t, 5, len(ts.scp.envs))
				require.Len(t, ts.scp.externalizedValues, 1)

				// duplicate should just no-op
				ts.scp.receiveEnvelope(comfirm2)
				require.Equal(t, 5, len(ts.scp.envs))
				require.Len(t, ts.scp.externalizedValues, 1)

				return ts
			}

			t.Run("bumpToBallot prevented once committed", func(t *testing.T) {
				prevent := func(ts *testState, b *xdr.ScpBallot) {
					confirm1b2 := makeConfirm(ts.v[1].secretKey, ts.qSetHash, 0, uint32(b.Counter), b,
						uint32(b.Counter), uint32(b.Counter))
					confirm2b2 := makeConfirm(ts.v[2].secretKey, ts.qSetHash, 0, uint32(b.Counter), b,
						uint32(b.Counter), uint32(b.Counter))
					confirm3b2 := makeConfirm(ts.v[3].secretKey, ts.qSetHash, 0, uint32(b.Counter), b,
						uint32(b.Counter), uint32(b.Counter))
					confirm4b2 := makeConfirm(ts.v[4].secretKey, ts.qSetHash, 0, uint32(b.Counter), b,
						uint32(b.Counter), uint32(b.Counter))

					ts.scp.receiveEnvelope(confirm1b2)
					ts.scp.receiveEnvelope(confirm2b2)
					ts.scp.receiveEnvelope(confirm3b2)
					ts.scp.receiveEnvelope(confirm4b2)
					require.Equal(t, 5, len(ts.scp.envs))
					require.Len(t, ts.scp.externalizedValues, 1)
				}

				t.Run("bumpToBallot prevented once committed (by value)", func(t *testing.T) {
					prevent(init(t), &xdr.ScpBallot{
						Counter: 1,
						Value:   yValue,
					})
				})

				t.Run("bumpToBallot prevented once committed (by counter)", func(t *testing.T) {
					prevent(init(t), &xdr.ScpBallot{
						Counter: 2,
						Value:   xValue,
					})
				})

				t.Run("bumpToBallot prevented once committed (by value and counter)", func(t *testing.T) {
					prevent(init(t), &xdr.ScpBallot{
						Counter: 2,
						Value:   yValue,
					})
				})
			})
		})

		t.Run("range check", func(t *testing.T) {
			ts := init(t)
			ts.nodesAllPledgeToCommit()
			require.Len(t, ts.scp.envs, 3)

			b := &xdr.ScpBallot{
				Counter: 1,
				Value:   xValue,
			}

			prepareC1 := makePrepare(ts.v[1].secretKey, ts.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32(b.Counter))
			prepareC2 := makePrepare(ts.v[2].secretKey, ts.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32(b.Counter))
			prepareC3 := makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32(b.Counter))
			//prepareC4 := makePrepare(ts.v[4].secretKey, ts.qSetHash, 0, b, b, nil, uint32(b.Counter), uint32//(b.Counter))

			// those should not trigger anything just yet
			ts.scp.receiveEnvelope(prepareC1)
			ts.scp.receiveEnvelope(prepareC2)
			require.Len(t, ts.scp.envs, 3)

			// this should cause the node to accept 'commit b' (quorum)
			// and therefore send a "CONFIRM" message
			ts.scp.receiveEnvelope(prepareC3)
			require.Len(t, ts.scp.envs, 4)

			ts.scp.verifyConfirm(ts.scp.envs[3], ts.v[0].secretKey, ts.qSetHash0, 0, 1, b, uint32(b.Counter), uint32(b.Counter))

			// bunch of confirm messages with different ranges
			/*b5 := &xdr.ScpBallot{
				Counter: 5,
				Value:   xValue,
			}*/

			confirm1 := makeConfirm(ts.v[1].secretKey, ts.qSetHash, 0, 4, &xdr.ScpBallot{4, xValue}, 2, 4)
			confirm2 := makeConfirm(ts.v[2].secretKey, ts.qSetHash, 0, 6, &xdr.ScpBallot{6, xValue}, 2, 6)
			//confirm3 := makeConfirm(ts.v[3].secretKey, ts.qSetHash, 0, 5, &xdr.ScpBallot{5, xValue}, 3, 5)
			confirm4 := makeConfirm(ts.v[4].secretKey, ts.qSetHash, 0, 6, &xdr.ScpBallot{6, xValue}, 3, 6)

			// this should not trigger anything just yet
			ts.scp.receiveEnvelope(confirm1)

			// v-blocking
			//   * b gets bumped to (4,x)
			//   * p gets bumped to (4,x)
			//   * (c,h) gets bumped to (2,4)
			ts.scp.receiveEnvelope(confirm2)
			require.Len(t, ts.scp.envs, 5)

			ts.scp.verifyConfirm(ts.scp.envs[4], ts.v[0].secretKey, ts.qSetHash0, 0, 4, &xdr.ScpBallot{4, xValue}, 2, 4)

			// this causes to externalize
			// range is [3,4]
			ts.scp.receiveEnvelope(confirm4)
			require.Len(t, ts.scp.envs, 6)

			// The slot should have externalized the value
			require.Len(t, ts.scp.externalizedValues, 1)
			require.True(t, bytes.Compare(ts.scp.externalizedValues[0], xValue) == 0)

			ts.scp.verifyExternalize(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash, 0, &xdr.ScpBallot{3, xValue}, 4)
		})

		t.Run("timeout when h is set -> stay locked on h", func(t *testing.T) {
			ts := init(t)

			bx := &xdr.ScpBallot{
				Counter: 1,
				Value:   xValue,
			}

			require.True(t, ts.scp.BumpState(0, xValue))
			require.Len(t, ts.scp.envs, 1)

			// v-blocking -> prepared
			// quorum -> confirm prepared

			ts.recvQuorum(prepareGen{
				qSetHash: ts.qSetHash,
				ballot:   bx,
				prepared: bx,
			}.make())
			require.Len(t, ts.scp.envs, 3)

			ts.scp.verifyPrepare(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash0, 0, bx, bx, nil, uint32(bx.Counter), uint32(bx.Counter))

			// now, see if we can timeout and move to a different value
			require.True(t, ts.scp.BumpState(0, yValue))
			require.Len(t, ts.scp.envs, 4)
			newbx := &xdr.ScpBallot{
				Counter: 2,
				Value:   xValue,
			}
			ts.scp.verifyPrepare(ts.scp.envs[3], ts.v[0].secretKey, ts.qSetHash0, 0, newbx, bx, nil, uint32(bx.Counter), uint32(bx.Counter))
		})

		t.Run("timeout when h exists but can't be set -> vote for h", func(t *testing.T) {
			ts := init(t)
			// start with (1,y)

			by := &xdr.ScpBallot{
				Counter: 1,
				Value:   yValue,
			}
			require.True(t, ts.scp.BumpState(0, yValue))
			require.Len(t, ts.scp.envs, 1)

			bx := &xdr.ScpBallot{
				Counter: 1,
				Value:   xValue,
			}
			// but quorum goes with (1,x)
			// v-blocking -> prepared

			ts.recvVBlocking(prepareGen{
				qSetHash: ts.qSetHash,
				ballot:   bx,
				prepared: bx,
			}.make())
			require.Len(t, ts.scp.envs, 2)

			ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0, 0, by, bx, nil, 0, 0)
			// quorum -> confirm prepared (no-op as b > h)
			ts.recvQuorumChecks(prepareGen{
				qSetHash: ts.qSetHash,
				ballot:   bx,
				prepared: bx,
			}.make(), false, false)
			require.Len(t, ts.scp.envs, 2)

			require.True(t, ts.scp.BumpState(0, yValue))
			require.Len(t, ts.scp.envs, 3)
			newbx := &xdr.ScpBallot{
				Counter: 2,
				Value:   xValue,
			}
			// on timeout:
			// * we should move to the quorum's h value
			// * c can't be set yet as b > h

			ts.scp.verifyPrepare(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash0, 0, newbx, bx, nil, 0, uint32(bx.Counter))
		})

		t.Run("timeout from multiple nodes", func(t *testing.T) {
			ts := init(t)

			require.True(t, ts.scp.BumpState(0, xValue))

			x1 := &xdr.ScpBallot{
				Counter: 1,
				Value:   xValue,
			}

			require.Len(t, ts.scp.envs, 1)
			ts.scp.verifyPrepare(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, x1, nil, nil, 0, 0)

			ts.recvQuorum(prepareGen{
				qSetHash: ts.qSetHash,
				ballot:   x1,
			}.make())
			// quorum -> prepared (1,x)
			require.Len(t, ts.scp.envs, 2)
			ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0, 0, x1, x1, nil, 0, 0)

			x2 := &xdr.ScpBallot{
				Counter: 2,
				Value:   xValue,
			}
			// timeout from local node
			require.True(t, ts.scp.BumpState(0, xValue))
			// prepares (2,x)
			require.Len(t, ts.scp.envs, 3)
			ts.scp.verifyPrepare(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash0, 0, x2, x1, nil, 0, 0)

			ts.recvQuorum(prepareGen{
				qSetHash: ts.qSetHash,
				ballot:   x1,
				prepared: x1,
			}.make())
			// quorum -> set nH=1
			require.Len(t, ts.scp.envs, 4)
			ts.scp.verifyPrepare(ts.scp.envs[3], ts.v[0].secretKey, ts.qSetHash0, 0, x2, x1, nil, 0, 1)
			require.Len(t, ts.scp.envs, 4)

			ts.recvVBlocking(prepareGen{
				qSetHash: ts.qSetHash,
				ballot:   x2,
				prepared: x2,
				nC:       1,
				nH:       1,
			}.make())
			// v-blocking prepared (2,x) -> prepared (2,x)
			require.Len(t, ts.scp.envs, 5)
			ts.scp.verifyPrepare(ts.scp.envs[4], ts.v[0].secretKey, ts.qSetHash0, 0, x2, x2, nil, 0, 1)

			ts.recvQuorum(prepareGen{
				qSetHash: ts.qSetHash,
				ballot:   x2,
				prepared: x2,
				nC:       1,
				nH:       1,
			}.make())
			// quorum (including us) confirms (2,x) prepared -> set h=c=x2
			// we also get extra message: a quorum not including us confirms (1,x)
			// prepared
			//  -> we confirm c=h=x1
			require.Len(t, ts.scp.envs, 7)

			ts.scp.verifyPrepare(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash0, 0, x2, x2, nil, 2, 2)
			ts.scp.verifyConfirm(ts.scp.envs[6], ts.v[0].secretKey, ts.qSetHash0, 0, 2, x2, 1, 1)
		})

		t.Run("timeout after prepare, receive old messages to prepare", func(t *testing.T) {
			ts := init(t)
			require.True(t, ts.scp.BumpState(0, xValue))

			x1 := &xdr.ScpBallot{
				Counter: 1,
				Value:   xValue,
			}
			require.Len(t, ts.scp.envs, 1)
			ts.scp.verifyPrepare(ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, x1, nil, nil, 0, 0)

			ts.scp.receiveEnvelope(makePrepareD(ts.v[1].secretKey, ts.qSetHash, 0, x1))
			ts.scp.receiveEnvelope(makePrepareD(ts.v[2].secretKey, ts.qSetHash, 0, x1))
			ts.scp.receiveEnvelope(makePrepareD(ts.v[3].secretKey, ts.qSetHash, 0, x1))

			// quorum -> prepared (1,x)
			require.Len(t, ts.scp.envs, 2)
			ts.scp.verifyPrepare(ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0, 0, x1, x1, nil, 0, 0)

			x2 := &xdr.ScpBallot{
				Counter: 2,
				Value:   xValue,
			}
			// timeout from local node

			require.True(t, ts.scp.BumpState(0, xValue))
			// prepares (2,x)
			require.Len(t, ts.scp.envs, 3)
			ts.scp.verifyPrepare(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash0, 0, x2, x1, nil, 0, 0)

			x3 := &xdr.ScpBallot{
				Counter: 3,
				Value:   xValue,
			}
			// timeout again
			require.True(t, ts.scp.BumpState(0, xValue))
			// prepares (3,x)
			require.Len(t, ts.scp.envs, 4)
			ts.scp.verifyPrepare(ts.scp.envs[3], ts.v[0].secretKey, ts.qSetHash0, 0, x3, x1, nil, 0, 0)

			// other nodes moved on with x2
			ts.scp.receiveEnvelope(makePrepare(ts.v[1].secretKey, ts.qSetHash, 0, x2, x2, nil, 1, 2))
			ts.scp.receiveEnvelope(makePrepare(ts.v[2].secretKey, ts.qSetHash, 0, x2, x2, nil, 1, 2))
			// v-blocking -> prepared x2
			require.Len(t, ts.scp.envs, 5)
			ts.scp.verifyPrepare(ts.scp.envs[4], ts.v[0].secretKey, ts.qSetHash0, 0, x3, x2, nil, 0, 0)

			ts.scp.receiveEnvelope(makePrepare(ts.v[3].secretKey, ts.qSetHash, 0, x2, x2, nil, 1, 2))
			// quorum -> set nH=2
			require.Len(t, ts.scp.envs, 6)
			ts.scp.verifyPrepare(ts.scp.envs[5], ts.v[0].secretKey, ts.qSetHash0, 0, x3, x2, nil, 0, 2)
		})

		t.Run("non validator watching the network", func(t *testing.T) {
			ts := init(t)

			s := newSimulation(32)
			scpNV := newTestSCP(s.publicKey, &ts.qSet, false)
			scpNV.StoreQuorumSet(&ts.qSet)
			qSetHashNV := scpNV.scp.LocalNode().QuorumSetHash()

			b := &xdr.ScpBallot{
				Counter: 1,
				Value:   xValue,
			}

			require.True(t, scpNV.BumpState(0, xValue))
			require.Len(t, scpNV.envs, 0)
			ts.scp.verifyPrepare(scpNV.getCurrentEnvelope(0, xdr.NodeId(s.publicKey)), s.secretKey, qSetHashNV, 0, b, nil, nil, 0, 0)

			ext1 := makeExternalize(ts.v[1].secretKey, ts.qSetHash, 0, b, 1)
			ext2 := makeExternalize(ts.v[2].secretKey, ts.qSetHash, 0, b, 1)
			ext3 := makeExternalize(ts.v[3].secretKey, ts.qSetHash, 0, b, 1)
			ext4 := makeExternalize(ts.v[4].secretKey, ts.qSetHash, 0, b, 1)

			scpNV.receiveEnvelope(ext1)
			scpNV.receiveEnvelope(ext2)
			scpNV.receiveEnvelope(ext3)
			require.Len(t, scpNV.envs, 0)

			ts.scp.verifyConfirm(scpNV.getCurrentEnvelope(0, xdr.NodeId(s.publicKey)), s.secretKey, qSetHashNV, 0, math.MaxUint32, &xdr.ScpBallot{math.MaxUint32, xValue}, 1, math.MaxUint32)

			scpNV.receiveEnvelope(ext4)
			require.Len(t, scpNV.envs, 0)
			ts.scp.verifyExternalize(scpNV.getCurrentEnvelope(0, xdr.NodeId(s.publicKey)), s.secretKey, qSetHashNV, 0, b, math.MaxUint32)

			require.True(t, bytes.Equal(scpNV.externalizedValues[0], xValue))
		})

		t.Run("restore ballot protocol", func(t *testing.T) {
			t.Run("prepare", func(t *testing.T) {
				ts := init(t)
				scp2 := newTestSCP(ts.v[0].publicKey, &ts.qSet, true)
				scp2.StoreQuorumSet(&ts.qSet)
				b := xdr.ScpBallot{
					Counter: 2,
					Value:   xValue,
				}

				scp2.scp.SetStateFromEnvelope(0, makePrepareD(ts.v[0].secretKey, ts.qSetHash0, 0, &b))
			})

			t.Run("confirm", func(t *testing.T) {
				ts := init(t)
				scp2 := newTestSCP(ts.v[0].publicKey, &ts.qSet, true)
				scp2.StoreQuorumSet(&ts.qSet)
				b := xdr.ScpBallot{
					Counter: 2,
					Value:   xValue,
				}

				scp2.scp.SetStateFromEnvelope(0,
					makeConfirm(ts.v[0].secretKey, ts.qSetHash0, 0, 2, &b, 1, 2))
			})

			t.Run("externalize", func(t *testing.T) {
				ts := init(t)
				scp2 := newTestSCP(ts.v[0].publicKey, &ts.qSet, true)
				scp2.StoreQuorumSet(&ts.qSet)
				b := xdr.ScpBallot{
					Counter: 2,
					Value:   xValue,
				}

				scp2.scp.SetStateFromEnvelope(0,
					makeExternalize(ts.v[0].secretKey, ts.qSetHash0, 0, &b, 2))
			})
		})
	})

	t.Run("ballot protocol core3 (scp)", func(t *testing.T) {

		v0 := newSimulation(1)
		v1 := newSimulation(2)
		v2 := newSimulation(3)

		// core3 has an edge case where v-blocking and quorum can be the same
		// v-blocking set size: 2
		// threshold: 2 = 1 + self or 2 others

		qSet := xdr.ScpQuorumSet{
			Threshold:  2,
			Validators: []xdr.PublicKey{v0.publicKey, v1.publicKey, v2.publicKey},
		}

		b, err := qSet.MarshalBinary()
		if err != nil {
			panic(err)
		}
		qSetHash := sha256.Sum256(b)
		_ = qSetHash

		scp := newTestSCP(v0.publicKey, &qSet, true)
		scp.T = t
		scp.StoreQuorumSet(&qSet)
		qSetHash0 := scp.scp.localNode.QuorumSetHash()
		_ = qSetHash0

		require.True(t, bytes.Compare(xValue, yValue) < 0)

		recvQuorumChecksEx2 := func(gen genEnvelope, withChecks, delayedQuorum, checkUpcoming, minQuorum bool) {
			e1 := gen(v1.secretKey)
			e2 := gen(v2.secretKey)

			scp.bumpTimerOffset()
			i := len(scp.envs) + 1
			scp.receiveEnvelope(e1)
			if withChecks && !delayedQuorum {
				require.True(t, len(scp.envs) == i)
			}
			if checkUpcoming && !delayedQuorum {
				require.True(t, scp.hasBallotTimerUpcoming())
			}
			if !minQuorum {
				// nothing happens with an extra vote (unless we're in
				// delayedQuorum)
				scp.receiveEnvelope(e2)
				if withChecks {
					require.True(t, len(scp.envs) == i)
				}
			}
		}

		recvQuorumChecksEx := func(gen genEnvelope, withChecks, delayedQuorum, checkUpcoming bool) {
			recvQuorumChecksEx2(gen, withChecks, delayedQuorum, checkUpcoming, false)
		}
		recvQuorumChecks := func(gen genEnvelope, withChecks, delayedQuorum bool) {
			recvQuorumChecksEx(gen, withChecks, delayedQuorum, false)
		}
		recvQuorumEx := func(gen genEnvelope, checkUpcoming bool) {
			recvQuorumChecksEx(gen, true, false, checkUpcoming)
		}
		recvQuorum := func(gen genEnvelope) {
			recvQuorumEx(gen, false)
		}
		_, _ = recvQuorumChecks, recvQuorum

		// no timer is set
		require.False(t, scp.hasBallotProtocolTimer())

		aValue := yValue
		bValue := xValue

		A1 := xdr.ScpBallot{
			Counter: 1,
			Value:   aValue,
		}
		_ = A1
		B1 := xdr.ScpBallot{
			Counter: 1,
			Value:   bValue,
		}

		A2 := A1
		A2.Counter++

		A3 := A2
		A3.Counter++

		A4 := A3
		A4.Counter++

		A5 := A4
		A5.Counter++

		Ainf := xdr.ScpBallot{
			Counter: math.MaxUint32,
			Value:   bValue,
		}
		_ = Ainf

		B2 := B1
		B2.Counter++

		B3 := B2
		B3.Counter++

		require.True(t, scp.BumpState(0, aValue))
		require.Len(t, scp.envs, 1)
		require.False(t, scp.hasBallotProtocolTimer())

		t.Run("prepared B1 (quorum votes B1)", func(t *testing.T) {
			scp.bumpTimerOffset()
			recvQuorumChecks(prepareGen{
				qSetHash: qSetHash,
				ballot:   &B1,
			}.make(), true, true)
			require.Len(t, scp.envs, 2)
			scp.verifyPrepare(scp.envs[1], v0.secretKey, qSetHash0, 0, &A1, &B1, nil, 0, 0)
			require.True(t, scp.hasBallotTimerUpcoming())

			t.Run("quorum prepared B1", func(t *testing.T) {
				scp.bumpTimerOffset()
				recvQuorumChecks(prepareGen{
					qSetHash: qSetHash,
					ballot:   &B1,
					prepared: &B1,
				}.make(), false, false)
				require.Len(t, scp.envs, 2)
				// nothing happens:
				// computed_h = B1 (2)
				//    does not actually update h as b > computed_h
				//    also skips (3)
				require.False(t, scp.hasBallotTimerUpcoming())

				t.Run("quorum bumps to A1", func(t *testing.T) {
					scp.bumpTimerOffset()
					recvQuorumChecksEx2(prepareGen{
						qSetHash: qSetHash,
						ballot:   &A1,
						prepared: &B1,
					}.make(), false, false, false, true)

					require.Len(t, scp.envs, 3)
					// still does not set h as b > computed_h
					scp.verifyPrepare(scp.envs[2], v0.secretKey, qSetHash0, 0, &A1, &A1, &B1, 0, 0)
					require.False(t, scp.hasBallotTimerUpcoming())

					scp.bumpTimerOffset()
					// quorum commits A1
					recvQuorumChecksEx2(prepareGen{
						qSetHash:      qSetHash,
						ballot:        &A2,
						prepared:      &A1,
						preparedPrime: &B1,
						nC:            1,
						nH:            1,
					}.make(), false, false, false, true)

					require.Len(t, scp.envs, 4)
					scp.verifyConfirm(scp.envs[3], v0.secretKey, qSetHash0, 0, 2, &A1, 1, 1)
					require.False(t, scp.hasBallotTimerUpcoming())
				})
			})
		})
	})

	t.Run("nomination protocol", func(t *testing.T) {
		init := func(t *testing.T) *testState {
			v0 := newSimulation(0)
			v1 := newSimulation(1)
			v2 := newSimulation(2)
			v3 := newSimulation(3)
			v4 := newSimulation(4)

			// we need 5 nodes to avoid sharing various thresholds:
			// v-blocking set size: 2
			// threshold: 4 = 3 + self or 4 others

			qSet := xdr.ScpQuorumSet{
				Threshold:  4,
				Validators: []xdr.PublicKey{v0.publicKey, v1.publicKey, v2.publicKey, v3.publicKey, v4.publicKey},
			}

			b, err := qSet.MarshalBinary()
			if err != nil {
				panic(err)
			}
			qSetHash := sha256.Sum256(b)
			_ = qSetHash

			require.True(t, bytes.Compare(xValue, yValue) < 0)

			return &testState{
				T:        t,
				v:        [5]simulationNode{*v0, *v1, *v2, *v3, *v4},
				qSetHash: qSetHash,
				qSet:     qSet,
			}
		}

		t.Run("nomination - v0 is top", func(t *testing.T) {
			init := func(t *testing.T) *testState {
				ts := init(t)
				ts.scp = newTestSCP(ts.v[0].publicKey, &ts.qSet, true)
				ts.scp.T = t
				ts.qSetHash0 = ts.scp.scp.LocalNode().QuorumSetHash()
				ts.scp.StoreQuorumSet(&ts.qSet)

				return ts
			}

			t.Run("others nominate what v0 says (x) -> prepare x", func(t *testing.T) {
				init := func(t *testing.T) *testState {
					ts := init(t)
					require.True(t, ts.scp.nominate(0, xValue, false))

					var votes, accepted []xdr.Value
					votes = append(votes, xValue)

					require.Len(t, ts.scp.envs, 1)
					ts.scp.verifyNominate(
						ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, votes, accepted,
					)

					ts.nom[1] = makeNominate(ts.v[1].secretKey, ts.qSetHash, 0, votes, accepted)
					ts.nom[2] = makeNominate(ts.v[2].secretKey, ts.qSetHash, 0, votes, accepted)
					ts.nom[3] = makeNominate(ts.v[3].secretKey, ts.qSetHash, 0, votes, accepted)
					ts.nom[4] = makeNominate(ts.v[4].secretKey, ts.qSetHash, 0, votes, accepted)

					// nothing happens yet
					ts.scp.receiveEnvelope(ts.nom[1])
					ts.scp.receiveEnvelope(ts.nom[2])
					require.Len(t, ts.scp.envs, 1)

					// this causes 'x' to be accepted (quorum)
					ts.scp.receiveEnvelope(ts.nom[3])
					require.Len(t, ts.scp.envs, 2)

					ts.scp.expectedCandidates.Put(xValue)
					ts.scp.compositeValue = xValue

					accepted = append(accepted, xValue)
					ts.scp.verifyNominate(
						ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0, 0, votes, accepted,
					)

					// extra message doesn't do anything
					ts.scp.receiveEnvelope(ts.nom[4])
					require.Len(t, ts.scp.envs, 2)

					ts.acc[1] = makeNominate(ts.v[1].secretKey, ts.qSetHash, 0, votes, accepted)
					ts.acc[2] = makeNominate(ts.v[2].secretKey, ts.qSetHash, 0, votes, accepted)
					ts.acc[3] = makeNominate(ts.v[3].secretKey, ts.qSetHash, 0, votes, accepted)
					ts.acc[4] = makeNominate(ts.v[4].secretKey, ts.qSetHash, 0, votes, accepted)

					// nothing happens yet
					ts.scp.receiveEnvelope(ts.acc[1])
					ts.scp.receiveEnvelope(ts.acc[2])
					require.Len(t, ts.scp.envs, 2)

					ts.scp.compositeValue = xValue
					// this causes the node to send a prepare message (quorum)
					ts.scp.receiveEnvelope(ts.acc[3])
					require.Len(t, ts.scp.envs, 3)

					ts.scp.verifyPrepareD(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash, 0, &xdr.ScpBallot{1, xValue})

					ts.scp.receiveEnvelope(ts.acc[4])
					require.Len(t, ts.scp.envs, 3)

					ts.votes = votes
					ts.votes2 = append(votes, yValue)
					ts.accepted = accepted
					return ts
				}

				t.Run(`nominate x -> accept x -> prepare (x) ; others accepted y 
				-> update latest to (z=x+y)`, func(t *testing.T) {
					ts := init(t)

					acc1 := makeNominate(ts.v[1].secretKey, ts.qSetHash, 0, ts.votes2, ts.votes2)
					acc2 := makeNominate(ts.v[2].secretKey, ts.qSetHash, 0, ts.votes2, ts.votes2)
					acc3 := makeNominate(ts.v[3].secretKey, ts.qSetHash, 0, ts.votes2, ts.votes2)
					acc4 := makeNominate(ts.v[4].secretKey, ts.qSetHash, 0, ts.votes2, ts.votes2)

					ts.scp.receiveEnvelope(acc1)
					require.Len(t, ts.scp.envs, 3)

					// v-blocking
					ts.scp.receiveEnvelope(acc2)
					require.Len(t, ts.scp.envs, 4)
					ts.scp.verifyNominate(
						ts.scp.envs[3], ts.v[0].secretKey, ts.qSetHash0, 0, ts.votes2, ts.votes2,
					)

					ts.scp.expectedCandidates.Put(yValue)
					ts.scp.compositeValue = zValue
					// this updates the composite value to use next time
					// but does not prepare it
					ts.scp.receiveEnvelope(acc3)
					require.Len(t, ts.scp.envs, 4)

					require.True(t, bytes.Compare(ts.scp.getLatestCompositeCandidate(0), zValue) == 0)

					ts.scp.receiveEnvelope(acc4)
					require.Len(t, ts.scp.envs, 4)
				})

				t.Run("nomination - restored state", func(t *testing.T) {
					// at this point
					// votes = { x }
					// accepted = { x }

					// tests if nomination proceeds like normal
					// nominates x
					nominateRestore := func(ts *testState, scp2 *testSCP) {
						// restores from the previous state
						scp2.scp.SetStateFromEnvelope(0, makeNominate(
							ts.v[0].secretKey, ts.qSetHash0, 0, ts.votes, ts.accepted,
						))
						// tries to start nomination with yValue
						require.True(t, scp2.nominate(0, yValue, false))

						require.Len(t, scp2.envs, 1)
						ts.scp.verifyNominate(
							scp2.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, ts.votes2, ts.accepted,
						)

						// other nodes vote for 'x'
						scp2.receiveEnvelope(ts.nom[1])
						scp2.receiveEnvelope(ts.nom[2])
						require.Len(t, scp2.envs, 1)
						// 'x' is accepted (quorum)
						// but because the restored state already included
						// 'x' in the accepted set, no new message is emitted
						scp2.receiveEnvelope(ts.nom[3])

						scp2.expectedCandidates.Put(xValue)
						scp2.compositeValue = xValue

						// other nodes not emit 'x' as accepted
						scp2.receiveEnvelope(ts.acc[1])
						scp2.receiveEnvelope(ts.acc[2])
						require.Len(t, scp2.envs, 1)

						scp2.compositeValue = xValue
						// this causes the node to update its composite value to x
						scp2.receiveEnvelope(ts.acc[3])
					}

					t.Run("ballot protocol not started", func(t *testing.T) {
						ts := init(t)
						scp2 := newTestSCP(ts.v[0].publicKey, &ts.qSet, true)
						scp2.T = t
						scp2.StoreQuorumSet(&ts.qSet)

						// nomination ended up starting the ballot protocol
						nominateRestore(ts, scp2)
						require.Len(t, scp2.envs, 2)
						ts.scp.verifyPrepareD(scp2.envs[1], ts.v[0].secretKey, ts.qSetHash0, 0, &xdr.ScpBallot{1, xValue})
					})

					t.Run("ballot protocol started (on value z)", func(t *testing.T) {
						ts := init(t)
						scp2 := newTestSCP(ts.v[0].publicKey, &ts.qSet, true)
						scp2.T = t
						scp2.StoreQuorumSet(&ts.qSet)
						scp2.scp.SetStateFromEnvelope(0, makePrepareD(
							ts.v[0].secretKey, ts.qSetHash0, 0, &xdr.ScpBallot{1, zValue},
						))
						nominateRestore(ts, scp2)
						// nomination didn't do anything (already working on z)
						require.Len(t, scp2.envs, 1)
					})
				})
			})

			t.Run("self nominates 'x', others nominate y -> prepare y", func(t *testing.T) {
				init := func(t *testing.T) *testState {
					ts := init(t)

					ts.myVotes = []xdr.Value{xValue}
					ts.accepted = nil

					ts.scp.expectedCandidates = append(ts.scp.expectedCandidates, xValue)
					ts.scp.compositeValue = xValue
					require.True(t, ts.scp.nominate(0, xValue, false))

					require.Len(t, ts.scp.envs, 1)
					ts.scp.verifyNominate(
						ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, ts.myVotes, ts.accepted,
					)

					ts.votes = []xdr.Value{yValue}
					ts.acceptedY = append(ts.accepted, yValue)

					return ts
				}

				t.Run("others only vote for y", func(t *testing.T) {
					ts := init(t)

					ts.nom[1] = makeNominate(ts.v[1].secretKey, ts.qSetHash, 0, ts.votes, ts.accepted)
					ts.nom[2] = makeNominate(ts.v[2].secretKey, ts.qSetHash, 0, ts.votes, ts.accepted)
					ts.nom[3] = makeNominate(ts.v[3].secretKey, ts.qSetHash, 0, ts.votes, ts.accepted)
					ts.nom[4] = makeNominate(ts.v[4].secretKey, ts.qSetHash, 0, ts.votes, ts.accepted)

					// nothing happens yet
					ts.scp.receiveEnvelope(ts.nom[1])
					ts.scp.receiveEnvelope(ts.nom[2])
					ts.scp.receiveEnvelope(ts.nom[3])
					require.Len(t, ts.scp.envs, 1)

					// 'y' is accepted (quorum)
					ts.scp.receiveEnvelope(ts.nom[4])
					require.Len(t, ts.scp.envs, 2)

					ts.myVotes = append(ts.myVotes, yValue)
					ts.scp.verifyNominate(
						ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0, 0, ts.myVotes, ts.acceptedY,
					)
				})

				t.Run("others accepted y", func(t *testing.T) {
					ts := init(t)

					acc1 := makeNominate(ts.v[1].secretKey, ts.qSetHash, 0, ts.votes, ts.acceptedY)
					acc2 := makeNominate(ts.v[2].secretKey, ts.qSetHash, 0, ts.votes, ts.acceptedY)
					acc3 := makeNominate(ts.v[3].secretKey, ts.qSetHash, 0, ts.votes, ts.acceptedY)
					acc4 := makeNominate(ts.v[4].secretKey, ts.qSetHash, 0, ts.votes, ts.acceptedY)

					ts.scp.receiveEnvelope(acc1)
					require.Len(t, ts.scp.envs, 1)

					// this causes 'y' to be accepted (v-blocking)
					ts.scp.receiveEnvelope(acc2)
					require.Len(t, ts.scp.envs, 2)

					ts.myVotes = append(ts.myVotes, yValue)
					ts.scp.verifyNominate(
						ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0, 0, ts.myVotes, ts.acceptedY,
					)

					ts.scp.expectedCandidates = nil
					ts.scp.expectedCandidates.Put(yValue)
					ts.scp.compositeValue = yValue
					// this causes the node to send a prepare message (quorum)
					ts.scp.receiveEnvelope(acc3)
					require.Len(t, ts.scp.envs, 3)

					ts.scp.verifyPrepareD(ts.scp.envs[2], ts.v[0].secretKey, ts.qSetHash0, 0, &xdr.ScpBallot{1, yValue})

					ts.scp.receiveEnvelope(acc4)
					require.Len(t, ts.scp.envs, 3)
				})
			})
		})

		t.Run("v1 is top node", func(t *testing.T) {
			votesX := []xdr.Value{xValue}
			votesY := []xdr.Value{yValue}
			votesZ := []xdr.Value{zValue}

			votesXY := []xdr.Value{xValue, yValue}
			votesYZ := []xdr.Value{yValue, zValue}
			votesXZ := []xdr.Value{xValue, zValue}

			valuesHash := []xdr.Value{xValue, yValue, zValue}

			ts := init(t)
			nom1 := makeNominate(ts.v[1].secretKey, ts.qSetHash, 0, votesXY, nil)
			nom2 := makeNominate(ts.v[2].secretKey, ts.qSetHash, 0, votesXZ, nil)

			init := func(t *testing.T) *testState {
				ts := init(t)
				scp := newTestSCP(ts.v[0].publicKey, &ts.qSet, true)
				scp.T = t
				scp.StoreQuorumSet(&ts.qSet)
				ts.scp = scp
				ts.qSetHash0 = ts.scp.scp.LocalNode().QuorumSetHash()
				scp.priorityLookup = func(pk xdr.PublicKey) uint64 {
					if *pk.Ed25519 == *ts.v[1].publicKey.Ed25519 {
						return 1000
					}

					return 1
				}
				scp.HashValueCalculator = func(v xdr.Value) uint64 {
					for i, h := range valuesHash {
						if bytes.Equal(h, v) {
							return 1 + uint64(i)
						}
					}
					panic(nil)
				}

				return ts
			}

			t.Run("nomination waits for v1", func(t *testing.T) {
				ts := init(t)
				require.False(t, ts.scp.nominate(0, xValue, false))
				require.Len(t, ts.scp.envs, 0)

				nom3 := makeNominate(ts.v[3].secretKey, ts.qSetHash, 0, votesYZ, nil)
				nom4 := makeNominate(ts.v[4].secretKey, ts.qSetHash, 0, votesXZ, nil)

				// nothing happens with non top nodes
				ts.scp.receiveEnvelope(nom2)
				ts.scp.receiveEnvelope(nom3)
				require.Len(t, ts.scp.envs, 0)

				ts.scp.receiveEnvelope(nom1)
				require.Len(t, ts.scp.envs, 1)
				ts.scp.verifyNominate(
					ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash, 0, votesY, nil,
				)

				ts.scp.receiveEnvelope(nom4)
				require.Len(t, ts.scp.envs, 1)

				t.Run("timeout -> pick another value from v1", func(t *testing.T) {
					ts.scp.expectedCandidates.Put(xValue)
					ts.scp.compositeValue = xValue

					// note: value passed in here should be ignored
					require.True(t, ts.scp.nominate(0, zValue, true))
					// picks up 'x' from v1 (as we already have 'y')
					// which also happens to causes 'x' to be accepted
					require.Len(t, ts.scp.envs, 2)
					ts.scp.verifyNominate(
						ts.scp.envs[1], ts.v[0].secretKey, ts.qSetHash0, 0, votesXY, votesX,
					)
				})
			})

			t.Run("v1 dead, timeout", func(t *testing.T) {
				init := func(t *testing.T) *testState {
					ts := init(t)
					require.False(t, ts.scp.nominate(0, xValue, false))
					require.Len(t, ts.scp.envs, 0)
					ts.scp.receiveEnvelope(nom2)
					require.Len(t, ts.scp.envs, 0)
					return ts
				}

				t.Run("v0 is new top node", func(t *testing.T) {
					ts := init(t)

					ts.scp.priorityLookup = func(pk xdr.PublicKey) uint64 {
						if *pk.Ed25519 == *ts.v[0].publicKey.Ed25519 {
							return 1000
						}

						return 1
					}

					require.True(t, ts.scp.nominate(0, xValue, true))
					require.Len(t, ts.scp.envs, 1)
					ts.scp.verifyNominate(
						ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, votesX, nil,
					)
				})

				t.Run("v2 is new top node", func(t *testing.T) {
					ts := init(t)

					ts.scp.priorityLookup = func(pk xdr.PublicKey) uint64 {
						if *pk.Ed25519 == *ts.v[2].publicKey.Ed25519 {
							return 1000
						}

						return 1
					}

					require.True(t, ts.scp.nominate(0, xValue, true))
					require.Len(t, ts.scp.envs, 1)
					ts.scp.verifyNominate(
						ts.scp.envs[0], ts.v[0].secretKey, ts.qSetHash0, 0, votesZ, nil,
					)
				})

				t.Run("v3 is new top node", func(t *testing.T) {
					ts := init(t)

					ts.scp.priorityLookup = func(pk xdr.PublicKey) uint64 {
						if *pk.Ed25519 == *ts.v[3].publicKey.Ed25519 {
							return 1000
						}

						return 1
					}

					// nothing happens, we don't have any message for v3
					require.False(t, ts.scp.nominate(0, xValue, true))
					require.Len(t, ts.scp.envs, 0)
				})
			})

		})
	})

}

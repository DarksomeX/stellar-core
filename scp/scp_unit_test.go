package scp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/agl/ed25519"
	"github.com/stellar/go/xdr"
)

type simulationNode struct {
	hash      xdr.Hash
	secretKey [64]byte
	publicKey xdr.PublicKey
}

func newSimulation(i int) *simulationNode {
	hash := sha256.Sum256([]byte(fmt.Sprintf("NODE_SEED_%d", i)))

	reader := bytes.NewReader(hash[:])
	pub, seed, err := ed25519.GenerateKey(reader)
	if err != nil {
		panic(err)
	}

	uint256 := xdr.Uint256(*pub)

	return &simulationNode{
		hash:      hash,
		secretKey: *seed,
		publicKey: xdr.PublicKey{
			Ed25519: &uint256,
		},
	}
}

func isNear(r uint64, target float64) bool {
	v := float64(r) / float64(math.MaxUint64)
	return math.Abs(v-target) < 0.01
}

func TestSCPUnit(t *testing.T) {
	t.Log("nomination weight", "[scp]")

	s1 := newSimulation(1)
	s2 := newSimulation(2)
	s3 := newSimulation(3)
	s4 := newSimulation(4)
	s5 := newSimulation(5)

	qSet := xdr.ScpQuorumSet{
		Threshold: 3,
		Validators: []xdr.PublicKey{
			s1.publicKey,
			s2.publicKey,
			s3.publicKey,
			s4.publicKey,
		},
	}

	result := getNodeWeight(xdr.NodeId(s3.publicKey), &qSet)
	require.True(t, isNear(result, 0.75))

	result = getNodeWeight(xdr.NodeId(s5.publicKey), &qSet)
	require.Equal(t, result, uint64(0))

	iQSet := xdr.ScpQuorumSet{
		Threshold: 1,
		Validators: []xdr.PublicKey{
			s4.publicKey,
			s5.publicKey,
		},
	}
	qSet.InnerSets = append(qSet.InnerSets, iQSet)

	result = getNodeWeight(xdr.NodeId(s5.publicKey), &qSet)
	require.True(t, isNear(result, 0.6*0.5))
}

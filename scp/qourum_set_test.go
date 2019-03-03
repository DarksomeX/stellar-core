package scp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/agl/ed25519"
	"github.com/stretchr/testify/require"

	"github.com/stellar/go/xdr"
)

func TestQourumSet(t *testing.T) {
	makePublicKey := func(i int) xdr.PublicKey {
		hash := sha256.Sum256([]byte(fmt.Sprintf("NODE_SEED_%d", i)))

		reader := bytes.NewReader(hash[:])
		pub, _, err := ed25519.GenerateKey(reader)
		if err != nil {
			panic(err)
		}

		uint256 := xdr.Uint256(*pub)
		return xdr.PublicKey{
			Ed25519: &uint256,
		}
	}

	makeSingleton := func(pub xdr.PublicKey) xdr.ScpQuorumSet {
		return xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: []xdr.PublicKey{pub},
		}
	}

	keys := make([]xdr.PublicKey, 0, 1000)
	for i := 1; i <= 1001; i++ {
		keys = append(keys, makePublicKey(i))
	}

	check := func(qSetCheck *xdr.ScpQuorumSet, expected bool, expectedSelfQSet *xdr.ScpQuorumSet) {
		// first, without normalization
		require.Equal(t, expected, isQuorumSetSane(qSetCheck, false))

		// secondary test: attempts to build local node with the set
		// (this normalizes the set)
		normalizedQSet := *qSetCheck
		normalizeQSet(&normalizedQSet, nil)

		require.Equal(t, normalizedQSet, *expectedSelfQSet)
	}

	t.Log("{ t: 0 }")
	{
		qSet := new(xdr.ScpQuorumSet)
		qSet.Threshold = 0
		check(qSet, false, qSet)
	}

	validOneNode := makeSingleton(keys[0])

	t.Log("{ t: 0, v0 }")
	{
		qSet := validOneNode
		qSet.Threshold = 0
		check(&qSet, false, &qSet)
	}

	t.Log("{ t: 2, v0 }")
	{
		qSet := validOneNode
		qSet.Threshold = 2
		check(&qSet, false, &qSet)
	}

	t.Log("{ t: 1, v0 }")
	{
		check(&validOneNode, true, &validOneNode)
	}

	t.Log("{ t: 1, v0, { t: 1, v1 } -> { t:1, v0, v1 }")
	{
		qSet := xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: []xdr.PublicKey{keys[0]},
		}

		selfSet := qSet
		selfSet.Validators = append(selfSet.Validators, keys[1])

		qSet.InnerSets = append(qSet.InnerSets, xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: []xdr.PublicKey{keys[1]},
		})

		check(&qSet, true, &selfSet)
	}

	t.Log("{ t: 1, v0, { t: 1, v1 }, { t: 2, v2 } } -> { t:1, v0, v1, { t: 2, v2 } }")
	{
		qSet := xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: []xdr.PublicKey{keys[0]},
		}

		innerSet := xdr.ScpQuorumSet{
			Threshold:  2,
			Validators: []xdr.PublicKey{keys[1]},
		}

		qSet.InnerSets = append(qSet.InnerSets, innerSet)

		qSelfSet := qSet
		qSelfSet.Validators = append(qSelfSet.Validators, keys[2])

		innerSet2 := xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: []xdr.PublicKey{keys[2]},
		}

		qSet.InnerSets = append(qSet.InnerSets, innerSet2)

		check(&qSet, false, &qSelfSet)
	}

	validMultipleNodes := xdr.ScpQuorumSet{
		Threshold:  1,
		Validators: []xdr.PublicKey{keys[0]},
		InnerSets: []xdr.ScpQuorumSet{
			xdr.ScpQuorumSet{
				Threshold:  1,
				Validators: []xdr.PublicKey{keys[1]},
			},
			xdr.ScpQuorumSet{
				Threshold:  1,
				Validators: []xdr.PublicKey{keys[2], keys[3]},
			},
		},
	}

	validMulpipleNodesNormalized := xdr.ScpQuorumSet{
		Threshold:  1,
		Validators: []xdr.PublicKey{keys[0], keys[1]},
		InnerSets: []xdr.ScpQuorumSet{
			xdr.ScpQuorumSet{
				Threshold:  1,
				Validators: []xdr.PublicKey{keys[2], keys[3]},
			},
		},
	}

	t.Log("{ t: 1, v0, { t: 1, v1 }, { t: 1, v2, v3 } } -> { t:1, v0, v1, { t: 1, v2, v3 } }")
	{
		check(&validMultipleNodes, true, &validMulpipleNodesNormalized)
	}

	t.Log("{ t: 1, { t: 1, v0, { t: 1, v1 }, { t: 1, v2, v3 } } } -> { t:1, v0, v1, { t: 1, v2, v3 } }")
	{
		containingSet := xdr.ScpQuorumSet{
			Threshold: 1,
			InnerSets: []xdr.ScpQuorumSet{validMultipleNodes},
		}

		check(&containingSet, true, &validMulpipleNodesNormalized)
	}

	t.Log("{ t: 1, v0, { t: 1, v1, { t: 1, v2 } } } -> { t: 1, v0, { t: 1, v1, v2 } }")
	{
		qSet := makeSingleton(keys[0])
		qSet1 := makeSingleton(keys[1])
		qSet2 := makeSingleton(keys[2])
		qSet1.InnerSets = append(qSet1.InnerSets, qSet2)
		qSet.InnerSets = append(qSet.InnerSets, qSet1)

		qSelfSet := xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: []xdr.PublicKey{keys[0]},
			InnerSets: []xdr.ScpQuorumSet{
				xdr.ScpQuorumSet{
					Threshold:  1,
					Validators: []xdr.PublicKey{keys[1], keys[2]},
				},
			},
		}

		check(&qSet, true, &qSelfSet)
	}

	t.Log("{ t: 1, v0, { t: 1, v1, { t: 1, v2, { t: 1, v3 } } } } -> too deep")
	{
		qSet := makeSingleton(keys[0])
		qSet1 := makeSingleton(keys[1])
		qSet2 := makeSingleton(keys[2])
		qSet3 := makeSingleton(keys[3])
		qSet2.InnerSets = append(qSet2.InnerSets, qSet3)
		qSet1.InnerSets = append(qSet1.InnerSets, qSet2)
		qSet.InnerSets = append(qSet.InnerSets, qSet1)

		qSelfSet := xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: []xdr.PublicKey{keys[0]},
			InnerSets: []xdr.ScpQuorumSet{
				xdr.ScpQuorumSet{
					Threshold:  1,
					Validators: []xdr.PublicKey{keys[1]},
					InnerSets: []xdr.ScpQuorumSet{
						xdr.ScpQuorumSet{
							Threshold:  1,
							Validators: []xdr.PublicKey{keys[2], keys[3]},
						},
					},
				},
			},
		}

		check(&qSet, false, &qSelfSet)
	}

	t.Log("{ t: 1, v0..v999 } -> { t: 1, v0..v999 }")
	{
		qSet := xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: keys[:1000],
		}

		check(&qSet, true, &qSet)
	}

	t.Log("{ t: 1, v0..v1000 } -> too big")
	{
		qSet := xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: keys,
		}

		check(&qSet, false, &qSet)
	}

	t.Log("{ t: 1, v0, { t: 1, v1..v100 }, { t: 1, v101..v200} ... { t: 1, v901..v1000} -> too big")
	{
		qSet := xdr.ScpQuorumSet{
			Threshold:  1,
			Validators: []xdr.PublicKey{keys[0]},
		}

		for i := 0; i < 10; i++ {
			innerSet := xdr.ScpQuorumSet{
				Threshold: 1,
			}
			for j := i*100 + 1; j <= (i+1)*100; j++ {
				innerSet.Validators = append(innerSet.Validators, keys[j])
			}
			qSet.InnerSets = append(qSet.InnerSets, innerSet)
		}

		check(&qSet, false, &qSet)
	}

}

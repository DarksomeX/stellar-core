package herder

import (
	"time"

	"github.com/darksomex/stellar-core/scp"
	"github.com/darksomex/stellar-core/utils/network"
	"github.com/pkg/errors"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/strkey"
	"github.com/stellar/go/xdr"
)

type scpTiming struct {
	nominationStart *time.Time
	prepareStart    *time.Time
}

type ConsensusData struct {
	Index uint64
	Value *xdr.StellarValue
}

type SCPDriver struct {
	scp.Driver
	SCP *scp.SCP

	passphraseHash [32]byte
	seed           keypair.KP

	// if the local instance is tracking the current state of SCP
	// herder keeps track of the consensus index and ballot
	// when not set, it just means that herder will try to snap to any slot that
	// reached consensus
	// on startup, this can be set to a value persisted from the database
	trackingSCP *ConsensusData
	// when losing track of consensus, we remember the consensus value so that
	// we can ignore older ledgers (as we potentially receive old messages)
	// it only tracks actual consensus values (learned when externalizing)
	lastTrackingSCP *ConsensusData

	metrics *Metrics

	ExecutionTimes map[uint64]scpTiming
}

func (d *SCPDriver) bootstrap() {
	//CALLS APP REALLY? SHIT
	//stateChanged() mb channel?

	for key := range d.ExecutionTimes {
		delete(d.ExecutionTimes, key)
	}
}

func (d *SCPDriver) lostSync() {
	//stateChanged() mb channel?
	d.lastTrackingSCP = d.trackingSCP
	d.trackingSCP = nil
}

// State only returns "TRACKING" when we're tracking the actual network
// (lastTrackingSCP is also set when this happens)
func (d *SCPDriver) State() State {
	if d.trackingSCP != nil && d.lastTrackingSCP != nil {
		return StateTracking
	}
	return StateSyncing
}

func (d *SCPDriver) stateChanged() {
	//d.app.SyncOwnMetrics()
}

func (d *SCPDriver) restoreSCPState(index uint64, value *ConsensusData) {
	d.trackingSCP = value
}

func (d *SCPDriver) signEnvelope(env *xdr.ScpEnvelope) error {
	d.metrics.EnvelopeSign.Mark(1)

	hash, err := network.HashScpStatement(&env.Statement, d.passphraseHash)
	if err != nil {
		return errors.Wrap(err, "hash scp statement failed")
	}

	env.Signature, err = d.seed.Sign(hash[:])
	if err != nil {
		return errors.Wrap(err, "sign scp statement failed")
	}

	return nil
}

func (d *SCPDriver) verifyEnvelope(env *xdr.ScpEnvelope) error {
	hash, err := network.HashScpStatement(&env.Statement, d.passphraseHash)
	if err != nil {
		return errors.Wrap(err, "hash scp statement failed")
	}

	bytes, err := env.Statement.NodeId.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "failed to marshal node id")
	}

	key, err := strkey.Encode(strkey.VersionByteAccountID, bytes)
	if err != nil {
		return errors.Wrap(err, "failed to strkey encode node id")
	}

	kp, err := keypair.Parse(key)
	if err != nil {
		return errors.Wrap(err, "failed to parse node id keypair")
	}

	err = kp.Verify(hash[:], env.Signature)
	if err != nil {
		return errors.Wrap(err, "invalid signature")
	}

	/*
			if (b)
		    {
		        mSCPMetrics.mEnvelopeValidSig.Mark();
		    }
		    else
		    {
		        mSCPMetrics.mEnvelopeInvalidSig.Mark();
		    }
	*/

	return nil
}

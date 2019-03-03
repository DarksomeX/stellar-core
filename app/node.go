package app

import (
	"github.com/darksomex/stellar-core/herder"
	"github.com/darksomex/stellar-core/ledger"
	"github.com/darksomex/stellar-core/metrics"
	"github.com/sirupsen/logrus"
)

type State int

const (
	StateBooting State = iota
	StateAcquiringConsensus
	StateConnnectedStandby
	StateCatchingUp
	StateSynced
	StateStopping
)

type Node struct {
	herder *herder.Herder
	ledger *ledger.Manager

	PassphraseHash [32]byte
	/*
		if strings.TrimSpace(passphrase) == "" {
			return [32]byte{}, errors.New("empty network passphrase")
		}
		hash := network.ID(passphrase)
	*/
	config *Config

	Stopping bool

	StateCurrent *metrics.Counter
	log          *logrus.Entry
}

func (n *Node) Config() *Config {
	return n.config
}

func (n *Node) State() State {
	if n.Stopping {
		return StateStopping
	}

	if n.herder.State() == herder.StateSyncing {
		return StateAcquiringConsensus
	}

	switch n.ledger.State {
	case ledger.StateBooting:
		return StateConnnectedStandby
	case ledger.StateCatchingUp:
		return StateCatchingUp
	case ledger.StateSynced:
		return StateSynced
	default:
		n.log.Panicf("unexpected ledger state: %d", n.ledger.State)
	}

	return 0
}

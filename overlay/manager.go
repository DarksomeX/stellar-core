package overlay

import (
	"github.com/stellar/go/xdr"
)

type Manager struct {
	floodGate          *FloodGate
	authenticatedPeers map[xdr.NodeId]*Peer
}

func (m *Manager) BroadcastMessage(msg *xdr.StellarMessage, force bool) {
	//MessagesBrodcast.Mark() metric
	m.floodGate.broadcast(msg, force)
}

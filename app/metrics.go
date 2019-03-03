package app

func (n *Node) SyncOwnMetrics() {
	state := uint64(n.State())
	if n.StateCurrent.Count() != state {
		n.StateCurrent.Set(state)
	}

  // Flush crypto pure-global-cache stats. They don't belong
  // to a single app instance but first one to flush will claim
  // them.

}

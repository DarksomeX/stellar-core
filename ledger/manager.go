package ledger

type State int

const (
	StateBooting State = iota
	StateSynced
	StateCatchingUp
)

type Manager struct {
	State
}

func (m *Manager) Bootstrap() {
	m.State = StateSynced
}

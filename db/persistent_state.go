package db

import "github.com/pkg/errors"

type Entry int

const (
	LastClosedLedger Entry = iota
	HistoryArchiveState
	ForceSCPOnNextLaunch
	LastSCPData
	DatabaseSchema
	NetworkPassphrase
	LedgerUpgrades
	LastEntry
)

func (e Entry) String() string {
	switch e {
	case LastClosedLedger:
		return "lastclosedledger"
	case HistoryArchiveState:
		return "historyarchivestate"
	case ForceSCPOnNextLaunch:
		return "forcescponnextlaunch"
	case LastSCPData:
		return "lastscpdata"
	case DatabaseSchema:
		return "databaseschema"
	case NetworkPassphrase:
		return "networkpassphrase"
	case LedgerUpgrades:
		return "ledgerupgrades"
	}

	panic("unknown persistent state entry")
}

func (db *DB) SetState(stateName Entry, value string) {
	res, err := db.Exec(`UPDATE storestate SET state = $1 WHERE statement = $2;`, value, stateName)
	if err != nil {
		panic(errors.Wrap(err, "failed to update persistent state"))
	}

	affected, err := res.RowsAffected()
	if err != nil {
		panic(errors.Wrap(err, "failed to get affected rows"))
	}

	if affected == 1 {
		return
	}

	res, err = db.Exec(`INSERT INTO storestate (statename, state) VALUES ($1, $2);`, stateName, value)
	if err != nil {
		panic(errors.Wrap(err, "failed to insert persistent state"))
	}
}

func (db *DB) GetState(stateName Entry) string {
	row := db.QueryRow(`SELECT state FROM storestate WHERE statename = $1;`, stateName)

	var state string
	err := row.Scan(&state)
	if err != nil {
		panic(errors.Wrap(err, "failed to query persistent state"))
	}

	return state
}

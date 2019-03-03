package main

import (
	"database/sql"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
)

func main() {
	newDB("")
}

func newDB(dsn string) {
	db, err := sql.Open("postgres", "postgres://postgres:postgres@localhost/gocore?sslmode=disable")
	if err != nil {
		panic(errors.Wrap(err, "failed to open db connection"))
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS bans(
      node_id character(56)
    );
    TRUNCATE TABLE bans CASCADE;
    `)
	if err != nil {
		panic(errors.Wrap(err, "failed create bans table"))
	}
}

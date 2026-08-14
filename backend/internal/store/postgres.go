// Package store implements PostgreSQL persistence for the backend domain.
package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// DB is implemented by both pgxpool.Pool and an explicitly acquired
// pgxpool.Conn. The latter keeps lock-sensitive operations on a known backend.
type DB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
}

// Store groups repositories backed by PostgreSQL.
type Store struct {
	db DB
}

func New(db DB) *Store {
	return &Store{db: db}
}

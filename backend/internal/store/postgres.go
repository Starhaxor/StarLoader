// Package store implements PostgreSQL persistence for the backend domain.
package store

import "github.com/jackc/pgx/v5/pgxpool"

// Store groups repositories backed by one PostgreSQL connection pool.
type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

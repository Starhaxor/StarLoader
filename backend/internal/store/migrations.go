package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/starloader/backend/migrations"
)

const (
	initialMigrationVersion int64 = 1
	migrationAdvisoryLock   int64 = 0x535441524c4f4144 // "STARLOAD"
)

func MigrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	return executeVersionedMigration(ctx, pool, initialMigrationVersion, "000001_initial.up.sql", true)
}

func MigrateDown(ctx context.Context, pool *pgxpool.Pool) error {
	return executeVersionedMigration(ctx, pool, initialMigrationVersion, "000001_initial.down.sql", false)
}

func executeVersionedMigration(ctx context.Context, pool *pgxpool.Pool, version int64, name string, up bool) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock($1)`, migrationAdvisoryLock); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		create table if not exists schema_migrations (
			version bigint primary key,
			applied_at timestamptz not null default clock_timestamp()
		)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	var applied bool
	if err := tx.QueryRow(ctx, `select exists(select 1 from schema_migrations where version = $1)`, version).Scan(&applied); err != nil {
		return fmt.Errorf("read migration version %d: %w", version, err)
	}
	if applied == up {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s no-op: %w", name, err)
		}
		return nil
	}

	sql, err := migrations.Files.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx, string(sql)); err != nil {
		return fmt.Errorf("execute migration %s: %w", name, err)
	}
	if up {
		_, err = tx.Exec(ctx, `insert into schema_migrations (version) values ($1)`, version)
	} else {
		_, err = tx.Exec(ctx, `delete from schema_migrations where version = $1`, version)
	}
	if err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}
	return nil
}

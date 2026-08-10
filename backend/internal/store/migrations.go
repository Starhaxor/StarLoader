package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/starloader/backend/migrations"
)

func MigrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	return executeMigration(ctx, pool, "000001_initial.up.sql")
}

func MigrateDown(ctx context.Context, pool *pgxpool.Pool) error {
	return executeMigration(ctx, pool, "000001_initial.down.sql")
}

func executeMigration(ctx context.Context, pool *pgxpool.Pool, name string) error {
	sql, err := migrations.Files.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}
	if _, err := pool.Exec(ctx, string(sql)); err != nil {
		return fmt.Errorf("execute migration %s: %w", name, err)
	}
	return nil
}

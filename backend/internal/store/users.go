package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/starloader/backend/internal/domain"
)

const userColumns = `id::text, email, password_hash, status, created_at, updated_at`

func (s *Store) CreateUser(ctx context.Context, input domain.NewUser) (*domain.User, error) {
	row := s.pool.QueryRow(ctx, `
		insert into users (email, password_hash)
		values ($1, $2)
		returning `+userColumns, normalizeEmail(input.Email), input.PasswordHash)
	user, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	user, err := scanUser(s.pool.QueryRow(ctx, `select `+userColumns+` from users where email = $1`, normalizeEmail(email)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return user, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func scanUser(row pgx.Row) (*domain.User, error) {
	var user domain.User
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Status, &user.CreatedAt, &user.UpdatedAt)
	return &user, err
}

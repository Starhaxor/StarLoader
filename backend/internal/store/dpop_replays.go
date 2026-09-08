package store

import (
	"context"
	"time"
)

// ConsumeDPoP admits a proof once across all server instances and restarts.
func (s *Store) ConsumeDPoP(ctx context.Context, digest [32]byte, expires time.Time) (bool, error) {
	var consumed bool
	err := s.db.QueryRow(ctx, `with cleanup as (delete from dpop_replays where expires_at < now()),
		inserted as (insert into dpop_replays (jti_digest, expires_at) values ($1,$2) on conflict do nothing returning 1)
		select exists(select 1 from inserted)`, digest[:], expires).Scan(&consumed)
	return consumed, err
}

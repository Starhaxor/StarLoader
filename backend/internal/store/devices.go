package store

// Device persistence is intentionally transaction-scoped: HMAC-only lookup
// and mutation methods belong on LockedChallenge so activation cannot escape
// the challenge transaction.

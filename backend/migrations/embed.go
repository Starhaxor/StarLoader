// Package migrations exposes the versioned SQL migrations embedded in the
// backend binary.
package migrations

import "embed"

// Files contains every migration shipped with the backend.
//
//go:embed *.sql
var Files embed.FS

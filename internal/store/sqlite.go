package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS honeytokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	type TEXT NOT NULL,
	path TEXT NOT NULL,
	hash TEXT NOT NULL,
	mtime INTEGER NOT NULL,
	status TEXT NOT NULL,
	placed_at TEXT NOT NULL,
	checked_at TEXT
);
`

// SQLiteStore persists honeytokens in a SQLite database file.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens or creates the database at dbPath and applies the honeytokens schema if needed.
func OpenSQLite(dbPath string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	dsn := dbPath + "?_foreign_keys=on"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

// Close releases the database handle.
func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close sqlite: %w", err)
	}
	return nil
}

// Insert adds a new honeytoken and returns its id.
func (s *SQLiteStore) Insert(rec Record) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO honeytokens (name, type, path, hash, mtime, status, placed_at, checked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Name, rec.Type, rec.Path, rec.Hash, rec.Mtime, rec.Status, rec.PlacedAt, nullIfEmpty(rec.CheckedAt),
	)
	if err != nil {
		return 0, fmt.Errorf("insert honeytoken: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}
	return id, nil
}

// List returns all honeytokens ordered by id.
func (s *SQLiteStore) List() ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT id, name, type, path, hash, mtime, status, placed_at, IFNULL(checked_at, '') FROM honeytokens ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("query honeytokens: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Path, &r.Hash, &r.Mtime, &r.Status, &r.PlacedAt, &r.CheckedAt); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	return out, nil
}

// UpdateAfterCheck sets status and checked_at for a row.
func (s *SQLiteStore) UpdateAfterCheck(id int64, status, checkedAt string) error {
	_, err := s.db.Exec(`UPDATE honeytokens SET status = ?, checked_at = ? WHERE id = ?`, status, checkedAt, id)
	if err != nil {
		return fmt.Errorf("update after check: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// NowRFC3339 returns the current UTC time in RFC3339 form.
func NowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

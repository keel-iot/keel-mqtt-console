package store

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type User struct {
	ID                        uuid.UUID
	Email, PasswordHash, Role string
	Enabled                   bool
}

type Store struct{ Pool *pgxpool.Pool }

//go:embed migrations/001_init.sql
var migrationSQL string

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	p, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	s := &Store{Pool: p}
	if err := s.Migrate(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, migrationSQL)
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return err
}

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM console_users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(ctx context.Context, email, passwordHash, role string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO console_users(id,email,password_hash,role) VALUES($1,$2,$3,$4) ON CONFLICT (email) DO NOTHING`, uuid.New(), strings.ToLower(email), passwordHash, role)
	return err
}

func (s *Store) FindUser(ctx context.Context, email string) (User, error) {
	var u User
	err := s.Pool.QueryRow(ctx, `SELECT id,email,password_hash,role,enabled FROM console_users WHERE email=$1`, strings.ToLower(email)).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Enabled)
	return u, err
}

func (s *Store) CreateSession(ctx context.Context, token, email, role string, userID *uuid.UUID, expiry time.Time) error {
	var id any
	if userID != nil {
		id = *userID
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO console_sessions(token_hash,user_id,email,role,expires_at) VALUES($1,$2,$3,$4,$5)`, hash(token), id, email, role, expiry)
	return err
}

func (s *Store) Session(ctx context.Context, token string) (email, role string, ok bool, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT email,role FROM console_sessions WHERE token_hash=$1 AND expires_at > now()`, hash(token)).Scan(&email, &role)
	if err == pgx.ErrNoRows {
		return "", "", false, nil
	}
	return email, role, err == nil, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM console_sessions WHERE token_hash=$1`, hash(token))
	return err
}

func (s *Store) Audit(ctx context.Context, actor, action, target string) {
	_, _ = s.Pool.Exec(ctx, `INSERT INTO console_audit_log(actor,action,target) VALUES($1,$2,$3)`, actor, action, target)
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

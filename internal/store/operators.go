package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Operators assigns the canonical integer operator_id of a verified
// (issuer, subject) pair from the Gateway's own sequence.
type Operators struct{ db *sql.DB }

func NewOperators(db *sql.DB) (*Operators, error) {
	if db == nil {
		return nil, errors.New("operators: db is nil")
	}
	return &Operators{db: db}, nil
}

// OperatorID returns the operator_id stored for the pair, assigning a new one
// on the first verified login. Concurrent first logins of one pair converge
// on the single row the unique constraint admits.
func (s *Operators) OperatorID(ctx context.Context, issuer, subject string) (int64, error) {
	if issuer == "" || subject == "" {
		return 0, errors.New("operators: issuer and subject are required")
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO api_gateway.operators (issuer, subject) VALUES ($1, $2)
		ON CONFLICT ON CONSTRAINT operators_identity_unique DO NOTHING RETURNING operator_id`, issuer, subject).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("assign operator_id: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT operator_id FROM api_gateway.operators WHERE issuer = $1 AND subject = $2`, issuer, subject).Scan(&id); err != nil {
		return 0, fmt.Errorf("read operator_id: %w", err)
	}
	return id, nil
}

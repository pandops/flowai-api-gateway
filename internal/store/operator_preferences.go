package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrPreferenceStale = errors.New("operator preference revision is stale")

type OperatorPreference struct {
	TimeZone *string
	Revision int64
}

// OperatorPreferences persists personal data independently of sessions and teams.
type OperatorPreferences struct{ db *sql.DB }

func NewOperatorPreferences(db *sql.DB) (*OperatorPreferences, error) {
	if db == nil {
		return nil, errors.New("operator preferences: db is nil")
	}
	return &OperatorPreferences{db: db}, nil
}

func (s *OperatorPreferences) Read(ctx context.Context, operatorID int64) (OperatorPreference, error) {
	var preference OperatorPreference
	err := s.db.QueryRowContext(ctx, `SELECT time_zone, revision FROM api_gateway.operator_preferences WHERE operator_id=$1`, operatorID).Scan(&preference.TimeZone, &preference.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return OperatorPreference{}, nil
	}
	if err != nil {
		return OperatorPreference{}, fmt.Errorf("read operator preference: %w", err)
	}
	return preference, nil
}

// Save uses one conditional statement, including first creation, so no pair of
// changing writes can win with the same revision. Identical saves retain it.
func (s *OperatorPreferences) Save(ctx context.Context, operatorID int64, zone string, revision int64) (OperatorPreference, error) {
	var preference OperatorPreference
	var err error
	if revision == 0 {
		err = s.db.QueryRowContext(ctx, `INSERT INTO api_gateway.operator_preferences(operator_id,time_zone,revision)
 VALUES($1,$2,1) ON CONFLICT(operator_id) DO NOTHING RETURNING time_zone,revision`, operatorID, zone).Scan(&preference.TimeZone, &preference.Revision)
	} else {
		err = s.db.QueryRowContext(ctx, `UPDATE api_gateway.operator_preferences
 SET time_zone=$2, revision=revision+CASE WHEN time_zone IS DISTINCT FROM $2 THEN 1 ELSE 0 END,
 updated_at=CASE WHEN time_zone IS DISTINCT FROM $2 THEN now() ELSE updated_at END
 WHERE operator_id=$1 AND revision=$3 RETURNING time_zone,revision`, operatorID, zone, revision).Scan(&preference.TimeZone, &preference.Revision)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return OperatorPreference{}, ErrPreferenceStale
	}
	if err != nil {
		return OperatorPreference{}, fmt.Errorf("save operator preference: %w", err)
	}
	return preference, nil
}

// Package teamregistry reads one canonical team through the only `service`
// subject API Gateway may publish, team-registry.service.get.pub.
package teamregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/broker"
)

const Subject = "team-registry.service.get.pub"

// AdminTeam is the `team` header value of an administrator route.
const AdminTeam = "admin"

var (
	ErrTeamNotFound = errors.New("canonical team not found")
	// ErrUnavailable: no responder, timeout or an unusable reply.
	ErrUnavailable = errors.New("team-registry unavailable")
)

type Team struct {
	TeamID     int64      `json:"team_id"`
	TeamName   string     `json:"team_name"`
	ArchivedAt *time.Time `json:"archived_at"`
}

type Client struct{ broker broker.Requester }

func New(requester broker.Requester) (*Client, error) {
	if requester == nil {
		return nil, errors.New("team-registry client: broker is nil")
	}
	return &Client{broker: requester}, nil
}

// GetTeam reads team teamID. teamHeader is the decimal team_id, or AdminTeam
// for OIDC mapping registration. A broken broker connection is returned as
// broker.ErrUnavailable; ctx bounds the wait.
func (c *Client) GetTeam(ctx context.Context, teamID int64, teamHeader string, requestID int64) (Team, error) {
	if teamID <= 0 || requestID <= 0 {
		return Team{}, fmt.Errorf("%w: team_id and request_id must be positive", ErrUnavailable)
	}
	body, err := json.Marshal(map[string]any{"params": map[string]int64{"team_id": teamID}})
	if err != nil {
		return Team{}, ErrUnavailable
	}
	reply, err := c.broker.Request(ctx, broker.Request{Subject: Subject, Header: map[string]string{"team": teamHeader, "request_id": strconv.FormatInt(requestID, 10)}, Body: body})
	if errors.Is(err, broker.ErrUnavailable) {
		return Team{}, broker.ErrUnavailable
	}
	if err != nil {
		return Team{}, ErrUnavailable
	}
	switch reply.Header["status"] {
	case "200":
	case "404":
		return Team{}, ErrTeamNotFound
	default:
		return Team{}, ErrUnavailable
	}
	var decoded struct {
		TeamID     int64   `json:"team_id"`
		TeamName   string  `json:"team_name"`
		ArchivedAt *string `json:"archived_at"`
	}
	if err := json.Unmarshal(reply.Body, &decoded); err != nil || decoded.TeamID != teamID || decoded.TeamName == "" {
		return Team{}, ErrUnavailable
	}
	team := Team{TeamID: decoded.TeamID, TeamName: decoded.TeamName}
	if decoded.ArchivedAt != nil {
		at, err := time.Parse(time.RFC3339Nano, *decoded.ArchivedAt)
		if err != nil {
			return Team{}, ErrUnavailable
		}
		at = at.UTC()
		team.ArchivedAt = &at
	}
	return team, nil
}

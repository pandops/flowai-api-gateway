package test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/httpapi"
	"github.com/pandops/flowai-api-gateway/internal/store"
)

// memPreferences has store.OperatorPreferences' conditional-revision
// semantics; loseResponse makes the next committed save report an error.
type memPreferences struct {
	mu           sync.Mutex
	rows         map[int64]store.OperatorPreference
	saves        int
	loseResponse bool
}

func (p *memPreferences) Read(_ context.Context, operatorID int64) (store.OperatorPreference, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rows[operatorID], nil
}

func (p *memPreferences) Save(_ context.Context, operatorID int64, zone string, revision int64) (store.OperatorPreference, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves++
	current := p.rows[operatorID]
	if current.Revision != revision {
		return store.OperatorPreference{}, store.ErrPreferenceStale
	}
	saved := store.OperatorPreference{TimeZone: &zone, Revision: revision + 1}
	p.rows[operatorID] = saved
	if p.loseResponse {
		p.loseResponse = false
		return store.OperatorPreference{}, errors.New("connection reset after commit")
	}
	return saved, nil
}

func newSettingsGateway(t *testing.T) (*gw, *memPreferences) {
	preferences := &memPreferences{rows: map[int64]store.OperatorPreference{}}
	g := newGateway(t, func(d *httpapi.Dependencies) { d.OperatorPreferences = preferences })
	return g, preferences
}

// settings reads the operator's own setting; the Gateway's own JSON ends with
// a newline, which is not part of the value.
func (g *gw) settings(token string, extra map[string]string) (*http.Response, string) {
	response, body := g.as(token, http.MethodGet, "/ui/v1/operator/settings", extra, "")
	return response, strings.TrimSpace(body)
}

func (g *gw) putZone(token, ifMatch, zone string) (*http.Response, string) {
	return g.as(token, http.MethodPut, "/ui/v1/operator/settings", map[string]string{"If-Match": ifMatch}, `{"time_zone":"`+zone+`"}`)
}

// api-gateway: Gateway owns personal operator time zone settings.
func TestV0048GatewayOwnsPersonalOperatorTimeZoneSettings(t *testing.T) {
	t.Parallel()

	t.Run("Same operator across devices and teams", func(t *testing.T) {
		g, preferences := newSettingsGateway(t)
		g.sessions.add("second-device-session", gwOperator, map[int64]string{gwOtherTeam: "Beta-Team"})
		g.sessions.add("other-operator-session", 43, map[int64]string{gwTeam: "Alpha-Team"})
		alpha := g.token(gwTeam)
		beta := g.tokenFor("second-device-session", gwOtherTeam)
		other := g.tokenFor("other-operator-session", gwTeam)
		response, body := g.settings(alpha, nil)
		if response.StatusCode != 200 || body != `{"time_zone":null}` || response.Header.Get("ETag") != `"op-0"` || preferences.saves != 0 {
			t.Fatalf("unset = %d %s %s", response.StatusCode, body, response.Header.Get("ETag"))
		}
		if response, body := g.putZone(alpha, `"op-0"`, "Europe/Berlin"); response.StatusCode != 200 || response.Header.Get("ETag") != `"op-1"` {
			t.Fatalf("save = %d %s", response.StatusCode, body)
		}
		response, body = g.settings(beta, nil)
		if body != `{"time_zone":"Europe/Berlin"}` || response.Header.Get("ETag") != `"op-1"` {
			t.Fatalf("other device/team = %s %s", body, response.Header.Get("ETag"))
		}
		// Forged identity input never selects another operator's record.
		response, body = g.settings(other, map[string]string{"X-FlowAI-Operator-ID": "42", "operator_id": "42"})
		if body != `{"time_zone":null}` || response.Header.Get("ETag") != `"op-0"` {
			t.Fatalf("forged operator read = %s", body)
		}
		if g.logout(gwSessionID) != http.StatusNoContent {
			t.Fatal("logout failed")
		}
		if _, body := g.settings(beta, nil); body != `{"time_zone":"Europe/Berlin"}` {
			t.Fatalf("logout dropped the preference: %s", body)
		}
		if got := len(g.broker.requests()); got != 0 {
			t.Fatalf("settings reached the broker: %v", g.broker.subjects())
		}
	})

	t.Run("First-use race and uncertain write", func(t *testing.T) {
		g, preferences := newSettingsGateway(t)
		g.sessions.add("second-device-session", gwOperator, map[int64]string{gwTeam: "Alpha-Team"})
		first, second := g.token(gwTeam), g.tokenFor("second-device-session", gwTeam)
		statuses := make([]int, 2)
		var wait sync.WaitGroup
		for index, token := range []string{first, second} {
			wait.Add(1)
			go func() {
				defer wait.Done()
				response, _ := g.putZone(token, `"op-0"`, []string{"Europe/Berlin", "Asia/Tokyo"}[index])
				statuses[index] = response.StatusCode
			}()
		}
		wait.Wait()
		if (statuses[0] != 200 || statuses[1] != 412) && (statuses[0] != 412 || statuses[1] != 200) {
			t.Fatalf("race statuses = %v", statuses)
		}
		preferences.mu.Lock()
		preferences.loseResponse = true
		preferences.mu.Unlock()
		saves := preferences.saves
		response, body := g.putZone(first, `"op-1"`, "UTC")
		assertEnvelope(t, response, body, http.StatusServiceUnavailable, "operator_settings_unavailable")
		if preferences.saves != saves+1 {
			t.Fatalf("uncertain write was retried: %d saves", preferences.saves-saves)
		}
		response, body = g.settings(second, nil)
		if body != `{"time_zone":"UTC"}` || response.Header.Get("ETag") != `"op-2"` {
			t.Fatalf("readback = %s %s", body, response.Header.Get("ETag"))
		}
	})
}

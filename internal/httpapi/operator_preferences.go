package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pandops/flowai-api-gateway/internal/store"
)

type OperatorPreferenceStore interface {
	Read(context.Context, int64) (store.OperatorPreference, error)
	Save(context.Context, int64, string, int64) (store.OperatorPreference, error)
}

var operatorZoneName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)*$`)

func operatorSettings(w http.ResponseWriter, r *http.Request, dependencies Dependencies) {
	w.Header().Set("Cache-Control", "no-store")
	token, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !bearer {
		token = ""
	}
	auth, ok := authenticateWorkingToken(w, r, dependencies, strings.TrimSpace(token))
	if !ok {
		return
	}
	if dependencies.OperatorPreferences == nil {
		writeError(w, 503, "operator_settings_unavailable", "Operator settings are unavailable")
		return
	}
	var preference store.OperatorPreference
	var err error
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		preference, err = dependencies.OperatorPreferences.Read(r.Context(), auth.Claims.OperatorID)
	} else {
		revision, valid := operatorExpectedRevision(r.Header.Get("If-Match"))
		if !valid {
			writeError(w, 400, "invalid_request", "Current operator settings revision is required")
			return
		}
		media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaErr != nil || media != "application/json" {
			writeError(w, 415, "invalid_request", "Use application/json for operator settings")
			return
		}
		raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		var oversized *http.MaxBytesError
		if errors.As(readErr, &oversized) {
			writeError(w, 413, "invalid_request", "Operator settings exceed the request limit")
			return
		}
		zone, valid := decodeOperatorZone(raw)
		if readErr != nil || !valid {
			writeError(w, 400, "invalid_request", "Provide exactly one time_zone string")
			return
		}
		if !validOperatorZone(zone) {
			writeError(w, 400, "invalid_time_zone", "Choose a supported IANA time zone")
			return
		}
		preference, err = dependencies.OperatorPreferences.Save(r.Context(), auth.Claims.OperatorID, zone, revision)
	}
	if errors.Is(err, store.ErrPreferenceStale) {
		writeError(w, 412, "stale_revision", "Operator settings changed; reload before saving")
		return
	}
	if err != nil {
		writeError(w, 503, "operator_settings_unavailable", "Operator settings are unavailable")
		return
	}
	w.Header().Set("ETag", `"op-`+strconv.FormatInt(preference.Revision, 10)+`"`)
	writeJSON(w, 200, struct {
		TimeZone *string `json:"time_zone"`
	}{TimeZone: preference.TimeZone})
}

func operatorExpectedRevision(raw string) (int64, bool) {
	if !strings.HasPrefix(raw, `"op-`) || !strings.HasSuffix(raw, `"`) {
		return 0, false
	}
	digits := raw[4 : len(raw)-1]
	if digits == "" {
		return 0, false
	}
	for _, char := range digits {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	revision, err := strconv.ParseInt(digits, 10, 64)
	return revision, err == nil
}

func decodeOperatorZone(raw []byte) (string, bool) {
	if !utf8.Valid(raw) {
		return "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') || !decoder.More() {
		return "", false
	}
	key, err := decoder.Token()
	if err != nil || key != "time_zone" {
		return "", false
	}
	var zone *string
	if decoder.Decode(&zone) != nil || zone == nil || decoder.More() {
		return "", false
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return "", false
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return "", false
	}
	return *zone, true
}

func validOperatorZone(zone string) bool {
	if len(zone) > 128 || zone == "Local" || !operatorZoneName.MatchString(zone) {
		return false
	}
	_, err := time.LoadLocation(zone)
	return err == nil
}

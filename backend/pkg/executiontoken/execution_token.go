package executiontoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
)

// ExecutionClaims authorizes a schedule, webhook, or SlackBot call to the normal session
// creation API. It carries identity, not session configuration.
type ExecutionClaims struct {
	TaskID          string                 `json:"task_id,omitempty"`
	TaskWorker      string                 `json:"task_worker,omitempty"`
	TaskGeneration  int64                  `json:"task_generation,omitempty"`
	ScheduleID      string                 `json:"schedule_id,omitempty"`
	SlackBotID      string                 `json:"slackbot_id,omitempty"`
	WebhookID       string                 `json:"webhook_id,omitempty"`
	TriggeredUserID string                 `json:"triggered_user_id,omitempty"`
	ExecutionID     string                 `json:"execution_id"`
	SessionID       string                 `json:"session_id"`
	UserID          string                 `json:"user_id"`
	Scope           entities.ResourceScope `json:"scope"`
	TeamID          string                 `json:"team_id,omitempty"`
	Teams           []string               `json:"teams,omitempty"`
	ExpiresAt       int64                  `json:"expires_at"`
}

func SignExecutionToken(secret []byte, claims ExecutionClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyExecutionToken(secret []byte, token string, now time.Time) (ExecutionClaims, error) {
	var claims ExecutionClaims
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return claims, errors.New("invalid execution token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, errors.New("invalid execution token")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return claims, errors.New("invalid execution token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, errors.New("invalid execution token")
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, errors.New("invalid execution token")
	}
	origins := 0
	for _, id := range []string{claims.ScheduleID, claims.SlackBotID, claims.WebhookID, claims.TaskID} {
		if id != "" {
			origins++
		}
	}
	if claims.TaskID != "" && (claims.TaskWorker == "" || claims.TaskGeneration <= 0) {
		return claims, errors.New("incomplete task execution token")
	}
	if origins != 1 || claims.ExecutionID == "" || claims.SessionID == "" || claims.UserID == "" || now.Unix() >= claims.ExpiresAt {
		return claims, errors.New("expired or incomplete execution token")
	}
	return claims, nil
}

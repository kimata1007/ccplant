package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/kvstore"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/repositories"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
	"github.com/takutakahashi/agentapi-proxy/pkg/auth"
	"github.com/takutakahashi/agentapi-proxy/pkg/config"
)

func TestTaskScopeAndIdempotency(t *testing.T) {
	store, err := kvstore.NewLibSQLStore(t.Context(), "file:"+filepath.Join(t.TempDir(), "task.db"), "")
	require.NoError(t, err)
	defer store.Close()
	tc := TaskController{Queue: &task.Queue{Repo: repositories.NewTaskRepository(store, "default"), Config: config.TaskQueueConfig{MaxPending: 10},
		Sessions: func(context.Context) (map[string]task.SessionSnapshot, error) { return nil, nil }}}
	e := echo.New()
	call := func(handler echo.HandlerFunc, method, path, id, body, principal, team string) (int, *httptest.ResponseRecorder) {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		request.Header.Set("Idempotency-Key", "unique")
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		ctx.SetParamNames("id")
		ctx.SetParamValues(id)
		ctx.Set("authz_context", &auth.AuthorizationContext{
			User:          entities.NewUser(entities.UserID(principal), entities.UserTypeRegular, principal),
			PersonalScope: auth.PersonalScopeAuth{UserID: principal, CanRead: true, CanCreate: true},
			TeamScope:     auth.TeamScopeAuth{Teams: []string{team}, TeamPermissions: map[string]auth.TeamPermissions{team: {TeamID: team, CanRead: true, CanCreate: true}}},
		})
		if err := handler(ctx); err != nil {
			e.HTTPErrorHandler(err, ctx)
		}
		return recorder.Code, recorder
	}
	const body = `{"apiVersion":"ccplant.io/v1alpha1","kind":"Task","metadata":{"name":"review"},"spec":{"start":{"scope":"team","team_id":"org/red","session_profile_id":"p1","params":{"message":"example prompt"}}}}`
	status, rec := call(tc.Submit, http.MethodPost, "/tasks", "", body, "alice", "org/red")
	require.Equal(t, http.StatusAccepted, status, rec.Body.String())
	var submitted struct {
		ID string `json:"task_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &submitted))
	require.NotEmpty(t, submitted.ID)
	status, rec = call(tc.Submit, http.MethodPost, "/tasks", "", body, "alice", "org/red")
	require.Equal(t, http.StatusAccepted, status)
	require.Contains(t, rec.Body.String(), submitted.ID)
	status, _ = call(tc.Submit, http.MethodPost, "/tasks", "", body, "bob", "org/blue")
	require.Equal(t, http.StatusForbidden, status)
	status, _ = call(tc.Show, http.MethodGet, "/tasks/"+submitted.ID, submitted.ID, "", "bob", "org/blue")
	require.Equal(t, http.StatusNotFound, status)
	status, rec = call(tc.List, http.MethodGet, "/tasks?scope=team", "", "", "bob", "org/blue")
	require.Equal(t, http.StatusOK, status)
	require.JSONEq(t, `{"items":[]}`, rec.Body.String())
	status, rec = call(tc.Show, http.MethodGet, "/tasks/"+submitted.ID, submitted.ID, "", "teammate", "org/red")
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, rec.Body.String(), "example prompt")
	status, rec = call(tc.Cancel, http.MethodPost, "/tasks/"+submitted.ID+"/cancel", submitted.ID, "", "teammate", "org/red")
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, rec.Body.String(), "CANCELLED")
}

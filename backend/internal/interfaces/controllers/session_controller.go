package controllers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	sessionrunnercore "github.com/takutakahashi/agentapi-proxy/internal/core/sessionrunner"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/services"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	sessionuc "github.com/takutakahashi/agentapi-proxy/internal/usecases/session"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
	"github.com/takutakahashi/agentapi-proxy/pkg/auth"
	"github.com/takutakahashi/agentapi-proxy/pkg/authzscope"
	"github.com/takutakahashi/agentapi-proxy/pkg/executiontoken"
	"github.com/takutakahashi/agentapi-proxy/pkg/hmacutil"
	"github.com/takutakahashi/agentapi-proxy/pkg/sessionsettings"
	"github.com/takutakahashi/agentapi-proxy/pkg/telemetry"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// SessionCreator is an interface for creating sessions
type SessionCreator interface {
	CreateSession(ctx context.Context, sessionID string, req entities.StartRequest, userID, userRole string, teams []string) (entities.Session, error)
	DeleteSessionByID(sessionID string) error
}

type sessionStartPreviewer interface {
	PreviewSession(ctx context.Context, sessionID string, req entities.StartRequest, userID, userRole string, teams []string) (*entities.SessionStartPreview, error)
}

type pendingSessionAllocationDeleter interface {
	DeletePendingSessionAllocation(ctx context.Context, sessionID string) (bool, error)
}

type sessionStatusMessageProvider interface {
	StatusMessage() string
}

type sessionErrorCodeProvider interface {
	ErrorCode() string
}

type sessionStatusCacheUpdater interface {
	SetStatusSilent(string)
}

// SessionManagerProvider provides access to the session manager
// This allows the session manager to be swapped at runtime (e.g., for testing)
type SessionManagerProvider interface {
	GetSessionManager() repositories.SessionManager
}

type ESMControlTunnel interface {
	IsConnected(context.Context, string) bool
	Do(context.Context, string, string, string, *http.Request) (*http.Response, error)
}

type esmControlEnqueuer interface {
	Enqueue(context.Context, string, string, string, *http.Request) (string, error)
}

type esmControlCommandReader interface {
	CommandResult(context.Context, string) (bool, int, error)
}

type sessionAnnotationUpdater interface {
	UpdateSessionAnnotations(ctx context.Context, sessionID string, patch entities.UpdateSessionAnnotationsRequest) (entities.SessionAnnotations, error)
}

type sessionAnnotationsProvider interface {
	Annotations() entities.SessionAnnotations
}

type sessionSandboxPolicyProvider interface {
	SandboxPolicyID() string
}

type sessionModelOptionsProvider interface {
	ModelOptions() []string
}

type sessionStatusUsageRecorder interface {
	RecordStatus(context.Context, repositories.SessionStatusEvent) error
	ResolveDimensions(context.Context, string) (repositories.SessionUsageDimensions, error)
	RecordResolvedStatus(context.Context, repositories.SessionUsageDimensions, repositories.SessionStatusEvent) error
}

type sessionConfigurationOwnerProvider interface {
	ConfigurationOwnerReference() (apiVersion, kind, name, uid string)
}

// SessionController handles session management endpoints
type SessionController struct {
	taskQueue              *task.Queue
	sessionManagerProvider SessionManagerProvider
	sessionCreator         SessionCreator
	validateTeamUC         *sessionuc.ValidateTeamAccessUseCase
	sessionRouteRepo       repositories.SessionRouteRepository
	settingsRepo           repositories.SettingsRepository
	sessionProfileRepo     repositories.SessionProfileRepository
	contextTemplateRepo    repositories.SessionContextTemplateRepository
	sessionStateStore      services.SessionStateStore
	sessionRunnerStore     sessionRunnerAllocationStore
	sessionStatusRecorder  sessionStatusUsageRecorder
	esmControlTunnel       ESMControlTunnel
	statusSubscribersMu    sync.RWMutex
	statusSubscribers      map[uint64]chan repositories.SessionStatusEvent
	nextStatusSubscriberID uint64
	routeStatusBus         repositories.RouteStatusEventBus
	routeStatusOrigin      string
	routeStatusOutbox      chan repositories.SessionStatusEvent
	// routeReconcile remembers, across reconciliation passes, since when a
	// routed runtime has been observed disconnected.
	routeReconcile      routeReconcileState
	githubTokenResolver interface {
		ResolveAccessToken(context.Context, *entities.User, string) (string, error)
		ResolveAccessTokenForOrganization(context.Context, *entities.User, string) (string, string, bool, error)
		IssueBrokerLeaseForOrganization(context.Context, string, string, string) (string, string, bool, error)
		IssueBrokerLeaseForRepositories(context.Context, string, string, string, []string) (string, string, bool, error)
		ResolveConnectionURLs(context.Context, string) (string, string, error)
		RevokeBrokerLeases(context.Context, string) error
	}
	sessionTokenDebug   bool
	githubBrokerBaseURL string
}

func WithGitHubTokenResolver(resolver interface {
	ResolveAccessToken(context.Context, *entities.User, string) (string, error)
	ResolveAccessTokenForOrganization(context.Context, *entities.User, string) (string, string, bool, error)
	IssueBrokerLeaseForOrganization(context.Context, string, string, string) (string, string, bool, error)
	IssueBrokerLeaseForRepositories(context.Context, string, string, string, []string) (string, string, bool, error)
	ResolveConnectionURLs(context.Context, string) (string, string, error)
	RevokeBrokerLeases(context.Context, string) error
}) SessionControllerOption {
	return func(c *SessionController) { c.githubTokenResolver = resolver }
}

// WithSessionTokenDebug enables safe token-routing diagnostics. Token values are never logged.
func WithSessionTokenDebug(enabled bool) SessionControllerOption {
	return func(c *SessionController) { c.sessionTokenDebug = enabled }
}

// WithGitHubBrokerBaseURL sets the session-reachable broker base URL, including any API prefix.
func WithGitHubBrokerBaseURL(baseURL string) SessionControllerOption {
	return func(c *SessionController) { c.githubBrokerBaseURL = baseURL }
}

func (c *SessionController) githubRepositoriesForSession(ctx context.Context, req entities.StartRequest, userID string, authzCtx *auth.AuthorizationContext) ([]string, error) {
	repositories := append([]string(nil), req.ProfileGitHubRepositories...)
	for _, repository := range req.ProfileRepositories {
		repositories = append(repositories, "^"+regexp.QuoteMeta(repository.FullName)+"$")
	}
	if len(repositories) == 0 && c.sessionProfileRepo != nil {
		profile, _, err := c.resolveSessionProfile(ctx, req.SessionProfileID, userID, req.Scope, req.TeamID, req.Tags, authzCtx)
		if err != nil {
			return nil, err
		}
		profileConfig, err := sessionuc.ResolveEffectiveSessionProfileConfig(ctx, c.sessionProfileRepo, profile, req.Scope, userID, req.TeamID)
		if err != nil {
			return nil, err
		}
		repositories = append(repositories, profileConfig.GitHubRepositories()...)
		for _, repository := range profileConfig.ProfileRepositories() {
			repositories = append(repositories, "^"+regexp.QuoteMeta(repository.Repository)+"$")
		}
	}
	if req.Scope == entities.ScopeTeam && req.TeamID != "" && c.settingsRepo != nil {
		exists, err := c.settingsRepo.Exists(ctx, req.TeamID)
		if err != nil {
			return nil, fmt.Errorf("check team GitHub repositories: %w", err)
		}
		if exists {
			settings, err := c.settingsRepo.FindByName(ctx, req.TeamID)
			if err != nil {
				return nil, fmt.Errorf("load team GitHub repositories: %w", err)
			}
			if settings != nil {
				repositories = append(repositories, settings.GitHubRepositories()...)
			}
		}
	}
	return normalizeRepositoryPatterns(repositories)
}

func (c *SessionController) githubRoutingDefaults(ctx context.Context, req entities.StartRequest, userID string, authzCtx *auth.AuthorizationContext) (string, string, error) {
	repository := sessionRepository(req)
	connectionID := ""
	if req.Params != nil {
		connectionID = req.Params.ConnectionID
	}
	if c.sessionProfileRepo == nil || (repository != "" && connectionID != "") {
		return repository, connectionID, nil
	}
	profile, _, err := c.resolveSessionProfile(ctx, req.SessionProfileID, userID, req.Scope, req.TeamID, req.Tags, authzCtx)
	if err != nil {
		return "", "", err
	}
	config, err := sessionuc.ResolveEffectiveSessionProfileConfig(ctx, c.sessionProfileRepo, profile, req.Scope, userID, req.TeamID)
	if err != nil {
		return "", "", err
	}
	if connectionID == "" && config.Params() != nil {
		connectionID = config.Params().ConnectionID
	}
	if repository == "" {
		if repositories := config.ProfileRepositories(); len(repositories) > 0 {
			repository = repositories[0].Repository
		}
	}
	return repository, connectionID, nil
}

// NewSessionController creates a new SessionController instance
func NewSessionController(
	sessionManagerProvider SessionManagerProvider,
	sessionCreator SessionCreator,
	opts ...SessionControllerOption,
) *SessionController {
	c := &SessionController{
		sessionManagerProvider: sessionManagerProvider,
		sessionCreator:         sessionCreator,
		validateTeamUC:         sessionuc.NewValidateTeamAccessUseCase(),
		statusSubscribers:      make(map[uint64]chan repositories.SessionStatusEvent),
		routeStatusOrigin:      uuid.NewString(),
		routeStatusOutbox:      make(chan repositories.SessionStatusEvent, routeStatusOutboxSize),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SessionControllerOption is a functional option for SessionController
type SessionControllerOption func(*SessionController)

// WithSessionRouteRepository sets the session route repository on the controller
func WithSessionRouteRepository(repo repositories.SessionRouteRepository) SessionControllerOption {
	return func(c *SessionController) {
		c.sessionRouteRepo = repo
	}
}

// WithSettingsRepository sets the settings repository on the controller
func WithSettingsRepository(repo repositories.SettingsRepository) SessionControllerOption {
	return func(c *SessionController) {
		c.settingsRepo = repo
	}
}

// WithSessionProfileRepository sets the session profile repository on the controller
func WithSessionProfileRepository(repo repositories.SessionProfileRepository) SessionControllerOption {
	return func(c *SessionController) {
		c.sessionProfileRepo = repo
	}
}

func WithSessionContextTemplates(repo repositories.SessionContextTemplateRepository, store services.SessionStateStore) SessionControllerOption {
	return func(c *SessionController) { c.contextTemplateRepo, c.sessionStateStore = repo, store }
}

func WithESMControlTunnel(tunnel ESMControlTunnel) SessionControllerOption {
	return func(c *SessionController) { c.esmControlTunnel = tunnel }
}

type sessionRunnerAllocationStore interface {
	GetAllocation(context.Context, string) (*sessionrunnercore.Allocation, error)
}

func WithSessionRunnerStore(store sessionRunnerAllocationStore) SessionControllerOption {
	return func(c *SessionController) { c.sessionRunnerStore = store }
}

func WithSessionStatusUsageRecorder(recorder sessionStatusUsageRecorder) SessionControllerOption {
	return func(c *SessionController) { c.sessionStatusRecorder = recorder }
}

func (c *SessionController) SetSessionStatusUsageRecorder(recorder sessionStatusUsageRecorder) {
	c.sessionStatusRecorder = recorder
}

// getSessionManager returns the current session manager
func (c *SessionController) getSessionManager() repositories.SessionManager {
	return c.sessionManagerProvider.GetSessionManager()
}

// GetName returns the name of this handler for logging
func (c *SessionController) GetName() string {
	return "SessionController"
}

// RegisterRoutes registers session management routes
func (c *SessionController) RegisterRoutes(e *echo.Echo) error {
	// Session management routes
	e.POST("/start", c.StartSession)
	e.GET("/search", c.SearchSessions)
	e.PATCH("/sessions/:sessionId/annotations", c.UpdateSessionAnnotations)
	e.POST("/sessions/:sessionId/resume", c.ResumeSession)
	e.POST("/sessions/:sessionId/restart", c.RestartSession)
	e.GET("/sessions/:sessionId/restart", c.RestartStatus)
	e.POST("/sessions/:sessionId/pause", c.PauseSession)
	e.POST("/sessions/:sessionId/templateize", c.TemplateizeSession)
	e.POST("/sessions/:sessionId/workspace", c.SaveSessionAsWorkspace)
	e.GET("/workspaces", c.ListWorkspaces)
	e.GET("/workspaces/:workspaceId", c.GetWorkspace)
	e.PATCH("/workspaces/:workspaceId", c.UpdateWorkspace)
	e.DELETE("/workspaces/:workspaceId", c.DeleteWorkspace)
	e.GET("/session-context-templates", c.ListSessionContextTemplates)
	e.GET("/session-context-templates/:templateId", c.GetSessionContextTemplate)
	e.PATCH("/session-context-templates/:templateId", c.UpdateSessionContextTemplate)
	e.DELETE("/session-context-templates/:templateId", c.DeleteSessionContextTemplate)
	e.DELETE("/sessions/:sessionId", c.DeleteSession)

	// Session proxy route
	e.Any("/:sessionId/*", c.RouteToSession)

	log.Printf("Registered session management routes")
	return nil
}

func (c *SessionController) SetTaskQueue(q *task.Queue) { c.taskQueue = q }

// StartSession handles POST /start requests to start a new agentapi server
func (c *SessionController) StartSession(ctx echo.Context) error {
	return telemetry.LoggedOperationErr(ctx.Request().Context(), "controllers.SessionController.StartSession", func(requestCtx context.Context) error {
		ctx.SetRequest(ctx.Request().WithContext(requestCtx))
		return c.startSession(ctx)
	})
}

func (c *SessionController) startSession(ctx echo.Context) error {
	c.setCORSHeaders(ctx)
	dryRun := false
	if raw := ctx.QueryParam("dry_run"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "dry_run must be a boolean")
		}
		dryRun = parsed
	}

	sessionID := uuid.New().String()
	var startReq entities.StartRequest
	claims, signed := ctx.Get("trigger_execution_claims").(executiontoken.ExecutionClaims)
	if signed {
		sessionID = claims.SessionID
	}
	if signed && claims.TaskID != "" {
		if c.taskQueue == nil || dryRun || ctx.Request().Header.Get("Idempotency-Key") != claims.ExecutionID ||
			claims.ExecutionID != task.ExecutionID(claims.TaskID, claims.TaskGeneration) {
			return echo.NewHTTPError(http.StatusConflict, "invalid task execution")
		}
		requestCtx, cancel := context.WithTimeout(ctx.Request().Context(), task.StartTimeout)
		defer cancel()
		ctx.SetRequest(ctx.Request().WithContext(requestCtx))
		record, err := c.taskQueue.Begin(requestCtx, claims.TaskID, sessionID, claims.TaskWorker, claims.TaskGeneration)
		if err != nil {
			return taskHTTPError(err)
		}
		if record.OwnerUserID != claims.UserID || record.Scope != claims.Scope || record.TeamID != claims.TeamID {
			return echo.NewHTTPError(http.StatusForbidden, "task identity mismatch")
		}
		startReq = record.Spec.Spec.Start.Request()
	} else {
		if signed && c.getSessionManager().GetSession(sessionID) != nil {
			return ctx.JSON(http.StatusOK, map[string]interface{}{"session_id": sessionID})
		}
		if err := ctx.Bind(&startReq); err != nil {
			log.Printf("Failed to parse request body (using defaults): %v", err)
		}
		if c.taskQueue != nil {
			delete(startReq.Tags, "task_id")
		}
	}
	if signed {
		// Bind worker-triggered identity and ownership to the signed claims.
		startReq.Scope = claims.Scope
		startReq.TeamID = claims.TeamID
		startReq.TriggeredUserID = claims.TriggeredUserID
		if startReq.Tags == nil {
			startReq.Tags = make(map[string]string)
		}
		for key, id := range map[string]string{"slackbot_id": claims.SlackBotID, "schedule_id": claims.ScheduleID, "webhook_id": claims.WebhookID} {
			delete(startReq.Tags, key)
			if id != "" {
				startReq.Tags[key] = id
			}
		}
		if claims.TaskID != "" {
			startReq.Tags["task_id"] = claims.TaskID
		}
		credentialSource := ""
		if startReq.Params != nil {
			credentialSource = startReq.Params.CredentialSource
		}
		ctx.SetRequest(ctx.Request().WithContext(withTriggerCredentialPrincipal(ctx.Request().Context(), claims, credentialSource)))
	}
	explicitSandbox := startReq.Params != nil && startReq.Params.Sandbox != nil
	explicitDocker := startReq.Params != nil && startReq.Params.Docker != nil

	// Get authorization context from middleware (guaranteed to be non-nil by AuthMiddleware)
	authzCtx := auth.GetAuthorizationContext(ctx)
	user := authzCtx.User
	userID := string(user.ID())

	var userRole string
	if len(user.Roles()) > 0 {
		userRole = string(user.Roles()[0])
	} else {
		userRole = "user"
	}

	// Use pre-resolved team information from authorization context
	teams := authzCtx.TeamScope.Teams
	log.Printf("[SESSION_DEBUG] Using authz context for user %s, teams count: %d", userID, len(teams))

	// Normalize scope: default to "user" if not specified.
	// This prevents downstream failures (e.g. memory dump) that require a valid scope.
	if startReq.Scope == "" {
		startReq.Scope = entities.ScopeUser
	}

	// Service accounts cannot use user scope.
	// Automatically route to the service account's team scope.
	{
		resolvedScope, resolvedTeamID := authzCtx.ResolveScope(string(startReq.Scope), startReq.TeamID)
		if resolvedScope != string(startReq.Scope) || resolvedTeamID != startReq.TeamID {
			log.Printf("[SESSION_DEBUG] Service account %s: routing scope %q → %q (team %q)", userID, startReq.Scope, resolvedScope, resolvedTeamID)
		}
		startReq.Scope = entities.ResourceScope(resolvedScope)
		startReq.TeamID = resolvedTeamID
	}
	repository, profileConnectionID, err := c.githubRoutingDefaults(ctx.Request().Context(), startReq, userID, authzCtx)
	if err != nil {
		return sessionProfileResolutionHTTPError(err)
	}
	if profileConnectionID != "" {
		if startReq.Params == nil {
			startReq.Params = &entities.SessionParams{}
		}
		if startReq.Params.ConnectionID == "" {
			startReq.Params.ConnectionID = profileConnectionID
		}
	}
	brokerConfigured := false
	useBroker := shouldUseGitHubBroker(startReq, repository)
	var allowedRepositories []string
	if !useBroker && startReq.Scope == entities.ScopeTeam && repository == "" && startReq.Params != nil && startReq.Params.GithubToken == "" && startReq.Params.ConnectionID == "" && c.githubTokenResolver != nil {
		allowedRepositories, err = c.githubRepositoriesForSession(ctx.Request().Context(), startReq, userID, authzCtx)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		useBroker = len(allowedRepositories) > 0
	}
	if useBroker && c.githubTokenResolver != nil {
		if !authzCtx.CanCreateInTeam(startReq.TeamID) {
			return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("user is not a member of team %s", startReq.TeamID))
		}
		var lease, connectionID string
		var matched bool
		var err error
		if dryRun {
			if repository == "" {
				matched = len(allowedRepositories) > 0
			} else {
				_, connectionID, matched, err = c.githubTokenResolver.ResolveAccessTokenForOrganization(ctx.Request().Context(), user, repositoryOwner(repository))
			}
			lease = "<generated-at-apply>"
		} else {
			if allowedRepositories == nil {
				allowedRepositories, err = c.githubRepositoriesForSession(ctx.Request().Context(), startReq, userID, authzCtx)
				if err != nil {
					return echo.NewHTTPError(http.StatusBadRequest, err.Error())
				}
			}
			lease, connectionID, matched, err = c.githubTokenResolver.IssueBrokerLeaseForRepositories(ctx.Request().Context(), sessionID, repositoryOwner(repository), repository, allowedRepositories)
		}
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		if matched {
			brokerConfigured = true
			if startReq.Environment == nil {
				startReq.Environment = make(map[string]string)
			}
			if connectionID != "" {
				if err := c.applyGitHubConnectionURLs(ctx.Request().Context(), &startReq, connectionID); err != nil {
					if !dryRun {
						c.revokeGitHubBrokerLeases(ctx.Request().Context(), sessionID)
					}
					return echo.NewHTTPError(http.StatusBadRequest, err.Error())
				}
			}
			brokerURL, err := githubBrokerURL(ctx, sessionID, c.githubBrokerBaseURL)
			if err != nil {
				if !dryRun {
					c.revokeGitHubBrokerLeases(ctx.Request().Context(), sessionID)
				}
				return echo.NewHTTPError(http.StatusBadRequest, err.Error())
			}
			startReq.Environment["AGENTAPI_GITHUB_BROKER_URL"] = brokerURL
			startReq.Environment["AGENTAPI_GITHUB_BROKER_TOKEN"] = lease
			startReq.Environment["AGENTAPI_GITHUB_CONNECTION_ID"] = connectionID
			if startReq.Params != nil {
				startReq.Params.GithubToken = ""
			}
			c.logSessionTokenRouting(sessionID, "team-broker", connectionID, "")
		}
	}
	if !brokerConfigured && startReq.Params != nil && startReq.Params.ConnectionID != "" {
		if c.githubTokenResolver == nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "GitHub connection credentials are unavailable")
		}
		token, err := c.githubTokenResolver.ResolveAccessToken(ctx.Request().Context(), user, startReq.Params.ConnectionID)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		startReq.Params.GithubToken = token
		if err := c.applyGitHubConnectionURLs(ctx.Request().Context(), &startReq, startReq.Params.ConnectionID); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		c.logSessionTokenRouting(sessionID, "explicit", startReq.Params.ConnectionID, token)
	} else if !brokerConfigured && (startReq.Params == nil || startReq.Params.GithubToken == "") && repositoryOwner(repository) != "" && c.githubTokenResolver != nil {
		token, connectionID, matched, err := c.githubTokenResolver.ResolveAccessTokenForOrganization(ctx.Request().Context(), user, repositoryOwner(repository))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		if matched {
			startReq.Params.GithubToken = token
			startReq.Params.ConnectionID = connectionID
			if err := c.applyGitHubConnectionURLs(ctx.Request().Context(), &startReq, connectionID); err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, err.Error())
			}
			c.logSessionTokenRouting(sessionID, "organization", connectionID, token)
		} else {
			populateGitHubTokenFromAuthHeader(ctx, &startReq)
			if startReq.Params != nil && startReq.Params.ConnectionID != "" {
				if err := c.applyGitHubConnectionURLs(ctx.Request().Context(), &startReq, startReq.Params.ConnectionID); err != nil {
					return echo.NewHTTPError(http.StatusBadRequest, err.Error())
				}
			}
			c.logSessionTokenRouting(sessionID, "authentication", "", startReq.Params.GithubToken)
		}
	} else if !brokerConfigured {
		populateGitHubTokenFromAuthHeader(ctx, &startReq)
		if startReq.Params != nil {
			if startReq.Params.ConnectionID != "" {
				if err := c.applyGitHubConnectionURLs(ctx.Request().Context(), &startReq, startReq.Params.ConnectionID); err != nil {
					return echo.NewHTTPError(http.StatusBadRequest, err.Error())
				}
			}
			c.logSessionTokenRouting(sessionID, "authentication", startReq.Params.ConnectionID, startReq.Params.GithubToken)
		}
	}

	// Validate team scope authorization
	if startReq.Scope == entities.ScopeTeam {
		if startReq.TeamID == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "team_id is required for team scope")
		}

		// Check if user can create in this team
		if !authzCtx.CanCreateInTeam(startReq.TeamID) {
			return echo.NewHTTPError(http.StatusForbidden, fmt.Sprintf("user is not a member of team %s", startReq.TeamID))
		}
	} else {
		// Personal scope - check if user can create personal resources
		if !authzCtx.PersonalScope.CanCreate {
			return echo.NewHTTPError(http.StatusForbidden, "user does not have permission to create sessions")
		}
	}

	contextTemplate, err := c.resolveContextTemplate(ctx, &startReq)
	if err != nil {
		return err
	}

	reuseResolution := map[string]interface{}{"reason": "reuse_not_requested", "requested": false}
	if dryRun {
		if existingID, reused, status, err := c.previewReuseStartSession(ctx, startReq, userID); err != nil {
			return err
		} else if reused {
			return ctx.JSON(http.StatusOK, map[string]interface{}{
				"dry_run": true, "session_id": existingID, "decision": "reuse",
				"reuse":      map[string]interface{}{"session_id": existingID, "status": status, "stop_before_reuse": startReq.StopBeforeReuse},
				"resolution": map[string]interface{}{"reuse": map[string]interface{}{"requested": true, "reason": "matching_live_session_selected", "session_id": existingID, "status": status}},
			})
		} else if len(startReq.ReuseMatchTags) > 0 && startReq.ReuseMessage != "" {
			reuseResolution = map[string]interface{}{"reason": "no_matching_live_session", "requested": true}
		}
	} else if existingID, reused, err := c.reuseStartSession(ctx, startReq, userID); err != nil {
		return err
	} else if reused {
		return ctx.JSON(http.StatusOK, map[string]interface{}{"session_id": existingID, "session_reused": true})
	}
	if startReq.MaxSessions > 0 && len(c.getSessionManager().ListSessions(entities.SessionFilter{Tags: startReq.LimitMatchTags})) >= startReq.MaxSessions {
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("session limit reached: maximum %d sessions", startReq.MaxSessions))
	}
	// Reuse and limit controls belong to this /start invocation and must not be
	// persisted as part of the session's restart configuration.
	startReq.ReuseMatchTags, startReq.ReuseMessage, startReq.StopBeforeReuse = nil, "", false
	startReq.LimitMatchTags, startReq.MaxSessions = nil, 0

	// Persist the explicit input before profile defaults are merged.
	startInput, err := json.Marshal(startReq)
	if err != nil {
		return echo.NewHTTPError(500, "failed to preserve session input")
	}
	profileResolution := map[string]interface{}{"reason": "profile_repository_unavailable"}
	if c.sessionProfileRepo != nil {
		profile, profileReason, err := c.resolveSessionProfile(
			ctx.Request().Context(),
			startReq.SessionProfileID,
			userID,
			startReq.Scope,
			startReq.TeamID,
			startReq.Tags,
			authzCtx,
		)
		if err != nil {
			return err
		}
		profileResolution = map[string]interface{}{"reason": profileReason}
		if profile != nil {
			profileResolution["selected_profile_id"] = profile.ID()
			profileResolution["selected_profile_name"] = profile.Name()
			if tags := profile.SelectorTags(); len(tags) > 0 {
				profileResolution["selector_tags"] = tags
			}
		}
		profileCfg, err := sessionuc.ResolveEffectiveSessionProfileConfig(
			ctx.Request().Context(),
			c.sessionProfileRepo,
			profile,
			startReq.Scope,
			userID,
			startReq.TeamID,
		)
		if err != nil {
			return sessionProfileResolutionHTTPError(err)
		}
		applySessionProfile(&startReq, profile, profileCfg, explicitSandbox, explicitDocker)
	}
	if !dryRun {
		if store, ok := c.sessionRunnerStore.(sessionConfigurationStore); ok {
			config := &sessionrunnercore.Configuration{SessionID: sessionID, TriggeredUserID: startReq.TriggeredUserID, Input: startInput, ProfileID: startReq.ResolvedSessionProfileID, UserID: userID, Scope: string(startReq.Scope), TeamID: startReq.TeamID, Teams: teams}
			if err := store.CreateConfiguration(ctx.Request().Context(), config); err != nil {
				return echo.NewHTTPError(503, "failed to preserve session input")
			}
		}
	}

	if dryRun {
		previewer, ok := c.sessionCreator.(sessionStartPreviewer)
		if !ok {
			return echo.NewHTTPError(http.StatusNotImplemented, "session start dry-run is not supported")
		}
		preview, err := previewer.PreviewSession(ctx.Request().Context(), sessionID, startReq, userID, userRole, teams)
		if err != nil {
			var quotaErr *sessionrunnercore.QuotaExceededError
			if errors.As(err, &quotaErr) {
				return ctx.JSON(http.StatusTooManyRequests, map[string]any{
					"error": quotaErr.Error(), "pool": quotaErr.Pool, "binding_id": quotaErr.BindingID,
					"max_concurrent": quotaErr.MaxConcurrent, "active": quotaErr.Active,
				})
			}
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		effectiveRequest, requestRedactions, err := redactSessionStartPreview(startReq)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to encode effective request")
		}
		settings, settingsRedactions, err := redactSessionStartPreview(preview.Settings)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to encode session settings")
		}
		redactions := make([]string, 0, len(requestRedactions)+len(settingsRedactions))
		for _, path := range requestRedactions {
			redactions = append(redactions, "/effective_request"+path)
		}
		for _, path := range settingsRedactions {
			redactions = append(redactions, "/settings"+path)
		}
		sort.Strings(redactions)
		effects := []map[string]interface{}{{"kind": "persist_configuration", "would_execute": true}, {"kind": "create_session", "would_execute": true}}
		if preview.Placement.Transport == repositories.SessionRouteTransportDirectRuntime {
			effects = append(effects, map[string]interface{}{"kind": "enqueue_allocation", "would_execute": true}, map[string]interface{}{"kind": "save_session_route", "would_execute": true})
		}
		resolution := map[string]interface{}{"reuse": reuseResolution, "profile": profileResolution}
		if placementResolution, ok := preview.Resolution.(map[string]interface{}); ok {
			for key, value := range placementResolution {
				resolution[key] = value
			}
		}
		return ctx.JSON(http.StatusOK, map[string]interface{}{
			"dry_run": true, "session_id": sessionID, "decision": "create",
			"effective_request": effectiveRequest, "resolved_session_profile_id": startReq.ResolvedSessionProfileID,
			"placement": preview.Placement, "settings": settings, "redactions": redactions,
			"resolution": resolution,
			"effects":    effects,
			"warnings":   []string{"Dry-run does not reserve capacity; a later start may resolve differently."},
		})
	}

	session, err := c.sessionCreator.CreateSession(ctx.Request().Context(), sessionID, startReq, userID, userRole, teams)
	if err != nil {
		c.revokeGitHubBrokerLeases(ctx.Request().Context(), sessionID)
		if errors.Is(err, task.ErrWaitingCapacity) {
			return echo.NewHTTPError(http.StatusTooManyRequests, "waiting for session capacity")
		}
		var quotaErr *sessionrunnercore.QuotaExceededError
		if errors.As(err, &quotaErr) {
			return ctx.JSON(http.StatusTooManyRequests, map[string]any{
				"error":          quotaErr.Error(),
				"pool":           quotaErr.Pool,
				"binding_id":     quotaErr.BindingID,
				"max_concurrent": quotaErr.MaxConcurrent,
				"active":         quotaErr.Active,
			})
		}
		log.Printf("Failed to create session: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session")
	}
	c.recordContextTemplateUse(ctx.Request().Context(), contextTemplate)
	if owner, ok := session.(sessionConfigurationOwnerProvider); ok {
		if store, ok := c.sessionRunnerStore.(sessionConfigurationOwnerStore); ok {
			apiVersion, kind, name, uid := owner.ConfigurationOwnerReference()
			if err := store.SetConfigurationOwnerReference(ctx.Request().Context(), sessionID, sessionrunnercore.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, UID: uid}); err != nil {
				log.Printf("Failed to set configuration owner reference for session %s: %v", sessionID, err)
			}
		}
	}

	response := map[string]interface{}{"session_id": session.ID()}
	if contextTemplate != nil {
		response["workspace_id"] = contextTemplate.ID
		response["context_template_id"] = contextTemplate.ID
	}
	return ctx.JSON(http.StatusOK, response)
}

func withTriggerCredentialPrincipal(ctx context.Context, claims executiontoken.ExecutionClaims, credentialSource string) context.Context {
	if claims.TriggeredUserID == "" || (credentialSource != "triggered_user" && credentialSource != "github_sender") {
		return ctx
	}
	principal, ok := authzscope.FromContext(ctx)
	if !ok {
		return ctx
	}
	for _, userID := range principal.DelegatedUserIDs {
		if userID == claims.TriggeredUserID {
			return ctx
		}
	}
	principal.DelegatedUserIDs = append(principal.DelegatedUserIDs, claims.TriggeredUserID)
	return authzscope.WithPrincipal(ctx, principal)
}

func (c *SessionController) previewReuseStartSession(ctx echo.Context, startReq entities.StartRequest, ownerUserID string) (string, bool, string, error) {
	if len(startReq.ReuseMatchTags) == 0 || startReq.ReuseMessage == "" {
		return "", false, "", nil
	}
	if c.sessionRouteRepo != nil {
		var routes []*repositories.SessionRoute
		var err error
		if filtered, ok := c.sessionRouteRepo.(repositories.FilteredSessionRouteRepository); ok {
			routes, err = filtered.ListFiltered(ctx.Request().Context(), repositories.SessionRouteFilter{
				UserID: ownerUserID, Scope: string(startReq.Scope), TeamID: startReq.TeamID, Tags: startReq.ReuseMatchTags,
			})
		} else {
			routes, err = c.sessionRouteRepo.List(ctx.Request().Context(), ownerUserID)
		}
		if err != nil {
			return "", false, "", echo.NewHTTPError(http.StatusInternalServerError, "failed to list reusable sessions").SetInternal(err)
		}
		sort.SliceStable(routes, func(i, j int) bool { return routes[i].StartedAt.After(routes[j].StartedAt) })
		for _, route := range routes {
			if route.Transport == repositories.SessionRouteTransportDirectRuntime && route.Scope == string(startReq.Scope) &&
				route.TeamID == startReq.TeamID && (startReq.Scope == entities.ScopeTeam || route.UserID == ownerUserID) &&
				tagsContain(route.Tags, startReq.ReuseMatchTags) && !terminalReuseStatus(route.Status) {
				return route.SessionID, true, route.Status, nil
			}
		}
	}
	for _, existing := range c.getSessionManager().ListSessions(entities.SessionFilter{Tags: startReq.ReuseMatchTags}) {
		status := strings.ToLower(existing.Status())
		if existing.Scope() == startReq.Scope && existing.TeamID() == startReq.TeamID &&
			(startReq.Scope == entities.ScopeTeam || existing.UserID() == ownerUserID) && !terminalReuseStatus(status) && status != "suspended" {
			return existing.ID(), true, existing.Status(), nil
		}
	}
	return "", false, "", nil
}

// reuseStartSession makes tag-based trigger reuse authoritative at /start.
// Direct-runtime prompts are appended to the durable reverse-RPC queue, so the
// request is not lost while a matching session is still connecting.
func (c *SessionController) reuseStartSession(ctx echo.Context, startReq entities.StartRequest, ownerUserID string) (string, bool, error) {
	if len(startReq.ReuseMatchTags) == 0 || startReq.ReuseMessage == "" {
		return "", false, nil
	}
	// Direct runtimes are durable routes and are intentionally absent from the
	// API process's local SessionManager. Search the route repository first.
	if c.sessionRouteRepo != nil {
		var routes []*repositories.SessionRoute
		var err error
		routes, err = telemetry.LoggedOperation(ctx.Request().Context(), "controllers.SessionController.FindReusableRoutes", func(operationCtx context.Context) ([]*repositories.SessionRoute, error) {
			if filtered, ok := c.sessionRouteRepo.(repositories.FilteredSessionRouteRepository); ok {
				return filtered.ListFiltered(operationCtx, repositories.SessionRouteFilter{
					UserID: ownerUserID, Scope: string(startReq.Scope), TeamID: startReq.TeamID, Tags: startReq.ReuseMatchTags,
				})
			}
			return c.sessionRouteRepo.List(operationCtx, ownerUserID)
		}, telemetry.Int64("session.reuse_tag_count", int64(len(startReq.ReuseMatchTags))))
		if err != nil {
			return "", false, echo.NewHTTPError(http.StatusInternalServerError, "failed to list reusable sessions").SetInternal(err)
		}
		sort.SliceStable(routes, func(i, j int) bool { return routes[i].StartedAt.After(routes[j].StartedAt) })
		for _, route := range routes {
			if route.Transport != repositories.SessionRouteTransportDirectRuntime ||
				route.Scope != string(startReq.Scope) || route.TeamID != startReq.TeamID ||
				(startReq.Scope != entities.ScopeTeam && route.UserID != ownerUserID) ||
				!tagsContain(route.Tags, startReq.ReuseMatchTags) || terminalReuseStatus(route.Status) {
				continue
			}
			enqueuer, ok := c.esmControlTunnel.(esmControlEnqueuer)
			if !ok {
				return "", false, echo.NewHTTPError(http.StatusServiceUnavailable, "session runtime queue is unavailable")
			}
			body, _ := json.Marshal(map[string]string{"content": startReq.ReuseMessage, "type": "user"})
			promptPath := "/internal/session-prompt"
			if startReq.StopBeforeReuse && strings.EqualFold(route.Status, "running") {
				promptPath = "/internal/session-interrupt-prompt"
			}
			req, reqErr := http.NewRequestWithContext(ctx.Request().Context(), http.MethodPost, "http://session.local"+promptPath, bytes.NewReader(body))
			if reqErr != nil {
				return "", false, echo.NewHTTPError(http.StatusInternalServerError, "failed to build reusable session message").SetInternal(reqErr)
			}
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			if strings.EqualFold(route.Status, "suspended") {
				resp, resumeErr := c.requestRemoteResume(ctx, route)
				if resumeErr != nil {
					return "", false, resumeErr
				}
				_ = resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					return "", false, echo.NewHTTPError(http.StatusServiceUnavailable, "failed to resume reusable session")
				}
			}
			commandID, err := telemetry.LoggedOperation(ctx.Request().Context(), "controllers.SessionController.EnqueueReusePrompt", func(operationCtx context.Context) (string, error) {
				return enqueuer.Enqueue(operationCtx, route.SessionID, route.SessionID, route.RemoteSessionID, req)
			}, telemetry.String("session.id", route.SessionID), telemetry.String("session.prompt_path", promptPath))
			if err != nil {
				return "", false, echo.NewHTTPError(http.StatusServiceUnavailable, "failed to queue reusable session prompt").SetInternal(err)
			}
			log.Printf("[SESSION_REUSE] Reused direct runtime %s command_id=%s for tags %v", route.SessionID, commandID, startReq.ReuseMatchTags)
			return route.SessionID, true, nil
		}
	}

	existingSessions, _ := telemetry.LoggedOperation(ctx.Request().Context(), "controllers.SessionController.FindReusableSessions", func(context.Context) ([]entities.Session, error) {
		return c.getSessionManager().ListSessions(entities.SessionFilter{Tags: startReq.ReuseMatchTags}), nil
	}, telemetry.Int64("session.reuse_tag_count", int64(len(startReq.ReuseMatchTags))))
	for _, existing := range existingSessions {
		if existing.Scope() != startReq.Scope || existing.TeamID() != startReq.TeamID || (startReq.Scope != entities.ScopeTeam && existing.UserID() != ownerUserID) {
			continue
		}
		status := strings.ToLower(existing.Status())
		if terminalReuseStatus(status) || status == "suspended" {
			continue
		}
		if startReq.StopBeforeReuse && status == "running" {
			if err := telemetry.LoggedOperationErr(ctx.Request().Context(), "controllers.SessionController.StopReusableSession", func(operationCtx context.Context) error {
				return c.getSessionManager().StopAgent(operationCtx, existing.ID())
			}, telemetry.String("session.id", existing.ID())); err != nil {
				return "", false, echo.NewHTTPError(http.StatusInternalServerError, "failed to interrupt reusable session").SetInternal(err)
			}
		}
		if err := telemetry.LoggedOperationErr(ctx.Request().Context(), "controllers.SessionController.SendReuseMessage", func(operationCtx context.Context) error {
			return c.getSessionManager().SendMessage(operationCtx, existing.ID(), startReq.ReuseMessage)
		}, telemetry.String("session.id", existing.ID())); err != nil {
			return "", false, echo.NewHTTPError(http.StatusInternalServerError, "failed to route reusable session message").SetInternal(err)
		}
		return existing.ID(), true, nil
	}
	return "", false, nil
}

func tagsContain(tags, expected map[string]string) bool {
	for key, value := range expected {
		if tags[key] != value {
			return false
		}
	}
	return true
}

func terminalReuseStatus(status string) bool {
	switch strings.ToLower(status) {
	case "stopped", "failed", "terminated", "terminating":
		return true
	default:
		return false
	}
}

func shouldUseGitHubBroker(startReq entities.StartRequest, repository string) bool {
	if startReq.Scope != entities.ScopeTeam || repository == "" {
		return false
	}
	return startReq.Params == nil || (startReq.Params.GithubToken == "" && startReq.Params.ConnectionID == "")
}

func githubBrokerURL(ctx echo.Context, sessionID, baseURL string) (string, error) {
	endpoint := "/internal/sessions/" + url.PathEscape(sessionID) + "/github-credentials"
	if baseURL = strings.TrimSpace(baseURL); baseURL != "" {
		base, err := url.Parse(baseURL)
		if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" ||
			base.User != nil || strings.ContainsAny(baseURL, "?#") {
			return "", errors.New("github_broker_base_url must be an absolute HTTP(S) URL without userinfo, query, or fragment")
		}
		// The configured base is authoritative; do not append forwarded prefixes
		// from the browser-facing route when sessions use a different endpoint.
		return strings.TrimRight(base.String(), "/") + endpoint, nil
	}
	scheme := strings.TrimSpace(ctx.Request().Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if ctx.Request().TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := strings.TrimSpace(ctx.Request().Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = ctx.Request().Host
	}
	if scheme != "http" && scheme != "https" {
		return "", errors.New("invalid GitHub broker scheme")
	}
	if host == "" || strings.ContainsAny(host, "\r\n/") {
		return "", errors.New("invalid GitHub broker host")
	}
	prefix := strings.TrimSuffix(strings.TrimSpace(ctx.Request().Header.Get("X-Forwarded-Prefix")), "/")
	if prefix != "" && (!strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") || strings.ContainsAny(prefix, "\r\n?#")) {
		return "", errors.New("invalid GitHub broker prefix")
	}
	return scheme + "://" + host + prefix + endpoint, nil
}

func populateGitHubTokenFromAuthHeader(ctx echo.Context, startReq *entities.StartRequest) {
	if startReq.Scope == entities.ScopeTeam {
		return
	}
	if startReq.Params == nil {
		startReq.Params = &entities.SessionParams{}
	}
	if startReq.Params.GithubToken != "" {
		return
	}
	if credential, ok := auth.GetGitHubCredentialFromContext(ctx); ok {
		startReq.Params.GithubToken = credential.Token
		startReq.Params.ConnectionID = credential.ConnectionID
	}
}

func (c *SessionController) logSessionTokenRouting(sessionID, source, connectionID, token string) {
	if !c.sessionTokenDebug {
		return
	}
	fingerprint := "none"
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		fingerprint = fmt.Sprintf("%x", sum[:6])
	}
	log.Printf("[SESSION_TOKEN_DEBUG] session_id=%s source=%s connection_id=%q token_fingerprint=%s token_present=%t", sessionID, source, connectionID, fingerprint, token != "")
}

func (c *SessionController) applyGitHubConnectionURLs(ctx context.Context, startReq *entities.StartRequest, connectionID string) error {
	baseURL, apiURL, err := c.githubTokenResolver.ResolveConnectionURLs(ctx, connectionID)
	if err != nil {
		return err
	}
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil || parsedBaseURL.Host == "" {
		return fmt.Errorf("selected GitHub connection has an invalid base URL")
	}
	if startReq.Environment == nil {
		startReq.Environment = make(map[string]string)
	}
	// These are part of the selected credential's routing context. Overwrite
	// request-provided values so a token is never sent to a different GitHub host.
	startReq.Environment["GITHUB_URL"] = baseURL
	startReq.Environment["GITHUB_API"] = apiURL
	// GH_HOST may already be present in deployment or team settings. Set it even
	// for github.com so gh cannot keep using a deployment-wide Enterprise host.
	startReq.Environment["GH_HOST"] = parsedBaseURL.Host
	return nil
}

func repositoryOwner(repoFullName string) string {
	parts := strings.SplitN(strings.TrimSpace(repoFullName), "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

func sessionRepository(startReq entities.StartRequest) string {
	if startReq.Params != nil && strings.TrimSpace(startReq.Params.RepoFullName) != "" {
		return startReq.Params.RepoFullName
	}
	return startReq.Tags["repository"]
}

func containsAllocatorSelector(tags map[string]string) bool {
	for key := range tags {
		if strings.HasPrefix(key, "allocator.") {
			return true
		}
	}
	return false
}

func hasRequestedSessionPool(startReq entities.StartRequest) bool {
	return startReq.Params != nil && strings.TrimSpace(startReq.Params.Pool) != ""
}

func removeImplicitAllocatorCapabilities(params *entities.SessionParams, explicitSandbox, explicitDocker bool) {
	if params == nil {
		return
	}
	if !explicitSandbox {
		params.Sandbox = nil
	}
	if !explicitDocker {
		params.Docker = nil
	}
}

// resolveSessionModelOptions returns the ACP model switching candidates exposed
// for a session: the value snapshotted in the session's run request, falling
// back to the session profile it was created from.
func (c *SessionController) resolveSessionModelOptions(ctx context.Context, session entities.Session, cache map[string][]string) []string {
	if provider, ok := session.(sessionModelOptionsProvider); ok {
		if options := provider.ModelOptions(); len(options) > 0 {
			return options
		}
	}
	return c.sessionModelOptionsFromTags(ctx, session.Tags(), cache)
}

// sessionModelOptionsFromTags resolves model switching candidates from the
// session profile referenced by a session's tags. Sessions handled by an
// external session manager no longer carry the original run request, so the
// profile is the durable source of truth for the candidates.
func (c *SessionController) sessionModelOptionsFromTags(ctx context.Context, tags map[string]string, cache map[string][]string) []string {
	if c.sessionProfileRepo == nil {
		return nil
	}
	profileID := strings.TrimSpace(tags["session_profile_id"])
	if profileID == "" {
		return nil
	}
	if cached, ok := cache[profileID]; ok {
		return cached
	}
	var options []string
	profile, err := c.sessionProfileRepo.Get(ctx, profileID)
	if err != nil {
		log.Printf("[SESSION] Warning: could not resolve model options from session profile %q: %v", profileID, err)
	} else if profile != nil {
		cfg := profile.Config()
		if params := cfg.Params(); params != nil {
			options = append([]string(nil), params.ModelOptions...)
		}
	}
	if cache != nil {
		cache[profileID] = options
	}
	return options
}

// SearchSessions handles GET /search requests to list and filter active sessions
func (c *SessionController) SearchSessions(ctx echo.Context) error {
	request := ctx.Request()
	return telemetry.OperationErr(request.Context(), "controllers.SessionController.SearchSessions", func(requestCtx context.Context) error {
		ctx.SetRequest(request.WithContext(requestCtx))
		return c.searchSessions(ctx)
	},
		telemetry.String("search.scope", ctx.QueryParam("scope")),
		telemetry.String("search.status", ctx.QueryParam("status")),
		telemetry.Bool("search.team_filter", ctx.QueryParam("team_id") != ""),
	)
}

func (c *SessionController) searchSessions(ctx echo.Context) error {
	c.setCORSHeaders(ctx)

	// Get authorization context from middleware (guaranteed to be non-nil by AuthMiddleware)
	authzCtx := auth.GetAuthorizationContext(ctx)
	status := ctx.QueryParam("status")
	scopeFilter := ctx.QueryParam("scope")
	teamIDFilter := ctx.QueryParam("team_id")

	userID := authzCtx.PersonalScope.UserID
	userTeamIDs := authzCtx.TeamScope.Teams

	// Service accounts cannot use user scope.
	// Automatically route to the service account's team scope when scope is not explicitly "team".
	{
		resolvedScope, resolvedTeamID := authzCtx.ResolveScope(scopeFilter, teamIDFilter)
		if resolvedScope != scopeFilter || resolvedTeamID != teamIDFilter {
			log.Printf("[SESSION_DEBUG] Service account %s search: routing scope %q → %q (team %q)", userID, scopeFilter, resolvedScope, resolvedTeamID)
		}
		scopeFilter = resolvedScope
		teamIDFilter = resolvedTeamID
	}

	tagFilters := make(map[string]string)
	for paramName, paramValues := range ctx.QueryParams() {
		if strings.HasPrefix(paramName, "tag.") && len(paramValues) > 0 {
			tagKey := strings.TrimPrefix(paramName, "tag.")
			tagFilters[tagKey] = paramValues[0]
		}
	}
	telemetry.SetAttributes(ctx.Request().Context(), telemetry.Int64("search.tag_filter_count", int64(len(tagFilters))))

	// Build filter
	filter := entities.SessionFilter{
		Status:  status,
		Tags:    tagFilters,
		Scope:   entities.ResourceScope(scopeFilter),
		TeamID:  teamIDFilter,
		TeamIDs: userTeamIDs,
	}

	// For non-team scope, always filter by user ID - even admins should not see
	// other users' personal sessions. Admin privileges apply to team-scoped resources only.
	if scopeFilter != "team" && teamIDFilter == "" {
		filter.UserID = userID
	}

	// Get sessions from session manager. Some implementations perform informer
	// initialization or Kubernetes fallback reads here, so keep this separate
	// from the in-memory authorization and response-building work below.
	sessions, _ := telemetry.Operation(ctx.Request().Context(), "controllers.SessionController.SearchSessions.ListLocalSessions", func(context.Context) ([]entities.Session, error) {
		return c.getSessionManager().ListSessions(filter), nil
	})
	telemetry.SetAttributes(ctx.Request().Context(), telemetry.Int64("search.local_session_count", int64(len(sessions))))

	// Filter by user authorization using authorization context
	matchingSessions, _ := telemetry.Operation(ctx.Request().Context(), "controllers.SessionController.SearchSessions.FilterLocalSessions", func(context.Context) ([]entities.Session, error) {
		matching := make([]entities.Session, 0)
		for _, session := range sessions {
			// Scope isolation
			sessionScope := session.Scope()
			if scopeFilter == string(entities.ScopeTeam) {
				if sessionScope != entities.ScopeTeam {
					continue
				}
				if teamIDFilter != "" && session.TeamID() != teamIDFilter {
					continue
				}
			} else if sessionScope == entities.ScopeTeam {
				continue
			}

			// Check authorization using pre-resolved context. Admin bypasses are
			// handled within CanAccessResource for team-scoped resources only.
			if authzCtx.CanAccessResource(session.UserID(), string(sessionScope), session.TeamID()) {
				matching = append(matching, session)
			}
		}
		return matching, nil
	})

	// Exclude hidden sessions by default (unless caller explicitly requests them via tag.hidden=true)
	_, hiddenExplicitlyRequested := tagFilters["hidden"]
	if !hiddenExplicitlyRequested {
		matchingSessions = filterHiddenSessions(matchingSessions)
	}
	telemetry.SetAttributes(ctx.Request().Context(), telemetry.Int64("search.matching_local_session_count", int64(len(matchingSessions))))

	// Load ESM routes before building the response so the allocated session IDs
	// can be removed from the local list. Only the parent proxy's SessionID is
	// public; RemoteSessionID is an implementation detail used for routing.
	var routes []*repositories.SessionRoute
	allocatedSessions := make(map[string]entities.Session)
	if c.sessionRouteRepo != nil {
		var err error
		// Team-scoped routes may be owned by another team member (for example,
		// sessions launched by a team webhook). Do not owner-filter those routes;
		// the authorization checks below decide visibility. Personal routes remain
		// owner-filtered at the repository boundary.
		routes, err = telemetry.Operation(ctx.Request().Context(), "controllers.SessionController.SearchSessions.ListRoutes", func(routeCtx context.Context) ([]*repositories.SessionRoute, error) {
			if scopeFilter == string(entities.ScopeTeam) {
				if filtered, ok := c.sessionRouteRepo.(repositories.FilteredSessionRouteRepository); ok {
					routeFilter := repositories.SessionRouteFilter{Scope: string(entities.ScopeTeam), TeamID: teamIDFilter}
					if teamIDFilter == "" && !authzCtx.TeamScope.IsAdmin {
						routeFilter.TeamIDs = userTeamIDs
					}
					return filtered.ListFiltered(routeCtx, routeFilter)
				}
				return c.sessionRouteRepo.List(routeCtx, "")
			}
			if filtered, ok := c.sessionRouteRepo.(repositories.FilteredSessionRouteRepository); ok {
				return filtered.ListFiltered(routeCtx, repositories.SessionRouteFilter{
					UserID: userID, Scope: string(entities.ScopeUser),
				})
			}
			return c.sessionRouteRepo.List(routeCtx, userID)
		})
		if err != nil {
			log.Printf("[SEARCH] Failed to list session routes: %v", err)
			routes = nil
		} else {
			telemetry.SetAttributes(ctx.Request().Context(), telemetry.Int64("search.route_count", int64(len(routes))))
			telemetry.OperationVoid(ctx.Request().Context(), "controllers.SessionController.SearchSessions.ReconcileRoutes", func(reconcileCtx context.Context) {
				matchingSessions = excludeTemplatedSessions(matchingSessions, routes)
				activeRoutes := routes[:0]
				for _, route := range routes {
					// A templated session is retained as a tombstone so direct access can
					// explain where it went, but it is no longer a usable session and must
					// not appear in session listings.
					if route.Status == "templated" {
						continue
					}
					if c.reconcileQueuedDeletion(reconcileCtx, route) {
						continue
					}
					activeRoutes = append(activeRoutes, route)
				}
				routes = activeRoutes
				allocatedSessions = indexAllocatedSessions(matchingSessions, routes)
				matchingSessions = excludeAllocatedSessions(matchingSessions, routes)
			})
		}
	}

	filteredSessions := make([]map[string]interface{}, 0, len(matchingSessions))
	// Profiles are shared by many sessions, so resolve each one at most once per
	// request while building the response.
	modelOptionsCache := make(map[string][]string)
	// Track session IDs already present to avoid duplicates from route-based sessions
	localSessionIDs := make(map[string]struct{}, len(matchingSessions))
	telemetry.OperationVoid(ctx.Request().Context(), "controllers.SessionController.SearchSessions.BuildLocalResponse", func(buildCtx context.Context) {
		// Sort by start time (newest first)
		sort.Slice(matchingSessions, func(i, j int) bool {
			return matchingSessions[i].StartedAt().After(matchingSessions[j].StartedAt())
		})
		for _, session := range matchingSessions {
			localSessionIDs[session.ID()] = struct{}{}

			// Use session.Description() which returns the in-memory cached initial message.
			// This avoids reading from Kubernetes Secret (which is created asynchronously
			// after provisioning completes and would return empty for newly created sessions).
			// After a proxy restart, Description() is populated from the Secret during session
			// restoration in restoreSessionFromService.
			initialMessage := session.Description()

			annotations := getSessionAnnotations(session)
			description := initialMessage
			if annotations.Description != "" {
				description = annotations.Description
			}
			sessionData := map[string]interface{}{
				"session_id":      session.ID(),
				"user_id":         session.UserID(),
				"scope":           session.Scope(),
				"team_id":         session.TeamID(),
				"status":          session.Status(),
				"started_at":      session.StartedAt(),
				"updated_at":      session.UpdatedAt(),
				"last_message_at": session.LastMessageAt(),
				"addr":            session.Addr(),
				"tags":            session.Tags(),
				"annotations":     annotations,
				"metadata": map[string]interface{}{
					"description": description,
				},
			}
			if provider, ok := session.(sessionStatusMessageProvider); ok && provider.StatusMessage() != "" {
				sessionData["error_message"] = provider.StatusMessage()
			}
			if provider, ok := session.(sessionErrorCodeProvider); ok && provider.ErrorCode() != "" {
				sessionData["error_code"] = provider.ErrorCode()
			}
			if provider, ok := session.(sessionSandboxPolicyProvider); ok {
				if policyID := provider.SandboxPolicyID(); policyID != "" {
					sessionData["sandbox_policy_id"] = policyID
				}
			} else if ks, ok := session.(*services.KubernetesSession); ok {
				if req := ks.Request(); req != nil && req.Sandbox != nil {
					sessionData["sandbox_policy_id"] = req.Sandbox.PolicyID
				}
			}
			if modelOptions := c.resolveSessionModelOptions(buildCtx, session, modelOptionsCache); len(modelOptions) > 0 {
				sessionData["model_options"] = modelOptions
			}
			filteredSessions = append(filteredSessions, sessionData)
		}
	})

	// Include ESM-created sessions from session routes
	telemetry.OperationVoid(ctx.Request().Context(), "controllers.SessionController.SearchSessions.BuildRouteResponse", func(buildCtx context.Context) {
		for _, route := range routes {
			// Skip sessions already present in the local session manager
			if _, exists := localSessionIDs[route.SessionID]; exists {
				continue
			}
			// Apply scope filter
			if scopeFilter == string(entities.ScopeTeam) && route.Scope != string(entities.ScopeTeam) {
				continue
			}
			if scopeFilter != string(entities.ScopeTeam) && route.Scope == string(entities.ScopeTeam) {
				continue
			}
			if teamIDFilter != "" && route.TeamID != teamIDFilter {
				continue
			}
			if !authzCtx.CanAccessResource(route.UserID, route.Scope, route.TeamID) {
				continue
			}
			tags := route.Tags
			if tags == nil {
				tags = map[string]string{}
			}
			// Apply tag filters
			match := true
			for k, v := range tagFilters {
				if tags[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			status := routedSessionStatus(route, allocatedSessions)
			sessionData := map[string]interface{}{
				"session_id":           route.SessionID,
				"allocated_session_id": route.RemoteSessionID,
				"user_id":              route.UserID,
				"scope":                route.Scope,
				"team_id":              route.TeamID,
				"status":               status,
				"started_at":           route.StartedAt,
				"updated_at":           route.StartedAt,
				"last_message_at":      route.StartedAt,
				"addr":                 "",
				"tags":                 tags,
				"annotations":          entities.SessionAnnotations{},
				"metadata": map[string]interface{}{
					"description": route.InitialMessage,
				},
			}
			// External session managers keep the run request on their side, so the
			// candidates are recovered from the session profile referenced by the route.
			if modelOptions := c.sessionModelOptionsFromTags(buildCtx, tags, modelOptionsCache); len(modelOptions) > 0 {
				sessionData["model_options"] = modelOptions
			}
			filteredSessions = append(filteredSessions, sessionData)
		}
	})
	telemetry.SetAttributes(ctx.Request().Context(), telemetry.Int64("search.result_count", int64(len(filteredSessions))))

	return telemetry.OperationErr(ctx.Request().Context(), "controllers.SessionController.SearchSessions.WriteResponse", func(context.Context) error {
		return ctx.JSON(http.StatusOK, map[string]interface{}{
			"sessions": filteredSessions,
		})
	})
}

func routedSessionStatus(route *repositories.SessionRoute, allocatedSessions map[string]entities.Session) string {
	if route.Transport == repositories.SessionRouteTransportDirectRuntime && route.Status != "" {
		return route.Status
	}
	if route.RemoteSessionID == "" {
		return "creating"
	}
	if allocatedSession := allocatedSessions[route.RemoteSessionID]; allocatedSession != nil {
		return allocatedSession.Status()
	}
	if route.Status != "" {
		return route.Status
	}
	return "starting"
}

// RecordRemoteSessionStatus persists a status pushed by a direct runtime and
// immediately fans it out to the proxy-wide SSE subscribers.
func (c *SessionController) RecordRemoteSessionStatus(ctx context.Context, route *repositories.SessionRoute, runtimeStatus string) error {
	if route == nil || runtimeStatus == "" {
		return nil
	}
	if route.DeletionRequestID != "" {
		// A late status push from a terminating Pod must not resurrect the route.
		return nil
	}
	status := publicSessionStatus(runtimeStatus)
	previous := route.Status
	// StatusUpdatedAt is the completion timestamp used by session TTL cleanup.
	// Repeated /status reads and runtime retries must not move that deadline.
	if previous == status && !route.StatusUpdatedAt.IsZero() {
		return nil
	}
	route.Status, route.StatusUpdatedAt = status, time.Now()
	if err := c.sessionRouteRepo.Save(ctx, route); err != nil {
		return err
	}
	if previous != status {
		event := repositories.SessionStatusEvent{SessionID: route.SessionID, Status: status, Timestamp: route.StatusUpdatedAt}
		c.recordSessionStatusUsage(ctx, event)
		c.publishRemoteStatusEvent(event)
	}
	return nil
}

func (c *SessionController) recordSessionStatusUsage(ctx context.Context, event repositories.SessionStatusEvent) {
	if c.sessionStatusRecorder == nil {
		return
	}
	if err := c.sessionStatusRecorder.RecordStatus(ctx, event); err != nil {
		log.Printf("[SESSION_COUNT_EVENTS] Failed to record status for %s: %v", event.SessionID, err)
	}
}

func (c *SessionController) resolveSessionUsageDimensions(ctx context.Context, sessionID, deletePath string) *repositories.SessionUsageDimensions {
	if c.sessionStatusRecorder == nil {
		return nil
	}
	dimensions, err := c.sessionStatusRecorder.ResolveDimensions(ctx, sessionID)
	if err != nil {
		log.Printf("[SESSION_COUNT_EVENTS] session_usage_dimensions_resolve_failed session=%s delete_path=%s: %v", sessionID, deletePath, err)
		return nil
	}
	return &dimensions
}

func (c *SessionController) recordSessionTerminated(ctx context.Context, dimensions *repositories.SessionUsageDimensions, deletePath string, timestamp time.Time) {
	if c.sessionStatusRecorder == nil || dimensions == nil {
		return
	}
	if !dimensions.LastStatusAt.IsZero() && !timestamp.After(dimensions.LastStatusAt) {
		timestamp = dimensions.LastStatusAt.Add(time.Nanosecond)
	}
	event := repositories.SessionStatusEvent{SessionID: dimensions.SessionID, Status: "terminated", Timestamp: timestamp}
	if err := c.sessionStatusRecorder.RecordResolvedStatus(ctx, *dimensions, event); err != nil {
		log.Printf("[SESSION_COUNT_EVENTS] session_usage_terminal_event_failed session=%s delete_path=%s: %v", dimensions.SessionID, deletePath, err)
		return
	}
	log.Printf("[SESSION_COUNT_EVENTS] session_usage_terminal_event_recorded session=%s pool=%s scope=%s delete_path=%s", dimensions.SessionID, dimensions.Pool, dimensions.Scope, deletePath)
}

func (c *SessionController) rememberRemoteSessionStatus(ctx context.Context, route *repositories.SessionRoute, resp *http.Response) {
	if c.sessionRouteRepo == nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var payload struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Status == "" {
		return
	}
	if err := c.RecordRemoteSessionStatus(ctx, route, payload.Status); err != nil {
		log.Printf("[ROUTE] Failed to persist status for %s: %v", route.SessionID, err)
	}
}

func publicSessionStatus(runtimeStatus string) string {
	if runtimeStatus == "stable" {
		return "active"
	}
	return runtimeStatus
}

func (c *SessionController) subscribeRemoteStatusEvents() (<-chan repositories.SessionStatusEvent, func()) {
	c.statusSubscribersMu.Lock()
	c.nextStatusSubscriberID++
	id := c.nextStatusSubscriberID
	ch := make(chan repositories.SessionStatusEvent, 32)
	c.statusSubscribers[id] = ch
	c.statusSubscribersMu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			c.statusSubscribersMu.Lock()
			delete(c.statusSubscribers, id)
			c.statusSubscribersMu.Unlock()
		})
	}
}

func (c *SessionController) publishRemoteStatusEvent(evt repositories.SessionStatusEvent) {
	c.deliverRemoteStatusEventLocal(evt)
	c.enqueueRouteStatusEvent(evt)
}

func (c *SessionController) deliverRemoteStatusEventLocal(evt repositories.SessionStatusEvent) {
	c.statusSubscribersMu.RLock()
	defer c.statusSubscribersMu.RUnlock()
	for _, ch := range c.statusSubscribers {
		select {
		case ch <- evt:
		default:
		}
	}
}

func indexAllocatedSessions(sessions []entities.Session, routes []*repositories.SessionRoute) map[string]entities.Session {
	allocatedIDs := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if route.RemoteSessionID != "" && route.RemoteSessionID != route.SessionID {
			allocatedIDs[route.RemoteSessionID] = struct{}{}
		}
	}

	allocatedSessions := make(map[string]entities.Session, len(allocatedIDs))
	for _, session := range sessions {
		if _, allocated := allocatedIDs[session.ID()]; allocated {
			allocatedSessions[session.ID()] = session
		}
	}
	return allocatedSessions
}

func excludeAllocatedSessions(sessions []entities.Session, routes []*repositories.SessionRoute) []entities.Session {
	allocatedIDs := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if route.RemoteSessionID != "" && route.RemoteSessionID != route.SessionID {
			allocatedIDs[route.RemoteSessionID] = struct{}{}
		}
	}

	filtered := make([]entities.Session, 0, len(sessions))
	for _, session := range sessions {
		if _, allocated := allocatedIDs[session.ID()]; !allocated {
			filtered = append(filtered, session)
		}
	}
	return filtered
}

func excludeTemplatedSessions(sessions []entities.Session, routes []*repositories.SessionRoute) []entities.Session {
	templatedIDs := make(map[string]struct{})
	for _, route := range routes {
		if route.Status != "templated" {
			continue
		}
		templatedIDs[route.SessionID] = struct{}{}
		if route.RemoteSessionID != "" {
			templatedIDs[route.RemoteSessionID] = struct{}{}
		}
	}
	if len(templatedIDs) == 0 {
		return sessions
	}

	filtered := make([]entities.Session, 0, len(sessions))
	for _, session := range sessions {
		if _, templated := templatedIDs[session.ID()]; !templated {
			filtered = append(filtered, session)
		}
	}
	return filtered
}

func getSessionAnnotations(session entities.Session) entities.SessionAnnotations {
	if annotated, ok := session.(sessionAnnotationsProvider); ok {
		return annotated.Annotations()
	}
	return entities.SessionAnnotations{}
}

// UpdateSessionAnnotations handles PATCH /sessions/:sessionId/annotations.
func (c *SessionController) UpdateSessionAnnotations(ctx echo.Context) error {
	c.setCORSHeaders(ctx)

	sessionID := ctx.Param("sessionId")
	if sessionID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Session ID is required")
	}

	session := c.getSessionManager().GetSession(sessionID)
	if session == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Session not found")
	}

	authzCtx := auth.GetAuthorizationContext(ctx)
	if !authzCtx.CanModifyResource(session.UserID(), string(session.Scope()), session.TeamID()) {
		return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to update this session")
	}

	var req entities.UpdateSessionAnnotationsRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	updater, ok := c.getSessionManager().(sessionAnnotationUpdater)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "Session annotations are not supported")
	}

	annotations, err := updater.UpdateSessionAnnotations(ctx.Request().Context(), sessionID, req)
	if err != nil {
		log.Printf("Failed to update session annotations for %s: %v", sessionID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update session annotations")
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"session_id":  sessionID,
		"annotations": annotations,
		"metadata": map[string]interface{}{
			"description": annotations.Description,
		},
	})
}

// DeleteSession handles DELETE /sessions/:sessionId requests to terminate a session
func (c *SessionController) DeleteSession(ctx echo.Context) error {
	if err := c.checkRestartHold(ctx); err != nil {
		return err
	}
	c.setCORSHeaders(ctx)

	sessionID := ctx.Param("sessionId")
	clientIP := ctx.RealIP()

	log.Printf("Request: DELETE /sessions/%s from %s", sessionID, clientIP)

	if sessionID == "" {
		log.Printf("Delete session failed: missing session ID from %s", clientIP)
		return echo.NewHTTPError(http.StatusBadRequest, "Session ID is required")
	}

	session := c.getSessionManager().GetSession(sessionID)
	uncreatedAllocation := false
	if session == nil {
		// Check if it's a remote session
		if c.sessionRouteRepo != nil {
			route, err := c.sessionRouteRepo.Get(ctx.Request().Context(), sessionID)
			if err != nil {
				log.Printf("Delete session: failed to look up route for %s: %v", sessionID, err)
			} else if route != nil {
				if route.Status == "templated" {
					authzCtx := auth.GetAuthorizationContext(ctx)
					if authzCtx == nil || !authzCtx.CanAccessResource(route.UserID, route.Scope, route.TeamID) {
						return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to access this session")
					}
					return ctx.JSON(http.StatusGone, map[string]string{"error": "session_templated", "template_id": route.ContextTemplateID})
				}
				if route.ManagerID == "" && route.RemoteSessionID != "" {
					return c.deleteLocalSessionAlias(ctx, route)
				}
				return c.deleteRemoteSession(ctx, route)
			}
		}
		session = findUncreatedSessionAllocation(c.getSessionManager().ListSessions(entities.SessionFilter{}), sessionID)
		if session == nil {
			// DELETE is idempotent. The UI may still hold a stale search result after
			// an orphaned route or allocation has already been cleaned up. Treating
			// that state as success lets the client remove the stale entry without
			// exposing whether an unknown session ID ever existed.
			log.Printf("Delete session: session %s is already absent (requested by %s)", sessionID, clientIP)
			c.cleanupSessionConfiguration(ctx.Request().Context(), sessionID)
			return ctx.JSON(http.StatusOK, map[string]interface{}{
				"message":    "Session already absent",
				"session_id": sessionID,
				"status":     "terminated",
			})
		}
		uncreatedAllocation = true
	}

	// Check authorization using pre-resolved authorization context (guaranteed to be non-nil by AuthMiddleware)
	authzCtx := auth.GetAuthorizationContext(ctx)
	if !authzCtx.CanModifyResource(session.UserID(), string(session.Scope()), session.TeamID()) {
		log.Printf("Delete session failed: user does not have access to session %s (requested by %s)", sessionID, clientIP)
		return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to delete this session")
	}

	log.Printf("Deleting session %s (status: %s, user: %s) requested by %s",
		sessionID, session.Status(), session.UserID(), clientIP)
	deletePath := "managed_session"
	if uncreatedAllocation {
		deletePath = "pending_allocation"
	}
	usageDimensions := c.resolveSessionUsageDimensions(ctx.Request().Context(), sessionID, deletePath)

	if uncreatedAllocation {
		deleter, ok := c.sessionCreator.(pendingSessionAllocationDeleter)
		if !ok {
			log.Printf("Failed to delete pending session allocation %s: deletion is unsupported", sessionID)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete session allocation")
		}
		deleted, err := deleter.DeletePendingSessionAllocation(ctx.Request().Context(), sessionID)
		if err != nil {
			log.Printf("Failed to delete pending session allocation %s: %v", sessionID, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete session allocation")
		}
		if !deleted {
			log.Printf("Pending session allocation %s was claimed before deletion", sessionID)
			return echo.NewHTTPError(http.StatusConflict, "Session allocation is no longer pending")
		}
		c.recordSessionTerminated(ctx.Request().Context(), usageDimensions, "pending_allocation", time.Now())
		log.Printf("Pending session allocation %s deletion completed successfully", sessionID)
		c.revokeGitHubBrokerLeases(ctx.Request().Context(), sessionID)
		c.cleanupSessionConfiguration(ctx.Request().Context(), sessionID)
		return ctx.JSON(http.StatusOK, map[string]interface{}{
			"message":    "Session allocation deleted successfully",
			"session_id": sessionID,
			"status":     "terminated",
		})
	}

	if err := c.sessionCreator.DeleteSessionByID(sessionID); err != nil {
		log.Printf("Failed to delete session %s: %v", sessionID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete session")
	}
	c.recordSessionTerminated(ctx.Request().Context(), usageDimensions, "managed_session", time.Now())

	log.Printf("Session %s deletion completed successfully", sessionID)
	c.revokeGitHubBrokerLeases(ctx.Request().Context(), sessionID)
	c.cleanupSessionConfiguration(ctx.Request().Context(), sessionID)

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Session terminated successfully",
		"session_id": sessionID,
		"status":     "terminated",
	})
}

// DeleteSessionFromWorker runs the durable deletion path for a request that was
// already authenticated by WorkerControlController. Worker cleanup is allowed
// to delete expired sessions regardless of their user or team owner.
func (c *SessionController) DeleteSessionFromWorker(ctx echo.Context) error {
	ctx.Set(workerAuthorizedDeleteContextKey, true)
	return c.DeleteSession(ctx)
}

func (c *SessionController) revokeGitHubBrokerLeases(ctx context.Context, sessionID string) {
	if c.githubTokenResolver == nil {
		return
	}
	if err := c.githubTokenResolver.RevokeBrokerLeases(ctx, sessionID); err != nil {
		log.Printf("Failed to revoke GitHub broker lease for session %s: %v", sessionID, err)
	}
}

func findUncreatedSessionAllocation(sessions []entities.Session, sessionID string) entities.Session {
	for _, session := range sessions {
		if session.ID() == sessionID && (session.Status() == "pending" || session.Status() == "allocating" || session.Status() == "error") {
			return session
		}
	}
	return nil
}

// ResumeSession explicitly recreates a suspended session workload. Read-only
// status, message, and SSE endpoints deliberately do not wake a session.
func (c *SessionController) ResumeSession(ctx echo.Context) error {
	if err := c.checkRestartHold(ctx); err != nil {
		return err
	}
	sessionID := ctx.Param("sessionId")
	workloadSessionID := sessionID
	session := c.getSessionManager().GetSession(sessionID)
	if session == nil && c.sessionRouteRepo != nil {
		route, err := c.sessionRouteRepo.Get(ctx.Request().Context(), sessionID)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to look up session route")
		}
		if route != nil {
			if route.ManagerID != "" {
				return c.resumeRemoteSession(ctx, route)
			}
			if route.RemoteSessionID != "" {
				workloadSessionID = route.RemoteSessionID
				session = c.getSessionManager().GetSession(workloadSessionID)
			}
		}
	}
	if session == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Session not found")
	}
	authzCtx := auth.GetAuthorizationContext(ctx)
	if !authzCtx.CanAccessResource(session.UserID(), string(session.Scope()), session.TeamID()) {
		return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to access this session")
	}
	ensurer, ok := c.getSessionManager().(repositories.SessionWorkloadEnsurer)
	if !ok {
		return echo.NewHTTPError(http.StatusNotImplemented, "Session resume is not supported by this session manager")
	}
	ensured, restoring, err := ensurer.EnsureSessionWorkload(ctx.Request().Context(), workloadSessionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, fmt.Sprintf("failed to restore session workload: %v", err))
	}
	status := "active"
	code := http.StatusOK
	if restoring {
		status = "resuming"
		code = http.StatusAccepted
		ctx.Response().Header().Set("Retry-After", "2")
	} else if ensured != nil {
		status = ensured.Status()
	}
	return ctx.JSON(code, map[string]interface{}{"session_id": sessionID, "status": status})
}

// SuspendSession asks the owning session manager to suspend the workload. The
// manager owns any checkpoint policy and does not expose it through this API.
func (c *SessionController) SuspendSession(ctx echo.Context) error {
	sessionID := ctx.Param("sessionId")
	session := c.getSessionManager().GetSession(sessionID)
	if session == nil && c.sessionRouteRepo != nil {
		route, err := c.sessionRouteRepo.Get(ctx.Request().Context(), sessionID)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to look up session route")
		}
		if route != nil && route.ManagerID != "" {
			return c.suspendRemoteSession(ctx, route)
		}
	}
	if session == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Session not found")
	}
	authzCtx := auth.GetAuthorizationContext(ctx)
	if !authzCtx.CanAccessResource(session.UserID(), string(session.Scope()), session.TeamID()) {
		return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to access this session")
	}
	suspender, ok := c.getSessionManager().(repositories.SessionSuspender)
	if !ok {
		return echo.NewHTTPError(http.StatusNotImplemented, "Session suspend is not supported by this session manager")
	}
	if err := suspender.SuspendSession(ctx.Request().Context(), sessionID); err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, fmt.Sprintf("failed to suspend session: %v", err))
	}
	return ctx.JSON(http.StatusOK, map[string]interface{}{"session_id": sessionID, "status": "suspended"})
}

func (c *SessionController) suspendRemoteSession(ctx echo.Context, route *repositories.SessionRoute) error {
	authzCtx := auth.GetAuthorizationContext(ctx)
	if authzCtx == nil || !authzCtx.CanAccessResource(route.UserID, route.Scope, route.TeamID) {
		return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to access this session")
	}
	if route.RemoteSessionID == "" || c.esmControlTunnel == nil || !c.esmControlTunnel.IsConnected(ctx.Request().Context(), route.ManagerID) {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "External session manager outbound control connection is unavailable")
	}
	targetURL := "http://esm.local/api/v1/sessions/" + url.PathEscape(route.RemoteSessionID) + "/suspend"
	if c.sessionRunnerStore == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Session resume data store is unavailable")
	}
	allocation, err := c.sessionRunnerStore.GetAllocation(ctx.Request().Context(), route.SessionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusConflict, "Session resume data is unavailable; the session was not suspended")
	}
	if len(allocation.ProvisionSettings) == 0 || strings.TrimSpace(allocation.RuntimeToken) == "" || allocation.Generation <= 0 {
		return echo.NewHTTPError(http.StatusConflict, "Session resume data is incomplete; the session was not suspended")
	}
	var settings sessionsettings.SessionSettings
	if err := json.Unmarshal(allocation.ProvisionSettings, &settings); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to decode session resume data; the session was not suspended")
	}
	settings.ParentRuntime = refreshedParentRuntime(ctx, settings.ParentRuntime, route, allocation)
	settingsBody, err := json.Marshal(&settings)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create session resume data; the session was not suspended")
	}
	req, err := http.NewRequestWithContext(ctx.Request().Context(), http.MethodPost, targetURL, bytes.NewReader(settingsBody))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to build suspend request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.esmControlTunnel.Do(ctx.Request().Context(), route.ManagerID, route.SessionID, route.RemoteSessionID, req)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to reach external session manager")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return echo.NewHTTPError(resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := c.recordRemoteLifecycleStatus(ctx.Request().Context(), route, "suspended"); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to persist suspended session status")
	}
	return ctx.JSON(http.StatusOK, map[string]interface{}{"session_id": route.SessionID, "status": "suspended"})
}

// recordRemoteLifecycleStatus keeps the public route and only the allocated
// session's local cache entry in sync after a remote lifecycle command.
func (c *SessionController) recordRemoteLifecycleStatus(ctx context.Context, route *repositories.SessionRoute, status string) error {
	if err := c.RecordRemoteSessionStatus(ctx, route, status); err != nil {
		return err
	}
	if session := c.getSessionManager().GetSession(route.RemoteSessionID); session != nil {
		if updater, ok := session.(sessionStatusCacheUpdater); ok {
			updater.SetStatusSilent(status)
		}
	}
	return nil
}

// RouteToSession routes requests to the appropriate agentapi server instance
func (c *SessionController) RouteToSession(ctx echo.Context) error {
	if err := c.checkRestartHold(ctx); err != nil {
		return err
	}
	return telemetry.OperationErr(ctx.Request().Context(), "controllers.SessionController.RouteToSession", func(requestCtx context.Context) error {
		ctx.SetRequest(ctx.Request().WithContext(requestCtx))
		return c.routeToSession(ctx)
	}, telemetry.String("http.request.method", ctx.Request().Method))
}

func (c *SessionController) routeToSession(ctx echo.Context) error {
	sessionID := ctx.Param("sessionId")

	session := c.getSessionManager().GetSession(sessionID)
	if session == nil {
		// Check if this is a remote session on External Session Manager
		if c.sessionRouteRepo != nil {
			route, err := c.sessionRouteRepo.Get(ctx.Request().Context(), sessionID)
			if err != nil {
				log.Printf("[ROUTE] Failed to look up session route for %s: %v", sessionID, err)
			} else if route != nil {
				if route.Status == "templated" {
					authzCtx := auth.GetAuthorizationContext(ctx)
					if authzCtx == nil || !authzCtx.CanAccessResource(route.UserID, route.Scope, route.TeamID) {
						return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to access this session")
					}
					return ctx.JSON(http.StatusGone, map[string]string{"error": "session_templated", "template_id": route.ContextTemplateID})
				}
				if route.ManagerID == "" && route.RemoteSessionID != "" {
					session = c.getSessionManager().GetSession(route.RemoteSessionID)
					if session == nil {
						return echo.NewHTTPError(http.StatusNotFound, "Session not found")
					}
				} else {
					return c.routeToRemoteSession(ctx, route)
				}
			}
		}
		if session == nil {
			if c.contextTemplateRepo != nil {
				authzCtx := auth.GetAuthorizationContext(ctx)
				if authzCtx != nil {
					templates, listErr := c.contextTemplateRepo.List(ctx.Request().Context(), repositories.SessionContextTemplateFilter{UserID: authzCtx.PersonalScope.UserID, TeamIDs: authzCtx.TeamScope.Teams})
					if listErr == nil {
						for _, template := range templates {
							if template.SourceSessionID == sessionID {
								return ctx.JSON(http.StatusGone, map[string]string{"error": "session_templated", "template_id": template.ID})
							}
						}
					}
				}
			}
			return echo.NewHTTPError(http.StatusNotFound, "Session not found")
		}
	}

	// Skip auth check for OPTIONS requests
	if ctx.Request().Method != "OPTIONS" {
		// Check authorization using pre-resolved context (guaranteed to be non-nil by AuthMiddleware)
		authzCtx := auth.GetAuthorizationContext(ctx)
		if !authzCtx.CanAccessResource(session.UserID(), string(session.Scope()), session.TeamID()) {
			log.Printf("User does not have access to session %s", sessionID)
			return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to access this session")
		}
	}

	// Runtime access is the resume boundary. Listing and proxy-level status
	// endpoints never reach this handler, so background polling cannot wake all
	// suspended sessions.
	if ctx.Request().Method != "OPTIONS" {
		if ctx.Request().Method == http.MethodGet && strings.HasSuffix(ctx.Request().URL.Path, "/status") && session.Status() == "suspended" {
			return ctx.JSON(http.StatusOK, map[string]string{"status": "suspended"})
		}
		if ensurer, ok := c.getSessionManager().(repositories.SessionWorkloadEnsurer); ok {
			ensured, resuming, err := ensurer.EnsureSessionWorkload(ctx.Request().Context(), session.ID())
			if err != nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "Failed to resume session workload").SetInternal(err)
			}
			if ensured != nil {
				session = ensured
			}
			if resuming {
				ctx.Response().Header().Set("Retry-After", "2")
				return ctx.JSON(http.StatusServiceUnavailable, map[string]interface{}{
					"error": map[string]string{"code": "session_resuming", "message": "Session workload is resuming", "session_id": sessionID, "status": "resuming"},
				})
			}
		}
	}

	// Determine target URL using session address
	targetURL := fmt.Sprintf("http://%s", session.Addr())
	target, err := url.Parse(targetURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Invalid target URL: %v", err))
	}

	// Capture first message for session description and update timestamp
	if ctx.Request().Method == "POST" && strings.HasSuffix(ctx.Request().URL.Path, "/message") {
		c.captureFirstMessage(ctx, session)
		c.updateSessionTimestamp(ctx, session)
	}

	req := ctx.Request()
	w := ctx.Response()

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = time.Millisecond * 100
	proxy.Transport = otelhttp.NewTransport(http.DefaultTransport)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Remove session ID from path before forwarding
		originalPath := req.URL.Path
		pathParts := strings.SplitN(originalPath, "/", 3)
		if len(pathParts) >= 3 {
			req.URL.Path = "/" + pathParts[2]
		} else {
			req.URL.Path = "/"
		}

		// Set forwarded headers
		originalHost := ctx.Request().Host
		if originalHost == "" {
			originalHost = ctx.Request().Header.Get("Host")
		}
		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Proto", "http")
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
	}

	originalModifyResponse := proxy.ModifyResponse
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Set CORS headers
		resp.Header.Set("Access-Control-Allow-Origin", "*")
		resp.Header.Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, PATCH, POST, DELETE, OPTIONS")
		resp.Header.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-API-Key")
		resp.Header.Set("Access-Control-Allow-Credentials", "true")
		resp.Header.Set("Access-Control-Max-Age", "86400")

		// Handle SSE streams
		if resp.Header.Get("Content-Type") == "text/event-stream" {
			resp.Header.Set("Cache-Control", "no-cache")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Del("Content-Length")
		}

		if originalModifyResponse != nil {
			return originalModifyResponse(resp)
		}
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error for session %s: %v", sessionID, err)

		// When the request is for the agent's /status endpoint and agentapi is
		// unreachable, check the provisioner's own /status to distinguish a
		// permanent failure (provisioner error → HTTP 500) from a transient
		// startup delay (provisioner still pending/provisioning → HTTP 502).
		if strings.HasSuffix(r.URL.Path, "/status") {
			if ks, ok := session.(*services.KubernetesSession); ok {
				provisionerURL := fmt.Sprintf("http://%s:%d/status", ks.ServiceDNS(), services.ProvisionerPort)
				provClient := &http.Client{Timeout: 2 * time.Second}
				provResp, provErr := provClient.Get(provisionerURL)
				if provErr == nil {
					defer func() { _ = provResp.Body.Close() }()
					if provResp.StatusCode == http.StatusInternalServerError {
						// Provisioner has permanently failed; relay its JSON error body.
						body, _ := io.ReadAll(provResp.Body)
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write(body)
						return
					}
				}
			}
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, req)
	return nil
}

func (c *SessionController) deleteLocalSessionAlias(ctx echo.Context, route *repositories.SessionRoute) error {
	usageDimensions := c.resolveSessionUsageDimensions(ctx.Request().Context(), route.SessionID, "local_alias")
	session := c.getSessionManager().GetSession(route.RemoteSessionID)
	if session == nil {
		// The runtime may already have removed itself (for example via a oneshot
		// Stop hook). Authorize from the persisted route metadata and make DELETE
		// idempotently clean up the stale public alias.
		authzCtx := auth.GetAuthorizationContext(ctx)
		if !authzCtx.CanModifyResource(route.UserID, route.Scope, route.TeamID) {
			return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to delete this session")
		}
		if err := c.sessionRouteRepo.Delete(ctx.Request().Context(), route.SessionID); err != nil {
			log.Printf("Failed to delete stale session alias %s: %v", route.SessionID, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete session alias")
		}
		c.recordSessionTerminated(ctx.Request().Context(), usageDimensions, "stale_local_alias", time.Now())
		c.cleanupRemoteProvisionRequest(ctx.Request().Context(), route.SessionID)
		c.cleanupSessionConfiguration(ctx.Request().Context(), route.SessionID)
		return ctx.JSON(http.StatusOK, map[string]interface{}{
			"message": "Stale session alias removed", "session_id": route.SessionID, "status": "terminated",
		})
	}
	authzCtx := auth.GetAuthorizationContext(ctx)
	if !authzCtx.CanModifyResource(session.UserID(), string(session.Scope()), session.TeamID()) {
		return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to delete this session")
	}
	if err := c.sessionCreator.DeleteSessionByID(route.RemoteSessionID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete session")
	}
	if err := c.sessionRouteRepo.Delete(ctx.Request().Context(), route.SessionID); err != nil {
		log.Printf("Failed to delete session alias %s: %v", route.SessionID, err)
	}
	c.recordSessionTerminated(ctx.Request().Context(), usageDimensions, "local_alias", time.Now())
	c.cleanupRemoteProvisionRequest(ctx.Request().Context(), route.SessionID)
	c.cleanupSessionConfiguration(ctx.Request().Context(), route.SessionID)
	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"message": "Session terminated successfully", "session_id": route.SessionID, "status": "terminated",
	})
}

// routeToRemoteSession sends session requests over an outbound connection opened
// by the Session Pod or external session manager. The parent never dials the manager.
func (c *SessionController) routeToRemoteSession(ctx echo.Context, route *repositories.SessionRoute) error {
	return telemetry.OperationErr(ctx.Request().Context(), "controllers.SessionController.routeToRemoteSession", func(requestCtx context.Context) error {
		ctx.SetRequest(ctx.Request().WithContext(requestCtx))
		return c.routeToRemoteSessionRequest(ctx, route)
	}, telemetry.String("session.transport", route.Transport))
}

func (c *SessionController) routeToRemoteSessionRequest(ctx echo.Context, route *repositories.SessionRoute) error {
	sessionID := ctx.Param("sessionId")
	if route.Transport != repositories.SessionRouteTransportDirectRuntime && (route.RemoteSessionID == "" || route.ManagerID == "") {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "External session manager has not reported a routable session yet")
	}
	if (route.Status == "suspended" || route.Status == "resuming") && ctx.Request().Method == http.MethodGet && strings.HasSuffix(ctx.Request().URL.Path, "/status") {
		return ctx.JSON(http.StatusOK, map[string]string{"status": route.Status})
	}
	if route.Status == "suspended" {
		resp, err := c.requestRemoteResume(ctx, route)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Failed to resume external session workload")
		}
		return sessionResumingResponse(ctx, route.SessionID)
	}
	if route.Status == "resuming" {
		return sessionResumingResponse(ctx, route.SessionID)
	}

	// Check authorization
	if ctx.Request().Method != "OPTIONS" {
		authzCtx := auth.GetAuthorizationContext(ctx)
		if authzCtx == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
		}
		// The route lookup itself is authoritative for legacy entries that may not
		// yet contain ownership metadata. New routes persist the owner fields.
	}

	// Build target URL: replace A's session ID with B's remote session ID in the path
	originalPath := ctx.Request().URL.Path
	// Path is /<sessionId>/rest/of/path - replace sessionId with remoteSessionID
	suffix := strings.TrimPrefix(originalPath, "/"+sessionID)
	targetPath := "/" + route.RemoteSessionID + suffix

	// Read body for HMAC signing
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read request body")
	}
	ctx.Request().Body = io.NopCloser(bytes.NewReader(body))

	if route.Transport == repositories.SessionRouteTransportDirectRuntime {
		if c.esmControlTunnel == nil || !c.esmControlTunnel.IsConnected(ctx.Request().Context(), route.SessionID) {
			ctx.Response().Header().Set("Retry-After", "2")
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Session runtime connection is unavailable")
		}
		suffix := strings.TrimPrefix(originalPath, "/"+sessionID)
		if suffix == "" {
			suffix = "/"
		}
		requestURL := &url.URL{Scheme: "http", Host: "session.local", Path: suffix, RawQuery: ctx.Request().URL.RawQuery}
		req, reqErr := http.NewRequestWithContext(ctx.Request().Context(), ctx.Request().Method, requestURL.String(), bytes.NewReader(body))
		if reqErr != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to build direct runtime request")
		}
		req.Header = ctx.Request().Header.Clone()
		telemetry.InjectHTTP(ctx.Request().Context(), req)
		resp, tunnelErr := c.esmControlTunnel.Do(ctx.Request().Context(), route.SessionID, route.SessionID, route.RemoteSessionID, req)
		if tunnelErr != nil {
			return echo.NewHTTPError(http.StatusBadGateway, tunnelErr.Error())
		}
		defer func() { _ = resp.Body.Close() }()
		if suffix == "/status" && ctx.Request().Method == http.MethodGet {
			c.rememberRemoteSessionStatus(ctx.Request().Context(), route, resp)
		}
		copyResponseHeaders(ctx.Response().Header(), resp.Header)
		return streamTunnelResponse(ctx, resp)
	}

	if c.esmControlTunnel != nil && c.esmControlTunnel.IsConnected(ctx.Request().Context(), route.ManagerID) {
		requestURL := &url.URL{Scheme: "http", Host: "esm.local", Path: targetPath, RawQuery: ctx.Request().URL.RawQuery}
		send := func() (*http.Response, error) {
			req, reqErr := http.NewRequestWithContext(ctx.Request().Context(), ctx.Request().Method, requestURL.String(), bytes.NewReader(body))
			if reqErr != nil {
				return nil, echo.NewHTTPError(http.StatusInternalServerError, "Failed to build outbound ESM request")
			}
			req.Header = ctx.Request().Header.Clone()
			telemetry.InjectHTTP(ctx.Request().Context(), req)
			authzCtx := auth.GetAuthorizationContext(ctx)
			if authzCtx != nil && authzCtx.PersonalScope.UserID != "" {
				req.Header.Set("X-Forwarded-User", authzCtx.PersonalScope.UserID)
			}
			if route.TeamID != "" {
				req.Header.Set("X-Forwarded-Team", route.TeamID)
			}
			resp, tunnelErr := c.esmControlTunnel.Do(ctx.Request().Context(), route.ManagerID, route.SessionID, route.RemoteSessionID, req)
			if tunnelErr != nil {
				return nil, echo.NewHTTPError(http.StatusBadGateway, tunnelErr.Error())
			}
			return resp, nil
		}
		resp, err := send()
		if err != nil {
			return err
		}
		if remoteWorkloadSuspended(resp) {
			_ = resp.Body.Close()
			if suffix == "/status" && ctx.Request().Method == http.MethodGet {
				if err := c.recordRemoteLifecycleStatus(ctx.Request().Context(), route, "suspended"); err != nil {
					log.Printf("[ROUTE] Failed to record suspended status for %s: %v", route.SessionID, err)
				}
				return ctx.JSON(http.StatusOK, map[string]string{"status": "suspended"})
			}
			resp, err = c.resumeAndRetryRemoteRequest(ctx, route, send)
			if err != nil {
				return err
			}
			if resp == nil {
				return sessionResumingResponse(ctx, route.SessionID)
			}
		}
		defer func() { _ = resp.Body.Close() }()
		if suffix == "/status" && ctx.Request().Method == http.MethodGet {
			c.rememberRemoteSessionStatus(ctx.Request().Context(), route, resp)
		}
		copyResponseHeaders(ctx.Response().Header(), resp.Header)
		return streamTunnelResponse(ctx, resp)
	}
	return echo.NewHTTPError(http.StatusServiceUnavailable, "External session manager outbound control connection is unavailable")
}

func (c *SessionController) resumeAndRetryRemoteRequest(ctx echo.Context, route *repositories.SessionRoute, send func() (*http.Response, error)) (*http.Response, error) {
	resumeResp, err := c.requestRemoteResume(ctx, route)
	if err != nil {
		return nil, err
	}
	_ = resumeResp.Body.Close()
	if resumeResp.StatusCode < 200 || resumeResp.StatusCode >= 300 {
		return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "Failed to resume external session workload")
	}
	resp, err := send()
	if err != nil {
		return nil, err
	}
	if remoteWorkloadSuspended(resp) {
		_ = resp.Body.Close()
		return nil, nil
	}
	return resp, nil
}

func remoteWorkloadSuspended(resp *http.Response) bool {
	if resp.StatusCode != http.StatusConflict {
		return false
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(data), resp.Body), resp.Body}
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	return json.Unmarshal(data, &payload) == nil && payload.Error.Code == "session_suspended"
}

func sessionResumingResponse(ctx echo.Context, sessionID string) error {
	ctx.Response().Header().Set("Retry-After", "2")
	return ctx.JSON(http.StatusServiceUnavailable, map[string]interface{}{
		"error": map[string]string{"code": "session_resuming", "message": "Session workload is resuming", "session_id": sessionID, "status": "resuming"},
	})
}

func (c *SessionController) resumeRemoteSession(ctx echo.Context, route *repositories.SessionRoute) error {
	resp, err := c.requestRemoteResume(ctx, route)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	for key, values := range resp.Header {
		for _, value := range values {
			ctx.Response().Header().Add(key, value)
		}
	}
	return ctx.Stream(resp.StatusCode, resp.Header.Get("Content-Type"), resp.Body)
}

func (c *SessionController) requestRemoteResume(ctx echo.Context, route *repositories.SessionRoute) (*http.Response, error) {
	if route.RemoteSessionID == "" {
		return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "External session manager has not reported a session yet")
	}
	if c.esmControlTunnel == nil {
		return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "External session manager outbound control connection is unavailable")
	}
	if route.Transport != repositories.SessionRouteTransportDirectRuntime && !c.esmControlTunnel.IsConnected(ctx.Request().Context(), route.ManagerID) {
		return nil, echo.NewHTTPError(http.StatusServiceUnavailable, "External session manager outbound control connection is unavailable")
	}
	targetURL := "http://esm.local/api/v1/sessions/" + url.PathEscape(route.RemoteSessionID) + "/resume"
	body, settingsErr := c.remoteResumeSettings(ctx, route)
	if settingsErr != nil {
		return nil, settingsErr
	}
	req, err := http.NewRequestWithContext(ctx.Request().Context(), http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "Failed to build resume request")
	}
	if len(body) != 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	ts := hmacutil.NowTimestamp()
	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "Invalid external session manager URL")
	}
	msg := hmacutil.BuildMessage(req.Method, parsedTarget.RequestURI(), ts, body)
	req.Header.Set("X-Hub-Signature-256", hmacutil.Sign([]byte(route.HMACSecret), msg))
	req.Header.Set(hmacutil.TimestampHeader, ts)
	if authzCtx := auth.GetAuthorizationContext(ctx); authzCtx != nil && authzCtx.PersonalScope.UserID != "" {
		req.Header.Set("X-Forwarded-User", authzCtx.PersonalScope.UserID)
	}
	if route.TeamID != "" {
		req.Header.Set("X-Forwarded-Team", route.TeamID)
	}
	previousStatus := route.Status
	if err := c.recordRemoteLifecycleStatus(ctx.Request().Context(), route, "resuming"); err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "Failed to persist resuming session status")
	}
	rollback := func() {
		if err := c.recordRemoteLifecycleStatus(context.Background(), route, previousStatus); err != nil {
			log.Printf("[ROUTE] Failed to roll back resume status for %s: %v", route.SessionID, err)
		}
	}
	resp, err := c.esmControlTunnel.Do(ctx.Request().Context(), route.ManagerID, route.SessionID, route.RemoteSessionID, req)
	if err != nil {
		rollback()
		return nil, echo.NewHTTPError(http.StatusBadGateway, "Failed to reach external session manager")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		rollback()
	}
	return resp, nil
}

// remoteResumeSettings refreshes mutable policy values before an existing pool
// allocation is restored. This prevents a session created under an older idle
// timeout from reverting to that timeout after every resume.
func (c *SessionController) remoteResumeSettings(ctx echo.Context, route *repositories.SessionRoute) ([]byte, error) {
	if c.sessionRunnerStore == nil {
		return nil, nil
	}
	allocation, err := c.sessionRunnerStore.GetAllocation(ctx.Request().Context(), route.SessionID)
	if err != nil || allocation == nil || len(allocation.ProvisionSettings) == 0 {
		return nil, nil
	}
	var settings sessionsettings.SessionSettings
	if err := json.Unmarshal(allocation.ProvisionSettings, &settings); err != nil {
		return nil, nil
	}
	persistedParentRuntime := settings.ParentRuntime
	persistedAutoSuspendEnabled := settings.Session.AutoSuspendEnabled
	persistedAutoSuspendMinutes := settings.Session.AutoSuspendMinutes
	// Re-resolve the original startup input on every resume so credentials stay
	// out of durable allocation data while short-lived tokens and profile secrets
	// are refreshed before the replacement workload starts.
	if store, ok := c.sessionRunnerStore.(sessionConfigurationStore); ok {
		if cfg, cfgErr := store.GetConfiguration(ctx.Request().Context(), route.SessionID); cfgErr == nil && cfg != nil {
			az := auth.GetAuthorizationContext(ctx)
			if az == nil {
				return nil, echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
			}
			// A GitHub OAuth token is deliberately omitted from the saved startup
			// input. Re-attach the caller's authenticated token only to an in-memory
			// copy used for this resume, so public/private repository setup can be
			// rebuilt without persisting the credential.
			resumeCfg := *cfg
			if token, ok := auth.GetGitHubTokenFromContext(ctx); ok {
				var start entities.StartRequest
				if json.Unmarshal(resumeCfg.Input, &start) == nil {
					if start.Params == nil {
						start.Params = &entities.SessionParams{}
					}
					start.Params.GithubToken = token
					if input, marshalErr := json.Marshal(start); marshalErr == nil {
						resumeCfg.Input = input
					}
				}
			}
			resolved, resolveErr := c.reloadSessionSettings(ctx.Request().Context(), &resumeCfg, resumeCfg.ProfileID, az)
			if resolveErr != nil {
				return nil, resolveErr
			}
			settings = *resolved
			// Auto-suspend is resolved separately from the startup settings. Keep
			// the allocation policy unless the scoped settings repository below
			// provides a newer explicit value. Otherwise a credential refresh can
			// silently replace an enabled policy with the resolver's zero value.
			settings.Session.AutoSuspendEnabled = persistedAutoSuspendEnabled
			settings.Session.AutoSuspendMinutes = persistedAutoSuspendMinutes
		}
	}
	if c.settingsRepo != nil {
		settingsName := route.UserID
		if route.Scope == string(entities.ScopeTeam) && route.TeamID != "" {
			settingsName = route.TeamID
		}
		if stored, findErr := c.settingsRepo.FindByName(ctx.Request().Context(), settingsName); findErr == nil && stored != nil && stored.AutoSuspend() != nil {
			policy := stored.AutoSuspend()
			settings.Session.AutoSuspendEnabled = &policy.Enabled
			settings.Session.AutoSuspendMinutes = policy.IdleTimeoutMinutes
		}
	}
	settings.ParentRuntime = refreshedParentRuntime(ctx, persistedParentRuntime, route, allocation)
	body, err := json.Marshal(&settings)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "Failed to encode refreshed resume settings")
	}
	return body, nil
}

// refreshedParentRuntime keeps the endpoint recorded by the runner when it
// claimed the allocation. Internal triggers reach /start through loopback or a
// cluster Service, so their request headers do not describe an endpoint that
// the resumed workload can necessarily reach.
func refreshedParentRuntime(ctx echo.Context, persisted *sessionsettings.ParentRuntimeConfig, route *repositories.SessionRoute, allocation *sessionrunnercore.Allocation) *sessionsettings.ParentRuntimeConfig {
	endpoint := ""
	if persisted != nil {
		endpoint = strings.TrimSpace(persisted.Endpoint)
	}
	// Retain the request-derived endpoint for allocations created before the
	// runner started persisting its parent runtime settings.
	if endpoint == "" {
		scheme := strings.TrimSpace(ctx.Request().Header.Get("X-Forwarded-Proto"))
		if scheme == "" {
			scheme = "https"
		}
		host := strings.TrimSpace(ctx.Request().Header.Get("X-Forwarded-Host"))
		if host == "" {
			host = ctx.Request().Host
		}
		prefix := strings.TrimSuffix(strings.TrimSpace(ctx.Request().Header.Get("X-Forwarded-Prefix")), "/")
		endpoint = scheme + "://" + host + prefix
	}
	return &sessionsettings.ParentRuntimeConfig{
		Enabled: true, Endpoint: endpoint, SessionID: route.SessionID,
		ManagerID: route.ManagerID, Token: allocation.RuntimeToken, Generation: allocation.Generation,
	}
}

// deleteRemoteSession deletes a session on External Session Manager via the session manager API.
func (c *SessionController) deleteRemoteSession(ctx echo.Context, route *repositories.SessionRoute) error {
	sessionID := ctx.Param("sessionId")
	// Routed sessions never reach the managed-session ownership check in
	// DeleteSession, and the manager does not re-authorize the forwarded user.
	// Enforce ownership here so every remote deletion path, including the local
	// finalization below, is authorized. Worker-authorized deletes (TTL and route
	// reconciliation) may delete regardless of owner, like managed sessions.
	if workerAuthorized, _ := ctx.Get(workerAuthorizedDeleteContextKey).(bool); !workerAuthorized {
		authzCtx := auth.GetAuthorizationContext(ctx)
		if authzCtx == nil || !authzCtx.CanModifyResource(route.UserID, route.Scope, route.TeamID) {
			return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to delete this session")
		}
	}
	usageDimensions := c.resolveSessionUsageDimensions(ctx.Request().Context(), route.SessionID, "remote_session")
	if route.ManagerID == "" || route.RemoteSessionID == "" {
		c.recordSessionStatusUsage(ctx.Request().Context(), repositories.SessionStatusEvent{SessionID: route.SessionID, Status: "terminating", Timestamp: time.Now()})
		routeDeleted := c.sessionRouteRepo == nil
		if c.sessionRouteRepo != nil {
			if err := c.sessionRouteRepo.Delete(ctx.Request().Context(), sessionID); err != nil {
				log.Printf("[REMOTE_DELETE] Warning: failed to delete pending route entry for session %s: %v", sessionID, err)
			} else {
				routeDeleted = true
			}
		}
		if routeDeleted {
			c.recordSessionTerminated(ctx.Request().Context(), usageDimensions, "pending_remote_route", time.Now())
		}
		c.cleanupRemoteProvisionRequest(ctx.Request().Context(), sessionID)
		c.cleanupSessionConfiguration(ctx.Request().Context(), sessionID)
		return ctx.JSON(http.StatusOK, map[string]interface{}{
			"message":    "Pending external session removed",
			"session_id": sessionID,
			"status":     "terminated",
		})
	}

	useTunnel := c.esmControlTunnel != nil && c.esmControlTunnel.IsConnected(ctx.Request().Context(), route.ManagerID)
	if !useTunnel {
		// The parent's routes are authoritative. On every heartbeat a manager
		// receives orphaned_session_ids for workloads that no longer have a route
		// and removes them through its own idempotent delete path. Finalizing the
		// route locally is therefore safe even while the manager is unreachable:
		// a manager that comes back reaps the workload, and one that is gone for
		// good (for example a deleted runner pool) can no longer leave the route
		// stranded as an undeletable stale session. This is also what the former
		// force=true escape hatch did, so requests that still pass it behave the same.
		log.Printf("[REMOTE_DELETE] Manager %s is unreachable; finalizing session %s locally (remote ID: %s)",
			route.ManagerID, sessionID, route.RemoteSessionID)
		if err := c.finalizeRouteLocally(ctx.Request().Context(), route, usageDimensions, "manager_unreachable"); err != nil {
			log.Printf("[REMOTE_DELETE] Failed to finalize session %s locally: %v", sessionID, err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete session")
		}
		return ctx.JSON(http.StatusOK, map[string]interface{}{
			"message":    "Session terminated successfully",
			"session_id": sessionID,
			"status":     "terminated",
		})
	}
	// The manager owns the allocated runner workload. The public session ID is
	// an API alias; deleting that alias on the manager would leave the Pod alive.
	targetURL := "http://esm.local/api/v1/sessions/" + route.RemoteSessionID

	req, err := http.NewRequestWithContext(ctx.Request().Context(), http.MethodDelete, targetURL, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to build delete request")
	}

	// Compute HMAC signature over METHOD\nPATH?QUERY\nTIMESTAMP\n(empty body)
	ts := hmacutil.NowTimestamp()
	parsedTarget, _ := url.Parse(targetURL)
	msg := hmacutil.BuildMessage(http.MethodDelete, parsedTarget.RequestURI(), ts, nil)
	sig := hmacutil.Sign([]byte(route.HMACSecret), msg)
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set(hmacutil.TimestampHeader, ts)
	if route.UserID != "" {
		req.Header.Set("X-Forwarded-User", route.UserID)
	}
	if route.TeamID != "" {
		req.Header.Set("X-Forwarded-Team", route.TeamID)
	}
	if route.Transport == repositories.SessionRouteTransportDirectRuntime {
		enqueuer, ok := c.esmControlTunnel.(esmControlEnqueuer)
		if !ok {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "External session manager lifecycle queue is unavailable")
		}
		if route.DeletionRequestID != "" {
			if c.reconcileQueuedDeletion(ctx.Request().Context(), route) {
				return ctx.JSON(http.StatusOK, map[string]interface{}{
					"message": "Session terminated successfully", "session_id": sessionID, "status": "terminated",
				})
			}
			return ctx.JSON(http.StatusAccepted, map[string]interface{}{
				"message": "Session deletion is still pending", "session_id": sessionID, "status": "terminating",
			})
		}
		requestID, err := enqueuer.Enqueue(ctx.Request().Context(), route.ManagerID, route.SessionID, route.RemoteSessionID, req)
		if err != nil {
			log.Printf("[REMOTE_DELETE] Failed to enqueue direct-runtime deletion %s: %v", sessionID, err)
			return echo.NewHTTPError(http.StatusBadGateway, "Failed to queue external session deletion")
		}
		route.DeletionRequestID = requestID
		route.Status = "terminating"
		route.StatusUpdatedAt = time.Now()
		if c.sessionRouteRepo == nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Session route repository is unavailable")
		}
		if err := c.sessionRouteRepo.Save(ctx.Request().Context(), route); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to persist session deletion state")
		}
		c.recordSessionStatusUsage(ctx.Request().Context(), repositories.SessionStatusEvent{SessionID: route.SessionID, Status: route.Status, Timestamp: route.StatusUpdatedAt})
		return ctx.JSON(http.StatusAccepted, map[string]interface{}{
			"message": "Session deletion queued", "session_id": sessionID, "status": "terminating",
		})
	}

	resp, err := c.esmControlTunnel.Do(ctx.Request().Context(), route.ManagerID, route.SessionID, route.RemoteSessionID, req)
	if err != nil {
		log.Printf("[REMOTE_DELETE] Failed to delete remote session %s over outbound control: %v", route.RemoteSessionID, err)
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to reach external session manager")
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		// success
	case http.StatusNotFound:
		// Session already gone on External Session Manager — treat as success so we can
		// still clean up the local route entry.
		log.Printf("[REMOTE_DELETE] Remote session %s not found on External Session Manager (already deleted), cleaning up local route", route.RemoteSessionID)
	default:
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[REMOTE_DELETE] External Session Manager returned status %d: %s", resp.StatusCode, string(respBody))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete remote session")
	}

	// Clean up local route entry regardless of whether External Session Manager had the session.
	c.recordSessionStatusUsage(ctx.Request().Context(), repositories.SessionStatusEvent{SessionID: route.SessionID, Status: "terminating", Timestamp: time.Now()})
	if c.sessionRouteRepo != nil {
		if err := c.sessionRouteRepo.Delete(ctx.Request().Context(), sessionID); err != nil {
			log.Printf("[REMOTE_DELETE] Warning: failed to delete route entry for session %s: %v", sessionID, err)
		}
	}
	c.recordSessionTerminated(ctx.Request().Context(), usageDimensions, "esm_sync", time.Now())
	c.cleanupRemoteProvisionRequest(ctx.Request().Context(), sessionID)
	c.cleanupSessionConfiguration(ctx.Request().Context(), sessionID)

	log.Printf("[REMOTE_DELETE] Deleted remote session %s (remote ID: %s) over outbound control", sessionID, route.RemoteSessionID)
	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Session terminated successfully",
		"session_id": sessionID,
		"status":     "terminated",
	})
}

// reconcileQueuedDeletion removes a route only after the manager has durably
// reported completion. It is intentionally called from both DELETE and search,
// making progress after API restarts without relying on in-memory goroutines.
func (c *SessionController) reconcileQueuedDeletion(ctx context.Context, route *repositories.SessionRoute) bool {
	if route == nil || route.DeletionRequestID == "" || c.sessionRouteRepo == nil {
		return false
	}
	reader, ok := c.esmControlTunnel.(esmControlCommandReader)
	if !ok {
		return false
	}
	done, status, err := reader.CommandResult(ctx, route.DeletionRequestID)
	if !done {
		return false
	}
	if err != nil || (status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound) {
		log.Printf("[REMOTE_DELETE] Manager deletion %s failed (status=%d): %v", route.DeletionRequestID, status, err)
		route.DeletionRequestID = ""
		route.Status = "delete_failed"
		route.StatusUpdatedAt = time.Now()
		_ = c.sessionRouteRepo.Save(ctx, route)
		return false
	}
	usageDimensions := c.resolveSessionUsageDimensions(ctx, route.SessionID, "direct_runtime_queued")
	if route.Status != "terminated" {
		route.Status = "terminated"
		route.StatusUpdatedAt = time.Now()
		if err := c.sessionRouteRepo.Save(ctx, route); err != nil {
			log.Printf("[REMOTE_DELETE] Failed to persist terminal route state %s: %v", route.SessionID, err)
			return false
		}
	}
	c.recordSessionTerminated(ctx, usageDimensions, "direct_runtime_queued", route.StatusUpdatedAt)
	if err := c.sessionRouteRepo.Delete(ctx, route.SessionID); err != nil {
		log.Printf("[REMOTE_DELETE] Failed to finalize route %s: %v", route.SessionID, err)
		return false
	}
	c.cleanupRemoteProvisionRequest(ctx, route.SessionID)
	c.cleanupSessionConfiguration(ctx, route.SessionID)
	log.Printf("[REMOTE_DELETE] Finalized queued deletion for session %s", route.SessionID)
	return true
}

func copyResponseHeaders(target, source http.Header) {
	for key, values := range source {
		for _, value := range values {
			target.Add(key, value)
		}
	}
}

func streamTunnelResponse(ctx echo.Context, resp *http.Response) error {
	ctx.Response().WriteHeader(resp.StatusCode)
	// The first tunnel frame already contains the upstream status and headers.
	// Flush them before waiting for a body frame so idle SSE streams transition
	// the browser's EventSource from CONNECTING to OPEN immediately.
	ctx.Response().Flush()
	buffer := make([]byte, 64*1024)
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := ctx.Response().Write(buffer[:n]); writeErr != nil {
				return writeErr
			}
			ctx.Response().Flush()
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (c *SessionController) cleanupRemoteProvisionRequest(ctx context.Context, sessionID string) {
	if cleaner, ok := c.sessionCreator.(interface {
		DeleteProvisionRequest(context.Context, string) error
	}); ok {
		if err := cleaner.DeleteProvisionRequest(ctx, sessionID); err != nil {
			log.Printf("[REMOTE_DELETE] Warning: failed to delete provision request for %s: %v", sessionID, err)
		}
	}
	if cleaner, ok := c.sessionCreator.(interface {
		DeleteSessionPoolAllocation(context.Context, string) error
	}); ok {
		if err := cleaner.DeleteSessionPoolAllocation(ctx, sessionID); err != nil {
			log.Printf("[REMOTE_DELETE] Warning: failed to delete session pool allocation for %s: %v", sessionID, err)
		}
	}
}

func (c *SessionController) cleanupSessionConfiguration(ctx context.Context, sessionID string) {
	store, ok := c.sessionRunnerStore.(sessionConfigurationDeleter)
	if !ok {
		return
	}
	if err := store.DeleteConfiguration(ctx, sessionID); err != nil {
		log.Printf("Warning: failed to delete session configuration for %s: %v", sessionID, err)
	}
}

// captureFirstMessage captures the first message content for session description
func (c *SessionController) captureFirstMessage(ctx echo.Context, session entities.Session) {
	// Skip if description already exists
	if session.Tags() != nil {
		if _, exists := session.Tags()["description"]; exists {
			return
		}
	}

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return
	}

	// Restore the request body for further processing
	ctx.Request().Body = io.NopCloser(bytes.NewBuffer(body))

	var messageReq map[string]interface{}
	if err := json.Unmarshal(body, &messageReq); err != nil {
		return
	}
}

// updateSessionTimestamp updates the session's updated_at and last_message_at timestamps.
// Called on every POST /message request routed through the proxy.
func (c *SessionController) updateSessionTimestamp(ctx echo.Context, session entities.Session) {
	toucher, ok := c.getSessionManager().(repositories.SessionToucher)
	if !ok {
		return
	}
	now := time.Now()
	go func() {
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := toucher.TouchSession(updateCtx, session.ID(), now); err != nil {
			log.Printf("[SESSION] Failed to update activity timestamp for session %s: %v", session.ID(), err)
		}
	}()
}

// filterHiddenSessions removes sessions tagged with hidden=true from the list.
func filterHiddenSessions(sessions []entities.Session) []entities.Session {
	result := make([]entities.Session, 0, len(sessions))
	for _, s := range sessions {
		if s.Tags()["hidden"] != "true" {
			result = append(result, s)
		}
	}
	return result
}

// setCORSHeaders sets CORS headers for all session management endpoints
func (c *SessionController) setCORSHeaders(ctx echo.Context) {
	ctx.Response().Header().Set("Access-Control-Allow-Origin", "*")
	ctx.Response().Header().Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, PATCH, POST, DELETE, OPTIONS")
	ctx.Response().Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-API-Key")
	ctx.Response().Header().Set("Access-Control-Allow-Credentials", "true")
	ctx.Response().Header().Set("Access-Control-Max-Age", "86400")
}

// mergeSessionParams merges base (profile) params with override (request) params.
// For each field: if the override field is the zero value, the base value is used.
func mergeSessionParams(base, override *entities.SessionParams) *entities.SessionParams {
	merged := *base // start from profile defaults
	if override.Pool != "" {
		merged.Pool = override.Pool
	}
	if override.ResumeFrom != "" {
		merged.ResumeFrom = override.ResumeFrom
	}
	if override.Message != "" {
		merged.Message = override.Message
	}
	if override.GithubToken != "" {
		merged.GithubToken = override.GithubToken
	}
	if override.ConnectionID != "" {
		merged.ConnectionID = override.ConnectionID
	}
	if override.AgentType != "" {
		merged.AgentType = override.AgentType
	}
	if override.Model != "" {
		merged.Model = override.Model
	}
	if len(override.ModelOptions) > 0 {
		merged.ModelOptions = append([]string(nil), override.ModelOptions...)
	}
	if override.Slack != nil {
		merged.Slack = override.Slack
	}
	if override.Oneshot {
		merged.Oneshot = override.Oneshot
	}
	if override.InitialMessageWaitSecond != nil {
		merged.InitialMessageWaitSecond = override.InitialMessageWaitSecond
	}
	if override.ManagerID != "" {
		merged.ManagerID = override.ManagerID
	}
	if override.CycleMessage != "" {
		merged.CycleMessage = override.CycleMessage
	}
	if override.CycleMaxCount != 0 {
		merged.CycleMaxCount = override.CycleMaxCount
	}
	if override.RepoFullName != "" {
		merged.RepoFullName = override.RepoFullName
	}
	if override.Sandbox != nil {
		merged.Sandbox = override.Sandbox
	}
	if override.Docker != nil {
		merged.Docker = override.Docker
	}
	if override.AuthProxy != nil {
		merged.AuthProxy = override.AuthProxy
	}
	if override.SessionTTL != "" {
		merged.SessionTTL = override.SessionTTL
	}
	if len(override.UnsyncedFilePaths) > 0 {
		merged.UnsyncedFilePaths = append([]string(nil), override.UnsyncedFilePaths...)
	}
	if override.CodexAuthMode != "" {
		merged.CodexAuthMode = override.CodexAuthMode
	}
	if override.ClaudeAuthMode != "" {
		merged.ClaudeAuthMode = override.ClaudeAuthMode
	}
	if override.CredentialSource != "" {
		merged.CredentialSource = override.CredentialSource
	}
	merged.Storages = mergeStorageAttachments(base.Storages, override.Storages)
	return &merged
}

// mergeStorageAttachments keeps profile ordering, replaces matching mount paths
// with explicit request entries, and appends request-only entries.
func mergeStorageAttachments(base, override []entities.StorageAttachment) []entities.StorageAttachment {
	if len(override) == 0 {
		return append([]entities.StorageAttachment(nil), base...)
	}
	overrides := make(map[string]entities.StorageAttachment, len(override))
	for _, attachment := range override {
		overrides[filepath.Clean(attachment.MountPath)] = attachment
	}
	result := make([]entities.StorageAttachment, 0, len(base)+len(override))
	seen := make(map[string]struct{}, len(base)+len(override))
	for _, attachment := range base {
		key := filepath.Clean(attachment.MountPath)
		if replacement, ok := overrides[key]; ok {
			attachment = replacement
		}
		result = append(result, attachment)
		seen[key] = struct{}{}
	}
	for _, attachment := range override {
		key := filepath.Clean(attachment.MountPath)
		if _, ok := seen[key]; ok {
			continue
		}
		result = append(result, attachment)
		seen[key] = struct{}{}
	}
	return result
}

func applyProfileSandboxDefaults(cfg entities.SessionProfileConfig, params *entities.SessionParams) {
	if params == nil {
		return
	}
	if cfg.SandboxPolicyID() != "" {
		if params.Sandbox == nil {
			params.Sandbox = &entities.SandboxParams{Enabled: true, PolicyID: cfg.SandboxPolicyID()}
		} else if params.Sandbox.PolicyID == "" {
			params.Sandbox.Enabled = true
			params.Sandbox.PolicyID = cfg.SandboxPolicyID()
		}
		return
	}
	if params.Sandbox == nil {
		params.Sandbox = &entities.SandboxParams{Enabled: true, CountMode: true}
	} else if params.Sandbox.PolicyID == "" {
		params.Sandbox.Enabled = true
		params.Sandbox.CountMode = true
	}
}

// SandboxDomainsResponse is the JSON body returned by GET /sessions/:sessionId/sandbox-domains.
type SandboxDomainsResponse struct {
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied"`
}

// GetSessionSandboxDomains handles GET /sessions/:sessionId/sandbox-domains.
// It forwards the request to the session's agent-provisioner /sandbox-domains endpoint,
// which in turn queries the network filter control server (127.0.0.1:3129/domains).
// Returns 404 when the session does not exist, 503 when the network filter is unavailable.
func (c *SessionController) GetSessionSandboxDomains(ctx echo.Context) error {
	sessionID := ctx.Param("sessionId")

	session := c.getSessionManager().GetSession(sessionID)
	if session == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Session not found")
	}

	authzCtx := auth.GetAuthorizationContext(ctx)
	if !authzCtx.CanAccessResource(session.UserID(), string(session.Scope()), session.TeamID()) {
		return echo.NewHTTPError(http.StatusForbidden, "You don't have permission to access this session")
	}

	reader, ok := c.getSessionManager().(repositories.SessionSandboxDomainReader)
	if !ok {
		return echo.NewHTTPError(http.StatusNotImplemented, "Sandbox domains not available for this session type")
	}
	domains, err := reader.GetSessionSandboxDomains(ctx.Request().Context(), sessionID)
	if err != nil {
		log.Printf("[SESSION] Failed to fetch sandbox domains for %s: %v", sessionID, err)
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Network filter not available")
	}
	return ctx.JSON(http.StatusOK, domains)
}

// resolveSessionProfile returns the session profile to apply for a session creation request.
// If profileID is set, it fetches that profile directly.
// Otherwise it searches for a selector_tags match before falling back to the settings default,
// then the legacy profile-level default flag.
func (c *SessionController) resolveSessionProfile(
	ctx context.Context,
	profileID,
	userID string,
	scope entities.ResourceScope,
	teamID string,
	tags map[string]string,
	authzCtx *auth.AuthorizationContext,
) (*entities.SessionProfile, string, error) {
	if profileID != "" {
		profile, err := c.sessionProfileRepo.Get(ctx, profileID)
		if err != nil {
			log.Printf("[SESSION] Warning: could not resolve session_profile_id %q: %v", profileID, err)
			if _, ok := err.(entities.ErrSessionProfileNotFound); ok {
				return nil, "", echo.NewHTTPError(http.StatusNotFound, err.Error())
			}
			return nil, "", echo.NewHTTPError(http.StatusInternalServerError, "failed to resolve session profile")
		}
		if !c.canUseSessionProfile(authzCtx, profile, scope, teamID) {
			return nil, "", echo.NewHTTPError(
				http.StatusForbidden,
				entities.ErrSessionProfileAccessDenied{ID: profile.ID()}.Error(),
			)
		}
		if profile.Scope() == entities.ScopeTeam && scope == entities.ScopeUser {
			enabledProfiles, enabledErr := listEnabledTeamSessionProfiles(ctx, c.sessionProfileRepo, c.settingsRepo, userID, authzCtx.TeamScope.Teams)
			if enabledErr != nil {
				return nil, "", echo.NewHTTPError(http.StatusInternalServerError, "failed to resolve enabled team profiles")
			}
			enabled := false
			for _, candidate := range enabledProfiles {
				enabled = enabled || candidate.ID() == profile.ID()
			}
			if !enabled {
				return nil, "", echo.NewHTTPError(http.StatusForbidden, entities.ErrSessionProfileAccessDenied{ID: profile.ID()}.Error())
			}
		}
		return profile, "explicit_profile_selected", nil
	}

	filter := repositories.SessionProfileFilter{
		UserID: userID,
		Scope:  scope,
	}
	if scope == entities.ScopeTeam {
		filter.TeamID = teamID
	}
	profiles, err := c.sessionProfileRepo.List(ctx, filter)
	if err != nil {
		log.Printf("[SESSION] Warning: could not list session profiles for default lookup: %v", err)
		return nil, "profile_list_unavailable", nil
	}
	if scope == entities.ScopeUser {
		var userTeamIDs []string
		if authzCtx != nil {
			userTeamIDs = authzCtx.TeamScope.Teams
		}
		teamProfiles, teamErr := listEnabledTeamSessionProfiles(ctx, c.sessionProfileRepo, c.settingsRepo, userID, userTeamIDs)
		if teamErr != nil {
			log.Printf("[SESSION] Warning: could not list enabled team profiles: %v", teamErr)
			return nil, "profile_list_unavailable", nil
		}
		profiles = append(profiles, teamProfiles...)
	}
	if profile := selectSessionProfileByTags(profiles, tags); profile != nil {
		log.Printf("[SESSION] Applying tag-selected session profile %q (%s) for user %s", profile.ID(), profile.Name(), userID)
		return profile, "most_specific_selector_tags_match", nil
	}
	if profile := c.resolveSettingsDefaultSessionProfile(ctx, userID, scope, teamID, profiles, authzCtx); profile != nil {
		log.Printf("[SESSION] Applying settings default session profile %q (%s) for user %s", profile.ID(), profile.Name(), userID)
		return profile, "settings_default_selected", nil
	}
	for _, p := range profiles {
		if p.IsDefault() {
			log.Printf("[SESSION] Applying default session profile %q (%s) for user %s", p.ID(), p.Name(), userID)
			return p, "legacy_default_selected", nil
		}
	}
	return nil, "no_matching_or_default_profile", nil
}

func (c *SessionController) canUseSessionProfile(
	authzCtx *auth.AuthorizationContext,
	profile *entities.SessionProfile,
	requestedScope entities.ResourceScope,
	requestedTeamID string,
) bool {
	if authzCtx == nil || profile == nil {
		return false
	}
	switch profile.Scope() {
	case entities.ScopeUser:
		return requestedScope == entities.ScopeUser && profile.UserID() == authzCtx.PersonalScope.UserID
	case entities.ScopeTeam:
		if requestedScope == entities.ScopeTeam {
			return profile.TeamID() == requestedTeamID && authzCtx.CanAccessTeam(profile.TeamID())
		}
		return requestedScope == entities.ScopeUser && authzCtx.CanAccessTeam(profile.TeamID())
	default:
		return false
	}
}

func sessionProfileResolutionHTTPError(err error) error {
	var notFound entities.ErrSessionProfileNotFound
	if errors.As(err, &notFound) {
		return echo.NewHTTPError(http.StatusNotFound, notFound.Error())
	}
	var invalid entities.ErrInvalidSessionProfile
	if errors.As(err, &invalid) {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, invalid.Error())
	}
	var accessDenied entities.ErrSessionProfileAccessDenied
	if errors.As(err, &accessDenied) {
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	}
	return echo.NewHTTPError(http.StatusInternalServerError, "failed to resolve session profile")
}

func (c *SessionController) resolveSettingsDefaultSessionProfile(
	ctx context.Context,
	userID string,
	scope entities.ResourceScope,
	teamID string,
	profiles []*entities.SessionProfile,
	authzCtx *auth.AuthorizationContext,
) *entities.SessionProfile {
	if c.settingsRepo == nil {
		return nil
	}
	settingsName := userID
	if scope == entities.ScopeTeam && teamID != "" {
		settingsName = teamID
	}
	settings, err := c.settingsRepo.FindByName(ctx, settingsName)
	if err != nil || settings == nil || settings.DefaultSessionProfileID() == "" {
		return nil
	}
	defaultID := settings.DefaultSessionProfileID()
	for _, p := range profiles {
		if p.ID() == defaultID {
			return p
		}
	}
	profile, err := c.sessionProfileRepo.Get(ctx, defaultID)
	if err != nil {
		log.Printf("[SESSION] Warning: could not resolve default_session_profile_id %q from settings %q: %v", defaultID, settingsName, err)
		return nil
	}
	if !c.canUseSessionProfile(authzCtx, profile, scope, teamID) {
		log.Printf("[SESSION] Warning: default session profile %q is not accessible from settings %q", defaultID, settingsName)
		return nil
	}
	return profile
}

func selectSessionProfileByTags(profiles []*entities.SessionProfile, tags map[string]string) *entities.SessionProfile {
	var matches []*entities.SessionProfile
	for _, p := range profiles {
		if p.MatchesSelectorTags(tags) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].SelectorSpecificity() != matches[j].SelectorSpecificity() {
			return matches[i].SelectorSpecificity() > matches[j].SelectorSpecificity()
		}
		if matches[i].IsDefault() != matches[j].IsDefault() {
			return matches[i].IsDefault()
		}
		if matches[i].Name() != matches[j].Name() {
			return matches[i].Name() < matches[j].Name()
		}
		return matches[i].ID() < matches[j].ID()
	})
	return matches[0]
}

func applySessionProfile(
	startReq *entities.StartRequest,
	profile *entities.SessionProfile,
	cfg entities.SessionProfileConfig,
	explicitSandbox,
	explicitDocker bool,
) {
	// Resolve session profile: merge profile config into startReq fields.
	// When SessionProfileID is set, use that profile. Otherwise fall back to the
	// user/team's default profile. The profile is the base; explicit request fields override.
	if profile != nil {
		if startReq.Tags == nil {
			startReq.Tags = make(map[string]string)
		}
		startReq.Tags["session_profile_id"] = profile.ID()
		startReq.ResolvedSessionProfileID = profile.ID()
		startReq.ProfileMCPServers = cfg.MCPServers()
		startReq.ProfileSkills = cfg.Skills()
		startReq.ProfileGitHubRepositories = cfg.GitHubRepositories()
		for _, repository := range cfg.ProfileRepositories() {
			startReq.ProfileRepositories = append(startReq.ProfileRepositories, sessionsettings.RepositoryConfig{
				FullName: repository.Repository, CloneDir: repository.Path, Branch: repository.Branch,
			})
		}
		startReq.ProfileCommandWrapper = cfg.CommandWrapperTemplate()
		startReq.ProfileSystemPrompt = cfg.SystemPrompt()
		if profileFiles := cfg.ProfileFiles(); len(profileFiles) > 0 {
			startReq.ProfileFiles = make([]sessionsettings.ManagedFile, len(profileFiles))
			for i, file := range profileFiles {
				startReq.ProfileFiles[i] = sessionsettings.ManagedFile{
					Path:        file.Path,
					Content:     file.Content,
					Permissions: file.Permissions,
				}
			}
		}

		// Keep profile environment separate so it can override team/user
		// settings without overriding explicit request keys.
		if len(cfg.Environment()) > 0 {
			startReq.ProfileEnvironment = make(map[string]string, len(cfg.Environment()))
			for k, v := range cfg.Environment() {
				startReq.ProfileEnvironment[k] = v
			}
		}
		// Tags: profile is base, request keys override
		if len(cfg.Tags()) > 0 {
			merged := make(map[string]string, len(cfg.Tags()))
			for k, v := range cfg.Tags() {
				merged[k] = v
			}
			for k, v := range startReq.Tags {
				merged[k] = v
			}
			startReq.Tags = merged
		}

		// Params: profile is base, request fields override per-field
		if cfg.Params() != nil {
			if startReq.Params == nil {
				startReq.Params = cfg.Params()
			} else {
				startReq.Params = mergeSessionParams(cfg.Params(), startReq.Params)
			}
		}
		if cfg.Pool() != "" {
			if startReq.Params == nil {
				startReq.Params = &entities.SessionParams{}
			}
			if startReq.Params.Pool == "" {
				startReq.Params.Pool = cfg.Pool()
			}
		}
		if containsAllocatorSelector(startReq.Tags) || hasRequestedSessionPool(*startReq) {
			removeImplicitAllocatorCapabilities(startReq.Params, explicitSandbox, explicitDocker)
		}

		// SandboxPolicyID: apply profile's policy when request does not already specify one.
		if startReq.Params == nil {
			startReq.Params = &entities.SessionParams{}
		}
		// Native allocator sessions intentionally do not support sandboxing.
		// Do not let a profile's implicit sandbox default turn an otherwise valid
		// allocator.* request into an unsupported-capability request. An explicit
		// sandbox in the request remains intact and is rejected by the allocator
		// selection layer.
		if !containsAllocatorSelector(startReq.Tags) && !hasRequestedSessionPool(*startReq) {
			applyProfileSandboxDefaults(cfg, startReq.Params)
		}

		// SessionTTL: apply profile's TTL when request does not already specify one.
		if cfg.SessionTTL() != "" {
			if startReq.Params == nil {
				startReq.Params = &entities.SessionParams{}
			}
			if startReq.Params.SessionTTL == "" {
				startReq.Params.SessionTTL = cfg.SessionTTL()
			}
		}
		if len(cfg.UnsyncedFilePaths()) > 0 {
			if startReq.Params == nil {
				startReq.Params = &entities.SessionParams{}
			}
			if len(startReq.Params.UnsyncedFilePaths) == 0 {
				startReq.Params.UnsyncedFilePaths = cfg.UnsyncedFilePaths()
			}
		}
		applyProfileSessionState(startReq, cfg.SessionState())
	}
}

func applyProfileSessionState(startReq *entities.StartRequest, state *entities.SessionStateConfig) {
	if state == nil || !state.Enabled || state.StorageID == "" {
		return
	}
	if startReq.Params == nil {
		startReq.Params = &entities.SessionParams{}
	}
	componentEnabled := func(value string) bool {
		for _, component := range state.Components {
			if component == value {
				return true
			}
		}
		return false
	}
	agentEnabled := func(value string) bool {
		for _, agent := range state.Agents {
			if agent == value {
				return true
			}
		}
		return false
	}
	appendManaged := func(storagePath, mountPath string) {
		startReq.Params.Storages = append(startReq.Params.Storages, entities.StorageAttachment{
			StorageID: state.StorageID, StoragePath: storagePath, MountPath: mountPath, Managed: true,
		})
	}
	if componentEnabled("agent_state") {
		agent := sessionStateAgent(startReq.Params.AgentType)
		// Codex keeps its resume index in SQLite. File-by-file object storage
		// synchronization cannot preserve a consistent database/WAL generation,
		// so persisted legacy profiles must not create a managed Codex mount.
		if agent == "" || agent == "claude" {
			if agentEnabled("claude") {
				appendManaged("session-state/claude", "/home/agentapi/.claude")
			}
		}
	}
	if componentEnabled("workspace") {
		appendManaged("workspace", "/home/agentapi/workdir")
	}
}

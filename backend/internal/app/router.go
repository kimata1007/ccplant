package app

import (
	"context"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	sessionallocation "github.com/takutakahashi/agentapi-proxy/internal/core/sessionallocation"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/repositories"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/services"
	"github.com/takutakahashi/agentapi-proxy/internal/interfaces/controllers"
	"github.com/takutakahashi/agentapi-proxy/internal/modules/slackbot"
	apitokenuc "github.com/takutakahashi/agentapi-proxy/internal/usecases/api_token"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/personal_api_key"
	portrepos "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/resource_transfer"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
	"github.com/takutakahashi/agentapi-proxy/pkg/auth"
	"github.com/takutakahashi/agentapi-proxy/pkg/config"
	"github.com/takutakahashi/agentapi-proxy/pkg/sessionsettings"
	"github.com/takutakahashi/agentapi-proxy/spec"
)

// Router handles route registration and management
type Router struct {
	echo     *echo.Echo
	server   *Server
	handlers *HandlerRegistry
}

// HandlerRegistry contains all handlers
type HandlerRegistry struct {
	notificationHandlers           *controllers.NotificationHandlers
	healthController               *controllers.HealthController
	sessionController              *controllers.SessionController
	acpController                  *controllers.ACPController
	settingsController             *controllers.SettingsController
	adminSettingsController        *controllers.AdminSettingsController
	githubConnectionsController    *controllers.GitHubConnectionsController
	googleConnectionsController    *controllers.GoogleConnectionsController
	teamConfigController           *controllers.TeamConfigController
	teamMembershipController       *controllers.TeamMembershipController
	googleOAuthController          *controllers.GoogleOAuthController
	credentialsController          *controllers.CredentialsController
	codexDeviceAuthController      *controllers.CodexDeviceAuthController
	userController                 *controllers.UserController
	shareController                *controllers.ShareController
	personalAPIKeyController       *controllers.PersonalAPIKeyController
	apiTokenController             *controllers.APITokenController
	adminLocalUserController       *controllers.AdminLocalUserController
	sandboxPolicyController        *controllers.SandboxPolicyController
	storageController              *controllers.StorageController
	resourceTransferController     *controllers.ResourceTransferController
	fileController                 *controllers.FileController
	sessionProfileController       *controllers.SessionProfileController
	provisionerController          *controllers.ProvisionerController
	externalAllocationController   *controllers.ProvisionerController
	workerControlController        *controllers.WorkerControlController
	taskController                 *controllers.TaskController
	sessionControlController       *controllers.SessionControlController
	sessionControlReaderController *controllers.SessionControlReaderController
	esmControlController           *controllers.ESMControlController
	sessionRuntimeController       *controllers.SessionRuntimeController
	sessionSecretController        *controllers.SessionSecretController
	sessionPoolController          *controllers.SessionPoolController
	usageController                *controllers.UsageController
	sessionUsageController         *controllers.SessionUsageController
	customHandlers                 []CustomHandler
}

// CustomHandler interface for adding custom routes
type CustomHandler interface {
	RegisterRoutes(e *echo.Echo) error
	GetName() string
}

// NewRouter creates a new Router instance
func NewRouter(e *echo.Echo, server *Server) *Router {
	// Create settings controller
	settingsController := controllers.NewSettingsController(server.settingsRepo, server.notificationSvc)
	settingsController.SetESMControlTunnel(server.esmControlTunnel)
	settingsController.SetSessionRunnerStore(server.sessionRunnerStore)
	var sessionPoolController *controllers.SessionPoolController
	if provider, ok := server.sessionManager.(interface {
		ExternalRuntimeProfile() *sessionsettings.RuntimeProfile
	}); ok {
		sessionPoolController = controllers.NewSessionPoolController(server.sessionRunnerStore, server.sessionRouteRepo, provider)
	} else {
		sessionPoolController = controllers.NewSessionPoolController(server.sessionRunnerStore, server.sessionRouteRepo)
	}
	if server.esmControlStore != nil {
		sessionPoolController.WithManagerLiveness(server.esmControlStore)
	}
	if server.esmControlTunnel != nil {
		sessionPoolController.WithManagerTunnel(server.esmControlTunnel)
	}
	if server.sessionAllocationNotifier != nil {
		sessionPoolController.WithAllocationNotifier(server.sessionAllocationNotifier)
	}
	if managedFiles, ok := server.credentialsRepo.(interface {
		SaveFiles(context.Context, string, []sessionsettings.ManagedFile) error
	}); ok {
		sessionPoolController.WithManagedFileStore(managedFiles)
	}

	var apiKeyRepo *repositories.KubernetesPersonalAPIKeyRepository
	var adminSettingsController *controllers.AdminSettingsController
	var githubConnectionsController *controllers.GitHubConnectionsController
	var teamMembershipController *controllers.TeamMembershipController
	var membershipRepo *repositories.KVStoreTeamMembershipRepository
	var googleConnectionsController *controllers.GoogleConnectionsController
	if server.persistenceClient != nil {
		apiKeyRepo = repositories.NewKubernetesPersonalAPIKeyRepository(
			server.GetPersistenceClient(),
			server.namespace,
		)
		if server.kvStore != nil {
			adminSettingsController = controllers.NewAdminSettingsController(server.kvStore, server.namespace, server.GetConfig()).WithRuntimeConfigProvider(server.GetConfigProvider())
		}
		encryptedStorage := false
		if cfg := server.GetConfig(); cfg != nil {
			encryptedStorage = supportsGitHubSecretStorage(cfg.KVStore)
		}
		githubConnectionsController = controllers.NewGitHubConnectionsController(server.GetPersistenceClient(), server.namespace, "", encryptedStorage)
		if cfg := server.GetConfig(); cfg != nil && cfg.Auth.GitHub != nil {
			githubConnectionsController.SetBuiltInAPIURL(cfg.Auth.GitHub.BaseURL)
		}
		membershipRepo = repositories.NewKVStoreTeamMembershipRepository(server.GetApplicationKVStore(), server.namespace)
		teamMembershipController = controllers.NewTeamMembershipController(server.teamConfigRepo, membershipRepo, githubConnectionsController)
		githubConnectionsController.SetMembershipRepository(membershipRepo)
		githubConnectionsController.SetMembershipSyncer(teamMembershipController)
		googleConnectionsController = controllers.NewGoogleConnectionsController(server.GetPersistenceClient(), server.namespace, "", encryptedStorage, githubConnectionsController)
		if simpleAuth, ok := server.container.AuthService.(*services.SimpleAuthService); ok {
			simpleAuth.SetGitHubMembershipResolver(githubConnectionsController)
			simpleAuth.SetGitHubConnectionCredentialResolver(githubConnectionsController)
		}
	}
	teamConfigController := controllers.NewTeamConfigController(server.teamConfigRepo)
	if membershipRepo != nil {
		teamConfigController.WithMembershipRepository(membershipRepo)
	}

	var googleOAuthController *controllers.GoogleOAuthController
	if cfg := server.GetConfig(); cfg != nil {
		googleOAuthController = controllers.NewGoogleOAuthController(cfg.Scia, server.GetPersistenceClient(), server.namespace)
		if apiKeyRepo != nil {
			googleOAuthController.WithPersonalAPIKeyRepository(apiKeyRepo)
		}
	}

	// Create credentials controller
	var credentialsController *controllers.CredentialsController
	if server.credentialsRepo != nil {
		credentialsController = controllers.NewCredentialsController(server.credentialsRepo)
		log.Printf("[ROUTER] Credentials controller initialized")
	}

	// Create Codex device auth controller (requires credentials repo).
	// Workloads are always delegated to an external session manager over the
	// outbound control tunnel; there is deliberately no in-process launcher.
	var codexDeviceAuthController *controllers.CodexDeviceAuthController
	if server.credentialsRepo != nil {
		if server.codexDeviceAuthLauncher != nil {
			codexDeviceAuthController = controllers.NewCodexDeviceAuthController(server.credentialsRepo, server.codexDeviceAuthLauncher)
		} else {
			codexDeviceAuthController = controllers.NewCodexDeviceAuthController(server.credentialsRepo)
		}
		if server.persistenceClient != nil {
			codexDeviceAuthController.WithAttemptStore(repositories.NewKubernetesCodexAuthAttemptRepository(server.GetPersistenceClient(), server.namespace))
		}
		if cfg := server.GetConfig(); cfg != nil {
			codexDeviceAuthController.WithCallbackBaseURL(cfg.CodexDeviceAuthCallbackBaseURL)
		}
		log.Printf("[ROUTER] Codex device auth controller initialized")
	}

	// Create session controller with proper dependencies
	// server implements SessionManagerProvider interface via GetSessionManager()
	// Note: ServiceAccount creation for team-scoped sessions is now handled in
	// KubernetesSessionManager.CreateSession() via the injected ServiceAccountEnsurer.
	sessionControllerOptions := []controllers.SessionControllerOption{
		controllers.WithSessionRouteRepository(server.GetSessionRouteRepository()),
		controllers.WithSettingsRepository(server.settingsRepo),
		controllers.WithSessionProfileRepository(server.sessionProfileRepo),
		controllers.WithSessionContextTemplates(server.contextTemplateRepo, server.sessionStateStore),
		controllers.WithESMControlTunnel(server.esmControlTunnel),
		controllers.WithSessionRunnerStore(server.sessionRunnerStore),
		controllers.WithSessionTokenDebug(server.config.SessionTokenDebug),
		controllers.WithGitHubBrokerBaseURL(server.config.GitHubBrokerBaseURL),
		controllers.WithRouteStatusEventBus(server.routeStatusBus),
	}
	if githubConnectionsController != nil {
		sessionControllerOptions = append(sessionControllerOptions, controllers.WithGitHubTokenResolver(githubConnectionsController))
	}
	sessionController := controllers.NewSessionController(
		server, // Server implements SessionManagerProvider interface
		server, // Server implements SessionCreator interface
		sessionControllerOptions...,
	)
	sessionPoolController.WithRouteStatusPublisher(sessionController)
	server.startRouteStatusRelay(sessionController)

	// Create share controller if share repository is available
	var shareController *controllers.ShareController
	if server.shareRepo != nil {
		shareController = controllers.NewShareController(
			server, // Server implements SessionManagerProvider interface
			server.shareRepo,
		)
		log.Printf("[ROUTER] Share controller initialized")
	}

	// Create personal API key controller if session manager is Kubernetes-based
	var personalAPIKeyController *controllers.PersonalAPIKeyController
	if apiKeyRepo != nil {
		getOrCreatePersonalAPIKeyUC := personal_api_key.NewGetOrCreatePersonalAPIKeyUseCase(apiKeyRepo)

		// Get auth service for loading API keys into memory
		var authService controllers.AuthServiceForPersonalAPIKey
		if simpleAuth, ok := server.container.AuthService.(*services.SimpleAuthService); ok {
			authService = simpleAuth
		}

		personalAPIKeyController = controllers.NewPersonalAPIKeyController(getOrCreatePersonalAPIKeyUC, authService)
		log.Printf("[ROUTER] Personal API key controller initialized")
	}

	// Create the unified multi API token controller (list/create/get/delete)
	// when the new API token repository is available (Kubernetes mode only).
	var apiTokenController *controllers.APITokenController
	var adminLocalUserController *controllers.AdminLocalUserController
	if server.apiTokenRepo != nil {
		var tokenAuthService apitokenuc.AuthService
		if simpleAuth, ok := server.container.AuthService.(*services.SimpleAuthService); ok {
			tokenAuthService = simpleAuth
		}
		createUC := apitokenuc.NewCreateAPITokenUseCase(server.apiTokenRepo, tokenAuthService)
		listUC := apitokenuc.NewListAPITokenUseCase(server.apiTokenRepo)
		getUC := apitokenuc.NewGetAPITokenUseCase(server.apiTokenRepo)
		deleteUC := apitokenuc.NewDeleteAPITokenUseCase(server.apiTokenRepo, tokenAuthService)
		apiTokenController = controllers.NewAPITokenController(createUC, listUC, getUC, deleteUC)
		if server.localUserRepo != nil {
			adminLocalUserController = controllers.NewAdminLocalUserController(server.localUserRepo, server.apiTokenRepo, tokenAuthService)
		}
		log.Printf("[ROUTER] API token controller initialized")
	}

	// Create sandbox policy controller if sandbox policy repository is available
	var sandboxPolicyController *controllers.SandboxPolicyController
	if server.sandboxPolicyRepo != nil {
		sandboxPolicyController = controllers.NewSandboxPolicyController(server.sandboxPolicyRepo, server.sandboxDomainRepo)
		log.Printf("[ROUTER] Sandbox policy controller initialized")
	}
	var storageController *controllers.StorageController
	if server.storageRepo != nil {
		storageController = controllers.NewStorageController(server.storageRepo, server.storageObjectStore)
		log.Printf("[ROUTER] Storage controller initialized")
	}

	resourceTransferOptions := []resource_transfer.Option{
		resource_transfer.WithSessionProfileRepository(server.sessionProfileRepo),
		resource_transfer.WithSandboxPolicyRepository(server.sandboxPolicyRepo),
	}
	if server.persistenceClient != nil {
		client := server.GetPersistenceClient()
		namespace := server.namespace
		resourceTransferOptions = append(resourceTransferOptions,
			resource_transfer.WithWebhookRepository(repositories.NewKubernetesWebhookRepository(client, namespace)),
			resource_transfer.WithSlackBotRepository(repositories.NewKubernetesSlackBotRepository(client, namespace)),
		)
	}
	resourceTransferController := controllers.NewResourceTransferController(resource_transfer.New(resourceTransferOptions...))
	log.Printf("[ROUTER] Resource transfer controller initialized")

	// Create file controller if user file repository is available
	var fileController *controllers.FileController
	if server.userFileRepo != nil {
		fileController = controllers.NewFileController(server.userFileRepo)
		log.Printf("[ROUTER] File controller initialized")
	}

	// Create session profile controller if session profile repository is available
	var sessionProfileController *controllers.SessionProfileController
	if server.sessionProfileRepo != nil {
		sessionProfileController = controllers.NewSessionProfileController(server.sessionProfileRepo, server.settingsRepo)
		log.Printf("[ROUTER] Session profile controller initialized")
	}

	var provisionerController *controllers.ProvisionerController
	var externalAllocationController *controllers.ProvisionerController
	var workerControlController *controllers.WorkerControlController
	var taskController *controllers.TaskController
	if cfg := server.GetConfig(); cfg != nil && cfg.TaskQueue.Enabled && cfg.Worker.ExecutionTokenSigningKey != "" && cfg.Worker.ControlAPIToken != "" {
		queue := &task.Queue{Repo: repositories.NewTaskRepository(server.GetApplicationKVStore(), server.namespace), Config: cfg.TaskQueue, Sessions: server.taskSessionSnapshot, RecoverAllocation: server.recoverTaskAllocation}
		queue.Metrics = task.NewMetrics(queue.Repo)
		taskController = &controllers.TaskController{Queue: queue, SigningKey: cfg.Worker.ExecutionTokenSigningKey}
		sessionController.SetTaskQueue(queue)
	}

	var sessionControlController *controllers.SessionControlController
	var sessionControlReaderController *controllers.SessionControlReaderController
	var esmControlController *controllers.ESMControlController
	var sessionRuntimeController *controllers.SessionRuntimeController
	var sessionSecretController *controllers.SessionSecretController
	if server.persistenceClient != nil {
		sessionSecretController = controllers.NewSessionSecretController(server.persistenceClient, server.namespace, server.sessionManager, server.sessionRouteRepo)
	}
	if k8sManager, ok := server.sessionManager.(*services.KubernetesSessionManager); ok {
		provisionerController = controllers.NewProvisionerController(k8sManager, k8sManager, server.settingsRepo, server.sessionRouteRepo, server.sessionStateStore)
		if server.sessionControlStore != nil {
			sessionControlController = controllers.NewSessionControlController(server.sessionControlStore, k8sManager)
		}
		if server.esmControlStore != nil {
			esmControlController = controllers.NewESMControlController(server.esmControlStore, provisionerController, server.sessionRunnerStore)
		}
		log.Printf("[ROUTER] Provisioner controller initialized")
	}
	if queue, ok := server.sessionManager.(sessionallocation.Queue); ok {
		if provisionerController != nil {
			externalAllocationController = provisionerController
		} else {
			externalAllocationController = controllers.NewProvisionerController(nil, queue, server.settingsRepo, server.sessionRouteRepo)
		}
		if server.esmControlStore != nil {
			esmControlController = controllers.NewESMControlController(server.esmControlStore, externalAllocationController, server.sessionRunnerStore)
		}
	}
	// A parent that delegates all execution through the unified session-manager
	// registry has neither a local Kubernetes manager nor the legacy allocation
	// queue. It still must expose the outbound lifecycle control endpoints used
	// by those registered managers.
	if esmControlController == nil && server.esmControlStore != nil && server.sessionRunnerStore != nil {
		esmControlController = controllers.NewESMControlController(server.esmControlStore, nil, server.sessionRunnerStore)
	}
	// Direct Session Pod runtime transport only depends on the shared control
	// store and durable session routes. Parent proxies using the unified
	// session-manager registry have neither a local Kubernetes manager nor the
	// legacy allocation queue, but must still expose the runtime endpoints.
	if server.esmControlStore != nil && server.sessionRouteRepo != nil {
		sessionRuntimeController = controllers.NewSessionRuntimeController(server.esmControlStore, server.sessionRouteRepo, sessionController).WithRunnerStore(server.sessionRunnerStore)
	}
	if cfg := server.GetConfig(); cfg != nil && cfg.Worker.ControlAPIToken != "" {
		namespace := cfg.KVStore.Namespace
		if namespace == "" {
			namespace = "default"
		}
		slackRepo := repositories.NewKubernetesSlackBotRepository(server.GetPersistenceClient(), namespace)
		slackResolver := slackbot.NewSlackChannelResolver(server.GetPersistenceClient(), namespace).WithSettingsRepository(server.GetSettingsRepository())
		workerControlController = controllers.NewWorkerControlController(server.sessionManager, cfg.Worker.ControlAPIToken, cfg.Worker.ExecutionTokenSigningKey, server, server.sessionRouteRepo).
			WithSlackBots(slackRepo, slackResolver).
			WithLeases(buildWorkerLeaseClient(cfg)).
			WithSessionDeleter(sessionController.DeleteSessionFromWorker).
			WithSessionPoolAllocationCleaner(server.DeleteSessionPoolAllocation)
		if server.scheduleManager != nil {
			workerControlController.WithScheduleManager(server.scheduleManager)
		}
		log.Printf("[ROUTER] Worker control controller initialized")
	}
	if server.sessionControlStore != nil {
		sessionControlReaderController = controllers.NewSessionControlReaderController(server.sessionControlStore, server.sessionManager)
	}

	acpController := controllers.NewACPController(server, server, server.GetSessionRouteRepository())
	acpController.SetESMControlTunnel(server.esmControlTunnel)
	var usageController *controllers.UsageController
	if server.usageRepo != nil {
		usageController = controllers.NewUsageController(server.usageRepo, server.sessionManager)
	}
	var sessionUsageController *controllers.SessionUsageController
	if repository, ok := server.sessionCountRepo.(portrepos.SessionRuntimeRepository); ok {
		sessionUsageController = controllers.NewSessionUsageController(repository, server.teamConfigRepo)
	}

	return &Router{
		echo:   e,
		server: server,
		handlers: &HandlerRegistry{
			notificationHandlers:           controllers.NewNotificationHandlers(server.notificationSvc, server.sessionManager),
			healthController:               controllers.NewHealthController(),
			sessionController:              sessionController,
			acpController:                  acpController,
			settingsController:             settingsController,
			adminSettingsController:        adminSettingsController,
			githubConnectionsController:    githubConnectionsController,
			googleConnectionsController:    googleConnectionsController,
			teamConfigController:           teamConfigController,
			teamMembershipController:       teamMembershipController,
			googleOAuthController:          googleOAuthController,
			credentialsController:          credentialsController,
			codexDeviceAuthController:      codexDeviceAuthController,
			userController:                 controllers.NewUserController(server.teamConfigRepo),
			shareController:                shareController,
			personalAPIKeyController:       personalAPIKeyController,
			apiTokenController:             apiTokenController,
			adminLocalUserController:       adminLocalUserController,
			sandboxPolicyController:        sandboxPolicyController,
			storageController:              storageController,
			resourceTransferController:     resourceTransferController,
			fileController:                 fileController,
			sessionProfileController:       sessionProfileController,
			provisionerController:          provisionerController,
			externalAllocationController:   externalAllocationController,
			workerControlController:        workerControlController,
			taskController:                 taskController,
			sessionControlController:       sessionControlController,
			sessionControlReaderController: sessionControlReaderController,
			esmControlController:           esmControlController,
			sessionRuntimeController:       sessionRuntimeController,
			sessionSecretController:        sessionSecretController,
			sessionPoolController:          sessionPoolController,
			usageController:                usageController,
			sessionUsageController:         sessionUsageController,
			customHandlers:                 make([]CustomHandler, 0),
		},
	}
}

func supportsGitHubSecretStorage(cfg config.KVStoreConfig) bool {
	backend := configuredKVBackend(cfg)
	return backend == "libsql-encrypted" || backend == "kubernetes"
}

// AddCustomHandler adds a custom handler to the registry
func (r *Router) AddCustomHandler(handler CustomHandler) {
	r.handlers.customHandlers = append(r.handlers.customHandlers, handler)
	log.Printf("Added custom handler: %s", handler.GetName())
}

// RegisterRoutes registers all routes
func (r *Router) RegisterRoutes() error {
	// Register core routes
	if err := r.registerCoreRoutes(); err != nil {
		return err
	}

	// Register conditional routes based on configuration
	if err := r.registerConditionalRoutes(); err != nil {
		return err
	}

	// Register custom handlers
	if err := r.registerCustomHandlers(); err != nil {
		return err
	}

	r.registerSessionProxyRoutes()

	return nil
}

// registerCoreRoutes registers the core routes that are always available
func (r *Router) registerCoreRoutes() error {
	// Health check endpoint
	r.echo.GET("/health", r.handlers.healthController.HealthCheck)

	// Static file serving for /public/* (no authentication required)
	// Embedded from spec/openapi.json - independent of working directory
	// Must be registered before the /:sessionId/* catch-all route
	r.echo.StaticFS("/public", spec.FS())
	log.Printf("[ROUTES] Static file serving registered at /public/*")

	// ACP (Agent Client Protocol) JSON-RPC 2.0 endpoints
	log.Printf("[ROUTES] Registering ACP endpoints...")
	r.echo.POST("/acp", r.handlers.acpController.HandleRPC, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	r.echo.GET("/acp", r.handlers.acpController.HandleSessionSSE, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	r.echo.OPTIONS("/acp", func(c echo.Context) error {
		log.Printf("[ACP] OPTIONS /acp preflight: origin=%s", c.Request().Header.Get("Origin"))
		c.Response().Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, Acp-Session-Id")
		c.Response().Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		return c.NoContent(http.StatusNoContent)
	})
	log.Printf("[ROUTES] ACP endpoints registered")

	// Session management routes
	log.Printf("[ROUTES] Registering session management endpoints...")
	r.echo.POST("/start", r.handlers.sessionController.StartSession)
	if tc := r.handlers.taskController; tc != nil {
		read := auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService)
		create := auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService)
		r.echo.POST("/tasks", tc.Submit, create)
		r.echo.GET("/tasks", tc.List, read)
		r.echo.GET("/tasks/stream", tc.Stream, read)
		r.echo.GET("/tasks/:id", tc.Show, read)
		r.echo.POST("/tasks/:id/cancel", tc.Cancel, create)
		r.echo.POST("/tasks/:id/retry", tc.Retry, create)
	}
	r.echo.GET("/search", r.handlers.sessionController.SearchSessions)
	if r.handlers.usageController != nil {
		r.echo.POST("/internal/usage-events", r.handlers.usageController.Create,
			auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/usage", r.handlers.usageController.Get,
			auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/usage/export.parquet", r.handlers.usageController.ExportParquet,
			auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/sessions/:sessionId/usage", r.handlers.usageController.GetSession,
			auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	}
	if r.handlers.sessionUsageController != nil {
		r.echo.GET("/session-usage/dashboard", r.handlers.sessionUsageController.GetDashboard,
			auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	}
	r.echo.PATCH("/sessions/:sessionId/annotations", r.handlers.sessionController.UpdateSessionAnnotations)
	r.echo.POST("/sessions/:sessionId/resume", r.handlers.sessionController.ResumeSession)
	r.echo.POST("/sessions/:sessionId/restart", r.handlers.sessionController.RestartSession)
	r.echo.GET("/sessions/:sessionId/restart", r.handlers.sessionController.RestartStatus)
	r.echo.POST("/sessions/:sessionId/pause", r.handlers.sessionController.PauseSession)
	r.echo.POST("/sessions/:sessionId/suspend", r.handlers.sessionController.SuspendSession)
	r.echo.POST("/sessions/:sessionId/templateize", r.handlers.sessionController.TemplateizeSession)
	r.echo.POST("/sessions/:sessionId/workspace", r.handlers.sessionController.SaveSessionAsWorkspace)
	r.echo.GET("/workspaces", r.handlers.sessionController.ListWorkspaces)
	r.echo.GET("/workspaces/:workspaceId", r.handlers.sessionController.GetWorkspace)
	r.echo.PATCH("/workspaces/:workspaceId", r.handlers.sessionController.UpdateWorkspace)
	r.echo.DELETE("/workspaces/:workspaceId", r.handlers.sessionController.DeleteWorkspace)
	r.echo.GET("/session-context-templates", r.handlers.sessionController.ListSessionContextTemplates)
	r.echo.GET("/session-context-templates/:templateId", r.handlers.sessionController.GetSessionContextTemplate)
	r.echo.PATCH("/session-context-templates/:templateId", r.handlers.sessionController.UpdateSessionContextTemplate)
	r.echo.DELETE("/session-context-templates/:templateId", r.handlers.sessionController.DeleteSessionContextTemplate)
	r.echo.DELETE("/sessions/:sessionId", r.handlers.sessionController.DeleteSession)
	if r.handlers.sessionSecretController != nil {
		r.echo.GET("/sessions/:sessionId/secrets", r.handlers.sessionSecretController.List,
			auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/sessions/:sessionId/secrets", r.handlers.sessionSecretController.Create,
			auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.POST("/sessions/:sessionId/secrets/:secretId/reauthorize", r.handlers.sessionSecretController.Reauthorize,
			auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/internal/session-control/:sessionId/secrets/next", r.handlers.sessionSecretController.ConsumeNext)
		r.echo.GET("/internal/session-control/:sessionId/secrets/:secretId", r.handlers.sessionSecretController.Consume)
	}
	if r.handlers.sessionPoolController != nil {
		r.echo.GET("/available-session-pools", r.handlers.sessionPoolController.ListAvailablePools,
			auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/internal/session-runners/register", r.handlers.sessionPoolController.RegisterRunner)
		r.echo.GET("/internal/session-runners/allocations/next", r.handlers.sessionPoolController.ClaimRunnerAllocation)
		r.echo.POST("/internal/session-runners/allocations/:sessionId/ack", r.handlers.sessionPoolController.AckRunnerAllocation)
		r.echo.POST("/internal/session-runners/allocations/:sessionId/fail", r.handlers.sessionPoolController.FailRunnerAllocation)
		r.echo.POST("/internal/session-managers/:id/runners/:runnerId/retire", r.handlers.sessionPoolController.RetireRunner)
		r.echo.POST("/internal/session-managers/:id/heartbeat", r.handlers.sessionPoolController.HeartbeatManager)
		r.echo.GET("/internal/session-managers/:id/runtime-profile", r.handlers.sessionPoolController.GetManagerRuntimeProfile)
		r.echo.PUT("/internal/session-managers/:id/sessions/:sessionId/managed-files", r.handlers.sessionPoolController.SaveManagerManagedFiles)
		r.echo.GET("/internal/session-managers/:id/version", r.handlers.sessionPoolController.GetManagerVersion)
	}

	// Proxy-wide session status push endpoints (registered before /:sessionId/* catch-all)
	r.echo.GET("/sessions/status/stream", r.handlers.sessionController.StreamSessionsStatus)
	r.echo.GET("/sessions/status/wait", r.handlers.sessionController.WaitSessionsStatus)
	// Per-session message update long-poll endpoint (must be before /:sessionId/* catch-all)
	r.echo.GET("/sessions/:sessionId/messages/wait", r.handlers.sessionController.WaitSessionMessages)
	// Sandbox domain viewer (must be before /:sessionId/* catch-all)
	r.echo.GET("/sessions/:sessionId/sandbox-domains", r.handlers.sessionController.GetSessionSandboxDomains,
		auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	log.Printf("[ROUTES] Session status/message push endpoints registered (SSE + long-poll)")

	if r.handlers.resourceTransferController != nil {
		log.Printf("[ROUTES] Registering resource transfer endpoint...")
		r.echo.POST("/resources/transfer", r.handlers.resourceTransferController.TransferResource, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.POST("/resources/*", func(c echo.Context) error {
			if c.Param("*") != "transfer" {
				return echo.NewHTTPError(http.StatusNotFound, "resource endpoint not found")
			}
			return r.handlers.resourceTransferController.TransferResource(c)
		}, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		log.Printf("[ROUTES] Resource transfer endpoint registered")
	}

	if r.handlers.provisionerController != nil {
		r.echo.POST("/internal/session-provisioners/connect", r.handlers.provisionerController.Connect)
		r.echo.GET("/internal/session-provisioners/:sessionId/provision-requests", r.handlers.provisionerController.GetProvisionRequest)
		r.echo.POST("/internal/session-provisioners/:sessionId/provision-requests/:requestId/status", r.handlers.provisionerController.UpdateProvisionRequestStatus)
		r.echo.GET("/internal/session-allocations/next", r.handlers.provisionerController.GetNextSessionAllocation)
		r.echo.POST("/internal/session-allocations/:sessionId/result", r.handlers.provisionerController.CompleteSessionAllocation)
		r.echo.PUT("/internal/session-state/:sessionId", r.handlers.provisionerController.SaveSessionState)
		r.echo.POST("/internal/session-state/:sessionId/suspend", r.handlers.provisionerController.ScheduleSessionSuspend)
		r.echo.POST("/internal/session-state/:sessionId/terminate", r.handlers.provisionerController.SuspendSessionOnTermination)
		r.echo.GET("/internal/session-state/:sessionId", r.handlers.provisionerController.LoadSessionState)
		r.echo.POST("/internal/session-state/:sessionId/uploads", r.handlers.provisionerController.BeginSessionStateUpload)
		r.echo.GET("/internal/session-state/:sessionId/uploads/:uploadId/parts/:partNumber", r.handlers.provisionerController.PresignSessionStatePart)
		r.echo.POST("/internal/session-state/:sessionId/uploads/:uploadId/complete", r.handlers.provisionerController.CompleteSessionStateUpload)
		r.echo.DELETE("/internal/session-state/:sessionId/uploads/:uploadId", r.handlers.provisionerController.AbortSessionStateUpload)
		r.echo.GET("/internal/session-state/:sessionId/download-url", r.handlers.provisionerController.PresignSessionStateDownload)
		log.Printf("[ROUTES] Internal provisioner endpoints registered")
	}
	if r.handlers.workerControlController != nil {
		worker := r.echo.Group("/internal/worker", r.handlers.workerControlController.Authenticate)
		worker.POST("/sessions/:sessionId", r.handlers.workerControlController.CreateSession)
		worker.GET("/sessions", r.handlers.workerControlController.ListSessions)
		worker.DELETE("/sessions/:sessionId", r.handlers.workerControlController.DeleteSession)
		worker.POST("/sessions/:sessionId/messages", r.handlers.workerControlController.SendMessage)
		worker.POST("/sessions/:sessionId/stop", r.handlers.workerControlController.StopAgent)
		worker.GET("/stock", r.handlers.workerControlController.Stock)
		worker.POST("/stock", r.handlers.workerControlController.Stock)
		worker.DELETE("/stock", r.handlers.workerControlController.Stock)
		worker.POST("/leases/:leaseName", r.handlers.workerControlController.Lease)
		if tc := r.handlers.taskController; tc != nil {
			worker.POST("/tasks/claim-due", tc.Claim)
			worker.POST("/tasks/:id/heartbeat", tc.Heartbeat)
			worker.POST("/tasks/:id/finalize", tc.Finalize)
			worker.POST("/tasks/prune", func(ctx echo.Context) error {
				if err := tc.Queue.Prune(ctx.Request().Context()); err != nil {
					return echo.NewHTTPError(http.StatusServiceUnavailable, "task retention cleanup failed").SetInternal(err)
				}
				return ctx.NoContent(http.StatusNoContent)
			})
		}
		worker.POST("/schedules/claim-due", r.handlers.workerControlController.ClaimDueSchedules)
		worker.POST("/schedules/:id/finalize", r.handlers.workerControlController.FinalizeSchedule)
		worker.GET("/slackbots", r.handlers.workerControlController.ListSlackBots)
		worker.GET("/slackbots/:id/credentials", r.handlers.workerControlController.GetSlackBotCredentials)
		log.Printf("[ROUTES] Isolated worker-control endpoints registered")
	}
	if r.handlers.sessionControlController != nil {
		r.echo.GET("/internal/session-control/:sessionId/commands", r.handlers.sessionControlController.WaitCommands)
		r.echo.POST("/internal/session-control/:sessionId/events", r.handlers.sessionControlController.AppendEvents)
		log.Printf("[ROUTES] Internal session control long-poll endpoints registered")
	}
	if r.handlers.sessionControlReaderController != nil {
		r.echo.GET("/sessions/:sessionId/control/events/wait", r.handlers.sessionControlReaderController.WaitEvents,
			auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	}
	if r.handlers.esmControlController != nil {
		r.echo.GET("/internal/external-session-manager/control/commands", r.handlers.esmControlController.WaitCommands)
		r.echo.POST("/internal/external-session-manager/control/frames", r.handlers.esmControlController.AppendFrames)
		r.echo.GET("/internal/external-session-managers/:managerId/control/commands", r.handlers.esmControlController.WaitCommands)
		r.echo.POST("/internal/external-session-managers/:managerId/control/frames", r.handlers.esmControlController.AppendFrames)
		log.Printf("[ROUTES] Internal outbound ESM control endpoints registered")
	}
	if r.handlers.sessionRuntimeController != nil {
		r.echo.GET("/internal/session-runtime/:sessionId/requests", r.handlers.sessionRuntimeController.WaitRequests)
		r.echo.POST("/internal/session-runtime/:sessionId/frames", r.handlers.sessionRuntimeController.AppendFrames)
		r.echo.POST("/internal/session-runtime/:sessionId/status", r.handlers.sessionRuntimeController.UpdateStatus)
		r.echo.POST("/internal/session-runtime/:sessionId/checkpoint", r.handlers.sessionRuntimeController.Checkpoint)
		log.Printf("[ROUTES] Direct Session Pod runtime endpoints registered")
	}

	// Session sharing routes
	if r.handlers.shareController != nil {
		log.Printf("[ROUTES] Registering session sharing endpoints...")
		r.echo.POST("/sessions/:sessionId/share", r.handlers.shareController.CreateShare)
		r.echo.GET("/sessions/:sessionId/share", r.handlers.shareController.GetShare)
		r.echo.DELETE("/sessions/:sessionId/share", r.handlers.shareController.DeleteShare)
		// Add OPTIONS handler for session share endpoints (CORS preflight)
		r.echo.OPTIONS("/sessions/:sessionId/share", func(c echo.Context) error {
			c.Response().Header().Set("Access-Control-Allow-Origin", "*")
			c.Response().Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			c.Response().Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-API-Key")
			c.Response().Header().Set("Access-Control-Max-Age", "86400")
			return c.NoContent(http.StatusNoContent)
		})
		// Shared session access route (read-only)
		r.echo.Any("/s/:shareToken/*", r.handlers.shareController.RouteToSharedSession)
		r.echo.OPTIONS("/s/:shareToken/*", func(c echo.Context) error {
			c.Response().Header().Set("Access-Control-Allow-Origin", "*")
			c.Response().Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
			c.Response().Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-API-Key")
			c.Response().Header().Set("Access-Control-Max-Age", "86400")
			return c.NoContent(http.StatusNoContent)
		})
		log.Printf("[ROUTES] Session sharing endpoints registered")
	}

	// Add explicit OPTIONS handler for DELETE endpoint to ensure CORS preflight works
	r.echo.OPTIONS("/sessions/:sessionId", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	log.Printf("[ROUTES] Session management endpoints registered")

	return nil
}

func (r *Router) registerSessionProxyRoutes() {
	// Session proxy route must be registered after all proxy-level routes so
	// paths such as /resources/transfer are not treated as session IDs.
	r.echo.Any("/:sessionId/*", r.handlers.sessionController.RouteToSession)

	// Add explicit OPTIONS handler for session proxy routes to ensure CORS preflight works
	r.echo.OPTIONS("/:sessionId/*", func(c echo.Context) error {
		// Set CORS headers for preflight
		c.Response().Header().Set("Access-Control-Allow-Origin", "*")
		c.Response().Header().Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, PATCH, POST, DELETE, OPTIONS")
		c.Response().Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-API-Key")
		c.Response().Header().Set("Access-Control-Allow-Credentials", "true")
		c.Response().Header().Set("Access-Control-Max-Age", "86400")
		return c.NoContent(http.StatusNoContent)
	})
}

// registerConditionalRoutes registers routes based on server configuration
func (r *Router) registerConditionalRoutes() error {
	// User info endpoint (requires authentication)
	log.Printf("[ROUTES] Registering user info endpoint...")
	r.echo.GET("/user/info", r.handlers.userController.GetUserInfo, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	r.echo.GET("/teams", r.handlers.teamConfigController.List, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	r.echo.POST("/teams", r.handlers.teamConfigController.Create, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
	r.echo.PATCH("/teams/:team", r.handlers.teamConfigController.Rename, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
	r.echo.DELETE("/teams/:team", r.handlers.teamConfigController.Delete, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
	r.echo.GET("/teams/:team/config", r.handlers.teamConfigController.Get, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
	r.echo.PUT("/teams/:team/config", r.handlers.teamConfigController.Update, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
	if r.handlers.teamMembershipController != nil {
		r.echo.GET("/teams/:team/members", r.handlers.teamMembershipController.Get, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/teams/:team/members/sync", r.handlers.teamMembershipController.Sync, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
	}
	log.Printf("[ROUTES] User info endpoint registered")

	// Add notification routes if service is available
	if r.server.notificationSvc != nil {
		log.Printf("[ROUTES] Registering notification endpoints...")
		// UI-compatible routes (proxied from agentapi-ui)
		r.echo.POST("/notification/subscribe", r.handlers.notificationHandlers.Subscribe, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/notification/subscribe", r.handlers.notificationHandlers.GetSubscriptions, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.DELETE("/notification/subscribe", r.handlers.notificationHandlers.DeleteSubscription, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))

		// Internal routes
		r.echo.POST("/notifications/webhook", r.handlers.notificationHandlers.Webhook, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/notifications/history", r.handlers.notificationHandlers.GetHistory, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/notifications/send", r.handlers.notificationHandlers.SendNotification, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		log.Printf("[ROUTES] Notification endpoints registered")
	} else {
		log.Printf("[ROUTES] Notification service not available, skipping notification routes")
	}

	// Add settings routes if settings repository is available (Kubernetes mode only)
	if r.server.settingsRepo != nil && r.handlers.settingsController != nil {
		log.Printf("[ROUTES] Registering settings endpoints...")
		r.echo.GET("/settings/managers", r.handlers.settingsController.GetAvailableManagers, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/settings/:name/secrets", r.handlers.settingsController.ListSecrets, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/settings/:name/secrets", r.handlers.settingsController.CreateSecret, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.PATCH("/settings/:name/secrets/:secretId", r.handlers.settingsController.UpdateSecret, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.PUT("/settings/:name/secrets/:secretId/values", r.handlers.settingsController.UpdateSecretValues, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.DELETE("/settings/:name/secrets/:secretId", r.handlers.settingsController.DeleteSecret, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/settings/:name", r.handlers.settingsController.GetSettings, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.PUT("/settings/:name", r.handlers.settingsController.UpdateSettings, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.DELETE("/settings/:name", r.handlers.settingsController.DeleteSettings, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		log.Printf("[ROUTES] Settings endpoints registered")
	} else {
		log.Printf("[ROUTES] Settings repository not available, skipping settings routes")
	}

	if r.handlers.adminSettingsController != nil {
		log.Printf("[ROUTES] Registering admin system settings endpoints...")
		r.echo.GET("/admin/system-settings", r.handlers.adminSettingsController.Get, auth.RequirePermission(entities.PermissionAdmin, r.server.container.AuthService))
		r.echo.GET("/admin/system-settings/versions", r.handlers.adminSettingsController.ListVersions, auth.RequirePermission(entities.PermissionAdmin, r.server.container.AuthService))
		r.echo.PUT("/admin/system-settings", r.handlers.adminSettingsController.Put, auth.RequirePermission(entities.PermissionAdmin, r.server.container.AuthService))
	}
	if r.handlers.adminLocalUserController != nil {
		admin := auth.RequirePermission(entities.PermissionAdmin, r.server.container.AuthService)
		c := r.handlers.adminLocalUserController
		r.echo.POST("/admin/users", c.Create, admin)
		r.echo.GET("/admin/users/:id", c.Get, admin)
		r.echo.POST("/admin/users/:id/api-tokens", c.CreateToken, admin)
		r.echo.GET("/admin/users/:id/api-tokens", c.ListTokens, admin)
		r.echo.DELETE("/admin/users/:id/api-tokens/:tokenId", c.DeleteToken, admin)
	}
	if r.handlers.githubConnectionsController != nil {
		admin := auth.RequirePermission(entities.PermissionAdmin, r.server.container.AuthService)
		read := auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService)
		write := auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService)
		controller := r.handlers.githubConnectionsController
		r.echo.GET("/github-connections/login-options", controller.ListLoginOptions)
		r.echo.POST("/github-connections/login", controller.StartLogin)
		r.echo.GET("/admin/github-connections", controller.List, admin)
		r.echo.POST("/admin/github-connections", controller.Create, admin)
		r.echo.GET("/admin/github-connections/:id", controller.Get, admin)
		r.echo.PATCH("/admin/github-connections/:id", controller.Update, admin)
		r.echo.DELETE("/admin/github-connections/:id", controller.Delete, admin)
		r.echo.PUT("/admin/github-connections/:id/secret", controller.UpdateSecret, admin)
		r.echo.DELETE("/admin/github-connections/:id/secret", controller.DeleteSecret, admin)
		r.echo.POST("/admin/github-connections/:id/test", controller.Test, admin)
		r.echo.PUT("/admin/github-connections/:id/github-app/private-key", controller.UpdateGitHubAppPrivateKey, admin)
		r.echo.DELETE("/admin/github-connections/:id/github-app/private-key", controller.DeleteGitHubAppPrivateKey, admin)
		r.echo.POST("/admin/github-connections/:id/github-app/test", controller.TestGitHubApp, admin)
		r.echo.DELETE("/admin/principals/:principalId", controller.DeletePrincipal, admin)
		r.echo.POST("/admin/principals/:principalId/repair", controller.RepairPrincipal, admin)
		r.echo.GET("/internal/sessions/:sessionId/github-credentials", controller.BrokerCredentials)
		r.echo.GET("/github-connections", controller.ListAvailable, read)
		r.echo.GET("/users/me/github-identities", controller.ListIdentities, read)
		r.echo.POST("/users/me/github-identities/link", controller.StartLink, write)
		r.echo.DELETE("/users/me/github-identities/:identity_id", controller.Unlink, write)
	}
	if r.handlers.googleConnectionsController != nil {
		admin := auth.RequirePermission(entities.PermissionAdmin, r.server.container.AuthService)
		read := auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService)
		write := auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService)
		controller := r.handlers.googleConnectionsController
		r.echo.GET("/google-connections/login-options", controller.ListLoginOptions)
		r.echo.POST("/google-connections/login", controller.StartLogin)
		r.echo.GET("/admin/google-connections", controller.List, admin)
		r.echo.POST("/admin/google-connections", controller.Create, admin)
		r.echo.GET("/admin/google-connections/:id", controller.Get, admin)
		r.echo.PATCH("/admin/google-connections/:id", controller.Update, admin)
		r.echo.DELETE("/admin/google-connections/:id", controller.Delete, admin)
		r.echo.PUT("/admin/google-connections/:id/secret", controller.UpdateSecret, admin)
		r.echo.DELETE("/admin/google-connections/:id/secret", controller.DeleteSecret, admin)
		r.echo.POST("/admin/google-connections/:id/test", controller.Test, admin)
		r.echo.GET("/google-connections", controller.ListAvailable, read)
		r.echo.GET("/users/me/google-identities", controller.ListIdentities, read)
		r.echo.POST("/users/me/google-identities/link", controller.StartLink, write)
		r.echo.DELETE("/users/me/google-identities/:identity_id", controller.Unlink, write)
	}
	if r.handlers.sessionPoolController != nil {
		admin := auth.RequirePermission(entities.PermissionAdmin, r.server.container.AuthService)
		poolRead := auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService)
		poolWrite := auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService)
		r.echo.POST("/session-managers/registration-tokens", r.handlers.sessionPoolController.IssueManagerRegistrationToken, poolWrite)
		r.echo.POST("/session-managers/enroll", r.handlers.sessionPoolController.EnrollManager)
		r.echo.GET("/session-managers", r.handlers.sessionPoolController.ListOwnedManagers, poolRead)
		r.echo.GET("/session-pools/status", r.handlers.sessionPoolController.ListManageablePoolStatus, poolRead)
		r.echo.GET("/session-managers/:id/logs", r.handlers.sessionPoolController.GetManagerLogs, poolRead)
		r.echo.GET("/session-runners/:id/logs", r.handlers.sessionPoolController.GetRunnerLogs, poolRead)
		r.echo.GET("/admin/session-runners", r.handlers.sessionPoolController.ListAdminRunners, admin)
		r.echo.GET("/admin/session-managers/:id/logs", r.handlers.sessionPoolController.GetAdminManagerLogs, admin)
		r.echo.GET("/admin/session-runners/:id/logs", r.handlers.sessionPoolController.GetAdminRunnerLogs, admin)
		r.echo.DELETE("/admin/session-runners/:id", r.handlers.sessionPoolController.DeleteAdminRunner, admin)
		r.echo.GET("/session-managers/:id", r.handlers.sessionPoolController.GetOwnedManager, poolRead)
		r.echo.PATCH("/session-managers/:id", r.handlers.sessionPoolController.PatchOwnedManager, poolWrite)
		r.echo.DELETE("/session-managers/:id", r.handlers.sessionPoolController.DeleteOwnedManager, poolWrite)
		r.echo.POST("/session-managers/:id/registration-token", r.handlers.sessionPoolController.RotateManagerRegistrationToken, poolWrite)
		r.echo.POST("/session-pools", r.handlers.sessionPoolController.CreateLogicalPool, poolWrite)
		r.echo.GET("/session-pools", r.handlers.sessionPoolController.ListPools, poolRead)
		r.echo.PATCH("/session-pools/:pool", r.handlers.sessionPoolController.PatchLogicalPool, poolWrite)
		r.echo.DELETE("/session-pools/:pool", r.handlers.sessionPoolController.DeleteLogicalPool, poolWrite)
		r.echo.POST("/session-pools/:pool/bindings", r.handlers.sessionPoolController.CreateBinding, poolWrite)
		r.echo.GET("/session-pools/:pool/bindings", r.handlers.sessionPoolController.ListBindings, poolRead)
		r.echo.PATCH("/session-pools/:pool/bindings/:bindingId", r.handlers.sessionPoolController.PatchBinding, poolWrite)
		r.echo.DELETE("/session-pools/:pool/bindings/:bindingId", r.handlers.sessionPoolController.DeleteBinding, poolWrite)
		r.echo.POST("/session-pools/:pool/suppliers/:id", r.handlers.sessionPoolController.CreatePoolSupplier, poolWrite)
		r.echo.GET("/session-pools/:pool/suppliers", r.handlers.sessionPoolController.ListPoolSuppliers, poolRead)
		r.echo.PATCH("/session-pools/:pool/suppliers/:id", r.handlers.sessionPoolController.PatchPoolSupplier, poolWrite)
		r.echo.DELETE("/session-pools/:pool/suppliers/:id", r.handlers.sessionPoolController.DeletePoolSupplier, poolWrite)
	}

	if r.handlers.googleOAuthController != nil {
		log.Printf("[ROUTES] Registering scia integration endpoints...")
		r.echo.GET("/integrations", r.handlers.googleOAuthController.GetIntegrations, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/integrations/:id/authorization-url", r.handlers.googleOAuthController.CreateAuthorizationURL, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/integrations/:id/revoke", r.handlers.googleOAuthController.RevokeIntegration, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/integrations/google-oauth/status", r.handlers.googleOAuthController.GetStatus, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		log.Printf("[ROUTES] scia integration endpoints registered")
	}

	// Add credentials routes if credentials repository is available (Kubernetes mode only)
	if r.server.credentialsRepo != nil && r.handlers.credentialsController != nil {
		log.Printf("[ROUTES] Registering credentials endpoints...")
		r.echo.GET("/credentials/:name", r.handlers.credentialsController.GetCredentials, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.PUT("/credentials/:name", r.handlers.credentialsController.UploadCredentials, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.DELETE("/credentials/:name", r.handlers.credentialsController.DeleteCredentials, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		log.Printf("[ROUTES] Credentials endpoints registered")
	} else {
		log.Printf("[ROUTES] Credentials repository not available, skipping credentials routes")
	}

	// Add Codex device auth routes (requires credentials repo)
	if r.handlers.codexDeviceAuthController != nil {
		log.Printf("[ROUTES] Registering Codex device auth endpoints...")
		r.echo.GET("/codex/device-auth/config", r.handlers.codexDeviceAuthController.GetConfig, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/codex/device-auth", r.handlers.codexDeviceAuthController.StartDeviceAuth, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.POST("/codex/device-auth/token", r.handlers.codexDeviceAuthController.PollDeviceAuth, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/codex/device-auth/:attemptId", r.handlers.codexDeviceAuthController.GetAttempt, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.DELETE("/codex/device-auth/:attemptId", r.handlers.codexDeviceAuthController.CancelAttempt, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.POST("/internal/codex-device-auth/:attemptId/challenge", r.handlers.codexDeviceAuthController.ReportChallenge)
		r.echo.POST("/internal/codex-device-auth/:attemptId/result", r.handlers.codexDeviceAuthController.ReportResult)
		log.Printf("[ROUTES] Codex device auth endpoints registered")
	}

	// Add personal API key routes if controller is available (Kubernetes mode only)
	if r.handlers.personalAPIKeyController != nil {
		log.Printf("[ROUTES] Registering personal API key endpoints...")
		r.echo.GET("/users/me/api-key", r.handlers.personalAPIKeyController.GetPersonalAPIKeyMetadata, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/users/me/api-key", r.handlers.personalAPIKeyController.GetOrCreatePersonalAPIKey, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		log.Printf("[ROUTES] Personal API key endpoints registered")
	} else {
		log.Printf("[ROUTES] Personal API key controller not available, skipping personal API key routes")
	}

	// Unified multi API token endpoints (list/create/get/delete). Available
	// in Kubernetes mode only, where the API token repository is initialized.
	if r.handlers.apiTokenController != nil {
		log.Printf("[ROUTES] Registering API token endpoints...")
		r.echo.GET("/api-tokens", r.handlers.apiTokenController.List, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/api-tokens", r.handlers.apiTokenController.Create, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/api-tokens/:tokenId", r.handlers.apiTokenController.Get, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.DELETE("/api-tokens/:tokenId", r.handlers.apiTokenController.Delete, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		log.Printf("[ROUTES] API token endpoints registered")
	} else {
		log.Printf("[ROUTES] API token controller not available, skipping API token routes")
	}

	// Add sandbox policy routes if sandbox policy repository is available (Kubernetes mode only)
	if r.server.sandboxPolicyRepo != nil && r.handlers.sandboxPolicyController != nil {
		log.Printf("[ROUTES] Registering sandbox policy endpoints...")
		r.echo.POST("/sandbox-policies", r.handlers.sandboxPolicyController.CreateSandboxPolicy, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/sandbox-policies", r.handlers.sandboxPolicyController.ListSandboxPolicies, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/sandbox-policies/:id", r.handlers.sandboxPolicyController.GetSandboxPolicy, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/sandbox-policies/:id/domains", r.handlers.sandboxPolicyController.GetSandboxPolicyDomains, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.PUT("/sandbox-policies/:id/domains/ignored", r.handlers.sandboxPolicyController.UpdateIgnoredDomains, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.PUT("/sandbox-policies/:id", r.handlers.sandboxPolicyController.UpdateSandboxPolicy, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.DELETE("/sandbox-policies/:id", r.handlers.sandboxPolicyController.DeleteSandboxPolicy, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		log.Printf("[ROUTES] Sandbox policy endpoints registered")
	} else {
		log.Printf("[ROUTES] Sandbox policy repository not available, skipping sandbox policy routes")
	}

	if r.server.storageRepo != nil && r.handlers.storageController != nil {
		log.Printf("[ROUTES] Registering storage endpoints...")
		r.echo.POST("/storages", r.handlers.storageController.Create, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/storages", r.handlers.storageController.List, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/storages/:id", r.handlers.storageController.Get, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.PATCH("/storages/:id", r.handlers.storageController.Update, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.DELETE("/storages/:id", r.handlers.storageController.Delete, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/storages/:id/files", r.handlers.storageController.ListFiles, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.PUT("/storages/:id/files/*", r.handlers.storageController.PutFile, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/storages/:id/files/*", r.handlers.storageController.GetFile, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.DELETE("/storages/:id/files/*", r.handlers.storageController.DeleteFile, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		log.Printf("[ROUTES] Storage endpoints registered")
	}

	// Add file routes if user file repository is available (Kubernetes mode only)
	if r.server.userFileRepo != nil && r.handlers.fileController != nil {
		log.Printf("[ROUTES] Registering user file endpoints...")
		r.echo.POST("/files", r.handlers.fileController.CreateFile, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/files", r.handlers.fileController.ListFiles, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/files/:fileId", r.handlers.fileController.GetFile, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.PUT("/files/:fileId", r.handlers.fileController.UpdateFile, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.DELETE("/files/:fileId", r.handlers.fileController.DeleteFile, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		log.Printf("[ROUTES] User file endpoints registered")
	} else {
		log.Printf("[ROUTES] User file repository not available, skipping file routes")
	}

	// Add session profile routes if session profile repository is available (Kubernetes mode only)
	if r.server.sessionProfileRepo != nil && r.handlers.sessionProfileController != nil {
		log.Printf("[ROUTES] Registering session profile endpoints...")
		r.echo.POST("/session-profiles", r.handlers.sessionProfileController.CreateSessionProfile, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.GET("/session-profiles", r.handlers.sessionProfileController.ListSessionProfiles, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.POST("/session-profiles/preview", r.handlers.sessionProfileController.PreviewSessionProfile, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.GET("/session-profiles/:id", r.handlers.sessionProfileController.GetSessionProfile, auth.RequirePermission(entities.PermissionSessionRead, r.server.container.AuthService))
		r.echo.PUT("/session-profiles/:id", r.handlers.sessionProfileController.UpdateSessionProfile, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		r.echo.DELETE("/session-profiles/:id", r.handlers.sessionProfileController.DeleteSessionProfile, auth.RequirePermission(entities.PermissionSessionCreate, r.server.container.AuthService))
		log.Printf("[ROUTES] Session profile endpoints registered")
	} else {
		log.Printf("[ROUTES] Session profile repository not available, skipping session profile routes")
	}

	return nil
}

// registerCustomHandlers registers all custom handlers
func (r *Router) registerCustomHandlers() error {
	for _, handler := range r.handlers.customHandlers {
		log.Printf("[ROUTES] Registering custom handler: %s", handler.GetName())
		if err := handler.RegisterRoutes(r.echo); err != nil {
			log.Printf("[ROUTES] Failed to register custom handler %s: %v", handler.GetName(), err)
			return err
		}
		log.Printf("[ROUTES] Successfully registered custom handler: %s", handler.GetName())
	}

	return nil
}

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
	"github.com/takutakahashi/agentapi-proxy/internal/core/esmcontrol"
	corerepo "github.com/takutakahashi/agentapi-proxy/internal/core/repository"
	"github.com/takutakahashi/agentapi-proxy/internal/core/sessioncontrol"
	sessionrunnercore "github.com/takutakahashi/agentapi-proxy/internal/core/sessionrunner"
	"github.com/takutakahashi/agentapi-proxy/internal/di"
	"github.com/takutakahashi/agentapi-proxy/internal/domain/entities"
	infraesmcontrol "github.com/takutakahashi/agentapi-proxy/internal/infrastructure/esmcontrol"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/kvstore"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/repositories"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/services"
	infrasessioncontrol "github.com/takutakahashi/agentapi-proxy/internal/infrastructure/sessioncontrol"
	"github.com/takutakahashi/agentapi-proxy/internal/infrastructure/sessionmanagerapi"
	infrasessionrunner "github.com/takutakahashi/agentapi-proxy/internal/infrastructure/sessionrunner"
	"github.com/takutakahashi/agentapi-proxy/internal/modules/schedule"
	"github.com/takutakahashi/agentapi-proxy/internal/modules/sessioncount"
	"github.com/takutakahashi/agentapi-proxy/internal/runtimeconfig"
	personalapikeyuc "github.com/takutakahashi/agentapi-proxy/internal/usecases/personal_api_key"
	portrepos "github.com/takutakahashi/agentapi-proxy/internal/usecases/ports/repositories"
	serviceaccountuc "github.com/takutakahashi/agentapi-proxy/internal/usecases/service_account"
	sessionuc "github.com/takutakahashi/agentapi-proxy/internal/usecases/session"
	"github.com/takutakahashi/agentapi-proxy/internal/usecases/task"
	"github.com/takutakahashi/agentapi-proxy/pkg/auth"
	"github.com/takutakahashi/agentapi-proxy/pkg/codexauth"
	"github.com/takutakahashi/agentapi-proxy/pkg/config"
	"github.com/takutakahashi/agentapi-proxy/pkg/logger"
	"github.com/takutakahashi/agentapi-proxy/pkg/notification"
	"github.com/takutakahashi/agentapi-proxy/pkg/sessionsettings"
	"github.com/takutakahashi/agentapi-proxy/pkg/telemetry"
	"github.com/takutakahashi/agentapi-proxy/pkg/urlutil"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

// Server represents the HTTP server
type Server struct {
	config                      *config.Config
	configProvider              *runtimeconfig.Provider
	runtimeConfigCancel         context.CancelFunc
	echo                        *echo.Echo
	verbose                     bool
	logger                      *logger.Logger
	oauthProvider               *auth.GitHubOAuthProvider
	oauthSessions               sync.Map // sessionID -> OAuthSession
	notificationSvc             *notification.Service
	container                   *di.Container            // Internal DI container
	sessionManager              portrepos.SessionManager // Session lifecycle manager
	codexDeviceAuthLauncher     codexauth.WorkloadLauncher
	persistenceClient           kubernetes.Interface // Secret/ConfigMap client for non-session application data
	kvStore                     kvstore.Store        // non-nil when persistenceClient is backed by libSQL
	usageRepo                   portrepos.UsageRepository
	sessionCountRepo            portrepos.SessionCountRepository
	sessionCountWorker          *sessioncount.Worker
	sessionCountWorkers         sync.WaitGroup
	sessionCountCancel          context.CancelFunc
	settingsRepo                portrepos.SettingsRepository                    // Settings repository
	credentialsRepo             portrepos.CredentialsRepository                 // Credentials repository
	shareRepo                   portrepos.ShareRepository                       // Share repository for session sharing
	teamConfigRepo              portrepos.TeamConfigRepository                  // Team configuration repository
	sandboxPolicyRepo           portrepos.SandboxPolicyRepository               // Sandbox policy repository
	storageRepo                 portrepos.StorageRepository                     // Scoped persistent storage metadata
	storageObjectStore          services.StorageObjectStore                     // Immutable object_snapshot blobs
	sandboxDomainRepo           *repositories.KubernetesSandboxDomainRepository // Sandbox domain log repository
	sessionRouteRepo            portrepos.SessionRouteRepository                // Session route repository for External Session Manager routing
	sessionRunnerStore          sessionrunnercore.Store                         // Cluster-wide managers, pools, bindings, runners and pool allocations
	sessionAllocationNotifier   sessionrunnercore.AllocationNotifier            // Wakes long-polling runners when durable allocations are created
	sessionAllocationRedis      *redis.Client
	routeStatusBus              portrepos.RouteStatusEventBus
	routeStatusCancel           context.CancelFunc
	userFileRepo                portrepos.UserFileRepository       // User-managed files repository
	sessionProfileRepo          portrepos.SessionProfileRepository // Session profile repository
	contextTemplateRepo         portrepos.SessionContextTemplateRepository
	scheduleManager             schedule.Manager
	apiTokenRepo                portrepos.APITokenRepository // Named API token repository
	localUserRepo               portrepos.LocalUserRepository
	apiTokenDeps                *apiTokenInitDeps // Wiring for bootstrap/reconcile
	sessionStateStore           services.SessionStateStore
	sessionControlStore         sessioncontrol.Store
	esmControlStore             esmcontrol.Store
	esmControlTunnel            *infraesmcontrol.Tunnel
	directSessionRuntimeEnabled bool
	localSessionFallbackEnabled bool
	namespace                   string
	personalAPIKeyRepo          portrepos.PersonalAPIKeyRepository
	router                      *Router // Router for custom handler registration
}

// NewServer creates a new server instance
func NewServer(cfg *config.Config, verbose bool) *Server {
	e := echo.New()

	// Disable Echo's default logger and use custom logging
	e.Logger.SetOutput(io.Discard)

	// Create server spans and HTTP RED metrics. Health probes are excluded to
	// avoid high-volume, low-value telemetry.
	e.Use(otelecho.Middleware("agentapi-proxy", otelecho.WithSkipper(func(c echo.Context) bool {
		switch c.Path() {
		case "/health", "/healthz", "/ready", "/readyz":
			return true
		default:
			return false
		}
	})))

	// Rewrite %2F in URL paths before route matching so that settings names
	// containing slashes (e.g. "org/team-slug") are routed correctly.
	e.Pre(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rawPath := c.Request().URL.RawPath
			if rawPath != "" {
				if rewritten, ok := urlutil.RewriteEncodedSlashes(rawPath); ok {
					c.Request().URL.Path = rewritten
					c.Request().URL.RawPath = rewritten
				}
			}
			return next(c)
		}
	})

	// Add recovery middleware
	e.Use(middleware.Recover())

	// Add security headers middleware
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		HSTSMaxAge:            31536000, // 1 year
		HSTSExcludeSubdomains: false,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}))

	// Add CORS middleware with secure configuration (only for non-proxy routes)
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		Skipper: func(c echo.Context) bool {
			// Skip CORS middleware only for proxy routes (/:sessionId/* pattern)
			// These routes handle CORS manually in the proxy
			path := c.Request().URL.Path
			pathParts := strings.Split(path, "/")
			// Skip CORS for shared session routes (/s/:shareToken/*)
			if len(pathParts) >= 3 && pathParts[1] == "s" {
				return true
			}
			// Skip CORS only for proxy routes that match /:sessionId/* pattern
			// (at least 3 parts, not starting with "start", "search", "sessions", "oauth", "auth", "notification", or "notifications")
			if len(pathParts) >= 3 && pathParts[1] != "" {
				firstSegment := pathParts[1]
				return firstSegment != "start" && firstSegment != "search" && firstSegment != "sessions" && firstSegment != "oauth" && firstSegment != "auth" && firstSegment != "notification" && firstSegment != "notifications" && firstSegment != "credentials" && firstSegment != "files" && firstSegment != "storages" && firstSegment != "session-profiles" && firstSegment != "sandbox-policies" && firstSegment != "integrations"
			}
			return false
		},
		AllowOriginFunc: func(origin string) (bool, error) {
			// Get allowed origins from environment variable
			allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
			if allowedOrigins == "" {
				// Fallback to localhost for development
				allowed := strings.HasPrefix(origin, "http://localhost") ||
					strings.HasPrefix(origin, "https://localhost") ||
					strings.HasPrefix(origin, "http://127.0.0.1") ||
					strings.HasPrefix(origin, "https://127.0.0.1")
				return allowed, nil
			}
			// Parse comma-separated allowed origins
			origins := strings.Split(allowedOrigins, ",")
			for _, allowed := range origins {
				if strings.TrimSpace(allowed) == origin {
					return true, nil
				}
			}
			return false, nil
		},
		AllowMethods:     []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, "X-Requested-With", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-API-Key", "Acp-Session-Id"},
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	// Initialize internal DI container
	container := di.NewContainer()

	// Initialize logger
	lgr := logger.NewLogger()

	// Compose the public API against the private session-manager API whenever it
	// is configured. In this mode the API receives no Kubernetes client or
	// ServiceAccount token; its Kubernetes-shaped repositories are backed only by
	// libSQL through the compatibility adapter.
	var settingsRepo portrepos.SettingsRepository
	var shareRepo portrepos.ShareRepository
	namespace := resolveApplicationNamespace(cfg.KVStore.Namespace)
	var k8sSessionManager *services.KubernetesSessionManager
	var remoteSessionManager *sessionmanagerapi.Client
	var sessionManager portrepos.SessionManager
	var persistenceClient kubernetes.Interface
	var applicationKVStore kvstore.Store
	var codexDeviceAuthLauncher codexauth.WorkloadLauncher
	var err error
	if cfg.SessionManager.APIURL != "" {
		if err := validateAPIKVStore(cfg.KVStore); err != nil {
			log.Fatalf("[SERVER] Invalid API KV persistence: %v", err)
		}
		remoteManager, clientErr := sessionmanagerapi.NewClient(cfg.SessionManager.APIURL, cfg.SessionManager.APIToken)
		if clientErr != nil {
			log.Fatalf("[SERVER] Failed to initialize session-manager client: %v", clientErr)
		}
		// Do not make API startup depend on session-manager readiness. The
		// in-cluster manager may itself register with this API during startup, so
		// waiting here creates a circular dependency during simultaneous rollouts.
		// Requests that need the manager surface the client error until it becomes
		// available.
		sessionManager = remoteManager
		remoteSessionManager = remoteManager
		var apiKVClient kubernetes.Interface = fake.NewSimpleClientset()
		if configuredKVBackend(cfg.KVStore) == "kubernetes" {
			restConfig, configErr := ctrlconfig.GetConfig()
			if configErr != nil {
				log.Fatalf("[SERVER] Failed to get Kubernetes config for API KV store: %v", configErr)
			}
			client, clientErr := kubernetes.NewForConfig(restConfig)
			if clientErr != nil {
				log.Fatalf("[SERVER] Failed to create Kubernetes client for API KV store: %v", clientErr)
			}
			apiKVClient = client
		}
		var wrapPersistence bool
		applicationKVStore, wrapPersistence, err = buildApplicationKVStore(cfg.KVStore, apiKVClient)
		if err != nil {
			log.Fatalf("[SERVER] Failed to initialize API KV store: %v", err)
		}
		persistenceClient = apiKVClient
		if wrapPersistence {
			persistenceClient = kvstore.NewKubernetesAdapter(apiKVClient, applicationKVStore)
		}
		log.Printf("[SERVER] Public API connected to isolated session manager: %s", cfg.SessionManager.APIURL)
	} else {
		// Legacy/test composition remains available for local development. The
		// production chart always supplies session_manager.api_url.
		log.Printf("[SERVER] Initializing legacy in-process Kubernetes session manager")
		k8sSessionManager, err = services.NewKubernetesSessionManager(cfg, verbose, lgr)
		if err != nil {
			log.Printf("[SERVER] Kubernetes config not available, using fake client: %v", err)
			k8sSessionManager, err = services.NewKubernetesSessionManagerWithClient(cfg, verbose, lgr, fake.NewSimpleClientset())
			if err != nil {
				log.Fatalf("[SERVER] Failed to initialize session manager with fake client: %v", err)
			}
		}
		sessionManager = k8sSessionManager
		// The session manager namespace is only a fallback for application data.
		// Keep an explicit runtime KV namespace authoritative in legacy/native
		// composition as well as in the isolated session-manager composition.
		namespace = resolveApplicationNamespace(k8sSessionManager.GetNamespace())
		persistenceClient = k8sSessionManager.GetClient()
		var wrapPersistence bool
		applicationKVStore, wrapPersistence, err = buildApplicationKVStore(cfg.KVStore, persistenceClient)
		if err != nil {
			log.Fatalf("Failed to initialize application KV store: %v", err)
		}
		if wrapPersistence {
			persistenceClient = kvstore.NewKubernetesAdapter(persistenceClient, applicationKVStore)
		}
	}
	if backend := configuredKVBackend(cfg.KVStore); backend == "libsql" || backend == "libsql-encrypted" {
		destinationName := cfg.KubernetesSession.SettingsBaseSecret
		if destinationName == "" {
			destinationName = "agentapi-settings-base"
		}
		var changed bool
		var backfillErr error
		if sourceFile := strings.TrimSpace(cfg.KubernetesSession.MCPServersBaseFile); sourceFile != "" {
			legacyData, readErr := os.ReadFile(sourceFile)
			switch {
			case readErr == nil:
				changed, backfillErr = backfillLegacyMCPServersBaseData(
					context.Background(), persistenceClient, namespace,
					cfg.KubernetesSession.MCPServersBaseSecret, destinationName, legacyData,
				)
			case !errors.Is(readErr, os.ErrNotExist):
				backfillErr = fmt.Errorf("read mounted legacy MCP base settings: %w", readErr)
			default:
				changed, backfillErr = backfillLegacyMCPServersBase(
					context.Background(), persistenceClient, namespace,
					cfg.KubernetesSession.MCPServersBaseSecret, destinationName,
				)
			}
		} else {
			changed, backfillErr = backfillLegacyMCPServersBase(
				context.Background(), persistenceClient, namespace,
				cfg.KubernetesSession.MCPServersBaseSecret, destinationName,
			)
		}
		if backfillErr != nil {
			log.Fatalf("[SERVER] Failed to backfill legacy MCP base settings: %v", backfillErr)
		}
		// Helm historically rendered an empty settings base name to disable the
		// unified base. When migration material is present, enable the canonical
		// destination so this and later starts use the normal settings path.
		if cfg.KubernetesSession.SettingsBaseSecret == "" {
			if _, getErr := persistenceClient.CoreV1().Secrets(namespace).Get(context.Background(), destinationName, metav1.GetOptions{}); getErr == nil {
				cfg.KubernetesSession.SettingsBaseSecret = destinationName
			} else if !apierrors.IsNotFound(getErr) {
				log.Fatalf("[SERVER] Failed to verify backfilled MCP base settings: %v", getErr)
			}
		}
		if changed {
			log.Printf("[SERVER] Backfilled legacy MCP base settings into %s", destinationName)
		}
	}
	runtimeProvider := runtimeconfig.New(cfg, applicationKVStore, namespace)
	if err := runtimeProvider.Reload(context.Background()); err != nil {
		log.Printf("[RUNTIME_CONFIG] Failed to load versioned settings; using startup configuration: %v", err)
	} else if runtimeProvider.Version() > 0 {
		cfg = runtimeProvider.Current()
		log.Printf("[RUNTIME_CONFIG] Loaded system settings version %d", runtimeProvider.Version())
	}
	if k8sSessionManager != nil {
		k8sSessionManager.SetConfigProvider(runtimeProvider)
	}
	runtimeConfigCtx, runtimeConfigCancel := context.WithCancel(context.Background())
	runtimeProvider.Start(runtimeConfigCtx, 30*time.Second, func(err error) { log.Printf("[RUNTIME_CONFIG] Reload failed: %v", err) })
	sessionAllocationNotifier, sessionAllocationRedis := buildSessionAllocationNotifier(cfg)
	var usageRepo portrepos.UsageRepository
	if cfg.Usage.Enabled {
		usageRepo, err = repositories.NewLibSQLUsageRepository(context.Background(), cfg.Usage.DatabaseURL, cfg.Usage.AuthToken)
		if err != nil {
			log.Fatalf("Failed to initialize usage store: %v", err)
		}
		log.Printf("[SERVER] Usage persistence initialized")
	}
	var sessionCountRepo portrepos.SessionCountRepository
	if cfg.SessionCount.Enabled {
		sessionCountRepo, err = repositories.NewSessionCountRepository(context.Background(), cfg.SessionCount.Backend, cfg.SessionCount.DatabaseURL, cfg.SessionCount.AuthToken)
		if err != nil {
			log.Fatalf("Failed to initialize session count store: %v", err)
		}
		log.Printf("[SERVER] Session count persistence initialized with backend %s", cfg.SessionCount.Backend)
	}

	// Initialize cross-pod status synchronisation via Redis (optional).
	// When Redis is not configured a no-op fallback is used transparently.
	statusEventRepo := buildStatusEventRepository(cfg)
	routeStatusBus, _ := statusEventRepo.(portrepos.RouteStatusEventBus)
	if k8sSessionManager != nil {
		k8sSessionManager.SetStatusEventRepository(statusEventRepo)
		if listCacheRepo, ok := statusEventRepo.(portrepos.SessionListCacheRepository); ok {
			k8sSessionManager.SetSessionListCacheRepository(listCacheRepo)
		}
	}

	// Initialize encryption service registry
	// The registry manages multiple encryption services and selects the appropriate one
	// based on encryption metadata when decrypting
	encryptionFactory := services.NewEncryptionServiceFactory("AGENTAPI_ENCRYPTION")
	primaryService, err := encryptionFactory.Create()
	if err != nil {
		log.Fatalf("Failed to create primary encryption service: %v", err)
	}

	// Create registry with primary service (used for encryption)
	encryptionRegistry := services.NewEncryptionServiceRegistry(primaryService)

	// Register Noop service for backward compatibility with plaintext data
	// This allows reading old unencrypted data
	noopService := services.NewNoopEncryptionService()
	encryptionRegistry.Register(noopService)

	// Try to register additional services for migration scenarios
	// These are optional and will be used for decryption if data was encrypted with them

	// Try to create a local encryption service (if different from primary)
	localFactory := services.NewEncryptionServiceFactory("AGENTAPI_DECRYPTION")
	if localService, err := localFactory.Create(); err == nil {
		// Only register if it's different from primary
		if localService.Algorithm() != primaryService.Algorithm() || localService.KeyID() != primaryService.KeyID() {
			encryptionRegistry.Register(localService)
		}
	}

	log.Printf("[SERVER] Encryption registry initialized with primary: %s (keyID: %s)",
		primaryService.Algorithm(), primaryService.KeyID())

	// Initialize settings repository
	settingsRepo = repositories.NewKubernetesSettingsRepository(
		persistenceClient,
		namespace,
		encryptionRegistry,
	)
	// Set settings repository in session manager for Bedrock integration
	if k8sSessionManager != nil {
		k8sSessionManager.SetSettingsRepository(settingsRepo)
		k8sSessionManager.SetSlackTokenClient(persistenceClient, namespace)
	}
	log.Printf("[SERVER] Settings repository initialized")

	// Initialize credentials repository
	credentialsRepo := portrepos.CredentialsRepository(repositories.NewKubernetesCredentialsRepository(
		persistenceClient,
		namespace,
	))
	log.Printf("[SERVER] Credentials repository initialized")

	// Wire the credentials repository into the session manager so that managed
	// credential files (Codex auth.json, Claude .credentials.json) are read from
	// the application KV store when embedding files into session pods.
	if k8sSessionManager != nil {
		k8sSessionManager.SetCredentialsRepository(credentialsRepo)
	}
	// Initialize share repository
	shareRepo = repositories.NewKubernetesShareRepository(
		persistenceClient,
		namespace,
	)
	log.Printf("[SERVER] Share repository initialized")

	// Initialize team config repository
	teamConfigRepo := repositories.NewKubernetesTeamConfigRepository(
		persistenceClient,
		namespace,
	)
	if simpleAuth, ok := container.AuthService.(*services.SimpleAuthService); ok {
		simpleAuth.SetTeamMembershipResolver(teamConfigRepo, cfg.TeamDiscovery)
	}
	// Set team config repository in session manager for service account integration
	if k8sSessionManager != nil {
		k8sSessionManager.SetTeamConfigRepository(teamConfigRepo)
	}
	log.Printf("[SERVER] Team config repository initialized")

	// Initialize personal API key repository
	personalAPIKeyRepo := repositories.NewKubernetesPersonalAPIKeyRepository(
		persistenceClient,
		namespace,
	)
	// Set personal API key repository in session manager
	if k8sSessionManager != nil {
		k8sSessionManager.SetPersonalAPIKeyRepository(personalAPIKeyRepo)
	}
	log.Printf("[SERVER] Personal API key repository initialized")

	// Initialize the named API token repository (multi-token CRUD). It is
	// backed by one Kubernetes Secret per token.
	apiTokenRepo := repositories.NewKubernetesAPITokenRepository(
		persistenceClient,
		namespace,
	)
	log.Printf("[SERVER] API token repository initialized")
	localUserRepo := repositories.NewKubernetesLocalUserRepository(persistenceClient, namespace)
	log.Printf("[SERVER] Local user repository initialized")

	// Initialize sandbox policy repository (Kubernetes ConfigMap-backed)
	sandboxPolicyRepo := portrepos.SandboxPolicyRepository(repositories.NewKubernetesSandboxPolicyRepository(
		persistenceClient,
		namespace,
	))
	if k8sSessionManager != nil {
		k8sSessionManager.SetSandboxPolicyRepository(sandboxPolicyRepo)
	}
	log.Printf("[SERVER] Sandbox policy repository initialized")
	storageRepo := portrepos.StorageRepository(repositories.NewKubernetesStorageRepository(
		persistenceClient,
		namespace,
	))
	log.Printf("[SERVER] Storage repository initialized")

	// Initialize sandbox domain repository (Kubernetes ConfigMap-backed)
	sandboxDomainRepo := repositories.NewKubernetesSandboxDomainRepository(
		persistenceClient,
		namespace,
	)
	log.Printf("[SERVER] Sandbox domain repository initialized")

	// Initialize session route repository (Kubernetes Secret-backed)
	sessionRouteRepo := repositories.NewKubernetesSessionRouteRepository(
		persistenceClient,
		namespace,
	)
	log.Printf("[SERVER] Session route repository initialized")
	sessionRunnerKVStore := applicationKVStore
	if sessionRunnerKVStore == nil {
		sessionRunnerKVStore = kvstore.NewKubernetesStore(persistenceClient)
	}
	sessionRunnerStore := infrasessionrunner.NewStore(sessionRunnerKVStore, namespace)
	log.Printf("[SERVER] Session runner pool repository initialized")
	startBuiltInSessionManagerReconciler(runtimeConfigCtx, sessionRunnerStore, cfg)

	// Initialize user file repository (Kubernetes Secret-backed)
	userFileRepo := portrepos.UserFileRepository(repositories.NewKubernetesUserFileRepository(
		persistenceClient,
		namespace,
	))
	if k8sSessionManager != nil {
		k8sSessionManager.SetUserFileRepository(userFileRepo)
	}
	log.Printf("[SERVER] User file repository initialized")

	// Initialize session profile repository (Kubernetes Secret-backed)
	sessionProfileRepo := portrepos.SessionProfileRepository(repositories.NewKubernetesSessionProfileRepository(
		persistenceClient,
		namespace, encryptionRegistry,
	))
	contextTemplateRepo := portrepos.SessionContextTemplateRepository(repositories.NewKubernetesSessionContextTemplateRepository(persistenceClient, namespace))
	if k8sSessionManager != nil {
		k8sSessionManager.SetSessionProfileRepository(sessionProfileRepo)
	}
	if remoteSessionManager != nil {
		// The API owns persistence encryption. Build the complete ephemeral
		// provision payload here and send it to the isolated session manager;
		// the manager never receives encryption keys or decrypts stored records.
		settingsBuilder, builderErr := services.NewKubernetesSessionManagerWithClient(cfg, false, lgr, fake.NewSimpleClientset())
		if builderErr != nil {
			log.Fatalf("[SERVER] Failed to initialize API-side provision settings builder: %v", builderErr)
		}
		settingsBuilder.SetSettingsRepository(settingsRepo)
		settingsBuilder.SetSettingsSecretClient(persistenceClient, namespace)
		settingsBuilder.SetSlackTokenClient(persistenceClient, namespace)
		settingsBuilder.SetCredentialsRepository(credentialsRepo)
		settingsBuilder.SetTeamConfigRepository(teamConfigRepo)
		settingsBuilder.SetPersonalAPIKeyRepository(personalAPIKeyRepo)
		settingsBuilder.SetSandboxPolicyRepository(sandboxPolicyRepo)
		settingsBuilder.SetUserFileRepository(userFileRepo)
		settingsBuilder.SetSessionProfileRepository(sessionProfileRepo)
		remoteSessionManager.SetProvisionSettingsBuilder(settingsBuilder)
	}
	log.Printf("[SERVER] Session profile repository initialized")

	sessionStateStore, err := services.NewSessionStateStore(context.Background(), cfg.SessionPersistence)
	if err != nil {
		if cfg.SessionPersistence.Backend != "s3" {
			log.Fatalf("[SERVER] Failed to initialize session state store: %v", err)
		}
		log.Printf("[SERVER] Session persistence disabled because S3 store initialization failed: %v", err)
		sessionStateStore = nil
	}
	storageObjectStore, err := services.NewStorageObjectStore(context.Background(), cfg.SessionPersistence.S3)
	if err != nil {
		log.Printf("[SERVER] Object-backed storage disabled because S3 store initialization failed: %v", err)
		storageObjectStore = nil
	}

	var sessionControlStore sessioncontrol.Store
	var esmControlStore esmcontrol.Store
	var esmControlTunnel *infraesmcontrol.Tunnel
	sessionControlStore = buildSessionControlStore(cfg)
	if sessionControlStore != nil && k8sSessionManager != nil {
		k8sSessionManager.SetSessionControlStore(sessionControlStore)
	}
	esmControlStore = buildESMControlStore(cfg)
	if esmControlStore != nil {
		esmControlTunnel = infraesmcontrol.NewTunnel(esmControlStore)
	}
	localSessionFallbackEnabled := !strings.EqualFold(os.Getenv("AGENTAPI_LOCAL_SESSION_FALLBACK_ENABLED"), "false")
	// Codex device auth workloads always run on a session manager's execution
	// plane, never inside the API process (whose Kubernetes client may be a
	// fake in compositions without cluster access). Route every attempt to an
	// enrolled, connected external session manager over the outbound control
	// tunnel; the manager creates the short-lived authentication Pod.
	var localCodexAuthLauncher codexauth.WorkloadLauncher
	if localSessionFallbackEnabled && k8sSessionManager != nil {
		localCodexAuthLauncher = k8sSessionManager
	}
	if sessionRunnerStore != nil && (esmControlTunnel != nil || localCodexAuthLauncher != nil) {
		codexDeviceAuthLauncher = infraesmcontrol.NewCodexDeviceAuthLauncher(esmControlTunnel, sessionRunnerStore, localCodexAuthLauncher)
		log.Printf("[SERVER] Codex device auth workloads use authorized session routes")
	}
	scheduleManager := schedule.NewKubernetesManager(persistenceClient, namespace)

	s := &Server{
		config:                      cfg,
		configProvider:              runtimeProvider,
		runtimeConfigCancel:         runtimeConfigCancel,
		echo:                        e,
		verbose:                     verbose,
		logger:                      lgr,
		container:                   container,
		sessionManager:              sessionManager,
		codexDeviceAuthLauncher:     codexDeviceAuthLauncher,
		persistenceClient:           persistenceClient,
		kvStore:                     applicationKVStore,
		usageRepo:                   usageRepo,
		sessionCountRepo:            sessionCountRepo,
		settingsRepo:                settingsRepo,
		credentialsRepo:             credentialsRepo,
		shareRepo:                   shareRepo,
		teamConfigRepo:              teamConfigRepo,
		sandboxPolicyRepo:           sandboxPolicyRepo,
		storageRepo:                 storageRepo,
		storageObjectStore:          storageObjectStore,
		sandboxDomainRepo:           sandboxDomainRepo,
		sessionRouteRepo:            sessionRouteRepo,
		sessionRunnerStore:          sessionRunnerStore,
		sessionAllocationNotifier:   sessionAllocationNotifier,
		sessionAllocationRedis:      sessionAllocationRedis,
		routeStatusBus:              routeStatusBus,
		userFileRepo:                userFileRepo,
		sessionProfileRepo:          sessionProfileRepo,
		contextTemplateRepo:         contextTemplateRepo,
		scheduleManager:             scheduleManager,
		apiTokenRepo:                apiTokenRepo,
		localUserRepo:               localUserRepo,
		namespace:                   namespace,
		personalAPIKeyRepo:          personalAPIKeyRepo,
		sessionStateStore:           sessionStateStore,
		sessionControlStore:         sessionControlStore,
		esmControlStore:             esmControlStore,
		esmControlTunnel:            esmControlTunnel,
		directSessionRuntimeEnabled: true,
		localSessionFallbackEnabled: localSessionFallbackEnabled,
	}

	// Add logging middleware if verbose
	if verbose {
		e.Use(s.loggingMiddleware())
	}

	// Initialize GitHub auth provider if configured.
	// A single *GitHubAuthProvider instance is shared across all subsystems
	// (SimpleAuthService and GitHubOAuthProvider) so they use the same
	// in-memory teamCache and ConfigMap-backed teamMappingRepo.
	var githubAuthProvider *auth.GitHubAuthProvider
	if cfg.Auth.GitHub != nil && cfg.Auth.GitHub.Enabled {
		log.Printf("[AUTH_INIT] Initializing GitHub auth provider...")
		for _, rule := range cfg.TeamDiscovery {
			cfg.Auth.GitHub.TeamDiscoveryPatterns = append(cfg.Auth.GitHub.TeamDiscoveryPatterns, rule.TeamPattern)
		}
		githubAuthProvider = auth.NewGitHubAuthProvider(cfg.Auth.GitHub)

		// Inject ConfigMap-backed team mapping cache (1 user = 1 key in the ConfigMap)
		teamMappingRepo := repositories.NewKubernetesUserTeamMappingRepository(
			persistenceClient,
			namespace,
		)
		githubAuthProvider.SetTeamMappingRepo(teamMappingRepo)
		log.Printf("[AUTH_INIT] GitHub auth provider initialized with ConfigMap team mapping cache")

		// Inject the shared provider into SimpleAuthService.
		if simpleAuth, ok := container.AuthService.(*services.SimpleAuthService); ok {
			simpleAuth.SetGitHubProvider(githubAuthProvider)
			simpleAuth.SetGitHubAuthConfig(cfg.Auth.GitHub)
			log.Printf("[AUTH_INIT] GitHub auth provider injected into internal auth service")
		}
	}

	// Add authentication middleware using internal auth service
	if bootstrap := cfg.Auth.BootstrapAdmin; bootstrap != nil && bootstrap.Enabled {
		if simpleAuth, ok := container.AuthService.(*services.SimpleAuthService); ok {
			if err := simpleAuth.LoadBootstrapAdmin(bootstrap.UserID, bootstrap.Username, bootstrap.Token); err != nil {
				log.Fatalf("[AUTH_INIT] Invalid bootstrap admin configuration: %v", err)
			}
			log.Printf("[AUTH_INIT] Bootstrap admin authentication enabled for user %q", bootstrap.UserID)
		}
	}
	// Register the single admin API key from AGENTAPI_AUTH_ADMIN_KEY as a
	// non-expiring admin credential for the X-API-Key header. This replaces the
	// removed static API key authentication (ccplant-deploy#66 F1).
	if cfg.Auth.AdminKey != "" {
		if simpleAuth, ok := container.AuthService.(*services.SimpleAuthService); ok {
			if err := simpleAuth.LoadBootstrapAdmin("admin-key", "admin-key", cfg.Auth.AdminKey); err != nil {
				log.Fatalf("[AUTH_INIT] Invalid AGENTAPI_AUTH_ADMIN_KEY configuration: %v", err)
			}
			log.Printf("[AUTH_INIT] Admin key authentication enabled (user \"admin-key\", header X-API-Key)")
		} else {
			log.Printf("[AUTH_INIT] Warning: AGENTAPI_AUTH_ADMIN_KEY is set but the auth service does not support API keys; it will be ignored")
		}
	}
	e.Use(auth.AuthMiddleware(runtimeProvider, container.AuthService))

	// Initialize OAuth provider if configured.
	// Reuses the shared githubAuthProvider so OAuth-authenticated users benefit from
	// the same teamCache and teamMappingRepo as token-based auth users.
	if cfg.Auth.GitHub != nil && cfg.Auth.GitHub.OAuth != nil &&
		cfg.Auth.GitHub.OAuth.ClientID != "" && cfg.Auth.GitHub.OAuth.ClientSecret != "" {
		log.Printf("[OAUTH_INIT] Initializing GitHub OAuth provider...")
		s.oauthProvider = auth.NewGitHubOAuthProvider(cfg.Auth.GitHub.OAuth, githubAuthProvider)
		log.Printf("[OAUTH_INIT] OAuth provider initialized successfully")
		// Start cleanup goroutine for expired OAuth sessions
		go s.cleanupExpiredOAuthSessions()
	} else {
		log.Printf("[OAUTH_INIT] OAuth provider not initialized - configuration missing or incomplete")
	}
	runtimeProvider.Subscribe(func(updated *config.Config) {
		if githubAuthProvider != nil && updated.Auth.GitHub != nil {
			githubAuthProvider.UpdateConfig(updated.Auth.GitHub)
		}
	})

	// Initialize notification service
	baseDir := notification.GetBaseDir()
	notificationSvc, err := notification.NewService(baseDir)
	if err != nil {
		log.Printf("Failed to initialize notification service: %v", err)
	} else {
		s.notificationSvc = notificationSvc
		notificationSvc.SetBaseURLResolver(func() string { return runtimeProvider.String("notifications.base_url") })
		log.Printf("Notification service initialized successfully")

		// Notification subscriptions are application data owned by the API role.
		// persistenceClient is either the legacy Kubernetes client or the libSQL-backed
		// compatibility adapter, so this wiring remains independent of the concrete
		// session-manager implementation and requires no API ServiceAccount token.
		syncer := services.NewKubernetesSubscriptionSecretSyncer(
			persistenceClient,
			namespace,
			notificationSvc.GetStorage(),
			"", // Use default prefix
		)
		notificationSvc.SetSecretSyncer(syncer)
		notificationSvc.SetSubscriptionReader(syncer)
		notificationSvc.SetSubscriptionWriter(syncer)
		log.Printf("Notification subscription persistence configured (read+write)")
		if k8sMgr, ok := s.sessionManager.(*services.KubernetesSessionManager); ok {
			k8sMgr.SetCodexAuthNotifier(notificationSvc.SendNotificationToUser)
		}
	}

	// Start cleanup goroutine for defunct processes
	go s.cleanupDefunctProcesses()

	// Start sandbox domain collector (Kubernetes mode only)
	if k8sMgr, ok := s.sessionManager.(*services.KubernetesSessionManager); ok && s.sandboxDomainRepo != nil {
		collector := newSandboxDomainCollector(k8sMgr, s.sandboxDomainRepo, 60*time.Second)
		go collector.start(context.Background())
		log.Printf("[SERVER] Sandbox domain collector started (interval: 60s)")
	}

	// Start cleanup goroutine for expired shares
	if s.shareRepo != nil {
		go s.cleanupExpiredShares()
	}

	// Bootstrap service accounts from team configs
	if teamConfigRepo != nil {
		if simpleAuth, ok := container.AuthService.(*services.SimpleAuthService); ok {
			ctx := context.Background()
			if err := services.BootstrapServiceAccounts(ctx, simpleAuth, teamConfigRepo); err != nil {
				log.Printf("[SERVER] Warning: failed to bootstrap service accounts: %v", err)
			}
		}
	}

	// Bootstrap personal API keys (Kubernetes mode only)
	if k8sSessionManager, ok := s.sessionManager.(*services.KubernetesSessionManager); ok {
		personalAPIKeyRepo := k8sSessionManager.GetPersonalAPIKeyRepository()
		if personalAPIKeyRepo != nil {
			if simpleAuth, ok := container.AuthService.(*services.SimpleAuthService); ok {
				ctx := context.Background()
				if err := services.BootstrapPersonalAPIKeys(ctx, simpleAuth, personalAPIKeyRepo); err != nil {
					log.Printf("[SERVER] Warning: failed to bootstrap personal API keys: %v", err)
				}
				// Wire up the auth service as the personal API key loader so keys
				// created on-the-fly (for new users) are immediately authenticatable.
				k8sSessionManager.SetPersonalAPIKeyLoader(simpleAuth)
			}
		}
	}

	// Migrate legacy API key material into the new multi-token repository and
	// load all named API tokens (migrated and pre-existing) into the auth
	// service. This is performed by Server.InitAPITokens, which is invoked by
	// the command layer (cmd/server.go) so that any migration or bootstrap
	// failure prevents the process from serving traffic. A background
	// reconciler keeps the in-memory token map consistent across replicas. We
	// only stash the wiring here; nothing fail-prone runs inside NewServer so
	// that tests constructing a Server are not blocked on Kubernetes.
	s.initAPITokenWiring()

	// Set up ServiceAccountEnsurer in KubernetesSessionManager so that all session creation
	// paths (start, webhook, schedule, etc.) automatically create TeamConfig on team-scoped sessions.
	if teamConfigRepo != nil {
		if simpleAuth, ok := container.AuthService.(*services.SimpleAuthService); ok {
			if k8sManager, ok := s.sessionManager.(*services.KubernetesSessionManager); ok {
				ensurer := serviceaccountuc.NewGetOrCreateServiceAccountUseCase(teamConfigRepo, simpleAuth)
				k8sManager.SetServiceAccountEnsurer(ensurer)
				log.Printf("[SERVER] ServiceAccountEnsurer configured for KubernetesSessionManager")
			}
		}
	}

	// Local allocation may expose a stable public session ID while running the
	// workload under an adopted stock-session ID.  A oneshot workload deletes
	// itself by that runtime ID, so remove the public alias at the same time.
	// Otherwise /search keeps synthesizing an active session from a route whose
	// workload no longer exists.
	if k8sManager, ok := sessionManager.(*services.KubernetesSessionManager); ok && sessionRouteRepo != nil {
		k8sManager.AddSessionDeletedHandler(func(ctx context.Context, sess entities.Session) {
			cleanupLocalSessionRoutes(ctx, sessionRouteRepo, sess.ID())
		})
		log.Printf("[SERVER] Local session route cleanup handler registered")
	}

	s.setupRoutes()

	return s
}

const (
	defaultSessionControlPoolSize         = 50
	defaultSessionControlBlockingPoolSize = 400
)

func buildSessionControlStore(cfg *config.Config) sessioncontrol.Store {
	commandPoolSize := cfg.Redis.SessionControlPoolSize
	if commandPoolSize <= 0 {
		commandPoolSize = defaultSessionControlPoolSize
	}
	blockingPoolSize := cfg.Redis.SessionControlBlockingPoolSize
	if blockingPoolSize <= 0 {
		blockingPoolSize = defaultSessionControlBlockingPoolSize
	}
	opts := &redis.Options{
		Addr:           cfg.Redis.Addr,
		Password:       cfg.Redis.Password,
		DB:             cfg.Redis.DB,
		PoolSize:       commandPoolSize,
		MaxActiveConns: commandPoolSize,
	}
	if d, err := time.ParseDuration(cfg.Redis.DialTimeout); err == nil && d > 0 {
		opts.DialTimeout = d
	}
	if d, err := time.ParseDuration(cfg.Redis.ReadTimeout); err == nil && d > 0 {
		opts.ReadTimeout = d
	}
	if d, err := time.ParseDuration(cfg.Redis.WriteTimeout); err == nil && d > 0 {
		opts.WriteTimeout = d
	}
	if cfg.Redis.TLSEnabled {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("[SESSION_CONTROL] Disabled: Redis ping failed: %v", err)
		_ = client.Close()
		return nil
	}
	log.Printf("[SESSION_CONTROL] Redis Streams control channel enabled (command_pool_size=%d, blocking_pool_size=%d)",
		commandPoolSize, blockingPoolSize)
	blockingOpts := *opts
	blockingOpts.ReadTimeout = 35 * time.Second
	blockingOpts.PoolSize = blockingPoolSize
	blockingOpts.MaxActiveConns = blockingPoolSize
	blockingClient := redis.NewClient(&blockingOpts)
	return infrasessioncontrol.NewRedisStoreWithBlockingClient(client, blockingClient)
}

func buildSessionAllocationNotifier(cfg *config.Config) (sessionrunnercore.AllocationNotifier, *redis.Client) {
	local := infrasessionrunner.NewLocalAllocationNotifier()
	if cfg.Redis.Addr == "" {
		log.Printf("[SESSION_POOL] Redis not configured; runner allocation notifications are process-local")
		return local, nil
	}
	opts := &redis.Options{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB, ReadTimeout: 35 * time.Second}
	if d, err := time.ParseDuration(cfg.Redis.DialTimeout); err == nil && d > 0 {
		opts.DialTimeout = d
	}
	if d, err := time.ParseDuration(cfg.Redis.WriteTimeout); err == nil && d > 0 {
		opts.WriteTimeout = d
	}
	if cfg.Redis.TLSEnabled {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("[SESSION_POOL] Redis unavailable; runner allocation notifications are process-local: %v", err)
		_ = client.Close()
		return local, nil
	}
	log.Printf("[SESSION_POOL] Redis runner allocation notifications enabled")
	return infrasessionrunner.NewRedisAllocationNotifier(client), client
}

func buildESMControlStore(cfg *config.Config) esmcontrol.Store {
	opts := &redis.Options{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB, ReadTimeout: 35 * time.Second}
	if d, err := time.ParseDuration(cfg.Redis.DialTimeout); err == nil && d > 0 {
		opts.DialTimeout = d
	}
	if d, err := time.ParseDuration(cfg.Redis.WriteTimeout); err == nil && d > 0 {
		opts.WriteTimeout = d
	}
	if cfg.Redis.TLSEnabled {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("[ESM_CONTROL] Disabled: Redis ping failed: %v", err)
		_ = client.Close()
		return nil
	}
	log.Printf("[ESM_CONTROL] Outbound manager tunnel enabled")
	return infraesmcontrol.NewRedisStore(client)
}

func buildApplicationKVStore(cfg config.KVStoreConfig, kubeClient kubernetes.Interface) (kvstore.Store, bool, error) {
	if cfg.Primary == nil && cfg.Secondary == nil {
		if cfg.Backend == "" || cfg.Backend == "kubernetes" {
			return nil, false, nil
		}
		store, err := buildKVBackend(config.KVStoreBackendConfig{Backend: cfg.Backend, DatabaseURL: cfg.DatabaseURL, AuthToken: cfg.AuthToken, Encryption: cfg.Encryption}, kubeClient)
		return store, err == nil, err
	}
	if cfg.Primary == nil {
		return nil, false, errors.New("kv_store.primary is required when secondary is configured")
	}
	if cfg.Backend != "" || cfg.DatabaseURL != "" || cfg.AuthToken != "" {
		return nil, false, errors.New("legacy kv_store fields cannot be combined with primary/secondary")
	}
	primary, err := buildKVBackend(*cfg.Primary, kubeClient)
	if err != nil {
		return nil, false, fmt.Errorf("primary: %w", err)
	}
	if cfg.Secondary == nil {
		if cfg.Primary.Backend == "kubernetes" || cfg.Primary.Backend == "" {
			return nil, false, nil
		}
		return primary, true, nil
	}
	secondary, err := buildKVBackend(*cfg.Secondary, kubeClient)
	if err != nil {
		_ = primary.Close()
		return nil, false, fmt.Errorf("secondary: %w", err)
	}
	mode := cfg.Replication.Mode
	if mode == "" {
		mode = string(kvstore.ReplicationModeRollback)
	}
	replicated, err := kvstore.NewReplicatedStore(primary, secondary, kvstore.ReplicationMode(mode))
	if err != nil {
		_ = errors.Join(primary.Close(), secondary.Close())
		return nil, false, err
	}
	return replicated, true, nil
}

func resolveApplicationNamespace(configured string) string {
	// Explicit runtime configuration must win over stale config snapshots.
	// Non-Kubernetes API runtimes have no service-account namespace fallback,
	// so honoring this override prevents application data from silently landing
	// in the "default" logical namespace.
	if namespace := strings.TrimSpace(os.Getenv("AGENTAPI_KV_STORE_NAMESPACE")); namespace != "" {
		return namespace
	}
	if namespace := strings.TrimSpace(configured); namespace != "" {
		return namespace
	}
	if namespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); namespace != "" {
		return namespace
	}
	return "default"
}

func validateAPIKVStore(cfg config.KVStoreConfig) error {
	backend := configuredKVBackend(cfg)
	if backend != "libsql" && backend != "libsql-encrypted" && backend != "kubernetes" {
		return fmt.Errorf("primary backend must be libsql, libsql-encrypted, or kubernetes, got %q", backend)
	}
	if cfg.Secondary != nil && cfg.Secondary.Backend != "libsql" && cfg.Secondary.Backend != "libsql-encrypted" && cfg.Secondary.Backend != "kubernetes" {
		return fmt.Errorf("secondary backend must be libsql, libsql-encrypted, or kubernetes in the API role, got %q", cfg.Secondary.Backend)
	}
	return nil
}

func configuredKVBackend(cfg config.KVStoreConfig) string {
	backend := cfg.Backend
	if cfg.Primary != nil {
		backend = cfg.Primary.Backend
	}
	if backend == "" {
		return "kubernetes"
	}
	return backend
}

func buildKVBackend(cfg config.KVStoreBackendConfig, kubeClient kubernetes.Interface) (kvstore.Store, error) {
	switch cfg.Backend {
	case "", "kubernetes":
		return kvstore.NewKubernetesStore(kubeClient), nil
	case "libsql", "libsql-encrypted":
		if strings.TrimSpace(cfg.DatabaseURL) == "" {
			return nil, errors.New("database_url is required for libSQL")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		store, err := kvstore.NewLibSQLStore(ctx, cfg.DatabaseURL, cfg.AuthToken)
		if err != nil {
			return nil, err
		}
		if cfg.Backend == "libsql" {
			return store, nil
		}
		cfg.Encryption.Keys = cfg.Encryption.EffectiveKeys()
		if cfg.Encryption.ActiveKeyID == "" || len(cfg.Encryption.Keys) == 0 {
			_ = store.Close()
			return nil, errors.New("KV encryption keys are required for libsql-encrypted")
		}
		keyring, err := buildKVEncryptionKeyring(ctx, cfg.Encryption, store)
		if err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("configure KV encryption: %w", err)
		}
		encrypted, err := kvstore.NewEncryptedStore(store, keyring)
		if err != nil {
			_ = store.Close()
			return nil, err
		}
		return encrypted, nil
	default:
		return nil, fmt.Errorf("unsupported backend %q", cfg.Backend)
	}
}

func buildKVEncryptionKeyring(ctx context.Context, encryption config.KVStoreEncryptionConfig, registry kvstore.BranchKeyRegistry) (kvstore.EnvelopeKeyring, error) {
	switch encryption.Provider {
	case "", "local":
		return kvstore.NewLocalKeyring(encryption.ActiveKeyID, encryption.Keys)
	case "aws-kms":
		return kvstore.NewKMSKeyring(ctx, encryption.ActiveKeyID, encryption.KMSRegion, encryption.Keys)
	case "aws-kms-branch":
		return kvstore.NewBranchKMSKeyring(ctx, encryption.ActiveKeyID, encryption.KMSRegion, encryption.Keys, registry,
			time.Duration(encryption.BranchCacheTTLSeconds)*time.Second, encryption.BranchCacheMaxEntries)
	case "aws-kms-branch-scoped":
		return kvstore.NewScopedBranchKMSKeyring(ctx, encryption.ActiveKeyID, encryption.KMSRegion, encryption.Keys, registry,
			time.Duration(encryption.BranchCacheTTLSeconds)*time.Second, encryption.BranchCacheMaxEntries)
	case "cloud-kms-branch":
		return kvstore.NewCloudBranchKMSKeyring(ctx, encryption.ActiveKeyID, encryption.Keys, registry,
			time.Duration(encryption.BranchCacheTTLSeconds)*time.Second, encryption.BranchCacheMaxEntries)
	case "cloud-kms-branch-scoped":
		return kvstore.NewScopedCloudBranchKMSKeyring(ctx, encryption.ActiveKeyID, encryption.Keys, registry,
			time.Duration(encryption.BranchCacheTTLSeconds)*time.Second, encryption.BranchCacheMaxEntries)
	default:
		return nil, fmt.Errorf("unsupported KV encryption provider %q", encryption.Provider)
	}
}

func cleanupLocalSessionRoutes(ctx context.Context, repo portrepos.SessionRouteRepository, runtimeSessionID string) {
	routes, err := repo.List(ctx, "")
	if err != nil {
		log.Printf("[SESSION_ROUTE] Warning: failed to list routes while deleting runtime session %s: %v", runtimeSessionID, err)
		return
	}
	for _, route := range routes {
		if route.ManagerID != "" || route.RemoteSessionID != runtimeSessionID {
			continue
		}
		if err := repo.Delete(ctx, route.SessionID); err != nil {
			log.Printf("[SESSION_ROUTE] Warning: failed to delete local alias %s for runtime session %s: %v", route.SessionID, runtimeSessionID, err)
		}
	}
}

// StartMonitoring starts the session monitoring (called after server is fully initialized)
func (s *Server) StartMonitoring() {
	// Session monitoring disabled - notifications handled by Claude Code hooks
}

// StartSessionCountWorker records the initial state once and then consumes
// session status notifications. It performs no periodic polling.
func (s *Server) StartSessionCountWorker(ctx context.Context) {
	if s.sessionCountRepo == nil {
		return
	}
	source, ok := s.sessionManager.(interface {
		GetSession(string) entities.Session
		ListSessions(entities.SessionFilter) []entities.Session
		SubscribeStatusEvents() (<-chan portrepos.SessionStatusEvent, func())
	})
	if !ok {
		log.Printf("[SESSION_COUNT_EVENTS] Session manager does not expose status notifications")
		return
	}
	worker := sessioncount.NewWorker(source, s.sessionRunnerStore, s.sessionRouteRepo, s.teamConfigRepo, s.sessionCountRepo)
	s.sessionCountWorker = worker
	if s.router != nil && s.router.handlers != nil && s.router.handlers.sessionController != nil {
		s.router.handlers.sessionController.SetSessionStatusUsageRecorder(worker)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	s.sessionCountCancel = cancel
	s.sessionCountWorkers.Add(1)
	go func() {
		defer s.sessionCountWorkers.Done()
		worker.Run(workerCtx)
	}()
	log.Printf("[SESSION_COUNT_EVENTS] Started status event recorder")
}

// loggingMiddleware returns Echo middleware for request logging
func (s *Server) loggingMiddleware() echo.MiddlewareFunc {
	return echo.MiddlewareFunc(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			log.Printf("Request: %s %s from %s", req.Method, req.URL.Path, req.RemoteAddr)
			return next(c)
		}
	})
}

// setupRoutes configures the router with all defined routes
func (s *Server) setupRoutes() {
	// Register non-auth routes using Router
	s.router = NewRouter(s.echo, s)
	if err := s.router.RegisterRoutes(); err != nil {
		log.Printf("Failed to register routes: %v", err)
	}

	// Register auth-related routes directly
	s.setupAuthRoutes()
}

// apiTokenInitDeps bundles the optional dependencies gathered during
// NewServer so the fail-prone migration/bootstrap step can run later (in
// InitAPITokens) without re-deriving them. Keeping them on the Server also
// lets tests drive initialization explicitly.
type apiTokenInitDeps struct {
	authService *services.SimpleAuthService
}

// initAPITokenWiring records the auth service and derives the repositories
// needed to run migration/bootstrap later. It must not perform any I/O or
// fail-prone work so that NewServer remains side-effect-free with respect to
// API token initialization.
func (s *Server) initAPITokenWiring() {
	simpleAuth, ok := s.container.AuthService.(*services.SimpleAuthService)
	if !ok {
		return
	}
	if s.apiTokenRepo == nil {
		return
	}
	s.apiTokenDeps = &apiTokenInitDeps{
		authService: simpleAuth,
	}
	// Wire the repository into the auth service so the background reconciler
	// can keep named tokens consistent across replicas. Legacy static and
	// personal API keys live in a separate map and are unaffected.
	simpleAuth.SetAPITokenRepository(s.apiTokenRepo)
	simpleAuth.SetLocalUserRepository(s.localUserRepo)
}

// InitAPITokens loads named API tokens into the in-memory auth service.
func (s *Server) InitAPITokens(ctx context.Context) error {
	if s.apiTokenRepo == nil || s.apiTokenDeps == nil {
		return nil
	}
	deps := s.apiTokenDeps
	if deps.authService == nil {
		return nil
	}
	if err := services.BootstrapAPITokens(ctx, deps.authService, s.apiTokenRepo); err != nil {
		return fmt.Errorf("api token bootstrap: %w", err)
	}
	return nil
}

// StartAPITokenReconciler launches a background goroutine that periodically
// reconciles the in-memory named-token map with the repository so revocation
// of a named token propagates across replicas within the given interval. It
// returns immediately; the goroutine stops when ctx is canceled. No-op when
// the named-token subsystem is not configured.
func (s *Server) StartAPITokenReconciler(ctx context.Context, interval time.Duration) {
	if s.apiTokenRepo == nil || s.apiTokenDeps == nil || s.apiTokenDeps.authService == nil {
		return
	}
	if interval <= 0 {
		return
	}
	authService := s.apiTokenDeps.authService
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := authService.ReconcileAPITokens(ctx); err != nil {
					log.Printf("[RECONCILE] api token reconciliation failed: %v", err)
				}
			}
		}
	}()
	log.Printf("[RECONCILE] api token reconciler started (interval: %s)", interval)
}

// AddCustomHandler adds a custom handler to the router
func (s *Server) AddCustomHandler(handler CustomHandler) {
	if s.router != nil {
		s.router.AddCustomHandler(handler)
		// Register routes immediately since router is already initialized
		if err := handler.RegisterRoutes(s.echo); err != nil {
			log.Printf("Failed to register custom handler %s: %v", handler.GetName(), err)
		}
	}
}

// GetSessionManager returns the session manager
func (s *Server) GetSessionManager() portrepos.SessionManager {
	return s.sessionManager
}

// GetScheduleManager returns the API-owned schedule persistence manager.
func (s *Server) GetScheduleManager() schedule.Manager {
	return s.scheduleManager
}

// GetPersistenceClient returns the Secret/ConfigMap client used by all
// application repositories outside KubernetesSessionManager.
func (s *Server) GetPersistenceClient() kubernetes.Interface {
	return s.persistenceClient
}

// GetApplicationKVStore returns the storage-neutral application persistence
// boundary. Kubernetes-only deployments are exposed through the Store adapter
// just like libSQL and replicated deployments.
func (s *Server) GetApplicationKVStore() kvstore.Store {
	if s.kvStore != nil {
		return s.kvStore
	}
	return kvstore.NewKubernetesStore(s.persistenceClient)
}

// ResolveApplicationUserIDForGitHubUser maps a GitHub webhook sender to the
// same stable application user ID used when personal credentials are saved.
func (s *Server) ResolveApplicationUserIDForGitHubUser(ctx context.Context, githubUserID int64, login string) (string, error) {
	if s.router == nil || s.router.handlers == nil || s.router.handlers.githubConnectionsController == nil {
		return strings.TrimSpace(login), nil
	}
	return s.router.handlers.githubConnectionsController.ResolveApplicationUserIDForGitHubUser(ctx, githubUserID, login)
}

// SetSessionManager allows configuration of a custom session manager (for testing)
func (s *Server) SetSessionManager(manager portrepos.SessionManager) {
	s.sessionManager = manager
}

// GetShareRepository returns the share repository
func (s *Server) GetShareRepository() portrepos.ShareRepository {
	return s.shareRepo
}

// SetShareRepository allows configuration of a custom share repository (for testing)
func (s *Server) SetShareRepository(repo portrepos.ShareRepository) {
	s.shareRepo = repo
}

// GetContainer returns the DI container
func (s *Server) GetContainer() *di.Container {
	return s.container
}

// GetSessionRouteRepository returns the session route repository
func (s *Server) GetSessionRouteRepository() portrepos.SessionRouteRepository {
	return s.sessionRouteRepo
}

// CreateSession creates a new agent session
func (s *Server) CreateSession(ctx context.Context, sessionID string, startReq entities.StartRequest, userID, userRole string, teams []string) (entities.Session, error) {
	return telemetry.Operation(ctx, "app.Server.CreateSession", func(ctx context.Context) (entities.Session, error) {
		return s.createSession(ctx, sessionID, startReq, userID, userRole, teams)
	}, telemetry.String("session.scope", string(startReq.Scope)))
}

// PreviewSession resolves placement and provision settings without creating or
// persisting any session resources. The returned session ID is only a candidate.
func (s *Server) PreviewSession(ctx context.Context, sessionID string, startReq entities.StartRequest, userID, userRole string, teams []string) (*entities.SessionStartPreview, error) {
	if startReq.Params != nil && startReq.Params.ManagerID != "" {
		esm, err := s.findESMByID(ctx, userID, teams, startReq.Params.ManagerID)
		if err != nil {
			return nil, fmt.Errorf("failed to find external session manager %s: %w", startReq.Params.ManagerID, err)
		}
		if esm == nil {
			return nil, fmt.Errorf("external session manager not found: %s", startReq.Params.ManagerID)
		}
		if s.sessionRunnerStore == nil || esm.Pool == "" {
			return nil, fmt.Errorf("session manager %s has no runner pool", startReq.Params.ManagerID)
		}
		pool, err := s.sessionRunnerStore.GetLogicalPool(ctx, esm.Pool)
		if err != nil || !pool.Enabled {
			return nil, fmt.Errorf("session manager pool is unavailable: %s", esm.Pool)
		}
		preview, err := s.previewWithPlacement(ctx, sessionID, startReq, userID, teams, entities.SessionStartPlacement{
			Transport: portrepos.SessionRouteTransportDirectRuntime, Pool: pool.Name, ManagerID: esm.ID,
		})
		if preview != nil {
			preview.Resolution = map[string]interface{}{"placement": map[string]interface{}{"reason": "explicit_manager_selected", "manager_id": esm.ID, "pool": pool.Name}}
		}
		return preview, err
	}

	if s.sessionRunnerStore != nil {
		subject := sessionrunnercore.Subject{Type: sessionrunnercore.SubjectUser, ID: userID}
		if startReq.Scope == entities.ScopeTeam {
			subject = sessionrunnercore.Subject{Type: sessionrunnercore.SubjectTeam, ID: startReq.TeamID}
		}
		resolved, trace, err := s.resolveSessionPoolWithTrace(ctx, subject, requestedSessionPool(startReq), startReq.Tags)
		if err != nil {
			return nil, fmt.Errorf("select session pool: %w", err)
		}
		if resolved != nil {
			route, err := s.resolveSessionRoute(ctx, subject, sessionrunnercore.RouteRequest{RequestedPool: resolved.Pool.Name, Tags: startReq.Tags})
			if err != nil {
				return nil, fmt.Errorf("resolve authorized session route: %w", err)
			}
			if route == nil {
				return nil, fmt.Errorf("no authorized and healthy session route is available")
			}
			if err := s.checkSessionPoolQuota(ctx, route); err != nil {
				return nil, err
			}
			placement := entities.SessionStartPlacement{Transport: portrepos.SessionRouteTransportDirectRuntime, Pool: route.PoolName(), BindingID: route.BindingID()}
			preview, err := s.previewWithPlacement(ctx, sessionID, startReq, userID, teams, placement)
			if preview != nil {
				preview.Resolution = map[string]interface{}{"pool": trace, "placement": map[string]interface{}{"reason": "session_runner_pool_selected"}}
			}
			return preview, err
		}
	}
	if requestedPool := requestedSessionPool(startReq); requestedPool != "" {
		return nil, fmt.Errorf("no authorized and healthy session pool matches %q", requestedPool)
	}

	sandboxRequested := startReq.Params != nil && startReq.Params.Sandbox != nil && startReq.Params.Sandbox.Enabled
	dindRequested := startReq.Params != nil && startReq.Params.Docker != nil && startReq.Params.Docker.Enabled
	hasAllocatorSelector := hasAllocatorSelector(startReq.Tags)
	if hasAllocatorSelector && (sandboxRequested || dindRequested) {
		return nil, fmt.Errorf("allocator.* routing does not support sandbox or Docker-in-Docker")
	}
	if !sandboxRequested && !dindRequested {
		selectedESM, err := s.findAutomaticAssignmentESM(ctx, userID, teams, startReq.Tags)
		if err != nil {
			return nil, fmt.Errorf("select external session manager: %w", err)
		}
		if selectedESM != nil {
			if startReq.Params == nil {
				startReq.Params = &entities.SessionParams{}
			}
			startReq.Params.ManagerID = selectedESM.ID
			return s.PreviewSession(ctx, sessionID, startReq, userID, userRole, teams)
		}
		if hasAllocatorSelector {
			return nil, fmt.Errorf("no external session manager matches allocator.* tags")
		}
	}
	if !s.localSessionFallbackEnabled {
		return nil, fmt.Errorf("no authorized and healthy session pool is available")
	}

	mergedEnv, err := services.MergeEnvironmentVariables(services.EnvMergeConfig{
		RoleEnvFiles: &s.config.RoleEnvFiles, UserRole: userRole,
		TeamEnvFile: services.ExtractTeamEnvFile(startReq.Tags), RequestEnv: startReq.Environment,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to merge environment variables: %w", err)
	}
	startReq.Environment = mergedEnv
	preview, err := s.previewWithPlacement(ctx, sessionID, startReq, userID, teams, entities.SessionStartPlacement{
		Transport: "local", LocalFallback: true,
	})
	if preview != nil {
		preview.Resolution = map[string]interface{}{"placement": map[string]interface{}{"reason": "no_remote_placement_local_fallback"}}
	}
	return preview, err
}

func (s *Server) previewWithPlacement(ctx context.Context, sessionID string, startReq entities.StartRequest, userID string, teams []string, placement entities.SessionStartPlacement) (*entities.SessionStartPreview, error) {
	builder, ok := s.sessionManager.(portrepos.RemoteProvisionSettingsBuilder)
	if !ok {
		return nil, fmt.Errorf("session settings preview is not supported")
	}
	resolvedStorages, err := s.resolveStorageAttachments(ctx, startReq, userID, placement.Pool)
	if err != nil {
		return nil, err
	}
	startReq.ResolvedStorages = resolvedStorages
	runReq := s.runRequestForStart(sessionID, startReq, userID, teams)
	runReq.Pool = placement.Pool
	settings, err := builder.BuildRemoteProvisionSettings(ctx, sessionID, runReq)
	if err != nil {
		return nil, fmt.Errorf("resolve session settings: %w", err)
	}
	if settings == nil {
		return nil, fmt.Errorf("session manager returned no provision settings")
	}
	settings.WebhookPayload = string(startReq.WebhookPayload)
	if placement.Pool != "" {
		s.applyPoolAutoSuspendPolicy(ctx, settings, startReq.Scope, userID, startReq.TeamID)
	}
	return &entities.SessionStartPreview{Placement: placement, Settings: settings}, nil
}

func (s *Server) createSession(ctx context.Context, sessionID string, startReq entities.StartRequest, userID, userRole string, teams []string) (entities.Session, error) {
	if s.sessionRunnerStore == nil {
		return nil, fmt.Errorf("authorized session routing is unavailable")
	}
	subject := sessionrunnercore.Subject{Type: sessionrunnercore.SubjectUser, ID: userID}
	if startReq.Scope == entities.ScopeTeam {
		subject = sessionrunnercore.Subject{Type: sessionrunnercore.SubjectTeam, ID: startReq.TeamID}
	}
	requestedPool := requestedSessionPool(startReq)
	explicitManagerID := ""
	if startReq.Params != nil {
		explicitManagerID = strings.TrimSpace(startReq.Params.ManagerID)
	}
	route, err := s.resolveSessionRoute(ctx, subject, sessionrunnercore.RouteRequest{
		RequestedPool: requestedPool, Tags: startReq.Tags, RequiredManagerID: explicitManagerID,
	})
	if err != nil {
		return nil, fmt.Errorf("select authorized session route: %w", err)
	}
	if route == nil {
		if startReq.Tags["task_id"] != "" && s.GetConfig().TaskQueue.Enabled {
			return nil, task.ErrWaitingCapacity
		}
		return nil, fmt.Errorf("no authorized and healthy session route is available")
	}
	if explicitManagerID != "" && !authorizedRouteContainsManager(route, explicitManagerID) {
		return nil, fmt.Errorf("requested session manager is not an authorized supplier of pool %q", route.PoolName())
	}
	resolvedStorages, err := s.resolveStorageAttachments(ctx, startReq, userID, route.PoolName())
	if err != nil {
		return nil, err
	}
	startReq.ResolvedStorages = resolvedStorages

	// Identity and TeamConfig mutation belong to the API. The execution-plane
	// manager receives an already-authorized request and never initializes the
	// public authentication service.
	if startReq.Scope == entities.ScopeTeam && startReq.TeamID != "" && s.teamConfigRepo != nil {
		if simpleAuth, ok := s.container.AuthService.(*services.SimpleAuthService); ok {
			ensurer := serviceaccountuc.NewGetOrCreateServiceAccountUseCase(s.teamConfigRepo, simpleAuth)
			if err := ensurer.EnsureServiceAccount(ctx, startReq.TeamID); err != nil {
				return nil, fmt.Errorf("ensure team service account: %w", err)
			}
		}
	}
	if startReq.Scope != entities.ScopeTeam {
		if err := s.EnsurePersonalAPIKey(ctx, userID); err != nil {
			return nil, fmt.Errorf("ensure personal API key: %w", err)
		}
	}
	switch route.Kind() {
	case sessionrunnercore.RouteKindPool:
		return s.createPoolSession(ctx, route, sessionID, startReq, userID, teams)
	case sessionrunnercore.RouteKindLocal:
		return s.createLocalSession(ctx, route, sessionID, startReq, userID, userRole, teams)
	default:
		return nil, fmt.Errorf("unsupported authorized session route kind %q", route.Kind())
	}
}

func (s *Server) createLocalSession(ctx context.Context, route sessionrunnercore.AuthorizedRoute, sessionID string, startReq entities.StartRequest, userID, userRole string, teams []string) (entities.Session, error) {
	if route == nil || route.Kind() != sessionrunnercore.RouteKindLocal {
		return nil, fmt.Errorf("authorized local session route is required")
	}
	mergedEnv, err := services.MergeEnvironmentVariables(services.EnvMergeConfig{
		RoleEnvFiles: &s.config.RoleEnvFiles, UserRole: userRole,
		TeamEnvFile: services.ExtractTeamEnvFile(startReq.Tags), RequestEnv: startReq.Environment,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to merge environment variables: %w", err)
	}
	startReq.Environment = mergedEnv
	repoInfo := s.extractRepositoryInfo(sessionID, startReq.Tags)
	var initialMessage, agentType, sessionTTL string
	var slackParams *entities.SlackParams
	var initialMessageWaitSecond *int
	var cycleMessage string
	var cycleMaxCount int
	var sandbox *entities.SandboxParams
	var docker *entities.DockerParams
	var authProxy *bool
	var unsyncedFilePaths, modelOptions []string
	var credentialSource, codexAuthMode, claudeAuthMode, model, resumeFrom string
	if startReq.Params != nil {
		initialMessage = startReq.Params.Message
		agentType = startReq.Params.AgentType
		slackParams = startReq.Params.Slack
		initialMessageWaitSecond = startReq.Params.InitialMessageWaitSecond
		cycleMessage = startReq.Params.CycleMessage
		cycleMaxCount = startReq.Params.CycleMaxCount
		sandbox = startReq.Params.Sandbox
		docker = startReq.Params.Docker
		authProxy = startReq.Params.AuthProxy
		sessionTTL = sessionuc.ResolveSessionTTL(startReq.Params)
		unsyncedFilePaths = append([]string(nil), startReq.Params.UnsyncedFilePaths...)
		credentialSource = startReq.Params.CredentialSource
		codexAuthMode = startReq.Params.CodexAuthMode
		claudeAuthMode = startReq.Params.ClaudeAuthMode
		resumeFrom = startReq.Params.ResumeFrom
		model = startReq.Params.Model
		modelOptions = append([]string(nil), startReq.Params.ModelOptions...)
	}
	result, err := sessionuc.NewLaunchUseCase(s.sessionManager).Launch(ctx, sessionID, sessionuc.LaunchRequest{
		WebhookPayload: startReq.WebhookPayload, ResumeFrom: resumeFrom, TriggeredUserID: startReq.TriggeredUserID,
		UserID: userID, Environment: startReq.Environment, ProfileEnvironment: startReq.ProfileEnvironment,
		Tags: startReq.Tags, RepoInfo: repoInfo, InitialMessage: initialMessage, Teams: teams,
		GithubToken: githubTokenForStartRequest(startReq), Scope: startReq.Scope, TeamID: startReq.TeamID,
		AgentType: agentType, Model: model, ModelOptions: modelOptions, SlackParams: slackParams,
		InitialMessageWaitSecond: initialMessageWaitSecond, CycleMessage: cycleMessage, CycleMaxCount: cycleMaxCount,
		Sandbox: sandbox, Docker: docker, AuthProxy: authProxy, SessionTTL: sessionTTL,
		UnsyncedFilePaths: unsyncedFilePaths, CredentialSource: credentialSource,
		CodexAuthMode: codexAuthMode, ClaudeAuthMode: claudeAuthMode, ProfileFiles: startReq.ProfileFiles, ProfileRepositories: startReq.ProfileRepositories,
		ProfileMCPServers: startReq.ProfileMCPServers, ResolvedSessionProfileID: startReq.ResolvedSessionProfileID,
		ProfileSkills: startReq.ProfileSkills, ProfileCommandWrapper: startReq.ProfileCommandWrapper,
		ProfileSystemPrompt: startReq.ProfileSystemPrompt,
		Storages:            startReq.ResolvedStorages,
	})
	if err != nil {
		return nil, err
	}
	return result.Session, nil
}

func (s *Server) resolveSessionPool(ctx context.Context, subject sessionrunnercore.Subject, requestedPool string, tags map[string]string) (*sessionrunnercore.ResolvedPool, error) {
	resolver := sessionrunnercore.NewResolver(s.sessionRunnerStore, 90*time.Second)
	if s.esmControlStore != nil {
		resolver.WithManagerLiveness(s.esmControlStore)
	}
	return resolver.Resolve(ctx, subject, requestedPool, tags)
}

func (s *Server) resolveSessionRoute(ctx context.Context, subject sessionrunnercore.Subject, request sessionrunnercore.RouteRequest) (sessionrunnercore.AuthorizedRoute, error) {
	resolver := sessionrunnercore.NewResolver(s.sessionRunnerStore, 90*time.Second)
	if s.esmControlStore != nil {
		resolver.WithManagerLiveness(s.esmControlStore)
	}
	resolver.WithLocalFallback(s.localSessionFallbackEnabled)
	return resolver.ResolveRoute(ctx, subject, request)
}

func authorizedRouteContainsManager(route sessionrunnercore.AuthorizedRoute, managerID string) bool {
	for _, manager := range route.Managers() {
		if manager.ID == managerID {
			return true
		}
	}
	return false
}

func (s *Server) resolveSessionPoolWithTrace(ctx context.Context, subject sessionrunnercore.Subject, requestedPool string, tags map[string]string) (*sessionrunnercore.ResolvedPool, *sessionrunnercore.ResolutionTrace, error) {
	resolver := sessionrunnercore.NewResolver(s.sessionRunnerStore, 90*time.Second)
	if s.esmControlStore != nil {
		resolver.WithManagerLiveness(s.esmControlStore)
	}
	return resolver.ResolveWithTrace(ctx, subject, requestedPool, tags)
}

func requestedSessionPool(startReq entities.StartRequest) string {
	if startReq.Params == nil {
		return ""
	}
	return strings.TrimSpace(startReq.Params.Pool)
}

func (s *Server) createPoolSession(ctx context.Context, route sessionrunnercore.AuthorizedRoute, sessionID string, startReq entities.StartRequest, userID string, teams []string) (entities.Session, error) {
	if route == nil {
		return nil, fmt.Errorf("authorized session route is required")
	}
	pool := route.PoolName()
	if err := s.checkSessionPoolQuota(ctx, route); err != nil {
		return nil, err
	}
	runReq := s.runRequestForStart(sessionID, startReq, userID, teams)
	runReq.Pool = pool
	initialMessage, agentType, sessionTTL, docker := runReq.InitialMessage, runReq.AgentType, runReq.SessionTTL, runReq.Docker
	var settings *sessionsettings.SessionSettings
	if builder, ok := s.sessionManager.(portrepos.RemoteProvisionSettingsBuilder); ok {
		var err error
		settings, err = builder.BuildRemoteProvisionSettings(ctx, sessionID, runReq)
		if err != nil {
			return nil, fmt.Errorf("resolve pool provision settings: %w", err)
		}
		if settings == nil {
			return nil, fmt.Errorf("session manager returned no provision settings")
		}
	}
	if settings == nil {
		settings = &sessionsettings.SessionSettings{
			Session: sessionsettings.SessionMeta{UserID: userID, Scope: string(startReq.Scope), TeamID: startReq.TeamID, AgentType: agentType, Teams: teams},
			Env:     startReq.Environment, InitialMessage: initialMessage, UnsyncedFilePaths: runReq.UnsyncedFilePaths,
		}
	}
	settings.WebhookPayload = string(startReq.WebhookPayload)
	s.applyPoolAutoSuspendPolicy(ctx, settings, startReq.Scope, userID, startReq.TeamID)
	settingsRaw, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("marshal pool provision settings: %w", err)
	}
	token, tokenHash, err := newDirectRuntimeToken()
	if err != nil {
		return nil, fmt.Errorf("create pool runtime credential: %w", err)
	}
	authorizedManagerIDs := make([]string, 0, len(route.Managers()))
	for _, manager := range route.Managers() {
		if manager != nil {
			authorizedManagerIDs = append(authorizedManagerIDs, manager.ID)
		}
	}
	allocation := &sessionrunnercore.Allocation{
		SessionID: sessionID, Pool: pool, BindingID: route.BindingID(), Generation: 1,
		AuthorizedManagerIDs: authorizedManagerIDs,
		Requirements: map[string]string{
			"agent_type": agentType,
			"dind":       fmt.Sprintf("%t", docker != nil && docker.Enabled),
		}, RuntimeToken: token,
		RuntimeTokenHash: tokenHash, ProvisionSettings: settingsRaw,
	}
	if err := s.sessionRunnerStore.Enqueue(ctx, allocation); err != nil {
		return nil, fmt.Errorf("enqueue session pool allocation: %w", err)
	}
	startedAt := time.Now().UTC()
	routeTags := make(map[string]string, len(startReq.Tags)+2)
	for key, value := range startReq.Tags {
		routeTags[key] = value
	}
	if sessionTTL != "" {
		routeTags["session_ttl"] = sessionTTL
	}
	if err := s.sessionRouteRepo.Save(ctx, &portrepos.SessionRoute{
		SessionID: sessionID, Transport: portrepos.SessionRouteTransportDirectRuntime,
		RuntimeTokenHash: tokenHash, Generation: 1, UserID: userID, Scope: string(startReq.Scope),
		TeamID: startReq.TeamID, Pool: pool, Tags: routeTags, StartedAt: startedAt, InitialMessage: initialMessage,
		Status: "creating", StatusUpdatedAt: startedAt,
	}); err != nil {
		return nil, fmt.Errorf("save pending pool session route: %w", err)
	}
	if s.sessionAllocationNotifier != nil {
		if err := s.sessionAllocationNotifier.Notify(ctx, pool); err != nil {
			log.Printf("[SESSION_POOL] Warning: failed to notify runners for allocation %s: %v", sessionID, err)
		}
	}
	return entities.NewProxySessionWithStatus(sessionID, userID, startReq.Scope, startReq.TeamID, startReq.Tags, startedAt, "creating"), nil
}

func (s *Server) applyPoolAutoSuspendPolicy(ctx context.Context, settings *sessionsettings.SessionSettings, scope entities.ResourceScope, userID, teamID string) {
	if settings == nil || s.settingsRepo == nil {
		return
	}
	settingsName := userID
	if scope == entities.ScopeTeam && teamID != "" {
		settingsName = teamID
	}
	stored, err := s.settingsRepo.FindByName(ctx, settingsName)
	if err != nil || stored == nil || stored.AutoSuspend() == nil {
		return
	}
	policy := stored.AutoSuspend()
	settings.Session.AutoSuspendEnabled = &policy.Enabled
	settings.Session.AutoSuspendMinutes = policy.IdleTimeoutMinutes
}

func (s *Server) checkSessionPoolQuota(ctx context.Context, route sessionrunnercore.AuthorizedRoute) error {
	if route == nil || route.MaxConcurrent() <= 0 {
		return nil
	}
	allocations, err := s.sessionRunnerStore.ListAllocations(ctx, route.PoolName())
	if err != nil {
		return fmt.Errorf("list session pool allocations: %w", err)
	}
	active := 0
	for _, allocation := range allocations {
		if allocation.BindingID == route.BindingID() && allocationCountsTowardQuota(allocation.Status) {
			active++
		}
	}
	if active >= route.MaxConcurrent() {
		return &sessionrunnercore.QuotaExceededError{
			Pool: route.PoolName(), BindingID: route.BindingID(),
			MaxConcurrent: route.MaxConcurrent(), Active: active,
		}
	}
	return nil
}

func allocationCountsTowardQuota(status sessionrunnercore.AllocationStatus) bool {
	switch status {
	case sessionrunnercore.AllocationPending,
		sessionrunnercore.AllocationLeased,
		sessionrunnercore.AllocationClaimed,
		sessionrunnercore.AllocationRunning:
		return true
	default:
		return false
	}
}

func (s *Server) EnsureTeamServiceAccount(ctx context.Context, teamID string) error {
	if teamID == "" || s.teamConfigRepo == nil {
		return nil
	}
	simpleAuth, ok := s.container.AuthService.(*services.SimpleAuthService)
	if !ok {
		return errors.New("team service-account auth service is unavailable")
	}
	return serviceaccountuc.NewGetOrCreateServiceAccountUseCase(s.teamConfigRepo, simpleAuth).EnsureServiceAccount(ctx, teamID)
}

func (s *Server) EnsurePersonalAPIKey(ctx context.Context, userID string) error {
	if userID == "" || s.personalAPIKeyRepo == nil {
		return nil
	}
	key, err := personalapikeyuc.NewGetOrCreatePersonalAPIKeyUseCase(s.personalAPIKeyRepo).Execute(ctx, entities.UserID(userID))
	if err != nil {
		return err
	}
	if simpleAuth, ok := s.container.AuthService.(*services.SimpleAuthService); ok {
		return simpleAuth.LoadPersonalAPIKey(ctx, key)
	}
	return errors.New("personal API-key auth service is unavailable")
}

func newDirectRuntimeToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:]), nil
}

func githubTokenForStartRequest(startReq entities.StartRequest) string {
	if startReq.Scope == entities.ScopeTeam || startReq.Params == nil {
		return ""
	}
	return startReq.Params.GithubToken
}

// findESMByID searches the user's settings and team settings for an ESM entry with the given ID.
// findAutomaticAssignmentESM searches user and team settings for a legacy, pool-less ESM enabled for automatic assignment.
// User settings take precedence over team settings.
func (s *Server) findAutomaticAssignmentESM(ctx context.Context, userID string, teams []string, tags map[string]string) (*entities.ExternalSessionManagerEntry, error) {
	if s.settingsRepo == nil {
		return nil, nil
	}

	// Search user settings first
	userSettings, err := s.settingsRepo.FindByName(ctx, userID)
	if err == nil && userSettings != nil {
		for _, esm := range userSettings.ExternalSessionManagers() {
			if esm.Pool == "" && esm.IsAutomaticAssignmentEnabled() && externalSessionManagerMatches(esm, tags) {
				entry := esm
				return &entry, nil
			}
		}
	}

	// Search team settings
	for _, teamID := range teams {
		teamSettings, err := s.settingsRepo.FindByName(ctx, teamID)
		if err != nil {
			continue
		}
		for _, esm := range teamSettings.ExternalSessionManagers() {
			if esm.Pool == "" && esm.IsAutomaticAssignmentEnabled() && externalSessionManagerMatches(esm, tags) {
				entry := esm
				return &entry, nil
			}
		}
	}

	return nil, nil
}

func hasAllocatorSelector(tags map[string]string) bool {
	for key := range tags {
		if strings.HasPrefix(key, "allocator.") && key != "allocator.pool" {
			return true
		}
	}
	return false
}

func externalSessionManagerMatches(manager entities.ExternalSessionManagerEntry, tags map[string]string) bool {
	for key, expected := range tags {
		if !strings.HasPrefix(key, "allocator.") || key == "allocator.pool" {
			continue
		}
		label := strings.TrimPrefix(key, "allocator.")
		if label == "id" {
			if manager.ID != expected {
				return false
			}
			continue
		}
		if manager.Labels[label] != expected {
			return false
		}
	}
	return true
}

func (s *Server) findESMByID(ctx context.Context, userID string, teams []string, managerID string) (*entities.ExternalSessionManagerEntry, error) {
	if s.settingsRepo == nil {
		return nil, nil
	}

	// Search user settings
	userSettings, err := s.settingsRepo.FindByName(ctx, userID)
	if err == nil && userSettings != nil {
		for _, esm := range userSettings.ExternalSessionManagers() {
			if esm.ID == managerID {
				return &esm, nil
			}
		}
	}

	// Search team settings
	for _, teamID := range teams {
		teamSettings, err := s.settingsRepo.FindByName(ctx, teamID)
		if err != nil {
			continue
		}
		for _, esm := range teamSettings.ExternalSessionManagers() {
			if esm.ID == managerID {
				return &esm, nil
			}
		}
	}

	return nil, nil
}

// DeleteSessionByID deletes a session by ID
func (s *Server) DeleteSessionByID(sessionID string) error {
	// Delete associated share link if exists (ignore errors as share may not exist)
	if s.shareRepo != nil {
		_ = s.shareRepo.Delete(sessionID)
	}

	return s.sessionManager.DeleteSession(sessionID)
}

// DeletePendingSessionAllocation deletes an allocation request that has not
// produced a session yet, including one orphaned after being claimed.
func (s *Server) DeletePendingSessionAllocation(ctx context.Context, sessionID string) (bool, error) {
	manager, ok := s.sessionManager.(interface {
		DeletePendingSessionAllocation(context.Context, string) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return manager.DeletePendingSessionAllocation(ctx, sessionID)
}

func (s *Server) DeleteProvisionRequest(ctx context.Context, sessionID string) error {
	if manager, ok := s.sessionManager.(interface {
		DeleteProvisionRequest(context.Context, string) error
	}); ok {
		return manager.DeleteProvisionRequest(ctx, sessionID)
	}
	return nil
}

func (s *Server) DeleteSessionPoolAllocation(ctx context.Context, sessionID string) error {
	if s.sessionRunnerStore == nil {
		return nil
	}
	allocation, err := s.sessionRunnerStore.GetAllocation(ctx, sessionID)
	if err == nil && allocation.RunnerID != "" {
		_ = s.sessionRunnerStore.DeleteRunner(ctx, allocation.RunnerID)
	}
	return s.sessionRunnerStore.DeleteAllocation(ctx, sessionID)
}

func (s *Server) startRouteStatusRelay(controller interface{ StartRouteStatusRelay(context.Context) }) {
	if s.routeStatusBus == nil {
		return
	}
	if s.routeStatusCancel != nil {
		s.routeStatusCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.routeStatusCancel = cancel
	controller.StartRouteStatusRelay(ctx)
}

// Shutdown gracefully stops all running sessions and waits for them to terminate
func (s *Server) Shutdown(timeout time.Duration) error {
	if s.runtimeConfigCancel != nil {
		s.runtimeConfigCancel()
	}
	if s.routeStatusCancel != nil {
		s.routeStatusCancel()
	}
	var managerErr error
	if s.sessionManager != nil {
		managerErr = s.sessionManager.Shutdown(timeout)
	}
	var usageErr error
	if s.usageRepo != nil {
		usageErr = s.usageRepo.Close()
	}
	var sessionCountErr error
	if s.sessionCountRepo != nil {
		if s.sessionCountCancel != nil {
			s.sessionCountCancel()
		}
		s.sessionCountWorkers.Wait()
		sessionCountErr = s.sessionCountRepo.Close()
	}
	var notifierErr error
	if s.sessionAllocationRedis != nil {
		notifierErr = s.sessionAllocationRedis.Close()
	}
	if s.kvStore != nil {
		return errors.Join(managerErr, usageErr, sessionCountErr, notifierErr, s.kvStore.Close())
	}
	return errors.Join(managerErr, usageErr, sessionCountErr, notifierErr)
}

// GetEcho returns the Echo instance for external access
func (s *Server) GetEcho() *echo.Echo {
	return s.echo
}

// GetConfig returns the server configuration
func (s *Server) GetConfig() *config.Config {
	if s.configProvider != nil {
		return s.configProvider.Current()
	}
	return s.config
}

func (s *Server) GetConfigProvider() *runtimeconfig.Provider { return s.configProvider }

// GetNotificationService returns the notification service
func (s *Server) GetNotificationService() *notification.Service {
	return s.notificationSvc
}

// GetSettingsRepository returns the settings repository
func (s *Server) GetSettingsRepository() portrepos.SettingsRepository {
	return s.settingsRepo
}

// GetSessionProfileRepository returns the session profile repository
func (s *Server) GetSessionProfileRepository() portrepos.SessionProfileRepository {
	return s.sessionProfileRepo
}

// ExtractRepositoryInfo extracts repository information from tags.
// This is a public function that can be used by other packages (e.g., schedule).
// The cloneDir parameter is typically the session ID.
func ExtractRepositoryInfo(tags map[string]string, cloneDir string) *entities.RepositoryInfo {
	repoInfo, err := corerepo.ExtractInfo(tags, cloneDir)
	if err != nil {
		log.Printf("Failed to extract repository full name: %v", err)
		return nil
	}
	return repoInfo
}

func extractRepoFullNameFromURL(repoURL string) (string, error) {
	return corerepo.FullNameFromURL(repoURL)
}

// extractRepositoryInfo extracts repository information from tags (internal method with verbose logging)
func (s *Server) extractRepositoryInfo(sessionID string, tags map[string]string) *entities.RepositoryInfo {
	if tags == nil {
		return nil
	}

	repoURL, exists := tags["repository"]
	if !exists || repoURL == "" {
		return nil
	}

	// Only process repository URLs that look like valid GitHub URLs
	if !corerepo.IsValidURL(repoURL) {
		if s.verbose {
			log.Printf("Repository tag found: %s, but it's not a valid repository URL. Skipping repository setup.", repoURL)
		}
		return nil
	}

	if s.verbose {
		log.Printf("Repository tag found: %s. Will pass to script as parameters.", repoURL)
	}

	repoInfo := ExtractRepositoryInfo(tags, sessionID)
	if repoInfo != nil && s.verbose {
		log.Printf("Extracted repository info - FullName: %s, CloneDir: %s", repoInfo.FullName, sessionID)
	}

	return repoInfo
}

// isValidRepositoryURL checks if a repository URL is valid for GitHub
// cleanupDefunctProcesses periodically checks for and cleans up defunct processes
func (s *Server) cleanupDefunctProcesses() {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		s.cleanupDefunctProcessesOnce()
	}
}

// cleanupDefunctProcessesOnce performs a single cleanup of defunct processes
func (s *Server) cleanupDefunctProcessesOnce() {
	// Find defunct processes
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to get process list for defunct cleanup: %v", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	defunctCount := 0

	for _, line := range lines {
		if strings.Contains(line, "<defunct>") || strings.Contains(line, " Z ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pidStr := fields[1]
				if pid, err := strconv.Atoi(pidStr); err == nil {
					// Try to reap the defunct process by sending signal 0
					// This doesn't actually send a signal but checks if we can access the process
					if err := syscall.Kill(pid, 0); err != nil {
						// Process is already gone or we can't access it
						continue
					}
					defunctCount++
				}
			}
		}
	}

	if defunctCount > 0 {
		log.Printf("Found %d defunct processes during periodic cleanup", defunctCount)

		// Try to trigger process reaping by the init system
		// This is a best-effort approach
		if defunctCount > 10 {
			log.Printf("High number of defunct processes detected (%d). Consider investigating process management.", defunctCount)
		}
	}
}

// cleanupExpiredShares periodically removes expired session shares
func (s *Server) cleanupExpiredShares() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if s.shareRepo != nil {
			count, err := s.shareRepo.CleanupExpired()
			if err != nil {
				log.Printf("Failed to cleanup expired shares: %v", err)
			} else if count > 0 {
				log.Printf("Cleaned up %d expired session shares", count)
			}
		}
	}
}

// buildStatusEventRepository constructs the appropriate StatusEventRepository
// based on the config:
//   - When cfg.Redis.Addr is non-empty a real RedisStatusRepository is returned.
//   - Otherwise a NoopStatusRepository is returned so existing single-pod
//     behaviour is preserved without any code changes in the callers.
func buildStatusEventRepository(cfg *config.Config) portrepos.StatusEventRepository {
	if cfg.Redis.Addr == "" {
		log.Printf("[SERVER] Redis not configured – using noop status event repository")
		return repositories.NewNoopStatusRepository()
	}

	opts := &redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	if d, err := time.ParseDuration(cfg.Redis.DialTimeout); err == nil && d > 0 {
		opts.DialTimeout = d
	}
	if d, err := time.ParseDuration(cfg.Redis.ReadTimeout); err == nil && d > 0 {
		opts.ReadTimeout = d
	}
	if d, err := time.ParseDuration(cfg.Redis.WriteTimeout); err == nil && d > 0 {
		opts.WriteTimeout = d
	}
	if cfg.Redis.TLSEnabled {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	client := redis.NewClient(opts)

	// Verify connectivity at startup (non-fatal: a misconfigured Redis falls
	// back to noop so the proxy can still serve requests).
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		log.Printf("[SERVER] Warning: Redis ping failed (%s) – falling back to noop status event repository: %v",
			cfg.Redis.Addr, err)
		_ = client.Close()
		return repositories.NewNoopStatusRepository()
	}

	podID, _ := os.Hostname()
	if podID == "" {
		podID = "unknown"
	}
	log.Printf("[SERVER] Redis status event repository connected: addr=%s podID=%s", cfg.Redis.Addr, podID)
	return repositories.NewRedisStatusRepository(client, podID)
}

func buildWorkerLeaseClient(cfg *config.Config) schedule.LeaseClient {
	if cfg.Redis.Addr == "" {
		log.Printf("[WORKER_CONTROL] Leader election disabled: API Redis is required")
		return nil
	}
	opts := &redis.Options{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB}
	if d, err := time.ParseDuration(cfg.Redis.DialTimeout); err == nil && d > 0 {
		opts.DialTimeout = d
	}
	if d, err := time.ParseDuration(cfg.Redis.ReadTimeout); err == nil && d > 0 {
		opts.ReadTimeout = d
	}
	if d, err := time.ParseDuration(cfg.Redis.WriteTimeout); err == nil && d > 0 {
		opts.WriteTimeout = d
	}
	if cfg.Redis.TLSEnabled {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return schedule.NewRedisLeaseClient(redis.NewClient(opts))
}

func (s *Server) runRequestForStart(sessionID string, startReq entities.StartRequest, userID string, teams []string) *entities.RunServerRequest {
	var initialMessage, agentType, credentialSource, codexAuthMode, claudeAuthMode, model, sessionTTL string
	var authProxy *bool
	var sandbox *entities.SandboxParams
	var docker *entities.DockerParams
	var unsyncedFilePaths, modelOptions []string
	if startReq.Params != nil {
		initialMessage = startReq.Params.Message
		agentType = startReq.Params.AgentType
		authProxy = startReq.Params.AuthProxy
		sandbox = startReq.Params.Sandbox
		docker = startReq.Params.Docker
		credentialSource = startReq.Params.CredentialSource
		codexAuthMode = startReq.Params.CodexAuthMode
		claudeAuthMode = startReq.Params.ClaudeAuthMode
		model = startReq.Params.Model
		if len(startReq.Params.ModelOptions) > 0 {
			modelOptions = append([]string(nil), startReq.Params.ModelOptions...)
		}
		sessionTTL = sessionuc.ResolveSessionTTL(startReq.Params)
		unsyncedFilePaths = append([]string(nil), startReq.Params.UnsyncedFilePaths...)
	}
	runReq := &entities.RunServerRequest{
		UserID: userID, Teams: teams, Scope: startReq.Scope, TeamID: startReq.TeamID,
		TriggeredUserID: startReq.TriggeredUserID,
		Pool:            requestedSessionPool(startReq), AgentType: agentType, Model: model, SessionTTL: sessionTTL, Environment: startReq.Environment,
		ModelOptions:       modelOptions,
		ProfileEnvironment: startReq.ProfileEnvironment, Tags: startReq.Tags,
		InitialMessage: initialMessage, RepoInfo: s.extractRepositoryInfo(sessionID, startReq.Tags),
		GithubToken: githubTokenForStartRequest(startReq), AuthProxy: authProxy,
		Sandbox: sandbox, Docker: docker,
		UnsyncedFilePaths: unsyncedFilePaths, CredentialSource: credentialSource,
		CodexAuthMode: codexAuthMode, ClaudeAuthMode: claudeAuthMode,
		ProfileFiles:             startReq.ProfileFiles,
		ProfileRepositories:      startReq.ProfileRepositories,
		ProfileMCPServers:        startReq.ProfileMCPServers,
		ProfileSkills:            startReq.ProfileSkills,
		ProfileCommandWrapper:    startReq.ProfileCommandWrapper,
		ProfileSystemPrompt:      startReq.ProfileSystemPrompt,
		ResolvedSessionProfileID: startReq.ResolvedSessionProfileID,
		Storages:                 append([]entities.ResolvedStorageAttachment(nil), startReq.ResolvedStorages...),
	}
	if startReq.Params != nil {
		runReq.SlackParams = startReq.Params.Slack
		runReq.ResumeFrom = startReq.Params.ResumeFrom
		runReq.InitialMessageWaitSecond = startReq.Params.InitialMessageWaitSecond
		runReq.CycleMessage = startReq.Params.CycleMessage
		runReq.CycleMaxCount = startReq.Params.CycleMaxCount
	}
	return runReq
}

func (s *Server) resolveStorageAttachments(ctx context.Context, startReq entities.StartRequest, userID, pool string) ([]entities.ResolvedStorageAttachment, error) {
	if startReq.Params == nil || len(startReq.Params.Storages) == 0 {
		return nil, nil
	}
	if s.storageRepo == nil {
		return nil, fmt.Errorf("storage repository is unavailable")
	}
	seenSources := make(map[string][]entities.StorageAttachment, len(startReq.Params.Storages))
	seenPaths := make(map[string]struct{}, len(startReq.Params.Storages))
	resolved := make([]entities.ResolvedStorageAttachment, 0, len(startReq.Params.Storages))
	for _, attachment := range startReq.Params.Storages {
		attachment.StorageID = strings.TrimSpace(attachment.StorageID)
		attachment.StoragePath = strings.Trim(strings.TrimSpace(attachment.StoragePath), "/")
		mountPath, err := normalizeStorageMountPath(attachment.MountPath)
		if attachment.StorageID == "" || err != nil {
			return nil, fmt.Errorf("storage_id and a valid non-root mount_path are required")
		}
		attachment.MountPath = mountPath
		if storageMountPathReserved(attachment.MountPath) && !attachment.Managed {
			return nil, fmt.Errorf("storage mount path %q is reserved", attachment.MountPath)
		}
		if attachment.StoragePath != "" {
			cleaned := filepath.ToSlash(filepath.Clean(attachment.StoragePath))
			if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || filepath.IsAbs(attachment.StoragePath) {
				return nil, fmt.Errorf("storage_path must be a normalized relative path")
			}
			attachment.StoragePath = cleaned
		}
		for _, existing := range seenSources[attachment.StorageID] {
			if storageSourcePathsOverlap(attachment.StoragePath, existing.StoragePath) && !managedStorageNamespaceOverlapAllowed(attachment, existing) {
				return nil, fmt.Errorf("storage path %q overlaps %q for storage %q", attachment.StoragePath, existing.StoragePath, attachment.StorageID)
			}
		}
		for existing := range seenPaths {
			if attachment.MountPath == existing || strings.HasPrefix(attachment.MountPath+"/", existing+"/") || strings.HasPrefix(existing+"/", attachment.MountPath+"/") {
				return nil, fmt.Errorf("storage mount path %q overlaps %q", attachment.MountPath, existing)
			}
		}
		storage, err := s.storageRepo.GetByID(ctx, attachment.StorageID)
		if err != nil {
			return nil, fmt.Errorf("load storage %q: %w", attachment.StorageID, err)
		}
		if storage.Scope() != startReq.Scope || (storage.Scope() == entities.ScopeUser && storage.OwnerID() != userID) || (storage.Scope() == entities.ScopeTeam && storage.TeamID() != startReq.TeamID) {
			return nil, fmt.Errorf("storage %q does not belong to the session scope", attachment.StorageID)
		}
		if storage.State() != entities.StorageStateReady {
			return nil, fmt.Errorf("storage %q is not ready", attachment.StorageID)
		}
		if storage.Pool() != "" && pool != "" && storage.Pool() != pool {
			return nil, fmt.Errorf("storage %q requires pool %q, selected pool is %q", attachment.StorageID, storage.Pool(), pool)
		}
		entry := entities.ResolvedStorageAttachment{
			StorageAttachment: attachment, Kind: storage.Kind(), Pool: storage.Pool(),
			Provider: storage.Provider(), Size: storage.Size(), Revision: storage.Revision(),
		}
		if storage.Kind() == entities.StorageKindObjectSnapshot {
			files := storage.Files()
			paths := make([]string, 0, len(files))
			selectedFiles := make(map[string]entities.StorageFile, len(files))
			for filePath, file := range files {
				if !storageAttachmentIncludesRemotePath(attachment, filePath) {
					continue
				}
				if attachment.StoragePath != "" {
					prefix := attachment.StoragePath + "/"
					if !strings.HasPrefix(filePath, prefix) {
						continue
					}
					filePath = strings.TrimPrefix(filePath, prefix)
					file.Path = filePath
				}
				if !file.Deleted {
					paths = append(paths, filePath)
					selectedFiles[filePath] = file
				}
			}
			sort.Strings(paths)
			for _, filePath := range paths {
				entry.Files = append(entry.Files, selectedFiles[filePath])
			}
		}
		seenSources[attachment.StorageID] = append(seenSources[attachment.StorageID], attachment)
		seenPaths[attachment.MountPath] = struct{}{}
		resolved = append(resolved, entry)
	}
	return resolved, nil
}

func normalizeStorageMountPath(value string) (string, error) {
	const sessionHome = "/home/agentapi"

	value = strings.TrimSpace(value)
	segments := strings.Split(filepath.ToSlash(value), "/")
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("mount path must not contain traversal segments")
		}
	}
	if value == "" {
		return "", fmt.Errorf("mount path is required")
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(sessionHome, value)
	}
	value = filepath.Clean(value)
	if value == "/" {
		return "", fmt.Errorf("mount path must not be root")
	}
	return value, nil
}

func storageSourcePathsOverlap(left, right string) bool {
	return left == "" || right == "" || left == right || strings.HasPrefix(left+"/", right+"/") || strings.HasPrefix(right+"/", left+"/")
}

func managedStorageNamespaceOverlapAllowed(left, right entities.StorageAttachment) bool {
	if left.Managed == right.Managed {
		return false
	}
	managed := left
	regular := right
	if !managed.Managed {
		managed, regular = right, left
	}
	return regular.StoragePath == "" && managedStorageNamespace(managed.StoragePath)
}

func managedStorageNamespace(storagePath string) bool {
	return storagePath == "workspace" || strings.HasPrefix(storagePath, "workspace/") || storagePath == "session-state" || strings.HasPrefix(storagePath, "session-state/")
}

// storageAttachmentIncludesRemotePath keeps system-managed state out of a
// regular root attachment. Managed attachments mount those namespaces at the
// agent-specific paths instead, so syncing them through both attachments would
// allow the two workers to overwrite or delete each other's files.
func storageAttachmentIncludesRemotePath(attachment entities.StorageAttachment, remotePath string) bool {
	if attachment.Managed || attachment.StoragePath != "" {
		return true
	}
	return !managedStorageNamespace(remotePath)
}

func storageMountPathReserved(value string) bool {
	reserved := []string{"/bin", "/boot", "/dev", "/etc", "/proc", "/sys", "/usr", "/var/run", "/session-settings", "/credentials", "/opt/ccplant", "/home/agentapi/.codex", "/home/agentapi/.claude", "/home/agentapi/.docker", "/home/agentapi/workdir"}
	for _, prefix := range reserved {
		if value == prefix || (prefix != "/home/agentapi/workdir" && strings.HasPrefix(value, prefix+"/")) {
			return true
		}
	}
	return false
}

func (s *Server) ResolveRestartSettings(ctx context.Context, id string, input entities.StartRequest, userID string, teams []string) (*sessionsettings.SessionSettings, error) {
	builder, ok := s.sessionManager.(portrepos.RemoteProvisionSettingsBuilder)
	if !ok {
		return nil, fmt.Errorf("settings reload is not supported")
	}
	return builder.BuildRemoteProvisionSettings(ctx, id, s.runRequestForStart(id, input, userID, teams))
}

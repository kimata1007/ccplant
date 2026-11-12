// Package config provides configuration management for agentapi-proxy using viper.
//
// Configuration can be loaded from:
//   - JSON files (backward compatibility)
//   - YAML files
//   - Environment variables with AGENTAPI_ prefix
//
// Environment variable examples:
//
//	AGENTAPI_START_PORT=8080
//	AGENTAPI_AUTH_ENABLED=true
//	AGENTAPI_AUTH_STATIC_ENABLED=true
//	AGENTAPI_AUTH_STATIC_HEADER_NAME=X-API-Key
//	AGENTAPI_AUTH_STATIC_KEYS_FILE=/path/to/keys.json
//	AGENTAPI_AUTH_GITHUB_ENABLED=true
//	AGENTAPI_AUTH_GITHUB_BASE_URL=https://api.github.com
//	AGENTAPI_AUTH_GITHUB_TOKEN_HEADER=Authorization
//	AGENTAPI_AUTH_GITHUB_OAUTH_CLIENT_ID=your_client_id
//	AGENTAPI_AUTH_GITHUB_OAUTH_CLIENT_SECRET=your_client_secret
//	AGENTAPI_AUTH_GITHUB_OAUTH_SCOPE=read:user read:org project
//	AGENTAPI_AUTH_GITHUB_USER_MAPPING_DEFAULT_ROLE=user
//	AGENTAPI_ENABLE_MULTIPLE_USERS=true
//	AGENTAPI_WEBHOOK_BASE_URL=https://example.com
//	AGENTAPI_WEBHOOK_GITHUB_ENTERPRISE_HOST=github.enterprise.com
//
// Configuration file search paths:
//   - Current directory
//   - $HOME/.agentapi/
//   - /etc/agentapi/
//
// Configuration file names: config.json, config.yaml, config.yml
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	sigsyaml "sigs.k8s.io/yaml"
)

// AuthConfig represents authentication configuration
type AuthConfig struct {
	// AdminKey enables a single non-expiring admin API key via the
	// X-API-Key header. Prefer AGENTAPI_AUTH_ADMIN_KEY over config files so
	// the value never lands in version control.
	AdminKey       string                    `json:"admin_key,omitempty" mapstructure:"admin_key"`
	BootstrapAdmin *BootstrapAdminAuthConfig `json:"bootstrap_admin,omitempty" mapstructure:"bootstrap_admin"`
	GitHub         *GitHubAuthConfig         `json:"github,omitempty" mapstructure:"github"`
}

// BootstrapAdminAuthConfig provides a break-glass administrator identity that
// is available before any external authentication provider is configured.
type BootstrapAdminAuthConfig struct {
	Enabled  bool   `json:"enabled" mapstructure:"enabled"`
	UserID   string `json:"user_id" mapstructure:"user_id"`
	Username string `json:"username" mapstructure:"username"`
	Token    string `json:"token" mapstructure:"token"`
}

// GitHubAuthConfig represents GitHub OAuth authentication
type GitHubAuthConfig struct {
	Enabled      bool               `json:"enabled" mapstructure:"enabled"`
	ConnectionID string             `json:"connection_id,omitempty" mapstructure:"connection_id"`
	BaseURL      string             `json:"base_url" mapstructure:"base_url"`
	TokenHeader  string             `json:"token_header" mapstructure:"token_header"`
	UserMapping  GitHubUserMapping  `json:"user_mapping" mapstructure:"user_mapping"`
	OAuth        *GitHubOAuthConfig `json:"oauth,omitempty" mapstructure:"oauth"`
	// TeamDiscoveryPatterns participate in membership fetching but not role mapping.
	TeamDiscoveryPatterns []string `json:"-" mapstructure:"-"`
}

// TeamDiscoveryRule creates/adopts a ccplant team when a GitHub membership
// matches TeamPattern. The initial implementation preserves the matched
// organization/team-slug as the team key.
type TeamDiscoveryRule struct {
	TeamPattern string `json:"team_pattern" mapstructure:"team_pattern" yaml:"team_pattern"`
}

// GitHubOAuthConfig represents GitHub OAuth2 configuration
type GitHubOAuthConfig struct {
	ClientID     string `json:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`
	Scope        string `json:"scope" mapstructure:"scope"`
	BaseURL      string `json:"base_url,omitempty" mapstructure:"base_url"`
}

// GitHubUserMapping represents user role mapping configuration
type GitHubUserMapping struct {
	DefaultRole           string                  `json:"default_role" mapstructure:"default_role" yaml:"default_role"`
	DefaultPermissions    []string                `json:"default_permissions" mapstructure:"default_permissions" yaml:"default_permissions"`
	AllowUsersWithoutTeam bool                    `json:"allow_users_without_team" mapstructure:"allow_users_without_team" yaml:"allow_users_without_team"`
	TeamRoleMapping       map[string]TeamRoleRule `json:"team_role_mapping" mapstructure:"team_role_mapping" yaml:"team_role_mapping"`
}

// TeamRoleRule represents a team-based role rule
type TeamRoleRule struct {
	Role        string   `json:"role" mapstructure:"role" yaml:"role"`
	Permissions []string `json:"permissions" mapstructure:"permissions" yaml:"permissions"`
	EnvFile     string   `json:"env_file,omitempty" mapstructure:"env_file" yaml:"env_file"`
}

// RoleEnvFilesConfig represents role-based environment files configuration
type RoleEnvFilesConfig struct {
	// Enabled enables role-based environment file loading
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// Path is the directory path containing role-specific .env files
	Path string `json:"path" mapstructure:"path"`
	// LoadDefault loads default.env before role-specific env file
	LoadDefault bool `json:"load_default" mapstructure:"load_default"`
}

// Toleration represents a Kubernetes toleration for session pods
type Toleration struct {
	// Key is the taint key that the toleration applies to
	Key string `json:"key" mapstructure:"key" yaml:"key"`
	// Operator represents a key's relationship to the value (Equal or Exists)
	Operator string `json:"operator" mapstructure:"operator" yaml:"operator"`
	// Value is the taint value the toleration matches to
	Value string `json:"value" mapstructure:"value" yaml:"value"`
	// Effect indicates the taint effect to match (NoSchedule, PreferNoSchedule, NoExecute)
	Effect string `json:"effect" mapstructure:"effect" yaml:"effect"`
	// TolerationSeconds is the period of time the toleration tolerates the taint (for NoExecute)
	TolerationSeconds *int64 `json:"toleration_seconds,omitempty" mapstructure:"toleration_seconds" yaml:"toleration_seconds"`
}

// ScheduleWorkerConfig represents schedule worker configuration
type ScheduleWorkerConfig struct {
	// Enabled enables the schedule worker
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// CheckInterval is how often to check for due schedules (e.g., "30s", "1m")
	CheckInterval string `json:"check_interval" mapstructure:"check_interval"`
	// Namespace is the Kubernetes namespace for schedule resources
	Namespace string `json:"namespace" mapstructure:"namespace"`
	// LeaseDuration is the duration that non-leader candidates will wait to force acquire leadership
	LeaseDuration string `json:"lease_duration" mapstructure:"lease_duration"`
	// RenewDeadline is the duration that the acting master will retry refreshing leadership before giving up
	RenewDeadline string `json:"renew_deadline" mapstructure:"renew_deadline"`
	// RetryPeriod is the duration the LeaderElector clients should wait between tries of actions
	RetryPeriod string `json:"retry_period" mapstructure:"retry_period"`
}

// SlackbotCleanupWorkerConfig represents Slackbot session cleanup worker configuration.
// The worker deletes Slackbot sessions whose processing ended more than SessionTTL ago.
type SlackbotCleanupWorkerConfig struct {
	// Enabled enables the Slackbot cleanup worker
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// CheckInterval is how often to scan for stale sessions (e.g., "1h", "30m")
	CheckInterval string `json:"check_interval" mapstructure:"check_interval"`
	// SessionTTL is the duration after processing ends before a session is deleted (e.g., "72h")
	SessionTTL string `json:"session_ttl" mapstructure:"session_ttl"`
	// SessionTTLCheckInterval is how often to scan for non-Slackbot sessions that have an
	// explicit agentapi.proxy/session-ttl annotation. This can be much shorter than
	// CheckInterval to support short-lived sessions. Default: "1m"
	SessionTTLCheckInterval string `json:"session_ttl_check_interval" mapstructure:"session_ttl_check_interval"`
	// DryRun disables actual deletion; stale sessions are only logged.
	// Useful for verifying TTL settings before enabling real cleanup.
	DryRun bool `json:"dry_run" mapstructure:"dry_run"`
	// LeaseDuration is the duration that non-leader candidates will wait to force acquire leadership
	LeaseDuration string `json:"lease_duration" mapstructure:"lease_duration"`
	// RenewDeadline is the duration that the acting master will retry refreshing leadership before giving up
	RenewDeadline string `json:"renew_deadline" mapstructure:"renew_deadline"`
	// RetryPeriod is the duration the LeaderElector clients should wait between tries of actions
	RetryPeriod string `json:"retry_period" mapstructure:"retry_period"`
}

// SessionRouteReconcilerConfig configures the API-side reconciler that
// finalizes session routes whose owning manager or runner is gone and garbage
// collects session configurations that no longer belong to any session.
type SessionRouteReconcilerConfig struct {
	// Enabled starts the reconciler on the elected API replica.
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// DryRun only logs what would be finalized.
	DryRun bool `json:"dry_run" mapstructure:"dry_run"`
	// Interval between reconciliation passes (e.g. "5m").
	Interval string `json:"interval" mapstructure:"interval"`
	// OrphanGrace protects routes whose status changed recently (e.g. "15m").
	OrphanGrace string `json:"orphan_grace" mapstructure:"orphan_grace"`
	// StuckDeletionGrace finalizes routes stuck terminating/delete_failed (e.g. "45m").
	StuckDeletionGrace string `json:"stuck_deletion_grace" mapstructure:"stuck_deletion_grace"`
	// RuntimeDisconnectGrace reclaims a TTL session whose runtime stayed disconnected this long (e.g. "10m").
	RuntimeDisconnectGrace string `json:"runtime_disconnect_grace" mapstructure:"runtime_disconnect_grace"`
	// ConfigurationOrphanGrace deletes unowned configurations idle for this long (e.g. "45m").
	ConfigurationOrphanGrace string `json:"configuration_orphan_grace" mapstructure:"configuration_orphan_grace"`
}

// StockInventoryWorkerConfig represents stock inventory worker configuration.
// The worker ensures a target number of pre-warmed stock sessions are always available.
// Note: Sandbox (network filter) and scia sidecar are now always enabled.
type StockInventoryWorkerConfig struct {
	// Enabled controls whether the worker runs. Default: false (opt-in).
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// CheckInterval is how often to check and replenish stock sessions. Default: "30s".
	CheckInterval string `json:"check_interval" mapstructure:"check_interval"`
	// TargetCount is the desired number of stock sessions to maintain. Default: 2.
	TargetCount int `json:"target_count" mapstructure:"target_count"`
	// DockerEnabled controls whether stock sessions include the Docker-in-Docker sidecar.
	DockerEnabled bool `json:"docker_enabled" mapstructure:"docker_enabled"`
	// Pools optionally configures multiple stock pools. When set, each pool is
	// replenished independently; otherwise the legacy single-pool fields above
	// are used.
	Pools []StockInventoryPoolConfig `json:"pools" mapstructure:"pools"`
	// Namespace overrides the Kubernetes namespace (falls back to KubernetesSession.Namespace).
	Namespace string `json:"namespace" mapstructure:"namespace"`
	// Leader election timings.
	LeaseDuration string `json:"lease_duration" mapstructure:"lease_duration"`
	RenewDeadline string `json:"renew_deadline" mapstructure:"renew_deadline"`
	RetryPeriod   string `json:"retry_period" mapstructure:"retry_period"`
}

// StockInventoryPoolConfig represents one stock inventory capability pool.
// Note: Sandbox (network filter) and scia sidecar are now always enabled.
// Only DockerEnabled remains configurable.
type StockInventoryPoolConfig struct {
	// Name is the logical session pool claimed directly by idle runners.
	Name string `json:"name" mapstructure:"name"`
	// TargetCount is the desired number of stock sessions for this capability pool.
	TargetCount int `json:"target_count" mapstructure:"target_count"`
	// DockerEnabled controls whether stock sessions include the Docker-in-Docker sidecar.
	DockerEnabled bool `json:"docker_enabled" mapstructure:"docker_enabled"`
}

// WebhookConfig represents webhook configuration
type WebhookConfig struct {
	// BaseURL is the base URL for webhook endpoints (e.g., "https://example.com")
	// If not set, the URL will be auto-detected from incoming request headers
	BaseURL string `json:"base_url" mapstructure:"base_url"`
	// GitHubEnterpriseHost is the default GitHub Enterprise host for webhook matching
	// When set, webhooks without explicit enterprise_url will match against this host
	// Example: "github.enterprise.com" (hostname only, without https://)
	GitHubEnterpriseHost string `json:"github_enterprise_host" mapstructure:"github_enterprise_host"`
}

// SciaConfig represents scia OAuth broker/proxy integration configuration.
type SciaConfig struct {
	// Enabled controls whether scia integration is exposed to clients and injected into sessions.
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// PublicBaseURL is the browser-reachable origin that serves /oauth and /_scia.
	// When empty, UI clients can still use same-origin relative OAuth URLs.
	PublicBaseURL string `json:"public_base_url" mapstructure:"public_base_url"`
	// OAuthInternalURL is the proxy-reachable scia OAuth server origin used for metadata.
	OAuthInternalURL string `json:"oauth_internal_url" mapstructure:"oauth_internal_url"`
	// ProxyURL is the forward proxy URL used by session Pods for outbound Google API calls.
	ProxyURL string `json:"proxy_url" mapstructure:"proxy_url"`
	// Credential is the scia credential ID used for Google OAuth, e.g. "takutakahashi.google".
	Credential string `json:"credential" mapstructure:"credential"`
	// UserNamespace is the scia user namespace used by the authorization-url endpoint.
	UserNamespace string `json:"user_namespace" mapstructure:"user_namespace"`
	// NoProxy is appended to the session NO_PROXY value when ProxyURL is injected.
	NoProxy string `json:"no_proxy" mapstructure:"no_proxy"`
	// SessionSidecarEnabled runs scia as a sidecar in each session Pod.
	SessionSidecarEnabled bool `json:"session_sidecar_enabled" mapstructure:"session_sidecar_enabled"`
	// SessionSidecarImage is the scia image used by the session sidecar.
	SessionSidecarImage string `json:"session_sidecar_image" mapstructure:"session_sidecar_image"`
	// SessionSidecarConfigImage is the shell-capable image used to render scia sidecar config.
	SessionSidecarConfigImage string `json:"session_sidecar_config_image" mapstructure:"session_sidecar_config_image"`
	// SessionSidecarPort is the localhost HTTP proxy port exposed by the sidecar.
	SessionSidecarPort int `json:"session_sidecar_port" mapstructure:"session_sidecar_port"`
	// GoogleHosts is the list of hosts where the sidecar injects the Google access token.
	GoogleHosts []string `json:"google_hosts" mapstructure:"google_hosts"`
	// GooglePaths is the list of paths where the sidecar injects the Google access token.
	GooglePaths []string `json:"google_paths" mapstructure:"google_paths"`
	// TodoistCredential is the scia credential ID used for Todoist OAuth, e.g. "takutakahashi.todoist".
	TodoistCredential string `json:"todoist_credential" mapstructure:"todoist_credential"`
	// TodoistHosts is the list of hosts where the sidecar injects the Todoist access token.
	TodoistHosts []string `json:"todoist_hosts" mapstructure:"todoist_hosts"`
	// TodoistPaths is the list of paths where the sidecar injects the Todoist access token.
	TodoistPaths []string `json:"todoist_paths" mapstructure:"todoist_paths"`
}

// DefaultKubernetesSessionImage is the immutable agent-assets revision used by
// Kubernetes session Pods. Application releases supply the ccplant CLI from
// the session-manager image independently.
const DefaultKubernetesSessionImage = "ghcr.io/ccplant/ccplant-agent:assets-8f5c4685e7ee739e600356c3e7b37900"

// KubernetesSessionConfig represents Kubernetes session manager configuration
type KubernetesSessionConfig struct {
	// Namespace is the Kubernetes namespace where session resources are created
	Namespace string `json:"namespace" mapstructure:"namespace"`
	// Image is the container image for session pods
	Image string `json:"image" mapstructure:"image"`
	// CLIImage supplies /usr/local/bin/ccplant through an initContainer. Empty disables injection.
	CLIImage string `json:"cli_image" mapstructure:"cli_image"`
	// ImagePullPolicy is the image pull policy for session pods
	ImagePullPolicy string `json:"image_pull_policy" mapstructure:"image_pull_policy"`
	// ServiceAccount is the service account for session pods
	ServiceAccount string `json:"service_account" mapstructure:"service_account"`
	// DisableServiceLinks prevents Kubernetes Service environment variables from being injected into session pods.
	DisableServiceLinks bool `json:"disable_service_links" mapstructure:"disable_service_links"`
	// DisableServiceAccountToken prevents Kubernetes service account credentials from being mounted into session pods.
	DisableServiceAccountToken bool `json:"disable_service_account_token" mapstructure:"disable_service_account_token"`
	// BasePort is the port that agentapi listens on in session pods
	BasePort int `json:"base_port" mapstructure:"base_port"`
	// CPURequest is the CPU request for session pods
	CPURequest string `json:"cpu_request" mapstructure:"cpu_request"`
	// CPULimit is the CPU limit for session pods
	CPULimit string `json:"cpu_limit" mapstructure:"cpu_limit"`
	// MemoryRequest is the memory request for session pods
	MemoryRequest string `json:"memory_request" mapstructure:"memory_request"`
	// MemoryLimit is the memory limit for session pods
	MemoryLimit string `json:"memory_limit" mapstructure:"memory_limit"`
	// ExecutorEnabled runs model-generated shell commands in a memory-isolated sidecar.
	ExecutorEnabled       bool   `json:"executor_enabled" mapstructure:"executor_enabled"`
	ExecutorCPURequest    string `json:"executor_cpu_request" mapstructure:"executor_cpu_request"`
	ExecutorCPULimit      string `json:"executor_cpu_limit" mapstructure:"executor_cpu_limit"`
	ExecutorMemoryRequest string `json:"executor_memory_request" mapstructure:"executor_memory_request"`
	ExecutorMemoryLimit   string `json:"executor_memory_limit" mapstructure:"executor_memory_limit"`
	// PVCEnabled enables PersistentVolumeClaim for session pods workdir
	// When disabled, EmptyDir is used instead (data is not persisted across pod restarts)
	PVCEnabled *bool `json:"pvc_enabled,omitempty" mapstructure:"pvc_enabled"`
	// PVCStorageClass is the storage class for session PVCs
	PVCStorageClass string `json:"pvc_storage_class" mapstructure:"pvc_storage_class"`
	// PVCStorageSize is the storage size for session PVCs
	PVCStorageSize string `json:"pvc_storage_size" mapstructure:"pvc_storage_size"`
	// PodStartTimeout is the timeout in seconds for pod startup
	PodStartTimeout int `json:"pod_start_timeout" mapstructure:"pod_start_timeout"`
	// PodStopTimeout is the timeout in seconds for pod termination
	PodStopTimeout int `json:"pod_stop_timeout" mapstructure:"pod_stop_timeout"`
	// ProvisionerToken authenticates session Pod calls to the internal
	// provisioner API.
	ProvisionerToken string `json:"provisioner_token" mapstructure:"provisioner_token"`
	// ProvisionerProxyURL is the base URL session Pods use to reach this proxy.
	ProvisionerProxyURL string `json:"provisioner_proxy_url" mapstructure:"provisioner_proxy_url"`
	// GitHubSecretName is the name of the Kubernetes Secret containing GitHub authentication credentials
	// This Secret is used by the clone-repo init container for repository cloning
	// Expected keys: GITHUB_TOKEN, GITHUB_APP_ID, GITHUB_APP_PEM, GITHUB_INSTALLATION_ID
	GitHubSecretName string `json:"github_secret_name" mapstructure:"github_secret_name"`
	// GitHubConfigSecretName is the name of the Kubernetes Secret containing GitHub configuration (non-auth)
	// This Secret contains GITHUB_API and GITHUB_URL for GitHub Enterprise Server support
	// It is kept separate from GitHubSecretName so that params.github_token can override authentication
	// without losing Enterprise Server URL settings
	GitHubConfigSecretName string `json:"github_config_secret_name" mapstructure:"github_config_secret_name"`
	// ConfigFile is the path to an external configuration file for kubernetes session settings
	// This file can contain node_selector and tolerations settings
	ConfigFile string `json:"config_file,omitempty" mapstructure:"config_file"`
	// SessionPodTemplateFile is the path to a PodTemplateSpec YAML file merged into every session Pod.
	SessionPodTemplateFile string `json:"session_pod_template_file,omitempty" mapstructure:"session_pod_template_file"`
	// NodeSelector is a selector which must be true for the pod to fit on a node
	// Example: {"disktype": "ssd", "kubernetes.io/arch": "amd64"}
	NodeSelector map[string]string `json:"node_selector,omitempty" mapstructure:"node_selector" yaml:"node_selector"`
	// Affinity configures Kubernetes affinity rules for session pods.
	Affinity map[string]interface{} `json:"affinity,omitempty" mapstructure:"affinity" yaml:"affinity"`
	// Tolerations are tolerations for session pods to schedule onto nodes with matching taints
	Tolerations []Toleration `json:"tolerations,omitempty" mapstructure:"tolerations" yaml:"tolerations"`

	// SettingsBaseSecret is the single base Kubernetes Secret shared by all sessions.
	// It contains settings.json in the agentapi settings format (env_vars, auth_mode, bedrock,
	// mcp_servers, marketplaces, enabled_plugins, hooks) and is merged at the lowest priority
	// level during session settings generation. Team and user settings can override it.
	SettingsBaseSecret string `json:"settings_base_secret" mapstructure:"settings_base_secret"`
	// MCPServersBaseSecret is the legacy organization-wide MCP Secret. It contains
	// mcp-servers.json in the {"mcpServers": {...}} format. Keep reading it as a
	// lower-priority compatibility layer while installations migrate to settings.json.
	MCPServersBaseSecret string `json:"mcp_servers_base_secret" mapstructure:"mcp_servers_base_secret"`
	// MCPServersBaseFile is an optional mounted copy of mcp-servers.json. It lets
	// libSQL-only API Pods backfill a Kubernetes Secret without API credentials.
	MCPServersBaseFile string `json:"mcp_servers_base_file" mapstructure:"mcp_servers_base_file"`

	// OpenTelemetry Collector configuration
	// OtelCollectorEnabled enables OpenTelemetry Collector sidecar for metrics collection
	OtelCollectorEnabled bool `json:"otel_collector_enabled" mapstructure:"otel_collector_enabled"`
	// OtelCollectorScrapeInterval is the scrape interval for Claude Code metrics
	OtelCollectorScrapeInterval string `json:"otel_collector_scrape_interval" mapstructure:"otel_collector_scrape_interval"`
	// OtelCollectorClaudeCodePort is the port where Claude Code exposes metrics
	OtelCollectorClaudeCodePort int `json:"otel_collector_claude_code_port" mapstructure:"otel_collector_claude_code_port"`
	// OtelCollectorExporterPort is the port where otelcol exposes labeled metrics
	OtelCollectorExporterPort int `json:"otel_collector_exporter_port" mapstructure:"otel_collector_exporter_port"`

	// Slack Integration configuration
	// SlackBotTokenSecretName is the Kubernetes Secret name containing the Slack bot token
	// Used by agent-provisioner to pass the token to the claude-posts subprocess
	SlackBotTokenSecretName string `json:"slack_bot_token_secret_name" mapstructure:"slack_bot_token_secret_name"`
	// SlackBotTokenSecretKey is the key within the Secret that holds the Slack bot token
	// Defaults to "bot-token"
	SlackBotTokenSecretKey string `json:"slack_bot_token_secret_key" mapstructure:"slack_bot_token_secret_key"`

	// NetworkFilterImage is the container image for the iptables rule generation init
	// container and the network-filter sidecar. Defaults to ghcr.io/takutakahashi/nfa:0.12.4.
	// The init container reads the generated policy config and runs "nfa setup-iptables --output";
	// the sidecar runs "nfa proxy --deferred-policy".
	NetworkFilterImage string `json:"network_filter_image" mapstructure:"network_filter_image"`

	// Network filter sidecar resource configuration
	NetworkFilterCPURequest    string `json:"network_filter_cpu_request" mapstructure:"network_filter_cpu_request"`
	NetworkFilterCPULimit      string `json:"network_filter_cpu_limit" mapstructure:"network_filter_cpu_limit"`
	NetworkFilterMemoryRequest string `json:"network_filter_memory_request" mapstructure:"network_filter_memory_request"`
	NetworkFilterMemoryLimit   string `json:"network_filter_memory_limit" mapstructure:"network_filter_memory_limit"`

	// Network filter init container resource configuration
	NetworkFilterInitCPURequest    string `json:"network_filter_init_cpu_request" mapstructure:"network_filter_init_cpu_request"`
	NetworkFilterInitCPULimit      string `json:"network_filter_init_cpu_limit" mapstructure:"network_filter_init_cpu_limit"`
	NetworkFilterInitMemoryRequest string `json:"network_filter_init_memory_request" mapstructure:"network_filter_init_memory_request"`
	NetworkFilterInitMemoryLimit   string `json:"network_filter_init_memory_limit" mapstructure:"network_filter_init_memory_limit"`

	// DinD (Docker in Docker) sidecar configuration.
	// Sessions with docker.enabled=true in their params get a privileged DinD sidecar
	// and DOCKER_HOST set so the main container can run docker commands.

	// DinDImage is the container image for the DinD sidecar.
	// Defaults to "docker:dind" if not specified.
	DinDImage string `json:"dind_image" mapstructure:"dind_image"`

	// DinD sidecar resource configuration
	DinDCPURequest    string `json:"dind_cpu_request" mapstructure:"dind_cpu_request"`
	DinDCPULimit      string `json:"dind_cpu_limit" mapstructure:"dind_cpu_limit"`
	DinDMemoryRequest string `json:"dind_memory_request" mapstructure:"dind_memory_request"`
	DinDMemoryLimit   string `json:"dind_memory_limit" mapstructure:"dind_memory_limit"`
}

// S3StorageConfig represents shared S3 storage configuration.
type S3StorageConfig struct {
	// Bucket is the S3 bucket name (required)
	Bucket string `json:"bucket" mapstructure:"bucket"`
	// Region is the AWS region (optional, uses AWS default config if empty)
	Region string `json:"region" mapstructure:"region"`
	// Prefix is the key prefix for stored objects.
	Prefix string `json:"prefix" mapstructure:"prefix"`
	// Endpoint is a custom S3-compatible endpoint URL (e.g., for rustfs or other S3-compatible services)
	Endpoint string `json:"endpoint" mapstructure:"endpoint"`
	// AccessKeyID and SecretAccessKey optionally isolate S3-compatible storage
	// credentials from the process-wide AWS credential chain (for example KMS).
	AccessKeyID     string `json:"access_key_id" mapstructure:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key" mapstructure:"secret_access_key"`
}

// SessionPersistenceConfig stores ACP conversation snapshots. "volume" writes
// to each Kubernetes session's workdir PVC; "s3" uses an S3-compatible service.
type SessionPersistenceConfig struct {
	Backend      string           `json:"backend" mapstructure:"backend"`
	Path         string           `json:"path" mapstructure:"path"`
	SuspendAfter string           `json:"suspend_after" mapstructure:"suspend_after"`
	S3           *S3StorageConfig `json:"s3,omitempty" mapstructure:"s3"`
}

// SessionManagerConfig holds configuration for the session manager forwarding endpoint.
// When enabled, External Session Manager (small-cluster mode) accepts pre-built SessionSettings from a
// trusted upstream proxy (親プロキシ) and creates sessions without requiring local secrets.
type SessionManagerConfig struct {
	// Enabled enables the /api/v1/sessions forwarding endpoint.
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// HMACSecret is the shared HMAC-SHA256 secret used to verify request signatures.
	// Every inbound request must carry X-Hub-Signature-256: sha256=<hex> computed
	// over the raw request body with this secret.
	// Can also be set via SESSION_MANAGER_HMAC_SECRET environment variable.
	HMACSecret string `json:"hmac_secret" mapstructure:"hmac_secret"`
	// UpstreamURL is the 親プロキシ URL to poll for external session allocations.
	// Can also be set via SESSION_MANAGER_UPSTREAM_URL.
	UpstreamURL string `json:"upstream_url" mapstructure:"upstream_url"`
	// ConnectionToken authenticates this manager to 親プロキシ's allocator endpoint.
	// Can also be set via SESSION_MANAGER_CONNECTION_TOKEN.
	ConnectionToken string `json:"connection_token" mapstructure:"connection_token"`
	// ID identifies this manager in the cluster-wide registry.
	ID string `json:"id" mapstructure:"id"`
	// RunnerPool enables GitHub Actions-style runner claim mode for stock pods.
	RunnerPool string `json:"runner_pool" mapstructure:"runner_pool"`
	// APIURL is the private peer API URL. The public API process uses it to call
	// the isolated session manager, while an external session-manager process
	// uses it as the local target for outbound control-tunnel requests.
	// It is intentionally distinct from UpstreamURL, which identifies the parent
	// control plane.
	APIURL string `json:"api_url" mapstructure:"api_url"`
	// LocalURL is the in-cluster URL of this session-manager process. Session
	// Pods use it even when APIURL or the runner upstream targets another plane.
	LocalURL string `json:"local_url" mapstructure:"local_url"`
	// APIToken authenticates outbound API -> session-manager requests.
	APIToken string `json:"api_token" mapstructure:"api_token"`
	// InternalAPIToken authenticates inbound requests to the private manager API.
	InternalAPIToken string `json:"internal_api_token" mapstructure:"internal_api_token"`
	// AutoUpgrade lets a Kubernetes manager roll its own Deployment forward to
	// the version advertised by the connected parent proxy.
	AutoUpgrade bool `json:"auto_upgrade" mapstructure:"auto_upgrade"`
	// UpgradeVersionURL is an optional HTTP endpoint polled by a standalone
	// Kubernetes manager. It must return JSON containing a "version" field.
	// When ConnectionToken is configured, the poller sends it as a Bearer token.
	UpgradeVersionURL string                                  `json:"upgrade_version_url" mapstructure:"upgrade_version_url"`
	DeploymentName    string                                  `json:"deployment_name" mapstructure:"deployment_name"`
	ImageRepository   string                                  `json:"image_repository" mapstructure:"image_repository"`
	CurrentVersion    string                                  `json:"current_version" mapstructure:"current_version"`
	Allocation        SessionManagerAllocationConfig          `json:"allocation" mapstructure:"allocation"`
	Builtin           SessionManagerBuiltinRegistrationConfig `json:"builtin" mapstructure:"builtin"`
}

type SessionManagerAllocationConfig struct {
	LeaseDuration string `json:"lease_duration" mapstructure:"lease_duration"`
	RenewDeadline string `json:"renew_deadline" mapstructure:"renew_deadline"`
	RetryPeriod   string `json:"retry_period" mapstructure:"retry_period"`
	LeaseName     string `json:"lease_name" mapstructure:"lease_name"`
}

type SessionManagerBuiltinBindingConfig struct {
	SubjectType string `json:"subject_type" mapstructure:"subject_type"`
	Role        string `json:"role" mapstructure:"role"`
}

type SessionManagerBuiltinPoolConfig struct {
	Name         string                             `json:"name" mapstructure:"name"`
	Labels       map[string]string                  `json:"labels" mapstructure:"labels"`
	LabelsJSON   string                             `json:"labels_json" mapstructure:"labels_json"`
	ExplicitOnly bool                               `json:"explicit_only" mapstructure:"explicit_only"`
	Priority     int                                `json:"priority" mapstructure:"priority"`
	Binding      SessionManagerBuiltinBindingConfig `json:"binding" mapstructure:"binding"`
}

type SessionManagerBuiltinRegistrationConfig struct {
	Enabled         bool                            `json:"enabled" mapstructure:"enabled"`
	ManagerID       string                          `json:"manager_id" mapstructure:"manager_id"`
	Name            string                          `json:"name" mapstructure:"name"`
	ConnectionToken string                          `json:"connection_token" mapstructure:"connection_token"`
	Pool            SessionManagerBuiltinPoolConfig `json:"pool" mapstructure:"pool"`
}

// WorkerConfig contains the only control-plane dependency of the worker.
// Worker persistence and leader election use KVStore and Redis respectively.
type WorkerConfig struct {
	ControlAPIURL            string `json:"control_api_url" mapstructure:"control_api_url"`
	ControlAPIToken          string `json:"control_api_token" mapstructure:"control_api_token"`
	ExecutionTokenSigningKey string `json:"execution_token_signing_key" mapstructure:"execution_token_signing_key"`
	SessionAPIURL            string `json:"session_api_url" mapstructure:"session_api_url"`
}

// RedisConfig holds configuration for the optional Redis backend used for
// cross-pod session status synchronisation.
type RedisConfig struct {
	// Addr is the Redis server address in "host:port" format (e.g. "redis:6379").
	// When empty, a no-op in-memory fallback is used and no real connection is made.
	Addr string `json:"addr" mapstructure:"addr"`
	// Password is the Redis AUTH password (optional).
	Password string `json:"password" mapstructure:"password"`
	// DB is the Redis database index to use (default: 0).
	DB int `json:"db" mapstructure:"db"`
	// TLSEnabled enables TLS for the Redis connection.
	TLSEnabled bool `json:"tls_enabled" mapstructure:"tls_enabled"`
	// DialTimeout is the timeout for establishing a connection (e.g. "5s").
	DialTimeout string `json:"dial_timeout" mapstructure:"dial_timeout"`
	// ReadTimeout is the timeout for socket reads (e.g. "3s").
	ReadTimeout string `json:"read_timeout" mapstructure:"read_timeout"`
	// WriteTimeout is the timeout for socket writes (e.g. "3s").
	WriteTimeout string `json:"write_timeout" mapstructure:"write_timeout"`
	// SessionControlPoolSize limits concurrent short session-control commands.
	SessionControlPoolSize int `json:"session_control_pool_size" mapstructure:"session_control_pool_size"`
	// SessionControlBlockingPoolSize limits concurrent session-control long polls.
	SessionControlBlockingPoolSize int `json:"session_control_blocking_pool_size" mapstructure:"session_control_blocking_pool_size"`
}

// KVStoreConfig configures persistence for application data represented as
// Kubernetes Secrets and ConfigMaps by the repository layer.
type KVStoreBackendConfig struct {
	Backend     string                  `json:"backend" mapstructure:"backend"`
	DatabaseURL string                  `json:"database_url" mapstructure:"database_url"`
	AuthToken   string                  `json:"auth_token" mapstructure:"auth_token"`
	Encryption  KVStoreEncryptionConfig `json:"encryption" mapstructure:"encryption"`
}

type KVStoreReplicationConfig struct {
	Mode string `json:"mode" mapstructure:"mode"`
}

type KVStoreEncryptionConfig struct {
	Provider              string            `json:"provider" mapstructure:"provider"`
	ActiveKeyID           string            `json:"active_key_id" mapstructure:"active_key_id"`
	KMSKeyID              string            `json:"kms_key_id" mapstructure:"kms_key_id"`
	KMSRegion             string            `json:"kms_region" mapstructure:"kms_region"`
	Keys                  map[string]string `json:"keys" mapstructure:"keys"`
	BranchCacheTTLSeconds int               `json:"branch_cache_ttl_seconds" mapstructure:"branch_cache_ttl_seconds"`
	BranchCacheMaxEntries int               `json:"branch_cache_max_entries" mapstructure:"branch_cache_max_entries"`
}

// EffectiveKeys returns the configured keyring, expanding the single-key KMS
// form used by Kubernetes Secret references when a full key map is absent.
func (c KVStoreEncryptionConfig) EffectiveKeys() map[string]string {
	if len(c.Keys) > 0 {
		return c.Keys
	}
	if c.ActiveKeyID == "" || strings.TrimSpace(c.KMSKeyID) == "" {
		return nil
	}
	return map[string]string{c.ActiveKeyID: c.KMSKeyID}
}

type KVStoreConfig struct {
	// Legacy single-backend fields. They remain supported as primary-only configuration.
	Namespace   string                   `json:"namespace" mapstructure:"namespace"`
	Backend     string                   `json:"backend" mapstructure:"backend"`
	DatabaseURL string                   `json:"database_url" mapstructure:"database_url"`
	AuthToken   string                   `json:"auth_token" mapstructure:"auth_token"`
	Primary     *KVStoreBackendConfig    `json:"primary" mapstructure:"primary"`
	Secondary   *KVStoreBackendConfig    `json:"secondary" mapstructure:"secondary"`
	Replication KVStoreReplicationConfig `json:"replication" mapstructure:"replication"`
	Encryption  KVStoreEncryptionConfig  `json:"encryption" mapstructure:"encryption"`
}

// UsageConfig configures the dedicated libSQL database used for usage events.
// It is intentionally independent from KVStoreConfig.
type UsageConfig struct {
	Enabled     bool   `json:"enabled" mapstructure:"enabled"`
	DatabaseURL string `json:"database_url" mapstructure:"database_url"`
	AuthToken   string `json:"auth_token" mapstructure:"auth_token"`
}

// SessionCountConfig configures append-only session status usage events.
type SessionCountConfig struct {
	Enabled     bool   `json:"enabled" mapstructure:"enabled"`
	Backend     string `json:"backend" mapstructure:"backend"`
	DatabaseURL string `json:"database_url" mapstructure:"database_url"`
	AuthToken   string `json:"auth_token" mapstructure:"auth_token"`
}

// Config represents the proxy configuration
type TaskQueueConfig struct {
	Enabled            bool `json:"enabled" mapstructure:"enabled"`
	MaxStartingGlobal  int  `json:"max_starting_global" mapstructure:"max_starting_global"`
	MaxStartingPerUser int  `json:"max_starting_per_user" mapstructure:"max_starting_per_user"`
	MaxStartingPerTeam int  `json:"max_starting_per_team" mapstructure:"max_starting_per_team"`
	MaxLivePerUser     int  `json:"max_live_sessions_per_user" mapstructure:"max_live_sessions_per_user"`
	MaxLivePerTeam     int  `json:"max_live_sessions_per_team" mapstructure:"max_live_sessions_per_team"`
	MaxPending         int  `json:"max_pending" mapstructure:"max_pending"`
	RetentionDays      int  `json:"retention_days" mapstructure:"retention_days"`
	TeamRetentionDays  int  `json:"team_retention_days" mapstructure:"team_retention_days"`
}

type Config struct {
	TaskQueue TaskQueueConfig `json:"task_queue" mapstructure:"task_queue"`
	// BinaryPath is the ccplant executable used by generated hooks and child processes.
	BinaryPath string `json:"binary_path" mapstructure:"binary_path"`
	// Auth represents authentication configuration
	Auth AuthConfig `json:"auth" mapstructure:"auth"`
	// TeamDiscovery contains connection-aware GitHub team discovery rules.
	TeamDiscovery []TeamDiscoveryRule `json:"team_discovery" mapstructure:"team_discovery"`
	// AuthConfigFile is the path to an external auth configuration file (e.g., from ConfigMap)
	AuthConfigFile string `json:"auth_config_file" mapstructure:"auth_config_file"`
	// RoleEnvFiles is the configuration for role-based environment files
	RoleEnvFiles RoleEnvFilesConfig `json:"role_env_files" mapstructure:"role_env_files"`
	// KubernetesSession is the configuration for Kubernetes-based session management
	KubernetesSession KubernetesSessionConfig `json:"kubernetes_session" mapstructure:"kubernetes_session"`
	// ScheduleWorker is the configuration for the schedule worker
	ScheduleWorker ScheduleWorkerConfig `json:"schedule_worker" mapstructure:"schedule_worker"`
	// SlackbotCleanupWorker is the configuration for the Slackbot session cleanup worker
	SlackbotCleanupWorker SlackbotCleanupWorkerConfig `json:"slackbot_cleanup_worker" mapstructure:"slackbot_cleanup_worker"`
	// SessionRouteReconciler finalizes abandoned session routes and orphaned configurations.
	SessionRouteReconciler SessionRouteReconcilerConfig `json:"session_route_reconciler" mapstructure:"session_route_reconciler"`
	// StockInventoryWorker is the configuration for the stock session inventory worker.
	StockInventoryWorker StockInventoryWorkerConfig `json:"stock_inventory_worker" mapstructure:"stock_inventory_worker"`
	// Webhook is the configuration for webhook functionality
	Webhook WebhookConfig `json:"webhook" mapstructure:"webhook"`
	// Scia is the configuration for scia OAuth token broker/proxy integration.
	Scia               SciaConfig               `json:"scia" mapstructure:"scia"`
	SessionPersistence SessionPersistenceConfig `json:"session_persistence" mapstructure:"session_persistence"`
	// Slack is the configuration for Slack bot inbound webhook functionality
	Slack SlackConfig `json:"slack" mapstructure:"slack"`
	// SessionManager is the configuration for the session manager forwarding endpoint.
	SessionManager SessionManagerConfig `json:"session_manager" mapstructure:"session_manager"`
	// Worker is deliberately separate from KubernetesSession. A worker has no
	// Kubernetes workload credentials and talks to the API over this endpoint.
	Worker WorkerConfig `json:"worker" mapstructure:"worker"`
	// Redis holds optional Redis configuration for cross-pod status synchronisation.
	// Redis is required by the API and session manager runtime.
	Redis RedisConfig `json:"redis" mapstructure:"redis"`
	// KVStore controls storage for application KV data currently backed by
	// Kubernetes Secrets and ConfigMaps.
	KVStore KVStoreConfig `json:"kv_store" mapstructure:"kv_store"`
	// Usage controls response-level token usage collection.
	Usage UsageConfig `json:"usage" mapstructure:"usage"`
	// SessionCount controls pool/principal session count collection.
	SessionCount SessionCountConfig `json:"session_count" mapstructure:"session_count"`
	// SessionTokenDebug enables non-secret token-routing diagnostics for session creation.
	SessionTokenDebug bool `json:"session_token_debug" mapstructure:"session_token_debug"`
	// GitHubBrokerBaseURL overrides the request-derived base URL for session GitHub credentials.
	GitHubBrokerBaseURL string `json:"github_broker_base_url" mapstructure:"github_broker_base_url"`
	// CodexDeviceAuthCallbackBaseURL overrides the request-derived base URL that
	// short-lived Codex device auth workers use to report their challenge and
	// result. Workloads run inside the session cluster, so the browser-facing
	// host (which may sit behind an authentication proxy such as Cloudflare
	// Access) is not necessarily reachable from them. Defaults to the
	// request-derived URL when empty.
	CodexDeviceAuthCallbackBaseURL string `json:"codex_device_auth_callback_base_url" mapstructure:"codex_device_auth_callback_base_url"`
}

// SlackConfig represents Slack bot (Socket Mode) configuration
type SlackConfig struct {
	// AppToken and BotToken are write-only runtime inputs used by the dedicated
	// worker to materialize its default Socket Mode credential in the KV store.
	AppToken string `json:"app_token" mapstructure:"app_token"`
	BotToken string `json:"bot_token" mapstructure:"bot_token"`
	// AppTokenSecretName is the K8s Secret name containing the default App-level token (xapp-...).
	// Used for the default Socket Mode connection.
	// If empty, falls back to KubernetesSession.SlackBotTokenSecretName.
	// Set via AGENTAPI_SLACK_APP_TOKEN_SECRET_NAME environment variable.
	AppTokenSecretName string `json:"app_token_secret_name" mapstructure:"app_token_secret_name"`
	// AppTokenSecretKey is the key within the Secret for the App-level token.
	// Defaults to "app-token".
	// Set via AGENTAPI_SLACK_APP_TOKEN_SECRET_KEY environment variable.
	AppTokenSecretKey string `json:"app_token_secret_key" mapstructure:"app_token_secret_key"`
	// DryRun enables dry-run mode: session creation and Slack posts are logged but not executed.
	// Useful for testing event routing without side effects.
	// Set via AGENTAPI_SLACK_DRY_RUN environment variable.
	DryRun bool `json:"dry_run" mapstructure:"dry_run"`
}

// LoadConfig loads configuration using viper with support for JSON, YAML, and environment variables
func LoadConfig(filename string) (*Config, error) {
	v := viper.New()

	// Set up configuration file
	if filename != "" {
		v.SetConfigFile(filename)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.agentapi")
		v.AddConfigPath("/etc/agentapi/")
	}

	// Enable environment variable support
	v.AutomaticEnv()
	v.SetEnvPrefix("AGENTAPI")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Explicitly bind environment variables for nested configuration
	bindEnvVars(v)

	// Set defaults
	setDefaults(v)

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		// If no config file is found, use defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		log.Printf("[CONFIG] No config file found, using defaults and environment variables")
	} else {
		log.Printf("[CONFIG] Using config file: %s", v.ConfigFileUsed())
	}

	var config Config
	decodeHook := mapstructure.ComposeDecodeHookFunc(stockInventoryPoolsDecodeHook(), teamDiscoveryDecodeHook(), stringMapJSONDecodeHook())
	if err := v.Unmarshal(&config, viper.DecodeHook(decodeHook)); err != nil {
		return nil, err
	}

	// Apply defaults for any fields that weren't set in config file
	applyConfigDefaults(&config)

	// Initialize config structs from environment variables if they don't exist
	initializeConfigStructsFromEnv(&config, v)

	// Load external auth configuration if specified
	if config.AuthConfigFile != "" {
		if err := loadAuthConfigFromFile(&config, config.AuthConfigFile); err != nil {
			log.Printf("[CONFIG] Warning: Failed to load auth config from %s: %v", config.AuthConfigFile, err)
		} else {
			log.Printf("[CONFIG] Loaded auth config from: %s", config.AuthConfigFile)
		}
	}

	// Apply post-processing
	if err := postProcessConfig(&config); err != nil {
		return nil, err
	}

	// Debug: Log configuration summary
	log.Printf("[CONFIG] Admin key authentication configured: %v", config.Auth.AdminKey != "")
	log.Printf("[CONFIG] GitHub auth enabled: %v", config.Auth.GitHub != nil && config.Auth.GitHub.Enabled)
	if config.Auth.GitHub != nil {
		log.Printf("[CONFIG] GitHub OAuth configured: %v", config.Auth.GitHub.OAuth != nil)
	}
	log.Printf("[CONFIG] Role-based env files enabled: %v", config.RoleEnvFiles.Enabled)

	return &config, nil
}

func stringMapJSONDecodeHook() mapstructure.DecodeHookFunc {
	stringMapType := reflect.TypeOf(map[string]string{})
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String || to != stringMapType {
			return data, nil
		}
		if data == "" {
			return map[string]string{}, nil
		}
		var values map[string]string
		if err := json.Unmarshal([]byte(data.(string)), &values); err != nil {
			return nil, err
		}
		return values, nil
	}
}

func stockInventoryPoolsDecodeHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String || to != reflect.TypeOf([]StockInventoryPoolConfig{}) {
			return data, nil
		}
		if data == "" {
			return []StockInventoryPoolConfig{}, nil
		}
		pools, err := parseStockInventoryPoolsJSON(data.(string))
		if err != nil {
			return nil, err
		}
		return pools, nil
	}
}

func teamDiscoveryDecodeHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String || to != reflect.TypeOf([]TeamDiscoveryRule{}) {
			return data, nil
		}
		if data == "" {
			return []TeamDiscoveryRule{}, nil
		}
		var rules []TeamDiscoveryRule
		if err := json.Unmarshal([]byte(data.(string)), &rules); err != nil {
			return nil, fmt.Errorf("parse team discovery JSON: %w", err)
		}
		return rules, nil
	}
}

func parseStockInventoryPoolsJSON(poolsJSON string) ([]StockInventoryPoolConfig, error) {
	var rawPools []map[string]interface{}
	if err := json.Unmarshal([]byte(poolsJSON), &rawPools); err != nil {
		return nil, err
	}

	pools := make([]StockInventoryPoolConfig, 0, len(rawPools))
	for _, rawPool := range rawPools {
		name, _ := rawPool["name"].(string)
		targetCount, err := jsonInt(rawPool, "target_count", "targetCount")
		if err != nil {
			return nil, err
		}
		dockerEnabled, err := jsonBool(rawPool, "docker_enabled", "dockerEnabled")
		if err != nil {
			return nil, err
		}

		pools = append(pools, StockInventoryPoolConfig{
			Name:          name,
			TargetCount:   targetCount,
			DockerEnabled: dockerEnabled,
		})
	}
	return pools, nil
}

func jsonInt(values map[string]interface{}, keys ...string) (int, error) {
	value, ok := jsonValue(values, keys...)
	if !ok {
		return 0, nil
	}
	switch typedValue := value.(type) {
	case float64:
		return int(typedValue), nil
	case string:
		return strconv.Atoi(typedValue)
	default:
		return 0, fmt.Errorf("expected integer for %s, got %T", keys[0], value)
	}
}

func jsonBool(values map[string]interface{}, keys ...string) (bool, error) {
	value, ok := jsonValue(values, keys...)
	if !ok {
		return false, nil
	}
	switch typedValue := value.(type) {
	case bool:
		return typedValue, nil
	case string:
		return strconv.ParseBool(typedValue)
	default:
		return false, fmt.Errorf("expected boolean for %s, got %T", keys[0], value)
	}
}

func jsonValue(values map[string]interface{}, keys ...string) (interface{}, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func commaSeparatedList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// initializeConfigStructsFromEnv initializes config structs from environment variables
func initializeConfigStructsFromEnv(config *Config, v *viper.Viper) {
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_ENABLED"); ok {
		config.SessionManager.Builtin.Enabled, _ = strconv.ParseBool(value)
	}
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_MANAGER_ID"); ok {
		config.SessionManager.Builtin.ManagerID = value
	}
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_NAME"); ok {
		config.SessionManager.Builtin.Name = value
	}
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_CONNECTION_TOKEN"); ok {
		config.SessionManager.Builtin.ConnectionToken = value
	}
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_POOL"); ok {
		config.SessionManager.Builtin.Pool.Name = value
	}
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_POOL_EXPLICIT_ONLY"); ok {
		config.SessionManager.Builtin.Pool.ExplicitOnly, _ = strconv.ParseBool(value)
	}
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_POOL_PRIORITY"); ok {
		config.SessionManager.Builtin.Pool.Priority, _ = strconv.Atoi(value)
	}
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_BINDING_SUBJECT_TYPE"); ok {
		config.SessionManager.Builtin.Pool.Binding.SubjectType = value
	}
	if value, ok := os.LookupEnv("AGENTAPI_SESSION_MANAGER_BUILTIN_BINDING_ROLE"); ok {
		config.SessionManager.Builtin.Pool.Binding.Role = value
	}
	if labelsJSON := os.Getenv("AGENTAPI_SESSION_MANAGER_BUILTIN_POOL_LABELS"); labelsJSON != "" {
		var labels map[string]string
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			log.Printf("[CONFIG] Warning: invalid built-in session manager pool labels: %v", err)
		} else {
			config.SessionManager.Builtin.Pool.Labels = labels
		}
	}

	config.SessionPersistence.Backend = v.GetString("session_persistence.backend")
	config.SessionPersistence.Path = v.GetString("session_persistence.path")
	config.SessionPersistence.SuspendAfter = v.GetString("session_persistence.suspend_after")
	if bucket := v.GetString("session_persistence.s3.bucket"); bucket != "" {
		config.SessionPersistence.S3 = &S3StorageConfig{
			Bucket: bucket, Region: v.GetString("session_persistence.s3.region"),
			Prefix: v.GetString("session_persistence.s3.prefix"), Endpoint: v.GetString("session_persistence.s3.endpoint"),
			AccessKeyID: v.GetString("session_persistence.s3.access_key_id"), SecretAccessKey: v.GetString("session_persistence.s3.secret_access_key"),
		}
	}
	// Static API key authentication was removed. Warn loudly when its legacy
	// settings are still present so operators do not assume they take effect.
	if v.IsSet("auth.static") || v.GetBool("auth.static.enabled") || os.Getenv("AGENTAPI_AUTH_STATIC_ENABLED") != "" || os.Getenv("AGENTAPI_AUTH_STATIC_HEADER_NAME") != "" {
		log.Printf("[CONFIG] Warning: static API key authentication has been removed; ignoring legacy auth.static settings. Set AGENTAPI_AUTH_ADMIN_KEY to provide a single admin API key instead.")
	}
	// Initialize Auth.BootstrapAdmin if environment variables are set
	if config.Auth.BootstrapAdmin == nil && (v.GetBool("auth.bootstrap_admin.enabled") || v.GetString("auth.bootstrap_admin.token") != "") {
		config.Auth.BootstrapAdmin = &BootstrapAdminAuthConfig{
			Enabled:  v.GetBool("auth.bootstrap_admin.enabled"),
			UserID:   v.GetString("auth.bootstrap_admin.user_id"),
			Username: v.GetString("auth.bootstrap_admin.username"),
			Token:    v.GetString("auth.bootstrap_admin.token"),
		}
	}

	// Initialize Auth.GitHub if environment variables are set
	if config.Auth.GitHub == nil && (v.GetBool("auth.github.enabled") || v.GetString("auth.github.base_url") != "" || v.GetString("auth.github.token_header") != "") {
		config.Auth.GitHub = &GitHubAuthConfig{
			Enabled:      v.GetBool("auth.github.enabled"),
			ConnectionID: v.GetString("auth.github.connection_id"),
			BaseURL:      v.GetString("auth.github.base_url"),
			TokenHeader:  v.GetString("auth.github.token_header"),
			UserMapping: GitHubUserMapping{
				DefaultRole:           v.GetString("auth.github.user_mapping.default_role"),
				DefaultPermissions:    v.GetStringSlice("auth.github.user_mapping.default_permissions"),
				AllowUsersWithoutTeam: v.GetBool("auth.github.user_mapping.allow_users_without_team"),
			},
		}
		log.Printf("[CONFIG] Initialized GitHub auth config from environment variables")
	}

	// Initialize Auth.GitHub.OAuth if environment variables are set
	if config.Auth.GitHub != nil && config.Auth.GitHub.OAuth == nil {
		// Check if OAuth environment variables are set
		clientID := v.GetString("auth.github.oauth.client_id")
		clientSecret := v.GetString("auth.github.oauth.client_secret")

		if clientID != "" || clientSecret != "" {
			config.Auth.GitHub.OAuth = &GitHubOAuthConfig{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scope:        v.GetString("auth.github.oauth.scope"),
				BaseURL:      v.GetString("auth.github.oauth.base_url"),
			}
			log.Printf("[CONFIG] Initialized GitHub OAuth config from environment variables")
			log.Printf("[CONFIG] OAuth ClientID from env: %v", clientID != "")
			log.Printf("[CONFIG] OAuth ClientSecret from env: %v", clientSecret != "")
		}
	}

	if namespace := os.Getenv("AGENTAPI_K8S_SESSION_NAMESPACE"); namespace != "" {
		config.KubernetesSession.Namespace = namespace
	}
	if namespace := os.Getenv("AGENTAPI_SCHEDULE_WORKER_NAMESPACE"); namespace != "" {
		config.ScheduleWorker.Namespace = namespace
	}
	if namespace := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_NAMESPACE"); namespace != "" {
		config.StockInventoryWorker.Namespace = namespace
	}
	if enabled := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_ENABLED"); enabled != "" {
		if parsed, err := strconv.ParseBool(enabled); err == nil {
			config.StockInventoryWorker.Enabled = parsed
		}
	}
	if checkInterval := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_CHECK_INTERVAL"); checkInterval != "" {
		config.StockInventoryWorker.CheckInterval = checkInterval
	}
	if targetCount := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_TARGET_COUNT"); targetCount != "" {
		if parsed, err := strconv.Atoi(targetCount); err == nil {
			config.StockInventoryWorker.TargetCount = parsed
		}
	}
	if dockerEnabled := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_DOCKER_ENABLED"); dockerEnabled != "" {
		if parsed, err := strconv.ParseBool(dockerEnabled); err == nil {
			config.StockInventoryWorker.DockerEnabled = parsed
		}
	}
	if leaseDuration := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_LEASE_DURATION"); leaseDuration != "" {
		config.StockInventoryWorker.LeaseDuration = leaseDuration
	}
	if renewDeadline := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_RENEW_DEADLINE"); renewDeadline != "" {
		config.StockInventoryWorker.RenewDeadline = renewDeadline
	}
	if retryPeriod := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_RETRY_PERIOD"); retryPeriod != "" {
		config.StockInventoryWorker.RetryPeriod = retryPeriod
	}
	if poolsJSON := os.Getenv("AGENTAPI_STOCK_INVENTORY_WORKER_POOLS"); poolsJSON != "" {
		pools, err := parseStockInventoryPoolsJSON(poolsJSON)
		if err != nil {
			log.Printf("[CONFIG] Warning: Failed to parse stock inventory worker pools JSON: %v", err)
		} else {
			config.StockInventoryWorker.Pools = pools
		}
	}

	if enabled, ok := os.LookupEnv("AGENTAPI_SCIA_ENABLED"); ok {
		config.Scia.Enabled = strings.EqualFold(enabled, "true")
	}
	if publicBaseURL := os.Getenv("AGENTAPI_SCIA_PUBLIC_BASE_URL"); publicBaseURL != "" {
		config.Scia.PublicBaseURL = publicBaseURL
	}
	if proxyURL := os.Getenv("AGENTAPI_SCIA_PROXY_URL"); proxyURL != "" {
		config.Scia.ProxyURL = proxyURL
	}
	if credential := os.Getenv("AGENTAPI_SCIA_CREDENTIAL"); credential != "" {
		config.Scia.Credential = credential
	}
	if userNamespace := os.Getenv("AGENTAPI_SCIA_USER_NAMESPACE"); userNamespace != "" {
		config.Scia.UserNamespace = userNamespace
	}
	if noProxy := os.Getenv("AGENTAPI_SCIA_NO_PROXY"); noProxy != "" {
		config.Scia.NoProxy = noProxy
	}
	if enabled, ok := os.LookupEnv("AGENTAPI_SCIA_SESSION_SIDECAR_ENABLED"); ok {
		config.Scia.SessionSidecarEnabled = strings.EqualFold(enabled, "true")
	}
	if image := os.Getenv("AGENTAPI_SCIA_SESSION_SIDECAR_IMAGE"); image != "" {
		config.Scia.SessionSidecarImage = image
	}
	if image := os.Getenv("AGENTAPI_SCIA_SESSION_SIDECAR_CONFIG_IMAGE"); image != "" {
		config.Scia.SessionSidecarConfigImage = image
	}
	if port := os.Getenv("AGENTAPI_SCIA_SESSION_SIDECAR_PORT"); port != "" {
		if parsed, err := strconv.Atoi(port); err == nil {
			config.Scia.SessionSidecarPort = parsed
		}
	}
	if hosts := commaSeparatedList(os.Getenv("AGENTAPI_SCIA_GOOGLE_HOSTS")); len(hosts) > 0 {
		config.Scia.GoogleHosts = hosts
	}
	if paths := commaSeparatedList(os.Getenv("AGENTAPI_SCIA_GOOGLE_PATHS")); len(paths) > 0 {
		config.Scia.GooglePaths = paths
	}
	if credential := os.Getenv("AGENTAPI_SCIA_TODOIST_CREDENTIAL"); credential != "" {
		config.Scia.TodoistCredential = credential
	}
	if hosts := commaSeparatedList(os.Getenv("AGENTAPI_SCIA_TODOIST_HOSTS")); len(hosts) > 0 {
		config.Scia.TodoistHosts = hosts
	}
	if paths := commaSeparatedList(os.Getenv("AGENTAPI_SCIA_TODOIST_PATHS")); len(paths) > 0 {
		config.Scia.TodoistPaths = paths
	}

	// Override fields if environment variables are set (even if structures already exist)
	if config.Auth.GitHub != nil {
		if v.IsSet("auth.github.user_mapping.default_role") {
			config.Auth.GitHub.UserMapping.DefaultRole = v.GetString("auth.github.user_mapping.default_role")
		}
		if v.IsSet("auth.github.user_mapping.default_permissions") {
			config.Auth.GitHub.UserMapping.DefaultPermissions = v.GetStringSlice("auth.github.user_mapping.default_permissions")
		}
		if v.IsSet("auth.github.user_mapping.allow_users_without_team") {
			config.Auth.GitHub.UserMapping.AllowUsersWithoutTeam = v.GetBool("auth.github.user_mapping.allow_users_without_team")
		}

		// Override OAuth settings if already exists
		if config.Auth.GitHub.OAuth != nil {
			if clientID := v.GetString("auth.github.oauth.client_id"); clientID != "" {
				config.Auth.GitHub.OAuth.ClientID = clientID
			}
			if clientSecret := v.GetString("auth.github.oauth.client_secret"); clientSecret != "" {
				config.Auth.GitHub.OAuth.ClientSecret = clientSecret
			}
			if scope := v.GetString("auth.github.oauth.scope"); scope != "" {
				config.Auth.GitHub.OAuth.Scope = scope
			}
			if baseURL := v.GetString("auth.github.oauth.base_url"); baseURL != "" {
				config.Auth.GitHub.OAuth.BaseURL = baseURL
			}
		}
	}

}

// bindEnvVars explicitly binds environment variables to configuration keys
func bindEnvVars(v *viper.Viper) {
	// Bind nested configuration keys to environment variables
	// Note: BindEnv errors are generally not critical and can be ignored
	// as they typically occur only when the key is already bound
	_ = v.BindEnv("binary_path", "CCPLANT_BINARY_PATH")

	// Auth configuration
	_ = v.BindEnv("auth.admin_key")
	_ = v.BindEnv("auth.bootstrap_admin.enabled")
	_ = v.BindEnv("auth.bootstrap_admin.user_id")
	_ = v.BindEnv("auth.bootstrap_admin.username")
	_ = v.BindEnv("auth.bootstrap_admin.token")

	// GitHub auth configuration
	_ = v.BindEnv("auth.github.enabled")
	_ = v.BindEnv("auth.github.connection_id")
	_ = v.BindEnv("auth.github.base_url")
	_ = v.BindEnv("auth.github.token_header")
	_ = v.BindEnv("auth.github.user_mapping.default_role")
	_ = v.BindEnv("auth.github.user_mapping.default_permissions")
	_ = v.BindEnv("auth.github.user_mapping.allow_users_without_team")

	// GitHub OAuth configuration
	_ = v.BindEnv("auth.github.oauth.client_id")
	_ = v.BindEnv("auth.github.oauth.client_secret")
	_ = v.BindEnv("auth.github.oauth.scope")
	_ = v.BindEnv("auth.github.oauth.base_url")

	// Other configuration
	_ = v.BindEnv("auth_config_file")
	_ = v.BindEnv("team_discovery", "AGENTAPI_TEAM_DISCOVERY")
	_ = v.BindEnv("session_token_debug", "AGENTAPI_SESSION_TOKEN_DEBUG_ENABLED")
	_ = v.BindEnv("github_broker_base_url", "AGENTAPI_GITHUB_BROKER_BASE_URL")
	_ = v.BindEnv("codex_device_auth_callback_base_url", "AGENTAPI_CODEX_DEVICE_AUTH_CALLBACK_BASE_URL")
	_ = v.BindEnv("kv_store.backend", "AGENTAPI_KV_STORE_BACKEND")
	_ = v.BindEnv("kv_store.namespace", "AGENTAPI_KV_STORE_NAMESPACE")
	_ = v.BindEnv("kv_store.database_url", "AGENTAPI_KV_STORE_DATABASE_URL")
	_ = v.BindEnv("kv_store.auth_token", "AGENTAPI_KV_STORE_AUTH_TOKEN")
	_ = v.BindEnv("kv_store.primary.backend", "AGENTAPI_KV_STORE_PRIMARY_BACKEND")
	_ = v.BindEnv("kv_store.primary.database_url", "AGENTAPI_KV_STORE_PRIMARY_DATABASE_URL")
	_ = v.BindEnv("kv_store.primary.auth_token", "AGENTAPI_KV_STORE_PRIMARY_AUTH_TOKEN")
	bindKVEncryptionEnv(v, "kv_store.primary.encryption", "AGENTAPI_KV_STORE_PRIMARY_ENCRYPTION")
	_ = v.BindEnv("kv_store.secondary.backend", "AGENTAPI_KV_STORE_SECONDARY_BACKEND")
	_ = v.BindEnv("kv_store.secondary.database_url", "AGENTAPI_KV_STORE_SECONDARY_DATABASE_URL")
	_ = v.BindEnv("kv_store.secondary.auth_token", "AGENTAPI_KV_STORE_SECONDARY_AUTH_TOKEN")
	bindKVEncryptionEnv(v, "kv_store.secondary.encryption", "AGENTAPI_KV_STORE_SECONDARY_ENCRYPTION")
	_ = v.BindEnv("kv_store.replication.mode", "AGENTAPI_KV_STORE_REPLICATION_MODE")
	_ = v.BindEnv("kv_store.encryption.active_key_id", "AGENTAPI_KV_ENCRYPTION_ACTIVE_KEY_ID")
	_ = v.BindEnv("kv_store.encryption.provider", "AGENTAPI_KV_ENCRYPTION_PROVIDER")
	_ = v.BindEnv("kv_store.encryption.kms_region", "AGENTAPI_KV_ENCRYPTION_KMS_REGION")
	_ = v.BindEnv("kv_store.encryption.keys", "AGENTAPI_KV_ENCRYPTION_KEYS")
	_ = v.BindEnv("kv_store.encryption.branch_cache_ttl_seconds", "AGENTAPI_KV_ENCRYPTION_BRANCH_CACHE_TTL_SECONDS")
	_ = v.BindEnv("kv_store.encryption.branch_cache_max_entries", "AGENTAPI_KV_ENCRYPTION_BRANCH_CACHE_MAX_ENTRIES")
	_ = v.BindEnv("usage.enabled", "AGENTAPI_USAGE_ENABLED")
	_ = v.BindEnv("usage.database_url", "AGENTAPI_USAGE_DATABASE_URL")
	_ = v.BindEnv("usage.auth_token", "AGENTAPI_USAGE_AUTH_TOKEN")
	_ = v.BindEnv("session_count.enabled", "AGENTAPI_SESSION_COUNT_ENABLED")
	_ = v.BindEnv("session_count.backend", "AGENTAPI_SESSION_COUNT_BACKEND")
	_ = v.BindEnv("session_count.database_url", "AGENTAPI_SESSION_COUNT_DATABASE_URL")
	_ = v.BindEnv("session_count.auth_token", "AGENTAPI_SESSION_COUNT_AUTH_TOKEN")

	// scia OAuth broker/proxy configuration
	_ = v.BindEnv("scia.enabled", "AGENTAPI_SCIA_ENABLED")
	_ = v.BindEnv("scia.public_base_url", "AGENTAPI_SCIA_PUBLIC_BASE_URL")
	_ = v.BindEnv("scia.oauth_internal_url", "AGENTAPI_SCIA_OAUTH_INTERNAL_URL")
	_ = v.BindEnv("scia.proxy_url", "AGENTAPI_SCIA_PROXY_URL")
	_ = v.BindEnv("scia.credential", "AGENTAPI_SCIA_CREDENTIAL")
	_ = v.BindEnv("scia.user_namespace", "AGENTAPI_SCIA_USER_NAMESPACE")
	_ = v.BindEnv("scia.no_proxy", "AGENTAPI_SCIA_NO_PROXY")
	_ = v.BindEnv("scia.session_sidecar_enabled", "AGENTAPI_SCIA_SESSION_SIDECAR_ENABLED")
	_ = v.BindEnv("scia.session_sidecar_image", "AGENTAPI_SCIA_SESSION_SIDECAR_IMAGE")
	_ = v.BindEnv("scia.session_sidecar_config_image", "AGENTAPI_SCIA_SESSION_SIDECAR_CONFIG_IMAGE")
	_ = v.BindEnv("scia.session_sidecar_port", "AGENTAPI_SCIA_SESSION_SIDECAR_PORT")
	_ = v.BindEnv("scia.google_hosts", "AGENTAPI_SCIA_GOOGLE_HOSTS")
	_ = v.BindEnv("scia.google_paths", "AGENTAPI_SCIA_GOOGLE_PATHS")
	_ = v.BindEnv("scia.todoist_credential", "AGENTAPI_SCIA_TODOIST_CREDENTIAL")
	_ = v.BindEnv("scia.todoist_hosts", "AGENTAPI_SCIA_TODOIST_HOSTS")
	_ = v.BindEnv("scia.todoist_paths", "AGENTAPI_SCIA_TODOIST_PATHS")

	// Role-based environment files configuration
	_ = v.BindEnv("role_env_files.enabled")
	_ = v.BindEnv("role_env_files.path")
	_ = v.BindEnv("role_env_files.load_default")

	// Kubernetes session configuration
	_ = v.BindEnv("kubernetes_session.namespace", "AGENTAPI_K8S_SESSION_NAMESPACE")
	_ = v.BindEnv("kubernetes_session.image", "AGENTAPI_K8S_SESSION_IMAGE")
	_ = v.BindEnv("kubernetes_session.cli_image", "AGENTAPI_K8S_SESSION_CLI_IMAGE")
	_ = v.BindEnv("kubernetes_session.image_pull_policy", "AGENTAPI_K8S_SESSION_IMAGE_PULL_POLICY")
	_ = v.BindEnv("kubernetes_session.service_account", "AGENTAPI_K8S_SESSION_SERVICE_ACCOUNT")
	_ = v.BindEnv("kubernetes_session.disable_service_links", "AGENTAPI_K8S_SESSION_DISABLE_SERVICE_LINKS")
	_ = v.BindEnv("kubernetes_session.disable_service_account_token", "AGENTAPI_K8S_SESSION_DISABLE_SERVICE_ACCOUNT_TOKEN")
	_ = v.BindEnv("kubernetes_session.base_port", "AGENTAPI_K8S_SESSION_BASE_PORT")
	_ = v.BindEnv("kubernetes_session.cpu_request", "AGENTAPI_K8S_SESSION_CPU_REQUEST")
	_ = v.BindEnv("kubernetes_session.cpu_limit", "AGENTAPI_K8S_SESSION_CPU_LIMIT")
	_ = v.BindEnv("kubernetes_session.memory_request", "AGENTAPI_K8S_SESSION_MEMORY_REQUEST")
	_ = v.BindEnv("kubernetes_session.memory_limit", "AGENTAPI_K8S_SESSION_MEMORY_LIMIT")
	_ = v.BindEnv("kubernetes_session.executor_enabled", "AGENTAPI_K8S_SESSION_EXECUTOR_ENABLED")
	_ = v.BindEnv("kubernetes_session.executor_cpu_request", "AGENTAPI_K8S_SESSION_EXECUTOR_CPU_REQUEST")
	_ = v.BindEnv("kubernetes_session.executor_cpu_limit", "AGENTAPI_K8S_SESSION_EXECUTOR_CPU_LIMIT")
	_ = v.BindEnv("kubernetes_session.executor_memory_request", "AGENTAPI_K8S_SESSION_EXECUTOR_MEMORY_REQUEST")
	_ = v.BindEnv("kubernetes_session.executor_memory_limit", "AGENTAPI_K8S_SESSION_EXECUTOR_MEMORY_LIMIT")
	_ = v.BindEnv("kubernetes_session.pvc_enabled", "AGENTAPI_K8S_SESSION_PVC_ENABLED")
	_ = v.BindEnv("kubernetes_session.pvc_storage_class", "AGENTAPI_K8S_SESSION_PVC_STORAGE_CLASS")
	_ = v.BindEnv("kubernetes_session.pvc_storage_size", "AGENTAPI_K8S_SESSION_PVC_STORAGE_SIZE")
	_ = v.BindEnv("kubernetes_session.pod_start_timeout", "AGENTAPI_K8S_SESSION_POD_START_TIMEOUT")
	_ = v.BindEnv("kubernetes_session.pod_stop_timeout", "AGENTAPI_K8S_SESSION_POD_STOP_TIMEOUT")
	_ = v.BindEnv("kubernetes_session.provisioner_proxy_url", "AGENTAPI_K8S_SESSION_PROVISIONER_PROXY_URL")
	_ = v.BindEnv("kubernetes_session.provisioner_token", "AGENTAPI_K8S_SESSION_PROVISIONER_TOKEN")
	_ = v.BindEnv("kubernetes_session.network_filter_image", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_IMAGE")
	_ = v.BindEnv("kubernetes_session.network_filter_cpu_request", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_CPU_REQUEST")
	_ = v.BindEnv("kubernetes_session.network_filter_cpu_limit", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_CPU_LIMIT")
	_ = v.BindEnv("kubernetes_session.network_filter_memory_request", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_MEMORY_REQUEST")
	_ = v.BindEnv("kubernetes_session.network_filter_memory_limit", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_MEMORY_LIMIT")
	_ = v.BindEnv("kubernetes_session.network_filter_init_cpu_request", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_INIT_CPU_REQUEST")
	_ = v.BindEnv("kubernetes_session.network_filter_init_cpu_limit", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_INIT_CPU_LIMIT")
	_ = v.BindEnv("kubernetes_session.network_filter_init_memory_request", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_INIT_MEMORY_REQUEST")
	_ = v.BindEnv("kubernetes_session.network_filter_init_memory_limit", "AGENTAPI_K8S_SESSION_NETWORK_FILTER_INIT_MEMORY_LIMIT")
	_ = v.BindEnv("kubernetes_session.github_secret_name", "AGENTAPI_K8S_SESSION_GITHUB_SECRET_NAME")
	_ = v.BindEnv("kubernetes_session.github_config_secret_name", "AGENTAPI_K8S_SESSION_GITHUB_CONFIG_SECRET_NAME")
	_ = v.BindEnv("kubernetes_session.config_file", "AGENTAPI_K8S_SESSION_CONFIG_FILE")
	_ = v.BindEnv("kubernetes_session.session_pod_template_file", "AGENTAPI_K8S_SESSION_POD_TEMPLATE_FILE")
	// MCP servers configuration

	// Settings base secret configuration
	_ = v.BindEnv("kubernetes_session.settings_base_secret", "AGENTAPI_K8S_SESSION_SETTINGS_BASE_SECRET")
	_ = v.BindEnv("kubernetes_session.mcp_servers_base_secret", "AGENTAPI_K8S_SESSION_MCP_SERVERS_BASE_SECRET")
	_ = v.BindEnv("kubernetes_session.mcp_servers_base_file", "AGENTAPI_K8S_SESSION_MCP_SERVERS_BASE_FILE")

	// OpenTelemetry Collector configuration
	_ = v.BindEnv("kubernetes_session.otel_collector_enabled", "AGENTAPI_KUBERNETES_SESSION_OTEL_COLLECTOR_ENABLED")
	_ = v.BindEnv("kubernetes_session.otel_collector_scrape_interval", "AGENTAPI_KUBERNETES_SESSION_OTEL_COLLECTOR_SCRAPE_INTERVAL")
	_ = v.BindEnv("kubernetes_session.otel_collector_claude_code_port", "AGENTAPI_KUBERNETES_SESSION_OTEL_COLLECTOR_CLAUDE_CODE_PORT")
	_ = v.BindEnv("kubernetes_session.otel_collector_exporter_port", "AGENTAPI_KUBERNETES_SESSION_OTEL_COLLECTOR_EXPORTER_PORT")

	// Slack Integration configuration
	_ = v.BindEnv("kubernetes_session.slack_bot_token_secret_name", "AGENTAPI_KUBERNETES_SESSION_SLACK_BOT_TOKEN_SECRET_NAME")
	_ = v.BindEnv("kubernetes_session.slack_bot_token_secret_key", "AGENTAPI_KUBERNETES_SESSION_SLACK_BOT_TOKEN_SECRET_KEY")

	// Schedule worker configuration
	_ = v.BindEnv("schedule_worker.enabled", "AGENTAPI_SCHEDULE_WORKER_ENABLED")
	_ = v.BindEnv("schedule_worker.check_interval", "AGENTAPI_SCHEDULE_WORKER_CHECK_INTERVAL")
	_ = v.BindEnv("schedule_worker.namespace", "AGENTAPI_SCHEDULE_WORKER_NAMESPACE")
	_ = v.BindEnv("schedule_worker.lease_duration", "AGENTAPI_SCHEDULE_WORKER_LEASE_DURATION")
	_ = v.BindEnv("schedule_worker.renew_deadline", "AGENTAPI_SCHEDULE_WORKER_RENEW_DEADLINE")
	_ = v.BindEnv("schedule_worker.retry_period", "AGENTAPI_SCHEDULE_WORKER_RETRY_PERIOD")

	// Slackbot cleanup worker configuration
	_ = v.BindEnv("slackbot_cleanup_worker.enabled", "AGENTAPI_SLACKBOT_CLEANUP_WORKER_ENABLED")
	_ = v.BindEnv("slackbot_cleanup_worker.check_interval", "AGENTAPI_SLACKBOT_CLEANUP_WORKER_CHECK_INTERVAL")
	_ = v.BindEnv("slackbot_cleanup_worker.session_ttl", "AGENTAPI_SLACKBOT_CLEANUP_WORKER_SESSION_TTL")
	_ = v.BindEnv("slackbot_cleanup_worker.session_ttl_check_interval", "AGENTAPI_SLACKBOT_CLEANUP_WORKER_SESSION_TTL_CHECK_INTERVAL")
	_ = v.BindEnv("slackbot_cleanup_worker.dry_run", "AGENTAPI_SLACKBOT_CLEANUP_WORKER_DRY_RUN")
	_ = v.BindEnv("slackbot_cleanup_worker.lease_duration", "AGENTAPI_SLACKBOT_CLEANUP_WORKER_LEASE_DURATION")
	_ = v.BindEnv("slackbot_cleanup_worker.renew_deadline", "AGENTAPI_SLACKBOT_CLEANUP_WORKER_RENEW_DEADLINE")
	_ = v.BindEnv("slackbot_cleanup_worker.retry_period", "AGENTAPI_SLACKBOT_CLEANUP_WORKER_RETRY_PERIOD")

	// Session route reconciler configuration
	_ = v.BindEnv("session_route_reconciler.enabled", "AGENTAPI_SESSION_ROUTE_RECONCILER_ENABLED")
	_ = v.BindEnv("session_route_reconciler.dry_run", "AGENTAPI_SESSION_ROUTE_RECONCILER_DRY_RUN")
	_ = v.BindEnv("session_route_reconciler.interval", "AGENTAPI_SESSION_ROUTE_RECONCILER_INTERVAL")
	_ = v.BindEnv("session_route_reconciler.orphan_grace", "AGENTAPI_SESSION_ROUTE_RECONCILER_ORPHAN_GRACE")
	_ = v.BindEnv("session_route_reconciler.stuck_deletion_grace", "AGENTAPI_SESSION_ROUTE_RECONCILER_STUCK_DELETION_GRACE")
	_ = v.BindEnv("session_route_reconciler.runtime_disconnect_grace", "AGENTAPI_SESSION_ROUTE_RECONCILER_RUNTIME_DISCONNECT_GRACE")
	_ = v.BindEnv("session_route_reconciler.configuration_orphan_grace", "AGENTAPI_SESSION_ROUTE_RECONCILER_CONFIGURATION_ORPHAN_GRACE")

	// Stock inventory worker configuration
	_ = v.BindEnv("stock_inventory_worker.enabled", "AGENTAPI_STOCK_INVENTORY_WORKER_ENABLED")
	_ = v.BindEnv("stock_inventory_worker.check_interval", "AGENTAPI_STOCK_INVENTORY_WORKER_CHECK_INTERVAL")
	_ = v.BindEnv("stock_inventory_worker.target_count", "AGENTAPI_STOCK_INVENTORY_WORKER_TARGET_COUNT")
	_ = v.BindEnv("stock_inventory_worker.docker_enabled", "AGENTAPI_STOCK_INVENTORY_WORKER_DOCKER_ENABLED")
	_ = v.BindEnv("stock_inventory_worker.pools", "AGENTAPI_STOCK_INVENTORY_WORKER_POOLS")
	_ = v.BindEnv("stock_inventory_worker.namespace", "AGENTAPI_STOCK_INVENTORY_WORKER_NAMESPACE")
	_ = v.BindEnv("stock_inventory_worker.lease_duration", "AGENTAPI_STOCK_INVENTORY_WORKER_LEASE_DURATION")
	_ = v.BindEnv("stock_inventory_worker.renew_deadline", "AGENTAPI_STOCK_INVENTORY_WORKER_RENEW_DEADLINE")
	_ = v.BindEnv("stock_inventory_worker.retry_period", "AGENTAPI_STOCK_INVENTORY_WORKER_RETRY_PERIOD")

	// Webhook configuration
	_ = v.BindEnv("webhook.base_url", "AGENTAPI_WEBHOOK_BASE_URL")
	_ = v.BindEnv("webhook.github_enterprise_host", "AGENTAPI_WEBHOOK_GITHUB_ENTERPRISE_HOST")

	// Slack configuration
	_ = v.BindEnv("slack.app_token_secret_name", "AGENTAPI_SLACK_APP_TOKEN_SECRET_NAME")
	_ = v.BindEnv("slack.app_token_secret_key", "AGENTAPI_SLACK_APP_TOKEN_SECRET_KEY")
	_ = v.BindEnv("slack.app_token", "AGENTAPI_SLACK_APP_TOKEN")
	_ = v.BindEnv("slack.bot_token", "AGENTAPI_SLACK_BOT_TOKEN")
	_ = v.BindEnv("slack.dry_run", "AGENTAPI_SLACK_DRY_RUN")

	// Session manager configuration
	_ = v.BindEnv("session_manager.enabled", "AGENTAPI_SESSION_MANAGER_ENABLED", "SESSION_MANAGER_ENABLED")
	_ = v.BindEnv("session_manager.hmac_secret", "AGENTAPI_SESSION_MANAGER_HMAC_SECRET", "SESSION_MANAGER_HMAC_SECRET")
	_ = v.BindEnv("session_manager.upstream_url", "AGENTAPI_SESSION_MANAGER_UPSTREAM_URL", "SESSION_MANAGER_UPSTREAM_URL")
	_ = v.BindEnv("session_manager.connection_token", "AGENTAPI_SESSION_MANAGER_CONNECTION_TOKEN", "SESSION_MANAGER_CONNECTION_TOKEN")
	_ = v.BindEnv("session_manager.id", "AGENTAPI_SESSION_MANAGER_ID", "SESSION_MANAGER_ID")
	_ = v.BindEnv("session_manager.runner_pool", "AGENTAPI_SESSION_MANAGER_RUNNER_POOL", "SESSION_MANAGER_RUNNER_POOL")
	_ = v.BindEnv("session_manager.api_url", "AGENTAPI_SESSION_MANAGER_API_URL")
	_ = v.BindEnv("session_manager.local_url", "AGENTAPI_SESSION_MANAGER_LOCAL_URL")
	_ = v.BindEnv("session_manager.api_token", "AGENTAPI_SESSION_MANAGER_API_TOKEN")
	_ = v.BindEnv("session_manager.internal_api_token", "AGENTAPI_SESSION_MANAGER_INTERNAL_API_TOKEN")
	_ = v.BindEnv("session_manager.auto_upgrade", "AGENTAPI_SESSION_MANAGER_AUTO_UPGRADE")
	_ = v.BindEnv("session_manager.upgrade_version_url", "AGENTAPI_SESSION_MANAGER_UPGRADE_VERSION_URL")
	_ = v.BindEnv("session_manager.deployment_name", "AGENTAPI_SESSION_MANAGER_DEPLOYMENT_NAME")
	_ = v.BindEnv("session_manager.image_repository", "AGENTAPI_SESSION_MANAGER_IMAGE_REPOSITORY")
	_ = v.BindEnv("session_manager.current_version", "AGENTAPI_SESSION_MANAGER_CURRENT_VERSION")
	_ = v.BindEnv("session_manager.allocation.lease_duration", "AGENTAPI_SESSION_MANAGER_ALLOCATION_LEASE_DURATION")
	_ = v.BindEnv("session_manager.allocation.renew_deadline", "AGENTAPI_SESSION_MANAGER_ALLOCATION_RENEW_DEADLINE")
	_ = v.BindEnv("session_manager.allocation.retry_period", "AGENTAPI_SESSION_MANAGER_ALLOCATION_RETRY_PERIOD")
	_ = v.BindEnv("session_manager.allocation.lease_name", "AGENTAPI_SESSION_MANAGER_ALLOCATION_LEASE_NAME")
	_ = v.BindEnv("session_manager.builtin.enabled", "AGENTAPI_SESSION_MANAGER_BUILTIN_ENABLED")
	_ = v.BindEnv("session_manager.builtin.manager_id", "AGENTAPI_SESSION_MANAGER_BUILTIN_MANAGER_ID")
	_ = v.BindEnv("session_manager.builtin.name", "AGENTAPI_SESSION_MANAGER_BUILTIN_NAME")
	_ = v.BindEnv("session_manager.builtin.connection_token", "AGENTAPI_SESSION_MANAGER_BUILTIN_CONNECTION_TOKEN")
	_ = v.BindEnv("session_manager.builtin.pool.name", "AGENTAPI_SESSION_MANAGER_BUILTIN_POOL")
	_ = v.BindEnv("session_manager.builtin.pool.explicit_only", "AGENTAPI_SESSION_MANAGER_BUILTIN_POOL_EXPLICIT_ONLY")
	_ = v.BindEnv("session_manager.builtin.pool.priority", "AGENTAPI_SESSION_MANAGER_BUILTIN_POOL_PRIORITY")
	_ = v.BindEnv("session_manager.builtin.pool.labels_json", "AGENTAPI_SESSION_MANAGER_BUILTIN_POOL_LABELS")
	_ = v.BindEnv("session_manager.builtin.pool.binding.subject_type", "AGENTAPI_SESSION_MANAGER_BUILTIN_BINDING_SUBJECT_TYPE")
	_ = v.BindEnv("session_manager.builtin.pool.binding.role", "AGENTAPI_SESSION_MANAGER_BUILTIN_BINDING_ROLE")

	// Background-worker control plane. These values are deliberately not part
	// of kubernetes_session: the worker must never receive a provisioner token.
	_ = v.BindEnv("worker.control_api_url", "AGENTAPI_WORKER_CONTROL_API_URL", "AGENTAPI_K8S_SESSION_PROVISIONER_PROXY_URL")
	_ = v.BindEnv("worker.control_api_token", "AGENTAPI_WORKER_CONTROL_TOKEN")
	_ = v.BindEnv("worker.execution_token_signing_key", "AGENTAPI_EXECUTION_TOKEN_SIGNING_KEY")
	_ = v.BindEnv("worker.session_api_url", "AGENTAPI_WORKER_SESSION_API_URL")

	_ = v.BindEnv("session_persistence.backend", "AGENTAPI_SESSION_PERSISTENCE_BACKEND")
	_ = v.BindEnv("session_persistence.path", "AGENTAPI_SESSION_PERSISTENCE_PATH")
	_ = v.BindEnv("session_persistence.suspend_after", "AGENTAPI_SESSION_PERSISTENCE_SUSPEND_AFTER")
	_ = v.BindEnv("session_persistence.s3.bucket", "AGENTAPI_SESSION_PERSISTENCE_S3_BUCKET")
	_ = v.BindEnv("session_persistence.s3.region", "AGENTAPI_SESSION_PERSISTENCE_S3_REGION")
	_ = v.BindEnv("session_persistence.s3.prefix", "AGENTAPI_SESSION_PERSISTENCE_S3_PREFIX")
	_ = v.BindEnv("session_persistence.s3.endpoint", "AGENTAPI_SESSION_PERSISTENCE_S3_ENDPOINT")
	_ = v.BindEnv("session_persistence.s3.access_key_id", "AGENTAPI_SESSION_PERSISTENCE_S3_ACCESS_KEY_ID")
	_ = v.BindEnv("session_persistence.s3.secret_access_key", "AGENTAPI_SESSION_PERSISTENCE_S3_SECRET_ACCESS_KEY")

	// External memory-server backend configuration

	// Redis configuration
	_ = v.BindEnv("redis.addr", "AGENTAPI_REDIS_ADDR")
	_ = v.BindEnv("redis.password", "AGENTAPI_REDIS_PASSWORD")
	_ = v.BindEnv("redis.db", "AGENTAPI_REDIS_DB")
	_ = v.BindEnv("redis.tls_enabled", "AGENTAPI_REDIS_TLS_ENABLED")
	_ = v.BindEnv("redis.dial_timeout", "AGENTAPI_REDIS_DIAL_TIMEOUT")
	_ = v.BindEnv("redis.read_timeout", "AGENTAPI_REDIS_READ_TIMEOUT")
	_ = v.BindEnv("redis.write_timeout", "AGENTAPI_REDIS_WRITE_TIMEOUT")
	_ = v.BindEnv("redis.session_control_pool_size", "AGENTAPI_REDIS_SESSION_CONTROL_POOL_SIZE")
	_ = v.BindEnv("redis.session_control_blocking_pool_size", "AGENTAPI_REDIS_SESSION_CONTROL_BLOCKING_POOL_SIZE")

}

func bindKVEncryptionEnv(v *viper.Viper, path, envPrefix string) {
	_ = v.BindEnv(path+".active_key_id", envPrefix+"_ACTIVE_KEY_ID")
	_ = v.BindEnv(path+".provider", envPrefix+"_PROVIDER")
	_ = v.BindEnv(path+".kms_key_id", envPrefix+"_KMS_KEY_ID")
	_ = v.BindEnv(path+".kms_region", envPrefix+"_KMS_REGION")
	_ = v.BindEnv(path+".keys", envPrefix+"_KEYS")
	_ = v.BindEnv(path+".branch_cache_ttl_seconds", envPrefix+"_BRANCH_CACHE_TTL_SECONDS")
	_ = v.BindEnv(path+".branch_cache_max_entries", envPrefix+"_BRANCH_CACHE_MAX_ENTRIES")
}

// setDefaults sets default values for viper configuration
func setDefaults(v *viper.Viper) {
	v.SetDefault("binary_path", "ccplant")
	// Auth defaults
	v.SetDefault("auth.bootstrap_admin.enabled", false)
	v.SetDefault("auth.bootstrap_admin.user_id", "bootstrap-admin")
	v.SetDefault("auth.bootstrap_admin.username", "admin")
	v.SetDefault("auth.bootstrap_admin.token", "")
	v.SetDefault("auth.admin_key", "")
	v.SetDefault("auth.github.enabled", false)
	v.SetDefault("auth.github.base_url", "https://api.github.com")
	v.SetDefault("auth.github.token_header", "Authorization")
	v.SetDefault("auth.github.oauth.client_id", "")
	v.SetDefault("auth.github.oauth.client_secret", "")
	v.SetDefault("auth.github.oauth.scope", "read:user read:org project")
	v.SetDefault("auth.github.oauth.base_url", "")

	// AWS auth defaults
	v.SetDefault("auth.aws.enabled", false)
	v.SetDefault("auth.aws.region", "ap-northeast-1")
	v.SetDefault("auth.aws.allowed_account_ids", []string{})
	v.SetDefault("auth.aws.team_tag_key", "Team")
	v.SetDefault("auth.aws.cache_ttl", "1h")
	v.SetDefault("usage.enabled", false)
	v.SetDefault("session_count.enabled", false)
	v.SetDefault("session_count.backend", "libsql")

	// Role-based environment files defaults
	v.SetDefault("role_env_files.enabled", false)
	v.SetDefault("role_env_files.path", "/etc/agentapi/env")
	v.SetDefault("role_env_files.load_default", true)

	// Kubernetes session defaults
	v.SetDefault("kubernetes_session.namespace", "")
	v.SetDefault("kubernetes_session.image", "")
	v.SetDefault("kubernetes_session.cli_image", "")
	v.SetDefault("kubernetes_session.image_pull_policy", "IfNotPresent")
	v.SetDefault("kubernetes_session.service_account", "agentapi-proxy-session")
	v.SetDefault("kubernetes_session.base_port", 9000)
	v.SetDefault("kubernetes_session.cpu_request", "500m")
	v.SetDefault("kubernetes_session.cpu_limit", "2")
	v.SetDefault("kubernetes_session.memory_request", "512Mi")
	v.SetDefault("kubernetes_session.memory_limit", "4Gi")
	v.SetDefault("kubernetes_session.executor_enabled", true)
	v.SetDefault("kubernetes_session.executor_cpu_request", "10m")
	v.SetDefault("kubernetes_session.executor_cpu_limit", "2")
	v.SetDefault("kubernetes_session.executor_memory_request", "512Mi")
	v.SetDefault("kubernetes_session.executor_memory_limit", "4Gi")
	v.SetDefault("kubernetes_session.pvc_enabled", true)
	v.SetDefault("kubernetes_session.pvc_storage_class", "")
	v.SetDefault("kubernetes_session.pvc_storage_size", "10Gi")
	v.SetDefault("kubernetes_session.pod_start_timeout", 120)
	v.SetDefault("kubernetes_session.pod_stop_timeout", 30)
	v.SetDefault("kubernetes_session.provisioner_proxy_url", "")
	v.SetDefault("kubernetes_session.network_filter_image", "ghcr.io/takutakahashi/nfa:0.12.4")
	v.SetDefault("kubernetes_session.network_filter_cpu_request", "250m")
	v.SetDefault("kubernetes_session.network_filter_cpu_limit", "1000m")
	v.SetDefault("kubernetes_session.network_filter_memory_request", "256Mi")
	v.SetDefault("kubernetes_session.network_filter_memory_limit", "512Mi")
	v.SetDefault("kubernetes_session.network_filter_init_cpu_request", "50m")
	v.SetDefault("kubernetes_session.network_filter_init_cpu_limit", "100m")
	v.SetDefault("kubernetes_session.network_filter_init_memory_request", "32Mi")
	v.SetDefault("kubernetes_session.network_filter_init_memory_limit", "64Mi")
	v.SetDefault("kubernetes_session.github_secret_name", "")
	v.SetDefault("task_queue.enabled", false)
	_ = v.BindEnv("task_queue.enabled", "AGENTAPI_TASK_QUEUE_ENABLED")
	v.SetDefault("task_queue.max_starting_global", 10)
	_ = v.BindEnv("task_queue.max_starting_global", "AGENTAPI_TASK_QUEUE_MAX_STARTING_GLOBAL")
	v.SetDefault("task_queue.max_starting_per_user", 2)
	_ = v.BindEnv("task_queue.max_starting_per_user", "AGENTAPI_TASK_QUEUE_MAX_STARTING_PER_USER")
	v.SetDefault("task_queue.max_starting_per_team", 2)
	_ = v.BindEnv("task_queue.max_starting_per_team", "AGENTAPI_TASK_QUEUE_MAX_STARTING_PER_TEAM")
	v.SetDefault("task_queue.max_live_sessions_per_user", 10)
	_ = v.BindEnv("task_queue.max_live_sessions_per_user", "AGENTAPI_TASK_QUEUE_MAX_LIVE_SESSIONS_PER_USER")
	v.SetDefault("task_queue.max_live_sessions_per_team", 10)
	_ = v.BindEnv("task_queue.max_live_sessions_per_team", "AGENTAPI_TASK_QUEUE_MAX_LIVE_SESSIONS_PER_TEAM")
	v.SetDefault("task_queue.max_pending", 2000)
	_ = v.BindEnv("task_queue.max_pending", "AGENTAPI_TASK_QUEUE_MAX_PENDING")
	v.SetDefault("task_queue.retention_days", 90)
	_ = v.BindEnv("task_queue.retention_days", "AGENTAPI_TASK_QUEUE_RETENTION_DAYS")
	v.SetDefault("task_queue.team_retention_days", 90)
	_ = v.BindEnv("task_queue.team_retention_days", "AGENTAPI_TASK_QUEUE_TEAM_RETENTION_DAYS")
	v.SetDefault("worker.control_api_url", "")
	v.SetDefault("worker.control_api_token", "")
	v.SetDefault("worker.session_api_url", "")
	v.SetDefault("session_manager.api_url", "")
	v.SetDefault("session_manager.local_url", "")
	v.SetDefault("session_manager.api_token", "")
	v.SetDefault("session_manager.internal_api_token", "")
	v.SetDefault("session_manager.allocation.lease_duration", "15s")
	v.SetDefault("session_manager.allocation.renew_deadline", "10s")
	v.SetDefault("session_manager.allocation.retry_period", "2s")
	v.SetDefault("session_manager.allocation.lease_name", "agentapi-session-allocator")
	v.SetDefault("session_manager.builtin.enabled", false)
	v.SetDefault("session_manager.builtin.manager_id", "")
	v.SetDefault("session_manager.builtin.name", "Built-in session manager")
	v.SetDefault("session_manager.builtin.connection_token", "")
	v.SetDefault("session_manager.builtin.pool.name", "")
	v.SetDefault("session_manager.builtin.pool.labels_json", "")
	v.SetDefault("session_manager.builtin.pool.explicit_only", false)
	v.SetDefault("session_manager.builtin.pool.priority", -1)
	v.SetDefault("session_manager.builtin.pool.binding.subject_type", "all")
	v.SetDefault("session_manager.builtin.pool.binding.role", "use")

	// Settings base secret default (single base Secret shared by all sessions,
	// merged with team/user settings at session settings generation time)
	v.SetDefault("kubernetes_session.settings_base_secret", "agentapi-settings-base")
	v.SetDefault("kubernetes_session.mcp_servers_base_secret", "mcp-servers-base")

	// Schedule worker defaults
	v.SetDefault("schedule_worker.enabled", true)
	v.SetDefault("schedule_worker.check_interval", "30s")
	v.SetDefault("schedule_worker.namespace", "")
	v.SetDefault("schedule_worker.lease_duration", "9m")
	v.SetDefault("schedule_worker.renew_deadline", "6m")
	v.SetDefault("schedule_worker.retry_period", "1m")

	// Slackbot cleanup worker defaults
	v.SetDefault("slackbot_cleanup_worker.enabled", false)
	v.SetDefault("slackbot_cleanup_worker.check_interval", "1h")
	v.SetDefault("slackbot_cleanup_worker.session_ttl", "72h")
	v.SetDefault("slackbot_cleanup_worker.session_ttl_check_interval", "1m")
	v.SetDefault("slackbot_cleanup_worker.namespace", "")
	v.SetDefault("slackbot_cleanup_worker.lease_duration", "9m")
	v.SetDefault("slackbot_cleanup_worker.renew_deadline", "6m")
	v.SetDefault("slackbot_cleanup_worker.retry_period", "1m")

	// Session route reconciler defaults. Every rule acts only on definitive
	// signals (deleted manager/runner records, an unacknowledged deletion, the
	// runtime's own live status), so it is enabled by default. The
	// thresholds reclaim a stale session within about an hour.
	v.SetDefault("session_route_reconciler.enabled", true)
	v.SetDefault("session_route_reconciler.dry_run", false)
	v.SetDefault("session_route_reconciler.interval", "5m")
	v.SetDefault("session_route_reconciler.orphan_grace", "15m")
	v.SetDefault("session_route_reconciler.stuck_deletion_grace", "45m")
	v.SetDefault("session_route_reconciler.runtime_disconnect_grace", "10m")
	v.SetDefault("session_route_reconciler.configuration_orphan_grace", "45m")

	// Stock inventory worker defaults
	v.SetDefault("stock_inventory_worker.enabled", false)
	v.SetDefault("stock_inventory_worker.check_interval", "30s")
	v.SetDefault("stock_inventory_worker.target_count", 2)
	v.SetDefault("stock_inventory_worker.docker_enabled", false)
	v.SetDefault("stock_inventory_worker.namespace", "")
	v.SetDefault("stock_inventory_worker.lease_duration", "9m")
	v.SetDefault("stock_inventory_worker.renew_deadline", "6m")
	v.SetDefault("stock_inventory_worker.retry_period", "1m")

	// Webhook defaults
	v.SetDefault("webhook.base_url", "")
	v.SetDefault("webhook.github_enterprise_host", "")

	// scia defaults
	v.SetDefault("scia.enabled", false)
	v.SetDefault("scia.public_base_url", "")
	v.SetDefault("scia.oauth_internal_url", "")
	v.SetDefault("scia.proxy_url", "")
	v.SetDefault("scia.credential", "")
	v.SetDefault("scia.user_namespace", "")
	v.SetDefault("scia.no_proxy", "localhost,127.0.0.1,.svc,.cluster.local")
	v.SetDefault("scia.session_sidecar_enabled", false)
	v.SetDefault("scia.session_sidecar_image", "ghcr.io/takutakahashi/scia:0.17.0")
	v.SetDefault("scia.session_sidecar_config_image", "busybox:1.36")
	v.SetDefault("scia.session_sidecar_port", 18081)
	v.SetDefault("scia.google_hosts", []string{"www.googleapis.com"})
	v.SetDefault("scia.google_paths", []string{"/calendar/v3/*"})
	v.SetDefault("scia.todoist_credential", "")
	v.SetDefault("scia.todoist_hosts", []string{"api.todoist.com"})
	v.SetDefault("scia.todoist_paths", []string{"/api/v1/*", "/rest/v2/*", "/sync/v9/*"})

	v.SetDefault("session_persistence.backend", "")
	v.SetDefault("session_persistence.path", "/var/lib/agentapi-session-state")
	v.SetDefault("session_persistence.suspend_after", "1h")
	v.SetDefault("session_persistence.s3.prefix", "agentapi-sessions/")

	// Slack defaults
	v.SetDefault("slack.dry_run", false)

	// Redis defaults (empty addr = disabled)
	v.SetDefault("redis.addr", "")
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.tls_enabled", false)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")
	v.SetDefault("redis.session_control_pool_size", 50)
	v.SetDefault("redis.session_control_blocking_pool_size", 400)
}

// applyConfigDefaults applies default values to any unset configuration fields
func applyConfigDefaults(config *Config) {
	if config.KubernetesSession.BasePort == 0 {
		config.KubernetesSession.BasePort = 9000
	}

	// Apply auth defaults
	if config.Auth.BootstrapAdmin != nil {
		if config.Auth.BootstrapAdmin.UserID == "" {
			config.Auth.BootstrapAdmin.UserID = "bootstrap-admin"
		}
		if config.Auth.BootstrapAdmin.Username == "" {
			config.Auth.BootstrapAdmin.Username = "admin"
		}
	}
	if config.Auth.GitHub != nil {
		if config.Auth.GitHub.BaseURL == "" {
			config.Auth.GitHub.BaseURL = "https://api.github.com"
		}
		if config.Auth.GitHub.TokenHeader == "" {
			config.Auth.GitHub.TokenHeader = "Authorization"
		}
		if config.Auth.GitHub.OAuth != nil && config.Auth.GitHub.OAuth.Scope == "" {
			config.Auth.GitHub.OAuth.Scope = "read:user read:org project"
		}
	}
	if config.Scia.NoProxy == "" {
		config.Scia.NoProxy = "localhost,127.0.0.1,.svc,.cluster.local"
	}
	if config.Scia.SessionSidecarImage == "" {
		config.Scia.SessionSidecarImage = "ghcr.io/takutakahashi/scia:0.17.0"
	}
	if config.Scia.SessionSidecarConfigImage == "" {
		config.Scia.SessionSidecarConfigImage = "busybox:1.36"
	}
	if config.Scia.SessionSidecarPort == 0 {
		config.Scia.SessionSidecarPort = 18081
	}
	if len(config.Scia.GoogleHosts) == 0 {
		config.Scia.GoogleHosts = []string{"www.googleapis.com"}
	}
	if len(config.Scia.GooglePaths) == 0 {
		config.Scia.GooglePaths = []string{"/calendar/v3/*"}
	}
	if len(config.Scia.TodoistHosts) == 0 {
		config.Scia.TodoistHosts = []string{"api.todoist.com"}
	}
	if len(config.Scia.TodoistPaths) == 0 {
		config.Scia.TodoistPaths = []string{"/api/v1/*", "/rest/v2/*", "/sync/v9/*"}
	}
}

// postProcessConfig applies post-processing logic to the configuration
func postProcessConfig(config *Config) error {
	// Set default auth configuration
	if config.Auth.GitHub != nil && config.Auth.GitHub.OAuth != nil {
		if config.Auth.GitHub.OAuth.BaseURL == "" {
			config.Auth.GitHub.OAuth.BaseURL = config.Auth.GitHub.BaseURL
		}
	}

	// Expand environment variables in OAuth configuration (for ${VAR_NAME} syntax in config files)
	if config.Auth.GitHub != nil && config.Auth.GitHub.OAuth != nil {
		config.Auth.GitHub.OAuth.ClientID = expandEnvVars(config.Auth.GitHub.OAuth.ClientID)
		config.Auth.GitHub.OAuth.ClientSecret = expandEnvVars(config.Auth.GitHub.OAuth.ClientSecret)
	}

	// Log OAuth configuration status (after expansion)
	if config.Auth.GitHub != nil && config.Auth.GitHub.OAuth != nil {
		log.Printf("[CONFIG] OAuth ClientID configured: %v", config.Auth.GitHub.OAuth.ClientID != "")
		log.Printf("[CONFIG] OAuth ClientSecret configured: %v", config.Auth.GitHub.OAuth.ClientSecret != "")

		// Warn if OAuth is configured but credentials are missing
		if config.Auth.GitHub.OAuth.ClientID == "" || config.Auth.GitHub.OAuth.ClientSecret == "" {
			log.Printf("[CONFIG] Warning: OAuth is configured but Client ID or Client Secret is missing")
		}
	}

	// Log role-based environment files configuration
	if config.RoleEnvFiles.Enabled {
		log.Printf("[CONFIG] Role-based environment files enabled")
		log.Printf("[CONFIG] Environment files path: %s", config.RoleEnvFiles.Path)
		log.Printf("[CONFIG] Load default.env: %v", config.RoleEnvFiles.LoadDefault)
	}

	// Load kubernetes session config from external file if specified
	if config.KubernetesSession.ConfigFile != "" {
		if err := loadK8sSessionConfigFromFile(config, config.KubernetesSession.ConfigFile); err != nil {
			log.Printf("[CONFIG] Warning: Failed to load kubernetes session config from %s: %v", config.KubernetesSession.ConfigFile, err)
		} else {
			log.Printf("[CONFIG] Loaded kubernetes session config from: %s", config.KubernetesSession.ConfigFile)
		}
	}

	return nil
}

// LoadConfigLegacy loads configuration from a JSON file (legacy method)
func LoadConfigLegacy(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Failed to close config file: %v", err)
		}
	}()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	applyConfigDefaults(&config)

	// Apply post-processing
	if err := postProcessConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// expandEnvVars expands environment variables in the form ${VAR_NAME}
func expandEnvVars(s string) string {
	if s == "" {
		return s
	}

	// Match ${VAR_NAME} pattern
	re := regexp.MustCompile(`\$\{([^}]+)\}`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		// Extract variable name (remove ${})
		varName := strings.TrimPrefix(strings.TrimSuffix(match, "}"), "${")

		// Get environment variable value
		if value := os.Getenv(varName); value != "" {
			return value
		}

		// Return original string if environment variable is not set
		log.Printf("[CONFIG] Warning: Environment variable %s is not set", varName)
		return match
	})
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Auth: AuthConfig{
			BootstrapAdmin: &BootstrapAdminAuthConfig{
				Enabled:  false,
				UserID:   "bootstrap-admin",
				Username: "admin",
			},
		},
		StockInventoryWorker: StockInventoryWorkerConfig{
			Enabled:       false,
			CheckInterval: "30s",
			TargetCount:   2,
			DockerEnabled: false,
			LeaseDuration: "9m",
			RenewDeadline: "6m",
			RetryPeriod:   "1m",
		},
	}
}

// AuthConfigOverride represents auth configuration overrides from external file
type AuthConfigOverride struct {
	GitHub *GitHubAuthConfigOverride `json:"github,omitempty" yaml:"github,omitempty"`
}

// GitHubAuthConfigOverride represents GitHub auth configuration overrides
type GitHubAuthConfigOverride struct {
	UserMapping *GitHubUserMapping `json:"user_mapping,omitempty" yaml:"user_mapping,omitempty"`
}

var authConfigOverrideSections = []string{"github"}

// LoadAuthConfigFromFile loads auth configuration from an external file (e.g., ConfigMap)
func LoadAuthConfigFromFile(config *Config, filename string) error {
	return loadAuthConfigFromFile(config, filename)
}

// loadAuthConfigFromFile loads auth configuration from an external file (e.g., ConfigMap)
func loadAuthConfigFromFile(config *Config, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Failed to close auth config file: %v", err)
		}
	}()

	var authOverride AuthConfigOverride

	// Determine file format based on extension
	if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
		// Use yaml package directly for YAML files
		decoder := yaml.NewDecoder(file)
		if err := decoder.Decode(&authOverride); err != nil {
			return err
		}
		warnUnknownAuthConfigSections(filename)
	} else {
		// Default to JSON
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&authOverride); err != nil {
			return err
		}
	}

	// Apply overrides to the main config
	if authOverride.GitHub != nil {
		// Initialize GitHub config if it doesn't exist
		if config.Auth.GitHub == nil {
			config.Auth.GitHub = &GitHubAuthConfig{}
		}

		// Override user mapping if provided
		if authOverride.GitHub.UserMapping != nil {
			log.Printf("[CONFIG] Applying GitHub user mapping from external config:")
			log.Printf("[CONFIG]   Default role: %s", authOverride.GitHub.UserMapping.DefaultRole)
			log.Printf("[CONFIG]   Default permissions: %v", authOverride.GitHub.UserMapping.DefaultPermissions)
			log.Printf("[CONFIG]   Team role mappings: %+v", authOverride.GitHub.UserMapping.TeamRoleMapping)

			config.Auth.GitHub.UserMapping = *authOverride.GitHub.UserMapping
			log.Printf("[CONFIG] Applied GitHub user mapping from external config")

			// Verify the configuration was applied
			log.Printf("[CONFIG] After applying - Default role: %s", config.Auth.GitHub.UserMapping.DefaultRole)
			log.Printf("[CONFIG] After applying - Default permissions: %v", config.Auth.GitHub.UserMapping.DefaultPermissions)
			log.Printf("[CONFIG] After applying - Team role mappings: %+v", config.Auth.GitHub.UserMapping.TeamRoleMapping)
		}
	} else {
		log.Printf("[CONFIG] No GitHub config found in auth override file")
	}

	return nil
}

// warnUnknownAuthConfigSections logs a warning for top-level sections the auth
// config loader does not understand, so operators never assume an unsupported
// setting took effect.
func warnUnknownAuthConfigSections(filename string) {
	rawFile, err := os.Open(filename)
	if err != nil {
		return
	}
	defer func() { _ = rawFile.Close() }()
	var raw map[interface{}]interface{}
	if err := yaml.NewDecoder(rawFile).Decode(&raw); err != nil {
		return
	}
	for key := range raw {
		name := fmt.Sprintf("%v", key)
		known := false
		for _, section := range authConfigOverrideSections {
			if name == section {
				known = true
				break
			}
		}
		if !known {
			log.Printf("[CONFIG] Warning: unknown section %q in auth config file %s is ignored (supported: %v)", name, filename, authConfigOverrideSections)
		}
	}
}

// K8sSessionConfigOverride represents kubernetes session configuration overrides from external file
type K8sSessionConfigOverride struct {
	KubernetesSession *struct {
		NodeSelector map[string]string      `json:"node_selector,omitempty" yaml:"node_selector"`
		Affinity     map[string]interface{} `json:"affinity,omitempty" yaml:"affinity"`
		Tolerations  []Toleration           `json:"tolerations,omitempty" yaml:"tolerations"`
	} `json:"kubernetes_session,omitempty" yaml:"kubernetes_session"`
}

// loadK8sSessionConfigFromFile loads kubernetes session configuration from an external file
func loadK8sSessionConfigFromFile(config *Config, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Failed to close kubernetes session config file: %v", err)
		}
	}()

	var k8sOverride K8sSessionConfigOverride

	// Determine file format based on extension
	if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
		data, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		// sigs.k8s.io/yaml converts YAML through JSON, ensuring nested arbitrary
		// values (notably affinity) use string-keyed maps that json.Marshal can
		// safely clone later in runtimeconfig.Provider.
		if err := sigsyaml.Unmarshal(data, &k8sOverride); err != nil {
			return err
		}
	} else {
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&k8sOverride); err != nil {
			return err
		}
	}

	// Apply overrides to the main config
	if k8sOverride.KubernetesSession != nil {
		if k8sOverride.KubernetesSession.NodeSelector != nil {
			config.KubernetesSession.NodeSelector = k8sOverride.KubernetesSession.NodeSelector
			log.Printf("[CONFIG] Applied kubernetes session node_selector: %v", config.KubernetesSession.NodeSelector)
		}
		if k8sOverride.KubernetesSession.Affinity != nil {
			config.KubernetesSession.Affinity = k8sOverride.KubernetesSession.Affinity
			log.Printf("[CONFIG] Applied kubernetes session affinity: %v", config.KubernetesSession.Affinity)
		}
		if k8sOverride.KubernetesSession.Tolerations != nil {
			config.KubernetesSession.Tolerations = k8sOverride.KubernetesSession.Tolerations
			log.Printf("[CONFIG] Applied kubernetes session tolerations: %+v", config.KubernetesSession.Tolerations)
		}
	}

	return nil
}

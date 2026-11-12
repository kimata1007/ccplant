import {
  Session,
  ResourceScope,
  SessionListParams,
  SessionListResponse,
  CreateSessionRequest,
  SessionMessage,
  SessionMessageListResponse,
  SessionMessageListParams,
  SendSessionMessageRequest,
  SessionEventData,
  SessionEventsOptions,
  Agent,
  AgentListResponse,
  AgentListParams,
  ToolStatusResponseBody,
  PendingAction,
  ActionRequest,
  ActionResponse,
  SessionContextTemplate,
  Workspace
} from '../types/agentapi';
import {
  Schedule,
  ScheduleListParams,
  ScheduleListResponse,
  CreateScheduleRequest,
  UpdateScheduleRequest,
  TriggerScheduleResponse
} from '../types/schedule';
import {
  Webhook,
  WebhookListParams,
  WebhookListResponse,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  RegenerateSecretResponse,
  TriggerWebhookRequest,
  TriggerWebhookResponse
} from '../types/webhook';
import {
  SlackBot,
  SlackBotListParams,
  SlackBotListResponse,
  CreateSlackBotRequest,
  UpdateSlackBotRequest
} from '../types/slackbot';
import {
  SessionProfile,
  SessionProfileListParams,
  SessionProfileListResponse,
  CreateSessionProfileRequest,
  UpdateSessionProfileRequest
} from '../types/session_profile';
import {
  ApiToken,
  ApiTokenListParams,
  ApiTokenListResponse,
  CreateApiTokenRequest,
  CreateApiTokenResponse
} from '../types/api_token';
import {
  SandboxPolicy,
  SandboxPolicyListParams,
  SandboxPolicyListResponse,
  CreateSandboxPolicyRequest,
  UpdateSandboxPolicyRequest
} from '../types/sandbox_policy';
import {
  CreateShareResponse,
  ShareStatus,
  RevokeShareResponse
} from '../types/share';
import { loadFullGlobalSettings, getDefaultProxySettings, addRepositoryToHistory, SettingsData, GoogleOAuthStatus, SciaAuthorizationURLResponse, SciaIntegrationsResponse, SciaRevokeResponse, AvailableManager, ExternalSessionManagerConfig, ExternalSessionManagerRegistrationToken, ExternalSessionManagerOperationalStatus, ExternalSessionManagerLogs } from '../types/settings';
import { ProxyUserInfo } from '../types/user';
import { TeamConfig, TeamMembershipState, TeamMembershipSyncResult } from '../types/team-config';
import { AdminSettingsDocument, AdminSettingsVersionsResponse, UpdateAdminSettingsRequest } from '../types/admin-settings';
import { AdminSessionRunner, ClusterSessionManager, LogicalSessionPool, SessionPoolBinding, SessionPoolLogs, SessionPoolStatusResponse, SessionPoolSupplier } from '../types/session_pool';
import { GitHubConnection, GitHubConnectionInput, GitHubIdentitiesResponse } from '../types/github-connection';
import { GoogleConnection, GoogleConnectionInput, GoogleIdentitiesResponse } from '../types/google-connection';
import { handleAuthenticationRequired, isAuthenticationRequiredError } from './auth-error-handler';

// React trees can mount multiple consumers of the same read endpoint at once
// (for example the conversation list and its tag sidebar). Share only the
// in-flight GET promise so a page bootstrap does not send duplicate expensive
// searches. The entry is removed immediately after completion; this is not a
// response cache and therefore cannot serve stale data after a mutation.
const inFlightGetRequests = new Map<string, Promise<unknown>>();

function defaultClientDebugEnabled(): boolean {
  return process.env.NODE_ENV !== 'production'
    && (process.env.NEXT_PUBLIC_DEBUG_LOGS === 'true' || process.env.DEBUG_LOGS === 'true');
}

function debugAllowed(requested: boolean): boolean {
  return process.env.NODE_ENV !== 'production' && requested;
}

function requestUrlForLog(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    return `${url.origin}${url.pathname}`;
  } catch {
    return rawUrl.split('?')[0];
  }
}

// CredentialsMetadata represents the metadata returned by the credentials API
export interface CredentialsMetadata {
  name: string;
  has_data: boolean;
  created_at: string;
  updated_at: string;
}

export type TransferableResourceType = 'webhook' | 'slackbot' | 'session_profile' | 'sandbox_policy';

export interface TransferResourceResult {
  resource_type: TransferableResourceType;
  resource_id: string;
  from: { scope: ResourceScope; user_id?: string; team_id?: string };
  to: { scope: ResourceScope; user_id?: string; team_id?: string };
  status: 'transferred' | 'dry_run';
  dry_run: boolean;
  warnings?: string[];
}

// CodexDeviceAuthConfig is returned by GET /codex/device-auth/config
export interface CodexDeviceAuthConfig {
  configured: boolean;
  execution_mode?: 'auth_workload';
}

// CodexDeviceAuthStart is returned by POST /codex/device-auth
export interface CodexDeviceAuthStart {
  attempt_id: string;
  status: 'starting' | 'waiting_for_user' | 'authorized' | 'denied' | 'failed' | 'cancelled';
  user_code?: string;
  verification_uri?: string;
  expires_at: string;
  poll_after_ms: number;
}

// CodexDeviceAuthStatus is returned by POST /codex/device-auth/token
export interface CodexDeviceAuthStatus {
  status: 'pending' | 'authorized' | 'denied';
}

export interface CodexDeviceAuthTarget {
  scope?: 'user' | 'team';
  team_id?: string;
  replace?: boolean;
}

// GitHubUser type (moved from profile.ts)
export interface GitHubUser {
  id: number;
  login: string;
  name?: string;
  email?: string;
  avatarUrl?: string;
}

// Define local AgentStatus type
interface AgentStatus {
  status: 'stable' | 'running' | 'error';
  last_activity?: string;
  current_task?: string;
  agent_type?: string;
  model?: string;
  /** Provisioner error message when status is 'error' */
  message?: string;
  error_code?: string;
}

/**
 * Proxy-wide session status change event emitted by GET /sessions/status/stream
 */
export interface ProxySessionStatusEvent {
  session_id: string;
  status: string;
  timestamp: string;
}

export interface CreateSessionSecretResponse {
  secret_id: string;
  expires_at: string;
  local_url: string;
}

export interface SessionSecretMetadata {
  secret_id: string;
  status: 'pending' | 'consumed' | 'expired';
  created_at: string;
  expires_at: string;
  consumed_at?: string;
}

export interface SessionSecretListResponse {
  secrets: SessionSecretMetadata[];
}

/**
 * Response from GET /sessions/:sessionId/messages/wait (long-poll).
 * Returns updated: true with session_id and timestamp when a message_update event occurred,
 * or updated: false when the timeout elapsed with no update.
 */
export type WaitSessionMessagesResponse =
  | { updated: true; session_id: string; timestamp: string }
  | { updated: false };

export interface AgentAPIProxyClientConfig {
  baseURL: string;
  apiKey?: string;
  timeout?: number;
  maxSessions?: number;
  sessionTimeout?: number;
  debug?: boolean;
}

export class AgentAPIProxyError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AgentAPIProxyError';
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// ACP (Agent Client Protocol) types
// ──────────────────────────────────────────────────────────────────────────────

/** Response from GET /{sessionId}/session for ACP sessions. */
export interface ACPConfigOption {
  id?: string;
  key?: string;
  name?: string;
  description?: string;
  category?: string;
  type?: string;
  value?: unknown;
  currentValue?: unknown;
  default?: unknown;
  options?: unknown;
}

export interface ACPSessionInfo {
  sessionId: string;
  status: string;
  model?: unknown;
  modelId?: unknown;
  currentModel?: unknown;
  selectedModel?: unknown;
  modelInfo?: unknown;
  configOptions?: ACPConfigOption[];
  _meta?: Record<string, unknown>;
}

export interface ACPPromptContentBlock {
  type: 'text' | 'image';
  text?: string;
  mimeType?: string;
  data?: string;
}

/** Discriminated union for ACP session/update payloads. */
export interface ACPSessionUpdate {
  sessionUpdate: string;
  // agent_message_chunk / user_message_chunk / agent_thought_chunk:
  //   content = { type: "text", text: "..." }
  // tool_call / tool_call_update:
  //   content = [{ type: "content"|"diff"|"terminal", content?: {type,text}, ... }]
  //   (ACP ToolCallContent[] — use extractACPToolContent() to get text)
  content?: unknown;
  messageId?: string;
  // tool_call / tool_call_update
  toolCallId?: string;
  kind?: string;
  /** Human-readable tool title (e.g. "Terminal", "Task", "Find …"). Takes precedence over kind. */
  title?: string;
  status?: string;
  /** File/location hints emitted with tool_call (matches ACP ToolCallInfo.locations). */
  locations?: Array<{ path: string; line?: number }>;
  /** Raw tool input (Anthropic SDK format). May be empty {} on streaming start; full input arrives in subsequent tool_call_update. */
  rawInput?: unknown;
  /** Raw tool output (Anthropic SDK format). Prefer content[] for display; rawOutput may contain non-text blocks. */
  rawOutput?: unknown;
  // plan
  entries?: Array<{ content: string; status: string; priority: string }>;
  // current_mode_update
  modeId?: string;
  // available_commands_update
  availableCommands?: Array<{ name: string; description: string; input?: { hint?: string } }>;
  // config_option_update
  configOptions?: ACPConfigOption[];
}

/**
 * Maps ACP tool `kind` values to human-readable tool names shown in the UI.
 * `kind` carries the semantic tool type (e.g. "execute", "read"), while
 * `title` often contains the full command/path text which is not suitable
 * as a short display name.
 */
const ACP_KIND_TO_NAME: Record<string, string> = {
  execute: 'Bash',
  read: 'Read',
  write: 'Write',
  edit: 'Edit',
  search: 'Search',
  glob: 'Glob',
  other: 'Tool',
  think: 'Think',
  task: 'Task',
  browse: 'Browser',
};

function titleToToolName(title: string | undefined): string | undefined {
  if (!title) return undefined;
  const match = title.match(/^[A-Za-z][A-Za-z0-9_-]*/);
  if (!match) return undefined;
  return match[0];
}

/**
 * Returns a short human-readable tool name for display.
 * Prefers the kind→name mapping; falls back to title, then kind, then 'tool'.
 */
function acpToolDisplayName(kind: string | undefined, title: string | undefined): string {
  if (kind && ACP_KIND_TO_NAME[kind]) return ACP_KIND_TO_NAME[kind];
  return titleToToolName(title) || kind || 'tool';
}

function acpToolNameFromRawInput(rawInput: unknown): string | undefined {
  if (!rawInput || typeof rawInput !== 'object' || Array.isArray(rawInput)) return undefined;
  const toolName = (rawInput as Record<string, unknown>)._toolName;
  if (typeof toolName !== 'string' || toolName.length === 0) return undefined;
  return ACP_KIND_TO_NAME[toolName] || titleToToolName(toolName) || toolName;
}

/** A permission option offered by the ACP agent. */
export interface ACPPermissionOption {
  optionId: string;
  name: string;
  kind?: string;
}

/** Params for session/request_permission (agent → client). */
export interface ACPPermissionParams {
  sessionId: string;
  toolCall: { toolCallId: string; kind?: string };
  options: ACPPermissionOption[];
}

/** Raw JSON-RPC 2.0 message envelope received from the SSE stream. */
export interface ACPJSONRPCMessage {
  jsonrpc: '2.0';
  id?: number | string | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string };
}

export interface ACPUserPromptInfo {
  index: number;
  preview?: string;
}

export interface ACPMessageHistoryResult {
  messages: SessionMessage[];
  lastEventId?: number;
  userPromptCount: number;
  userPromptIndex?: number;
  userPrompts: ACPUserPromptInfo[];
}

export interface EventSubscription {
  close: () => void;
}

export interface ACPInitializationSubscription extends EventSubscription {
  /** Resolves after the initial SSE handshake succeeds, or false on error/timeout. */
  opened: Promise<boolean>;
  /** Delivers events buffered while history was loading, skipping history-covered IDs. */
  resumeAfterHistory: (lastEventId?: number) => void;
}

/** Callbacks for subscribeToACPSessionEvents. */
export interface ACPSessionCallbacks {
  /** Called for each complete or streaming agent message. */
  onMessage: (message: SessionMessage) => void;
  /** Called with additional text to append to an existing streaming message. */
  onChunk: (messageId: number, text: string) => void;
  /** Called when an image is appended to an existing streaming message. */
  onImageChunk?: (messageId: number, image: { mimeType: string; data: string }) => void;
  /**
   * Called with additional thought text to append to an existing streaming message.
   * The thought is displayed in a collapsible "Thinking…" section.
   */
  onThoughtChunk: (messageId: number, thought: string) => void;
  /**
   * Called when a tool call's status changes to in_progress.
   * The message with matching toolUseId should update its visual state.
   */
  onToolUpdate?: (toolCallId: string, status: string) => void;
  /**
   * Called when a tool call's input is updated (step 2 of the 3-step ACP sequence).
   * The message with matching toolUseId should patch its input/title/locations.
   */
  onToolInputUpdate?: (
    toolCallId: string,
    input: unknown,
    title?: string,
    locations?: Array<{ path: string; line?: number }>
  ) => void;
  /**
   * Called when the agent switches to a different mode (current_mode_update).
   */
  onModeUpdate?: (modeId: string) => void;
  /**
   * Called when the agent advertises its slash-command list (available_commands_update).
   */
  onCommandsUpdate?: (commands: Array<{ name: string; description: string; hint?: string }>) => void;
  /**
   * Called when the agent reports updated session configuration options.
   */
  onConfigOptionsUpdate?: (configOptions: ACPConfigOption[]) => void;
  /** Called when a permission request arrives from the agent. */
  onPermission: (action: PendingAction, rpcId: number) => void;
  /** Called when the message SSE stream opens. */
  onConnectionOpen?: () => void;
  /** Called when the message SSE stream is connecting or retrying. */
  onConnectionConnecting?: (attempt?: number, delayMs?: number) => void;
  /** Called when the message SSE stream closes permanently. */
  onConnectionClosed?: () => void;
  /** Called on transport errors. */
  onError: (error: Error) => void;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Extract text from an ACP ContentBlock (used for agent/user message chunks). */
function acpExtractText(content: unknown): string {
  if (!content || typeof content !== 'object' || Array.isArray(content)) return '';
  const obj = content as Record<string, unknown>;
  if (obj.type === 'text' && typeof obj.text === 'string') return obj.text;
  return '';
}

function acpExtractImage(content: unknown): { mimeType: string; data: string } | null {
  if (!content || typeof content !== 'object' || Array.isArray(content)) return null;
  const obj = content as Record<string, unknown>;
  if (obj.type === 'image' && typeof obj.mimeType === 'string' && typeof obj.data === 'string') {
    return { mimeType: obj.mimeType, data: obj.data };
  }
  return null;
}

/**
 * Extract human-readable text from an ACP ToolCallContent array.
 * claude-agent-acp sends tool results via this content array (not rawOutput)
 * with each item having type "content" | "diff" | "terminal".
 */
function extractACPToolContent(content: unknown): string {
  if (!content || !Array.isArray(content)) return '';
  const texts: string[] = [];
  for (const item of content) {
    if (!item || typeof item !== 'object') continue;
    const obj = item as Record<string, unknown>;
    if (obj.type === 'content') {
      // { type: "content", content: { type: "text", text: "..." } }
      const inner = obj.content as Record<string, unknown> | undefined;
      if (inner && typeof inner.text === 'string') texts.push(inner.text);
    } else if (obj.type === 'diff') {
      // { type: "diff", path: "...", newText: "..." }
      if (typeof obj.newText === 'string') texts.push(obj.newText);
    }
    // "terminal" type: skip (has no text)
  }
  return texts.join('\n');
}

function extractACPToolImages(content: unknown): Array<{ mimeType: string; data: string }> {
  if (!Array.isArray(content)) return [];
  return content.flatMap(item => {
    if (!item || typeof item !== 'object') return [];
    const block = item as Record<string, unknown>;
    if (block.type !== 'content' || !block.content || typeof block.content !== 'object') return [];
    const image = acpExtractImage(block.content);
    return image ? [image] : [];
  });
}

/**
 * Extract human-readable text from rawOutput.
 * rawOutput can be:
 *   - string: returned as-is
 *   - Array of {text} or {type, text} ContentBlock objects (ACP think/explore tools)
 *   - Single {text} or {type, text} ContentBlock object
 *   - Arbitrary object: falls back to JSON.stringify
 */
function extractRawOutputText(rawOutput: unknown): string {
  if (rawOutput == null) return '';
  if (typeof rawOutput === 'string') return rawOutput;
  if (Array.isArray(rawOutput)) {
    return rawOutput
      .map(item => {
        if (typeof item === 'string') return item;
        if (item && typeof (item as Record<string, unknown>).text === 'string') {
          return (item as Record<string, unknown>).text as string;
        }
        return JSON.stringify(item);
      })
      .join('\n');
  }
  // Handle single ContentBlock object {type: "text", text: "..."} or {text: "..."}
  const obj = rawOutput as Record<string, unknown>;
  if (typeof obj.text === 'string') {
    return obj.text;
  }
  if (typeof obj.content === 'string') {
    return obj.content;
  }
  const outputParts: string[] = [];
  if (typeof obj.stdout === 'string' && obj.stdout.length > 0) {
    outputParts.push(obj.stdout);
  }
  if (typeof obj.stderr === 'string' && obj.stderr.length > 0) {
    outputParts.push(obj.stderr);
  }
  if (outputParts.length > 0) {
    if (typeof obj.exitCode === 'number') {
      outputParts.push(`exit code: ${obj.exitCode}`);
    }
    return outputParts.join('\n');
  }
  return JSON.stringify(rawOutput);
}

/** Convert ACP plan entries to a Markdown task list. */
function acpPlanToMarkdown(entries: NonNullable<ACPSessionUpdate['entries']>): string {
  let md = '## Plan\n\n';
  for (const e of entries) {
    const marker =
      e.status === 'completed' ? '- [x]' :
      e.status === 'in_progress' ? '- [~]' :
      e.status === 'cancelled' ? '- [!]' : '- [ ]';
    const priority =
      e.priority === 'high' ? ' 🔴' :
      e.priority === 'low' ? ' 🔵' : '';
    md += `${marker} ${e.content}${priority}\n`;
  }
  return md;
}

function parseACPJSONRPCMessages(rawMsgs: ACPJSONRPCMessage[]): SessionMessage[] {
  const result: SessionMessage[] = [];
  let nextLocalId = Date.now();
  let streamingMsgId: number | null = null;

  for (const msg of rawMsgs) {
    if (msg.method === 'session/update') {
      const acpParams = msg.params as { sessionId: string; update: ACPSessionUpdate; time?: string };
      const update = acpParams?.update;
      if (!update) continue;
      const now = acpParams?.time || new Date().toISOString();

      switch (update.sessionUpdate) {
        case 'agent_message_chunk': {
          const text = acpExtractText(update.content);
          const image = acpExtractImage(update.content);
          if (!text && !image) continue;
          if (streamingMsgId !== null) {
            const idx = result.findIndex(m => m.id === streamingMsgId);
            if (idx >= 0) {
              result[idx] = {
                ...result[idx],
                content: result[idx].content + text,
                images: image ? [...(result[idx].images ?? []), image] : result[idx].images,
              };
            }
          } else {
            const id = nextLocalId++;
            streamingMsgId = id;
            result.push({ id, role: 'agent', content: text, images: image ? [image] : undefined, time: now, type: 'normal' });
          }
          break;
        }
        case 'agent_thought_chunk': {
          const thought = acpExtractText(update.content);
          if (!thought) continue;
          if (streamingMsgId !== null) {
            const idx = result.findIndex(m => m.id === streamingMsgId);
            if (idx >= 0) result[idx] = { ...result[idx], thought: (result[idx].thought ?? '') + thought };
          } else {
            const id = nextLocalId++;
            streamingMsgId = id;
            result.push({ id, role: 'agent', content: '', thought, time: now, type: 'normal' });
          }
          break;
        }
        case 'tool_call': {
          streamingMsgId = null;
          const toolObj = {
            type: 'tool_use',
            name: acpToolNameFromRawInput(update.rawInput) || acpToolDisplayName(update.kind, update.title),
            id: update.toolCallId,
            input: update.rawInput ?? {},
            title: update.title,
            locations: update.locations,
          };
          result.push({ id: nextLocalId++, role: 'agent', content: JSON.stringify(toolObj), time: now, type: 'normal', toolUseId: update.toolCallId });
          break;
        }
        case 'tool_call_update': {
          const isSuccess = update.status === 'completed' || update.status === 'success';
          const isError = update.status === 'failed' || update.status === 'error';
          const isRunning = update.status === 'running' || update.status === 'in_progress';
          if (isRunning) continue;

          if (!isSuccess && !isError) {
            if (update.rawInput != null && update.toolCallId) {
              let idx = -1;
              for (let i = result.length - 1; i >= 0; i--) {
                if (result[i].toolUseId === update.toolCallId) { idx = i; break; }
              }
              if (idx >= 0) {
                try {
                  const toolObj = JSON.parse(result[idx].content);
                  toolObj.input = update.rawInput;
                  if (update.title) toolObj.title = update.title;
                  if (update.locations) toolObj.locations = update.locations;
                  result[idx] = { ...result[idx], content: JSON.stringify(toolObj) };
                } catch { /* ignore parse errors */ }
              }
            }
            continue;
          }

          const acpText = extractACPToolContent(update.content);
          const images = extractACPToolImages(update.content);
          const resultContent = acpText || extractRawOutputText(update.rawOutput);
          result.push({ id: nextLocalId++, role: 'tool_result', content: resultContent, images: images.length > 0 ? images : undefined, time: now, type: 'normal', parentToolUseId: update.toolCallId, status: isError ? 'error' : 'success' });
          break;
        }
        case 'plan': {
          streamingMsgId = null;
          if (!update.entries || update.entries.length === 0) continue;
          result.push({ id: nextLocalId++, role: 'agent', content: acpPlanToMarkdown(update.entries), time: now, type: 'plan' });
          break;
        }
        case 'user_message_chunk': {
          const text = acpExtractText(update.content);
          const image = acpExtractImage(update.content);
          if (!text && !image) continue;
          const previous = result[result.length - 1];
          if (image && previous?.role === 'user') {
            previous.images = [...(previous.images ?? []), image];
          } else {
            result.push({
              id: nextLocalId++,
              role: 'user',
              content: text,
              images: image ? [image] : undefined,
              time: now,
              type: 'normal',
            });
          }
          break;
        }
        default:
          streamingMsgId = null;
      }
    } else if (msg.result != null || msg.error) {
      streamingMsgId = null;
    }
  }

  return result;
}

/**
 * AgentAPIProxyClient handles session management and communicates directly with agentapi-proxy.
 */
export type SessionTaskState = 'QUEUED' | 'CLAIMED' | 'STARTING' | 'SESSION_READY' | 'FAILED' | 'CANCELLED' | 'EXPIRED';

export interface SessionTask {
  id: string;
  name: string;
  state: SessionTaskState;
  session_id: string | null;
  reason?: string;
  updated_at: string;
  cancel_requested?: boolean;
}

export type SessionTaskScope = { scope: 'user' | 'team'; team_id?: string };

export class AgentAPIProxyClient {
  private baseURL: string;
  private apiKey?: string;
  private timeout: number;
  private maxSessions: number;
  private sessionTimeout: number;
  private debug: boolean;

  constructor(config: AgentAPIProxyClientConfig) {
    this.baseURL = config.baseURL.replace(/\/$/, ''); // Remove trailing slash
    this.apiKey = config.apiKey;
    this.timeout = config.timeout || 10000;
    this.maxSessions = config.maxSessions || 10;
    this.sessionTimeout = config.sessionTimeout || 300000; // 5 minutes
    this.debug = debugAllowed(config.debug === true);

    if (this.debug) {
      console.log('[AgentAPIProxy] Initialized with config:', {
        baseURL: requestUrlForLog(this.baseURL),
        maxSessions: this.maxSessions,
        sessionTimeout: this.sessionTimeout
      });
    }
  }

  private subscribeWithEventSource(
    url: string,
    handlers: {
      onOpen?: () => void;
      onMessage: (event: MessageEvent) => void;
      onTransientError?: (event: Event, state: number) => void;
      onReconnect?: (attempt: number, delayMs: number) => void;
      onClosed?: (event: Event, state: number) => void;
    },
    options?: SessionEventsOptions,
    initialLastEventId?: number,
    initialization?: {
      deferMessages: boolean;
      handshakeTimeoutMs: number;
    }
  ): ACPInitializationSubscription {
    let eventSource: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let stableConnectionTimer: ReturnType<typeof setTimeout> | null = null;
    let closed = false;
    let reconnectAttempts = 0;
    let lastEventId = initialLastEventId;
    let deferred = initialization?.deferMessages === true;
    const deferredEvents: MessageEvent[] = [];
    let settleOpened: ((opened: boolean) => void) | null = null;
    const opened = new Promise<boolean>(resolve => {
      settleOpened = resolve;
    });
    const handshakeTimer = initialization
      ? setTimeout(() => {
          settleOpened?.(false);
          settleOpened = null;
        }, initialization.handshakeTimeoutMs)
      : null;

    const settleHandshake = (value: boolean) => {
      if (!settleOpened) return;
      if (handshakeTimer) clearTimeout(handshakeTimer);
      settleOpened(value);
      settleOpened = null;
    };

    const reconnectEnabled = options?.reconnect !== false;
    const baseDelayMs = options?.reconnectInterval ?? 1000;
    const maxDelayMs = 30000;

    const clearReconnectTimer = () => {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    const clearStableConnectionTimer = () => {
      if (stableConnectionTimer) {
        clearTimeout(stableConnectionTimer);
        stableConnectionTimer = null;
      }
    };

    const scheduleReconnect = (event: Event, state: number) => {
      if (closed || !reconnectEnabled) {
        handlers.onClosed?.(event, state);
        return;
      }

      reconnectAttempts += 1;
      if (options?.maxReconnectAttempts && reconnectAttempts > options.maxReconnectAttempts) {
        handlers.onClosed?.(event, state);
        return;
      }

      const delayMs = Math.min(baseDelayMs * Math.pow(2, reconnectAttempts - 1), maxDelayMs);
      handlers.onReconnect?.(reconnectAttempts, delayMs);
      clearReconnectTimer();
      reconnectTimer = setTimeout(connect, delayMs);
    };

    const connect = () => {
      if (closed) return;

      const reconnectUrl = lastEventId === undefined
        ? url
        : `${url}${url.includes('?') ? '&' : '?'}lastEventId=${encodeURIComponent(String(lastEventId))}`;
      const source = new EventSource(reconnectUrl);
      eventSource = source;

      source.onopen = () => {
        if (source !== eventSource || closed) return;
        // The BFF commits eager SSE responses before the upstream handshake.
        // Reset backoff only after the connection has remained healthy.
        clearStableConnectionTimer();
        stableConnectionTimer = setTimeout(() => {
          reconnectAttempts = 0;
          stableConnectionTimer = null;
        }, 30000);
        settleHandshake(true);
        handlers.onOpen?.();
      };

      source.addEventListener('agentapi_upstream_error', (event) => {
        if (source !== eventSource || closed) return;
        clearStableConnectionTimer();
        settleHandshake(false);
        source.close();
        eventSource = null;

        let retryable = true;
        let retryAfterMs: number | undefined;
        try {
          const payload = JSON.parse((event as MessageEvent).data) as {
            retryable?: boolean;
            retryAfterMs?: number;
          };
          retryable = payload.retryable !== false;
          retryAfterMs = payload.retryAfterMs;
        } catch {
          // Malformed errors remain retryable using the normal backoff.
        }

        if (!retryable) {
          handlers.onClosed?.(event, EventSource.CLOSED);
          return;
        }
        if (retryAfterMs !== undefined) {
          reconnectAttempts = Math.max(
            reconnectAttempts,
            Math.ceil(Math.log2(Math.max(1, retryAfterMs / baseDelayMs))),
          );
        }
        scheduleReconnect(event, EventSource.CLOSED);
      });

      source.onmessage = (event) => {
        if (source !== eventSource || closed) return;
        if (event.lastEventId !== '') {
          const parsedEventId = Number(event.lastEventId);
          if (Number.isSafeInteger(parsedEventId)) {
            if (lastEventId !== undefined && parsedEventId <= lastEventId) return;
            lastEventId = parsedEventId;
          }
        }
        if (deferred) {
          deferredEvents.push(event);
        } else {
          handlers.onMessage(event);
        }
      };

      source.onerror = (event) => {
        if (source !== eventSource || closed) return;

        settleHandshake(false);

        const state = source.readyState;
        if (state === EventSource.CLOSED) {
          source.close();
          eventSource = null;
          scheduleReconnect(event, state);
          return;
        }

        handlers.onTransientError?.(event, state);
      };
    };

    connect();

    return {
      close: () => {
        closed = true;
        settleHandshake(false);
        clearStableConnectionTimer();
        clearReconnectTimer();
        eventSource?.close();
        eventSource = null;
      },
      opened,
      resumeAfterHistory: (historyLastEventId?: number) => {
        if (!deferred) return;
        deferred = false;
        for (const event of deferredEvents.splice(0)) {
          const eventId = Number(event.lastEventId);
          if (
            historyLastEventId !== undefined &&
            Number.isSafeInteger(eventId) &&
            eventId <= historyLastEventId
          ) {
            continue;
          }
          handlers.onMessage(event);
        }
      },
    };
  }

  private makeRequest<T>(
    endpoint: string,
    options: RequestInit = {},
    attempt = 1
  ): Promise<T> {
    const method = (options.method || 'GET').toUpperCase();
    if (method !== 'GET' || attempt !== 1) {
      return this.makeRequestUncached<T>(endpoint, options, attempt);
    }

    const key = `${this.baseURL}|${this.apiKey || 'cookie'}|${endpoint}`;
    const existing = inFlightGetRequests.get(key);
    if (existing) return existing as Promise<T>;

    const request = this.makeRequestUncached<T>(endpoint, options, attempt);
    inFlightGetRequests.set(key, request);
    void request.finally(() => {
      if (inFlightGetRequests.get(key) === request) {
        inFlightGetRequests.delete(key);
      }
    }).catch(() => undefined);
    return request;
  }

  private async makeRequestUncached<T>(
    endpoint: string,
    options: RequestInit = {},
    attempt = 1
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    
    const defaultHeaders: HeadersInit = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, application/problem+json',
    };

    // Try Bearer token first, then fallback to X-API-Key
    if (this.apiKey) {
      // First attempt with Bearer token
      const bearerHeaders = { ...defaultHeaders, 'Authorization': `Bearer ${this.apiKey}` };
      const bearerRequestOptions: RequestInit = {
        ...options,
        headers: {
          ...bearerHeaders,
          ...options.headers,
        },
      };

      if (this.debug) {
        console.log(`[AgentAPIProxy] ${options.method || 'GET'} ${requestUrlForLog(url)} (authenticated)`, { attempt });
      }

      try {
        const response = await fetch(url, bearerRequestOptions);

        if (!response.ok) {
          // If Bearer token fails with 401/403, try X-API-Key fallback
          if (response.status === 401 || response.status === 403) {
            const fallbackHeaders = { ...defaultHeaders, 'X-API-Key': this.apiKey };
            const fallbackRequestOptions: RequestInit = {
              ...options,
              headers: {
                ...fallbackHeaders,
                ...options.headers,
              },
            };

            if (this.debug) {
              console.log(`[AgentAPIProxy] ${options.method || 'GET'} ${requestUrlForLog(url)} (authentication fallback)`, { attempt });
            }

            const fallbackResponse = await fetch(url, fallbackRequestOptions);

            if (!fallbackResponse.ok) {
              const errorData = await fallbackResponse.json().catch(() => ({
                message: `HTTP ${fallbackResponse.status}: ${fallbackResponse.statusText}`,
              }));

              // Auto-logout when the proxy rejects the request due to missing/expired session cookie
              if (isAuthenticationRequiredError(fallbackResponse.status, errorData)) {
                handleAuthenticationRequired();
              }

              // Support both Echo's simple format and structured error format
              const errorMessage = errorData.message || errorData.error?.message || `HTTP ${fallbackResponse.status}`;
              const errorCode = errorData.error?.code || 'HTTP_ERROR';
              const errorDetails = errorData.error?.details;

              throw new AgentAPIProxyError(
                fallbackResponse.status,
                errorCode,
                errorMessage,
                errorDetails
              );
            }

            // Handle 204 No Content (empty body)
            if (fallbackResponse.status === 204) {
              return undefined as T;
            }
            const fallbackData = await fallbackResponse.json();

            return fallbackData;
          }

          const errorData = await response.json().catch(() => ({
            message: `HTTP ${response.status}: ${response.statusText}`,
          }));

          // Support both Echo's simple format and structured error format
          const errorMessage = errorData.message || errorData.error?.message || `HTTP ${response.status}`;
          const errorCode = errorData.error?.code || 'HTTP_ERROR';
          const errorDetails = errorData.error?.details;

          throw new AgentAPIProxyError(
            response.status,
            errorCode,
            errorMessage,
            errorDetails
          );
        }

        // Handle 204 No Content (empty body)
        if (response.status === 204) {
          return undefined as T;
        }
        const data = await response.json();

        return data;
      } catch (error) {
        if (error instanceof AgentAPIProxyError) {
          throw error;
        }

        throw new AgentAPIProxyError(
          0,
          'NETWORK_ERROR',
          error instanceof Error ? error.message : 'Unknown network error'
        );
      }
    }

    // No API key case
    const requestOptions: RequestInit = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
    };

    if (this.debug) {
      console.log(`[AgentAPIProxy] ${options.method || 'GET'} ${requestUrlForLog(url)} (cookie/public auth)`, { attempt });
    }

    try {
      const response = await fetch(url, requestOptions);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          message: `HTTP ${response.status}: ${response.statusText}`,
        }));

        // Auto-logout when the proxy rejects the request due to missing/expired session cookie
        if (isAuthenticationRequiredError(response.status, errorData)) {
          handleAuthenticationRequired();
        }

        // Support both Echo's simple format and structured error format
        const errorMessage = errorData.message || errorData.error?.message || `HTTP ${response.status}`;
        const errorCode = errorData.error?.code || 'HTTP_ERROR';
        const errorDetails = errorData.error?.details;

        throw new AgentAPIProxyError(
          response.status,
          errorCode,
          errorMessage,
          errorDetails
        );
      }

      // Handle 204 No Content (empty body)
      if (response.status === 204) {
        return undefined as T;
      }
      const data = await response.json();

      return data;
    } catch (error) {
      if (error instanceof AgentAPIProxyError) {
        throw error;
      }

      throw new AgentAPIProxyError(
        0,
        'NETWORK_ERROR',
        error instanceof Error ? error.message : 'Unknown network error'
      );
    }
  }

  // High-level operations based on agentapi-proxy

  /**
   * Start a new session
   */
  async start(sessionData?: Partial<CreateSessionRequest> | Record<string, unknown>): Promise<Session> {
    // Handle backward compatibility and new format
    let data: Partial<CreateSessionRequest>;

    if (sessionData && (sessionData.environment || sessionData.tags || sessionData.metadata || sessionData.params || sessionData.scope || sessionData.team_id || sessionData.session_profile_id || sessionData.workspace_id || sessionData.context_template_id)) {
      // New format: sessionData contains environment, metadata, tags, params, scope, and/or team_id
      data = {
        environment: sessionData.environment as Record<string, string> | undefined,
        metadata: sessionData.metadata as Record<string, unknown> | undefined || { source: 'agentapi-ui' },
        tags: sessionData.tags as Record<string, string> | undefined,
        params: sessionData.params as { message?: string; github_token?: string; [key: string]: unknown } | undefined,
        scope: sessionData.scope as CreateSessionRequest['scope'],
        team_id: sessionData.team_id as string | undefined,
		session_profile_id: sessionData.session_profile_id as string | undefined,
		workspace_id: sessionData.workspace_id as string | undefined,
		context_template_id: sessionData.context_template_id as string | undefined,
      };
    } else {
      // Backward compatibility: sessionData is just metadata
      data = {
        metadata: (sessionData as Record<string, unknown>) || { source: 'agentapi-ui' }
      };
    }

    const session = await this.makeRequest<Session>('/start', {
      method: 'POST',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Started session: ${session.session_id}`);
    }

    return session;
  }

  /**
   * Search for sessions
   */
  async listSessionTasks(scope: SessionTaskScope): Promise<SessionTask[]> {
    const query = this.sessionTaskQuery(scope);
    query.set('limit', '200');
    const tasks: SessionTask[] = [];
    do {
      const page = await this.makeRequest<{ items: SessionTask[]; next_cursor?: string }>(`/tasks?${query}`);
      tasks.push(...page.items);
      if (!page.next_cursor) break;
      query.set('cursor', page.next_cursor);
    } while (true);
    return tasks;
  }

  async cancelSessionTask(id: string): Promise<SessionTask> {
    return this.makeRequest(`/tasks/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
  }

  async retrySessionTask(id: string): Promise<void> {
    await this.makeRequest(`/tasks/${encodeURIComponent(id)}/retry`, { method: 'POST' });
  }

  subscribeToSessionTaskChanges(scope: SessionTaskScope, invalidate: () => void): EventSource {
    const stream = new EventSource(`${this.baseURL}/tasks/stream?${this.sessionTaskQuery(scope)}`);
    stream.onopen = invalidate;
    stream.onmessage = invalidate;
    stream.addEventListener('agentapi_upstream_error', () => stream.close());
    return stream;
  }

  private sessionTaskQuery(scope: SessionTaskScope): URLSearchParams {
    const query = new URLSearchParams({ scope: scope.scope, state: 'queued,claimed,starting,failed,expired' });
    if (scope.team_id) query.set('team_id', scope.team_id);
    return query;
  }

  async search(params?: SessionListParams): Promise<SessionListResponse> {
    const searchParams = new URLSearchParams();
    
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.status) searchParams.set('status', params.status);
    if (params?.user_id) searchParams.set('user_id', params.user_id);
    if (params?.scope) searchParams.set('scope', params.scope);
    if (params?.team_id) searchParams.set('team_id', params.team_id);

    const endpoint = `/search${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const result = await this.makeRequest<SessionListResponse>(endpoint);

    // Keep the UI scope isolated even when an older proxy or an external
    // session manager returns a broader result set than requested.
    const sessions = (result.sessions || []).filter(session => {
      if (params?.scope && (session.scope || 'user') !== params.scope) return false;
      if (params?.team_id && session.team_id !== params.team_id) return false;
      return true;
    });
    
    return {
      ...result,
      sessions
    };
  }

  /**
   * Delete a session
   */
  async delete(sessionId: string): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Attempting to delete session: ${sessionId}`);
    }

    // Use the correct agentapi-proxy endpoint: DELETE /sessions/{sessionId}
    await this.makeRequest<void>(`/sessions/${sessionId}`, {
      method: 'DELETE',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Successfully deleted session: ${sessionId}`);
    }
  }

  async createSessionSecret(
    sessionId: string,
    value: string,
    expiresInSeconds = 600,
  ): Promise<CreateSessionSecretResponse> {
    return this.makeRequest<CreateSessionSecretResponse>(
      `/sessions/${encodeURIComponent(sessionId)}/secrets`,
      {
        method: 'POST',
        body: JSON.stringify({ value, expires_in_seconds: expiresInSeconds }),
      },
    );
  }

  async listSessionSecrets(sessionId: string): Promise<SessionSecretListResponse> {
    return this.makeRequest<SessionSecretListResponse>(
      `/sessions/${encodeURIComponent(sessionId)}/secrets`,
    );
  }

  async reauthorizeSessionSecret(
    sessionId: string,
    secretId: string,
    expiresInSeconds = 600,
  ): Promise<CreateSessionSecretResponse> {
    return this.makeRequest<CreateSessionSecretResponse>(
      `/sessions/${encodeURIComponent(sessionId)}/secrets/${encodeURIComponent(secretId)}/reauthorize`,
      {
        method: 'POST',
        body: JSON.stringify({ expires_in_seconds: expiresInSeconds }),
      },
    );
  }

  async resumeSession(sessionId: string): Promise<{ session_id: string; status: string }> {
    return this.makeRequest<{ session_id: string; status: string }>(`/sessions/${sessionId}/resume`, {
      method: 'POST',
    });
  }

  async restartSession(sessionId: string, reloadSettings = true): Promise<{ session_id: string; request_id: string }> {
    return this.makeRequest(
      `/sessions/${encodeURIComponent(sessionId)}/restart`,
      { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ reload_settings: reloadSettings, busy_policy: 'wait' }) },
    );
  }

  async pauseSession(sessionId: string): Promise<{ session_id: string; request_id: string }> {
    return this.makeRequest(`/sessions/${encodeURIComponent(sessionId)}/pause`, {
      method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ busy_policy: 'wait' }),
    });
  }

  async restartStatus(sessionId: string): Promise<{ phase: string; revision: number; error?: string }> {
    return this.makeRequest(`/sessions/${encodeURIComponent(sessionId)}/restart`);
  }

  async suspendSession(sessionId: string): Promise<{ session_id: string; status: string }> {
    return this.makeRequest<{ session_id: string; status: string }>(`/sessions/${sessionId}/suspend`, {
      method: 'POST',
    });
  }

  async templateizeSession(sessionId: string, name: string, description = ''): Promise<SessionContextTemplate> {
    return this.makeRequest<SessionContextTemplate>(`/sessions/${encodeURIComponent(sessionId)}/templateize`, {
      method: 'POST',
      headers: { 'Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify({ name, description, wait_for_idle: true }),
    });
  }

  async saveSessionAsWorkspace(sessionId: string, name: string, description = ''): Promise<Workspace> {
    return this.makeRequest<Workspace>(`/sessions/${encodeURIComponent(sessionId)}/workspace`, {
      method: 'POST',
      headers: { 'Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify({ name, description, wait_for_idle: true }),
    });
  }

  async listWorkspaces(): Promise<{ workspaces: Workspace[] }> {
    return this.makeRequest('/workspaces');
  }

  async getWorkspace(workspaceId: string): Promise<Workspace> {
    return this.makeRequest(`/workspaces/${encodeURIComponent(workspaceId)}`);
  }

  async updateWorkspace(workspaceId: string, input: { name?: string; description?: string }): Promise<Workspace> {
    return this.makeRequest(`/workspaces/${encodeURIComponent(workspaceId)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    });
  }

  async deleteWorkspace(workspaceId: string): Promise<void> {
    await this.makeRequest(`/workspaces/${encodeURIComponent(workspaceId)}`, { method: 'DELETE' });
  }

  async listSessionContextTemplates(): Promise<{ templates: SessionContextTemplate[] }> {
    return this.makeRequest('/session-context-templates');
  }

  async deleteSessionContextTemplate(templateId: string): Promise<void> {
    await this.makeRequest(`/session-context-templates/${encodeURIComponent(templateId)}`, { method: 'DELETE' });
  }


  // Session message operations

  async getSessionMessages(sessionId: string, params?: SessionMessageListParams): Promise<SessionMessageListResponse> {
    const searchParams = new URLSearchParams();

    // New API parameters (cursor-based pagination)
    if (params?.before !== undefined) searchParams.set('before', params.before.toString());
    if (params?.after !== undefined) searchParams.set('after', params.after.toString());

    // Limit and direction parameters
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.direction) searchParams.set('direction', params.direction);

    // Context-based pagination
    if (params?.around !== undefined) searchParams.set('around', params.around.toString());
    if (params?.context !== undefined) searchParams.set('context', params.context.toString());

    // Deprecated parameters (kept for backwards compatibility)
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.from) searchParams.set('from', params.from);
    if (params?.to) searchParams.set('to', params.to);

    const endpoint = `/${sessionId}/messages${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;

    if (this.debug) {
      console.log(`[AgentAPIProxy] Fetching messages for session ${sessionId} with params:`, Object.fromEntries(searchParams));
    }

    const result = await this.makeRequest<SessionMessageListResponse>(endpoint);

    return {
      ...result,
      messages: result.messages || []
    };
  }

  async sendSessionMessage(sessionId: string, data: SendSessionMessageRequest, retryCount = 0): Promise<SessionMessage> {
    const maxRetries = 2;
    
    try {
      if (this.debug) {
        console.log(`[AgentAPIProxy] Sending message to session ${sessionId} (attempt ${retryCount + 1})`);
      }

      const result = await this.makeRequest<SessionMessage>(`/${sessionId}/message`, {
        method: 'POST',
        body: JSON.stringify(data),
      });

      if (this.debug) {
        console.log(`[AgentAPIProxy] Successfully sent message to session ${sessionId}`);
      }

      return result;
    } catch (error) {
      if (this.debug) {
        console.error(`[AgentAPIProxy] Failed to send message to session ${sessionId} (attempt ${retryCount + 1}):`, error);
      }

      // Check if this is a timeout or screen stabilization error
      const isTimeoutError = error instanceof AgentAPIProxyError && 
        (error.message.includes('timeout') || 
         error.message.includes('screen to stabilize') ||
         error.message.includes('wait for condition'));

      // Retry for timeout errors
      if (isTimeoutError && retryCount < maxRetries) {
        const delay = (retryCount + 1) * 2000; // 2s, 4s delay
        if (this.debug) {
          console.log(`[AgentAPIProxy] Retrying message send in ${delay}ms...`);
        }
        
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.sendSessionMessage(sessionId, data, retryCount + 1);
      }

      // Enhance error message for timeout errors
      if (isTimeoutError) {
        throw new AgentAPIProxyError(
          error instanceof AgentAPIProxyError ? error.status : 500,
          'TIMEOUT_ERROR',
          'メッセージ送信がタイムアウトしました。画面の操作に時間がかかっている可能性があります。しばらく待ってからもう一度お試しください。',
          error instanceof AgentAPIProxyError ? error.details : undefined
        );
      }

      throw error;
    }
  }

  async getSessionStatus(sessionId: string): Promise<AgentStatus> {
    try {
      return await this.makeRequest<AgentStatus>(`/${sessionId}/status`);
    } catch (err) {
      if (err instanceof AgentAPIProxyError && err.status === 500) {
        // Provisioner has permanently failed – return the error status so polling
        // continues for other data without throwing and surface the message.
        return { status: 'error', message: err.message };
      }
      throw err;
    }
  }

  /**
   * Get active tool execution status for a session
   * Returns null if the endpoint is not available (404)
   */
  async getToolStatus(sessionId: string): Promise<ToolStatusResponseBody | null> {
    try {
      return await this.makeRequest<ToolStatusResponseBody>(`/${sessionId}/tool_status`);
    } catch (error) {
      // If the endpoint doesn't exist (404), return null
      if (error instanceof AgentAPIProxyError && error.status === 404) {
        if (this.debug) {
          console.log(`[AgentAPIProxy] Tool status endpoint not available for session ${sessionId}`);
        }
        return null;
      }
      throw error;
    }
  }

  // Session events using Server-Sent Events
  subscribeToSessionEvents(
    sessionId: string,
    onMessage: (message: SessionMessage) => void,
    onStatus?: (status: AgentStatus) => void,
    onError?: (error: Error) => void,
    options?: SessionEventsOptions
  ): EventSubscription {
    // For SSE, we need to construct the full URL - check if we're using proxy
    const isUsingProxy = this.baseURL.includes('/api/v1');
    const eventSourceUrl = isUsingProxy 
      ? `/api/v1/${sessionId}/events`
      : `${this.baseURL}/${sessionId}/events`;
    
    if (this.debug) {
      console.log(`[AgentAPIProxy] Creating EventSource for session ${sessionId}:`, eventSourceUrl);
    }

    return this.subscribeWithEventSource(
      eventSourceUrl,
      {
        onMessage: (event) => {
          try {
            const eventData: SessionEventData = JSON.parse(event.data);

            if (this.debug) {
              console.log(`[AgentAPIProxy] Session event received:`, eventData);
            }

            switch (eventData.type) {
              case 'message':
                onMessage(eventData.data as SessionMessage);
                break;
              case 'status':
                if (onStatus) {
                  onStatus(eventData.data as AgentStatus);
                }
                break;
              case 'error':
                if (onError) {
                  const errorData = eventData.data as { error: string };
                  onError(new Error(errorData.error));
                }
                break;
              default:
                if (this.debug) {
                  console.warn(`[AgentAPIProxy] Unknown event type: ${eventData.type}`);
                }
            }
          } catch (err) {
            console.error('[AgentAPIProxy] Failed to parse session event:', err);
            if (onError) {
              onError(err instanceof Error ? err : new Error('Failed to parse event data'));
            }
          }
        },
        onTransientError: (event, state) => {
          if (this.debug) {
            console.warn(`[AgentAPIProxy] Session EventSource transient error (readyState=${state})`, event);
          }
        },
        onReconnect: (attempt, delayMs) => {
          if (this.debug) {
            console.log(`[AgentAPIProxy] Session EventSource closed; reconnecting in ${delayMs}ms (attempt ${attempt})`);
          }
        },
        onClosed: (event, state) => {
          console.error(`[AgentAPIProxy] Session EventSource closed permanently (readyState=${state})`, event);
          onError?.(new Error('Session EventSource connection closed'));
        },
      },
      options
    );
  }

  /**
   * Subscribe to the ACP bridge's authoritative turn status.
   * The bridge emits the current value immediately and every running/stable
   * transition as a named `status_change` SSE event.
   */
  subscribeToACPStatus(
    sessionId: string,
    onStatus: (status: AgentStatus) => void,
    onError?: (error: Error) => void,
  ): EventSubscription {
    const isUsingProxy = this.baseURL.includes('/api/v1');
    const url = isUsingProxy
      ? `/api/v1/${sessionId}/events`
      : `${this.baseURL}/${sessionId}/events`;
    let source: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let stableTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempts = 0;
    let closed = false;

    const scheduleReconnect = (minimumDelayMs = 0) => {
      if (closed) return;
      reconnectAttempts += 1;
      const delay = Math.max(minimumDelayMs, Math.min(1000 * 2 ** (reconnectAttempts - 1), 30000));
      reconnectTimer = setTimeout(connect, delay);
    };
    const connect = () => {
      if (closed) return;
      const current = new EventSource(url);
      source = current;
      current.onopen = () => {
        if (source !== current || closed) return;
        if (stableTimer) clearTimeout(stableTimer);
        stableTimer = setTimeout(() => {
          reconnectAttempts = 0;
          stableTimer = null;
        }, 30000);
      };
      current.addEventListener('status_change', (event) => {
        try {
          const data = JSON.parse((event as MessageEvent).data) as { status?: unknown };
          if (data.status === 'running' || data.status === 'stable' || data.status === 'error') {
            onStatus({ status: data.status });
          }
        } catch (error) {
          onError?.(error instanceof Error ? error : new Error('Failed to parse ACP status event'));
        }
      });
      current.addEventListener('agentapi_upstream_error', (event) => {
        if (source !== current || closed) return;
        let retryable = true;
        let retryAfterMs = 0;
        try {
          const payload = JSON.parse((event as MessageEvent).data) as { retryable?: boolean; retryAfterMs?: number };
          retryable = payload.retryable !== false;
          retryAfterMs = payload.retryAfterMs ?? 0;
        } catch {
          // Use retry defaults for malformed events.
        }
        current.close();
        source = null;
        if (stableTimer) clearTimeout(stableTimer);
        if (retryable) scheduleReconnect(retryAfterMs);
        else onError?.(new Error('ACP status stream is no longer available'));
      });
      current.onerror = () => {
        if (source !== current || closed) return;
        current.close();
        source = null;
        if (stableTimer) clearTimeout(stableTimer);
        onError?.(new Error('ACP status event stream disconnected'));
        scheduleReconnect();
      };
    };
    connect();

    return { close: () => {
      closed = true;
      source?.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (stableTimer) clearTimeout(stableTimer);
    } };
  }

  /**
   * Long-poll for message updates in a specific session (GET /sessions/:sessionId/messages/wait).
   *
   * Blocks on the server until a message_update event is received from the agentapi backend
   * for the given session, or until the timeout expires.
   *
   * Returns { updated: true, session_id, timestamp } on update, or { updated: false } on timeout.
   * Callers should immediately re-issue the request to maintain continuous notification.
   *
   * @param sessionId - The session to watch for message updates.
   * @param options.timeout - Max wait seconds (default: 30, max: 60).
   * @param options.signal - AbortSignal to cancel the request (e.g. on component unmount).
   * @param options.since - Unix timestamp in milliseconds of the last known message update.
   *   If the session received a message_update after this time the server returns immediately
   *   with updated=true, allowing the client to catch up after a period of inactivity.
   */
  async waitSessionMessages(
    sessionId: string,
    options: { timeout?: number; signal?: AbortSignal; since?: number } = {}
  ): Promise<WaitSessionMessagesResponse> {
    const { timeout = 30, signal, since } = options;
    let endpoint = `/sessions/${sessionId}/messages/wait?timeout=${timeout}`;
    if (since !== undefined) {
      endpoint += `&since=${since}`;
    }

    if (this.debug) {
      console.log(`[AgentAPIProxy] Long-polling for message updates in session ${sessionId} (timeout=${timeout}s, since=${since})`);
    }

    return this.makeRequest<WaitSessionMessagesResponse>(endpoint, { signal });
  }

  /**
   * Subscribe to proxy-wide session status changes via SSE (GET /sessions/status/stream).
   * Each event carries the session_id, new status, and timestamp for any session
   * accessible by the current user.
   *
   * @returns The EventSource — call `.close()` to unsubscribe.
   */
  subscribeToSessionsStatusEvents(
    onEvent: (event: ProxySessionStatusEvent) => void,
    onError?: (error: Error) => void
  ): EventSource {
    const isUsingProxy = this.baseURL.includes('/api/v1');
    const eventSourceUrl = isUsingProxy
      ? `/api/v1/sessions/status/stream`
      : `${this.baseURL}/sessions/status/stream`;

    if (this.debug) {
      console.log(`[AgentAPIProxy] Creating EventSource for proxy-wide session status:`, eventSourceUrl);
    }

    const eventSource = new EventSource(eventSourceUrl);

    eventSource.addEventListener('agentapi_upstream_error', (event) => {
      eventSource.close();
      let status = 0;
      try {
        status = (JSON.parse((event as MessageEvent).data) as { status?: number }).status ?? 0;
      } catch {
        // Report a generic upstream stream failure below.
      }
      onError?.(new Error(`Proxy status stream upstream failed${status ? ` (${status})` : ''}`));
    });

    eventSource.onmessage = (event) => {
      // Skip heartbeat comments (EventSource ignores comment lines automatically,
      // but guard against empty data just in case)
      if (!event.data) return;
      try {
        const data: ProxySessionStatusEvent = JSON.parse(event.data);
        if (this.debug) {
          console.log(`[AgentAPIProxy] Proxy session status event:`, data);
        }
        onEvent(data);
      } catch (err) {
        console.error('[AgentAPIProxy] Failed to parse proxy session status event:', err);
      }
    };

    eventSource.onerror = () => {
      console.error('[AgentAPIProxy] Proxy status EventSource error');
      if (onError) {
        onError(new Error('Proxy session status EventSource connection error'));
      }
    };

    return eventSource;
  }

  // Bulk operations

  /**
   * Start multiple sessions in parallel
   */
  async startBatch(count: number, sessionData?: Partial<CreateSessionRequest> | Record<string, unknown>): Promise<Session[]> {
    const promises = Array.from({ length: count }, () => this.start(sessionData));
    return Promise.all(promises);
  }

  /**
   * Delete multiple sessions in parallel
   */
  async deleteBatch(sessionIds: string[]): Promise<void> {
    const promises = sessionIds.map(sessionId => this.delete(sessionId));
    await Promise.all(promises);
  }

  // Session management utilities

  // Agent operations

  /**
   * Get list of agents
   */
  async getAgents(params?: AgentListParams): Promise<AgentListResponse> {
    const searchParams = new URLSearchParams();
    
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.status) searchParams.set('status', params.status);
    if (params?.name) searchParams.set('name', params.name);

    const endpoint = `/agents${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const result = await this.makeRequest<AgentListResponse>(endpoint);
    
    return {
      ...result,
      agents: result.agents || []
    };
  }

  /**
   * Get a specific agent by ID
   */
  async getAgent(agentId: string): Promise<Agent> {
    return this.makeRequest<Agent>(`/agents/${agentId}`);
  }

  /**
   * Health check for the proxy
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.makeRequest('/health');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get authentication info for the current session
   */
  async getAuthInfo(): Promise<{ type: 'github' | 'none'; authenticated: boolean; user?: GitHubUser }> {
    try {
      return await this.makeRequest<{ type: 'github' | 'none'; authenticated: boolean; user?: GitHubUser }>('/auth/info');
    } catch (error) {
      // If the endpoint doesn't exist (404) or returns an error, assume no auth (older agentapi-proxy)
      if (this.debug) {
        console.log('[AgentAPIProxy] Auth info not available (likely older proxy version):', error);
      }
      return { type: 'none', authenticated: false };
    }
  }

  /**
   * Get user info from agentapi-proxy
   * Returns the stable principal ID, display username, and team memberships.
   */
  async getUserInfo(): Promise<ProxyUserInfo> {
    if (this.debug) {
      console.log('[AgentAPIProxy] Getting user info');
    }
    return await this.makeRequest<ProxyUserInfo>('/user/info');
  }

  async getTeamConfig(teamId: string): Promise<TeamConfig> {
    return await this.makeRequest<TeamConfig>(`/teams/${encodeURIComponent(teamId)}/config`);
  }

  async listTeamConfigs(): Promise<TeamConfig[]> {
    const response = await this.makeRequest<{ teams: TeamConfig[] }>('/teams');
    return response.teams;
  }

  async createTeam(name: string): Promise<TeamConfig> {
    return await this.makeRequest<TeamConfig>('/teams', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }

  async renameTeam(teamId: string, name: string): Promise<TeamConfig> {
    return await this.makeRequest<TeamConfig>(`/teams/${encodeURIComponent(teamId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ name }),
    });
  }

  async deleteTeam(teamId: string): Promise<void> {
    await this.makeRequest<void>(`/teams/${encodeURIComponent(teamId)}`, {
      method: 'DELETE',
    });
  }

  async updateTeamConfig(teamId: string, githubTeams: string[]): Promise<TeamConfig> {
    return await this.makeRequest<TeamConfig>(`/teams/${encodeURIComponent(teamId)}/config`, {
      method: 'PUT',
      body: JSON.stringify({ github_teams: githubTeams }),
    });
  }

  async getTeamMembers(teamId: string): Promise<TeamMembershipState> {
    return await this.makeRequest<TeamMembershipState>(`/teams/${encodeURIComponent(teamId)}/members`);
  }

  async syncTeamMembers(teamId: string): Promise<TeamMembershipSyncResult> {
    return await this.makeRequest<TeamMembershipSyncResult>(`/teams/${encodeURIComponent(teamId)}/members/sync`, {
      method: 'POST',
    });
  }

  /**
   * Get GitHub OAuth URL for authentication
   */
  async getGitHubAuthUrl(): Promise<string> {
    try {
      const response = await this.makeRequest<{ authUrl: string }>('/auth/github/url', {
        method: 'POST',
        body: JSON.stringify({})
      });
      return response.authUrl;
    } catch (error) {
      console.error('[AgentAPIProxy] Failed to get GitHub auth URL:', error);
      throw error;
    }
  }

  // Action operations (AskUserQuestion, etc.)

  /**
   * Get pending actions for a session (e.g., AskUserQuestion)
   */
  async getPendingActions(sessionId: string): Promise<PendingAction[]> {
    try {
      const response = await this.makeRequest<ActionResponse>(`/${sessionId}/action`);
      return response.pending_actions || [];
    } catch (error) {
      // If endpoint doesn't exist (404), return empty array
      if (error instanceof AgentAPIProxyError && error.status === 404) {
        if (this.debug) {
          console.log(`[AgentAPIProxy] Action endpoint not available for session ${sessionId}`);
        }
        return [];
      }
      throw error;
    }
  }

  /**
   * Send action response (e.g., answer to AskUserQuestion)
   */
  async sendAction(sessionId: string, action: ActionRequest): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Sending action to session ${sessionId}`);
    }

    await this.makeRequest<void>(`/${sessionId}/action`, {
      method: 'POST',
      body: JSON.stringify(action),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Successfully sent action to session ${sessionId}`);
    }
  }

  // Schedule operations

  /**
   * Create a new schedule
   */
  async createSchedule(data: CreateScheduleRequest): Promise<Schedule> {
    if (this.debug) {
      console.log('[AgentAPIProxy] Creating schedule');
    }

    const schedule = await this.makeRequest<Schedule>('/schedules', {
      method: 'POST',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Created schedule: ${schedule.id}`);
    }

    return schedule;
  }

  /**
   * Get list of schedules
   */
  async getSchedules(params?: ScheduleListParams): Promise<ScheduleListResponse> {
    const searchParams = new URLSearchParams();

    if (params?.status) searchParams.set('status', params.status);
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.scope) searchParams.set('scope', params.scope);
    if (params?.team_id) searchParams.set('team_id', params.team_id);

    const endpoint = `/schedules${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const result = await this.makeRequest<ScheduleListResponse>(endpoint);

    return {
      ...result,
      schedules: result.schedules || []
    };
  }

  /**
   * Get a specific schedule by ID
   */
  async getSchedule(scheduleId: string): Promise<Schedule> {
    return this.makeRequest<Schedule>(`/schedules/${scheduleId}`);
  }

  /**
   * Update a schedule
   */
  async updateSchedule(scheduleId: string, data: UpdateScheduleRequest): Promise<Schedule> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Updating schedule ${scheduleId}`);
    }

    const schedule = await this.makeRequest<Schedule>(`/schedules/${scheduleId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Updated schedule: ${schedule.id}`);
    }

    return schedule;
  }

  /**
   * Delete a schedule
   */
  async deleteSchedule(scheduleId: string): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleting schedule: ${scheduleId}`);
    }

    await this.makeRequest<void>(`/schedules/${scheduleId}`, {
      method: 'DELETE',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleted schedule: ${scheduleId}`);
    }
  }

  /**
   * Trigger a schedule immediately
   */
  async triggerSchedule(scheduleId: string): Promise<TriggerScheduleResponse> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Triggering schedule: ${scheduleId}`);
    }

    const result = await this.makeRequest<TriggerScheduleResponse>(`/schedules/${scheduleId}/trigger`, {
      method: 'POST',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Triggered schedule ${scheduleId}, session: ${result.session_id}`);
    }

    return result;
  }

  // Settings operations

  /**
   * Get settings for a user or team
   * @param name - User name or team name
   */
  async getSettings(name: string): Promise<SettingsData> {
    try {
      return await this.makeRequest<SettingsData>(`/settings/${encodeURIComponent(name)}`);
    } catch (error) {
      // If settings don't exist (404), return empty settings
      if (error instanceof AgentAPIProxyError && error.status === 404) {
        if (this.debug) {
          console.log(`[AgentAPIProxy] Settings not found for ${name}, returning empty settings`);
        }
        return {};
      }
      throw error;
    }
  }

  async listSettingsSecrets(name: string): Promise<import('../types/settings').SettingsSecret[]> {
    const result = await this.makeRequest<{ secrets: import('../types/settings').SettingsSecret[] }>(
      `/settings/${encodeURIComponent(name)}/secrets`,
    );
    return result.secrets || [];
  }

  async createSettingsSecret(
    name: string,
    data: { name: string; values: Record<string, string>; projections?: import('../types/settings').SecretProjection[] },
  ): Promise<import('../types/settings').SettingsSecret> {
    return this.makeRequest(`/settings/${encodeURIComponent(name)}/secrets`, {
      method: 'POST', body: JSON.stringify(data),
    });
  }

  async updateSettingsSecretValues(name: string, secretId: string, values: Record<string, string>, baseVersion: number) {
    return this.makeRequest<import('../types/settings').SettingsSecret>(
      `/settings/${encodeURIComponent(name)}/secrets/${encodeURIComponent(secretId)}/values`,
      { method: 'PUT', body: JSON.stringify({ values, base_version: baseVersion }) },
    );
  }

  async deleteSettingsSecret(name: string, secretId: string): Promise<void> {
    await this.makeRequest(`/settings/${encodeURIComponent(name)}/secrets/${encodeURIComponent(secretId)}`, { method: 'DELETE' });
  }

  /**
   * Save settings for a user or team
   * @param name - User name or team name
   * @param data - Settings data to save
   */
  async saveSettings(name: string, data: SettingsData): Promise<SettingsData> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Saving settings for: ${name}`);
    }
    const result = await this.makeRequest<SettingsData>(`/settings/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
    if (this.debug) {
      console.log(`[AgentAPIProxy] Successfully saved settings for: ${name}`);
    }
    return result;
  }

  /**
   * Get all external session managers available to the authenticated user
   * (from user's own settings + all team settings they belong to)
   * GET /settings/managers
   */
  async getAvailableManagers(): Promise<AvailableManager[]> {
    try {
      const result = await this.makeRequest<{ managers: AvailableManager[] }>('/settings/managers');
      return result.managers || [];
    } catch (error) {
      if (error instanceof AgentAPIProxyError && error.status === 404) {
        if (this.debug) {
          console.log('[AgentAPIProxy] /settings/managers not available, returning empty list');
        }
        return [];
      }
      throw error;
    }
  }

  async issueExternalSessionManagerRegistrationToken(
    scope: 'user' | 'team' = 'user',
    teamId?: string,
  ): Promise<ExternalSessionManagerRegistrationToken> {
	const result = await this.makeRequest<{ manager: { id: string }, registration_token: string, expires_at: string }>('/session-managers/registration-tokens', {
      method: 'POST',
      body: JSON.stringify({ name: `session-manager-${Date.now()}`, scope, ...(teamId ? { team_id: teamId } : {}) }),
    });
	return { manager_id: result.manager.id, registration_token: result.registration_token, expires_at: result.expires_at }
  }

  async rotateExternalSessionManagerToken(
    managerId: string,
    scope: 'user' | 'team' = 'user',
    teamId?: string,
  ): Promise<ExternalSessionManagerConfig> {
	void scope
	void teamId
	const result = await this.makeRequest<{ registration_token: string }>(`/session-managers/${encodeURIComponent(managerId)}/registration-token`, {
      method: 'POST',
    });
	return { id: managerId, name: managerId, connection_token: result.registration_token } as ExternalSessionManagerConfig
  }

  async getExternalSessionManagerOperationalStatus(managerId: string, scope: 'user' | 'team' = 'user', teamId?: string): Promise<ExternalSessionManagerOperationalStatus> {
	void managerId; void scope; void teamId
	throw new Error('Session Manager operational controls are not available through the unified manager API')
  }

  async getExternalSessionManagerLogs(managerId: string, scope: 'user' | 'team' = 'user', teamId?: string, tail = 200): Promise<ExternalSessionManagerLogs> {
	void managerId; void scope; void teamId; void tail
	throw new Error('Session Manager logs are not available through the unified manager API')
  }

  async restartExternalSessionManager(managerId: string, scope: 'user' | 'team' = 'user', teamId?: string): Promise<void> {
	void managerId; void scope; void teamId
	throw new Error('Session Manager restart is not available through the unified manager API')
  }

  async upgradeExternalSessionManager(managerId: string, version: string, scope: 'user' | 'team' = 'user', teamId?: string): Promise<void> {
	void managerId; void version; void scope; void teamId
	throw new Error('Session Manager upgrade is managed by ccplant session-manager install')
  }

  /**
   * Get scia Google OAuth integration status for the current user.
   */
  async getGoogleOAuthStatus(): Promise<GoogleOAuthStatus> {
    return await this.makeRequest<GoogleOAuthStatus>('/integrations/google-oauth/status');
  }

  /**
   * Get scia OAuth integrations configured for the current user.
   */
  async getIntegrations(): Promise<SciaIntegrationsResponse> {
    return await this.makeRequest<SciaIntegrationsResponse>('/integrations');
  }

  /**
   * Ask scia, through the proxy, to build an OAuth authorization URL.
   */
  async createIntegrationAuthorizationURL(integrationId: string, request: { scope_ids: string[]; redirect_uri: string }): Promise<SciaAuthorizationURLResponse> {
    return await this.makeRequest<SciaAuthorizationURLResponse>(`/integrations/${encodeURIComponent(integrationId)}/authorization-url`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  /**
   * Revoke/disconnect a scia OAuth integration for the current user.
   */
  async revokeIntegration(integrationId: string): Promise<SciaRevokeResponse> {
    return await this.makeRequest<SciaRevokeResponse>(`/integrations/${encodeURIComponent(integrationId)}/revoke`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  /**
   * Delete settings for a user or team
   * @param name - User name or team name
   */
  async deleteSettings(name: string): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleting settings for: ${name}`);
    }
    await this.makeRequest<void>(`/settings/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
    if (this.debug) {
      console.log(`[AgentAPIProxy] Successfully deleted settings for: ${name}`);
    }
  }

  /**
   * Set debug mode
   */
  setDebug(debug: boolean): void {
    this.debug = debugAllowed(debug);
  }

  // Credentials operations

  /**
   * Get credential metadata (does not return raw data)
   * GET /credentials/{name}
   */
  async getCredentials(name: string): Promise<CredentialsMetadata | null> {
    try {
      return await this.makeRequest<CredentialsMetadata>(`/credentials/${encodeURIComponent(name)}`);
    } catch (error) {
      if (error instanceof AgentAPIProxyError && error.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Upload or replace credential JSON data
   * PUT /credentials/{name}
   */
  async uploadCredentials(name: string, data: Record<string, unknown>): Promise<CredentialsMetadata> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Uploading credentials: ${name}`);
    }
    return await this.makeRequest<CredentialsMetadata>(`/credentials/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  /**
   * Delete credentials
   * DELETE /credentials/{name}
   */
  async deleteCredentials(name: string): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleting credentials: ${name}`);
    }
    await this.makeRequest<void>(`/credentials/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
  }

  // Codex device auth operations

  /**
   * Check if Codex device auth is configured on the proxy
   * GET /codex/device-auth/config
   */
  async getCodexDeviceAuthConfig(): Promise<CodexDeviceAuthConfig> {
    return await this.makeRequest<CodexDeviceAuthConfig>('/codex/device-auth/config');
  }

  /**
   * Start Codex OAuth device authorization flow
   * POST /codex/device-auth
   */
  async startCodexDeviceAuth(target?: CodexDeviceAuthTarget): Promise<CodexDeviceAuthStart> {
    if (this.debug) {
      console.log('[AgentAPIProxy] Starting Codex device auth');
    }
    return await this.makeRequest<CodexDeviceAuthStart>('/codex/device-auth', {
      method: 'POST',
      ...(target ? { body: JSON.stringify(target) } : {}),
    });
  }

  /**
   * Poll for Codex device auth status
   * POST /codex/device-auth/token
   */
  async pollCodexDeviceAuth(): Promise<CodexDeviceAuthStatus> {
    return await this.makeRequest<CodexDeviceAuthStatus>('/codex/device-auth/token', {
      method: 'POST',
    });
  }

  async getCodexDeviceAuthAttempt(attemptId: string): Promise<CodexDeviceAuthStart> {
    return await this.makeRequest<CodexDeviceAuthStart>(`/codex/device-auth/${encodeURIComponent(attemptId)}`);
  }

  async cancelCodexDeviceAuth(attemptId: string): Promise<void> {
    await this.makeRequest<void>(`/codex/device-auth/${encodeURIComponent(attemptId)}`, { method: 'DELETE' });
  }

  // Session sharing operations

  /**
   * Create a share URL for a session
   * POST /sessions/{sessionId}/share
   */
  async createShare(sessionId: string): Promise<CreateShareResponse> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Creating share for session: ${sessionId}`);
    }

    const result = await this.makeRequest<CreateShareResponse>(`/sessions/${sessionId}/share`, {
      method: 'POST',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Created share for session ${sessionId}`);
    }

    return result;
  }

  /**
   * Get share status for a session
   * GET /sessions/{sessionId}/share
   */
  async getShareStatus(sessionId: string): Promise<ShareStatus | null> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Getting share status for session: ${sessionId}`);
    }

    try {
      const result = await this.makeRequest<ShareStatus>(`/sessions/${sessionId}/share`);

      if (this.debug) {
        console.log(`[AgentAPIProxy] Share status loaded for session ${sessionId}`);
      }

      return result;
    } catch (error) {
      // If share doesn't exist (404), return null
      if (error instanceof AgentAPIProxyError && error.status === 404) {
        if (this.debug) {
          console.log(`[AgentAPIProxy] No share found for session ${sessionId}`);
        }
        return null;
      }
      throw error;
    }
  }

  /**
   * Revoke share for a session
   * DELETE /sessions/{sessionId}/share
   */
  async getSandboxPolicyDomains(policyId: string): Promise<{ allowed: string[]; denied: string[]; ignored: string[]; updated_at?: string }> {
    return this.makeRequest<{ allowed: string[]; denied: string[]; ignored: string[]; updated_at?: string }>(`/sandbox-policies/${policyId}/domains`);
  }

  async updateIgnoredSandboxPolicyDomains(policyId: string, ignored: string[]): Promise<{ allowed: string[]; denied: string[]; ignored: string[]; updated_at?: string }> {
    return this.makeRequest<{ allowed: string[]; denied: string[]; ignored: string[]; updated_at?: string }>(`/sandbox-policies/${policyId}/domains/ignored`, {
      method: 'PUT',
      body: JSON.stringify({ ignored }),
    });
  }

  async getSessionSandboxDomains(sessionId: string): Promise<{ allowed: string[]; denied: string[] }> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Fetching sandbox domains for session: ${sessionId}`);
    }
    return this.makeRequest<{ allowed: string[]; denied: string[] }>(`/sessions/${sessionId}/sandbox-domains`);
  }

  async revokeShare(sessionId: string): Promise<RevokeShareResponse> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Revoking share for session: ${sessionId}`);
    }

    const result = await this.makeRequest<RevokeShareResponse>(`/sessions/${sessionId}/share`, {
      method: 'DELETE',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Revoked share for session ${sessionId}`);
    }

    return result;
  }

  // Webhook operations

  /**
   * Create a new webhook
   */
  async createWebhook(data: CreateWebhookRequest): Promise<Webhook> {
    if (this.debug) {
      console.log('[AgentAPIProxy] Creating webhook');
    }

    const webhook = await this.makeRequest<Webhook>('/webhooks', {
      method: 'POST',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Created webhook: ${webhook.id}`);
    }

    return webhook;
  }

  /**
   * Get list of webhooks
   */
  async getWebhooks(params?: WebhookListParams): Promise<WebhookListResponse> {
    const searchParams = new URLSearchParams();

    if (params?.type) searchParams.set('type', params.type);
    if (params?.status) searchParams.set('status', params.status);
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    if (params?.scope) searchParams.set('scope', params.scope);
    if (params?.team_id) searchParams.set('team_id', params.team_id);

    const endpoint = `/webhooks${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const result = await this.makeRequest<WebhookListResponse>(endpoint);

    return {
      ...result,
      webhooks: result.webhooks || []
    };
  }

  /**
   * Get a specific webhook by ID
   */
  async getWebhook(webhookId: string): Promise<Webhook> {
    return this.makeRequest<Webhook>(`/webhooks/${webhookId}`);
  }

  /**
   * Update a webhook
   */
  async updateWebhook(webhookId: string, data: UpdateWebhookRequest): Promise<Webhook> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Updating webhook ${webhookId}`);
    }

    const webhook = await this.makeRequest<Webhook>(`/webhooks/${webhookId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Updated webhook: ${webhook.id}`);
    }

    return webhook;
  }

  /**
   * Delete a webhook
   */
  async deleteWebhook(webhookId: string): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleting webhook: ${webhookId}`);
    }

    await this.makeRequest<void>(`/webhooks/${webhookId}`, {
      method: 'DELETE',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleted webhook: ${webhookId}`);
    }
  }

  /**
   * Regenerate webhook secret
   */
  async regenerateWebhookSecret(webhookId: string): Promise<RegenerateSecretResponse> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Regenerating secret for webhook: ${webhookId}`);
    }

    const result = await this.makeRequest<RegenerateSecretResponse>(`/webhooks/${webhookId}/regenerate-secret`, {
      method: 'POST',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Regenerated secret for webhook ${webhookId}`);
    }

    return result;
  }

  /**
   * Trigger a webhook with a test payload
   */
  async triggerWebhook(webhookId: string, data: TriggerWebhookRequest): Promise<TriggerWebhookResponse> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Triggering webhook ${webhookId}`);
    }

    const result = await this.makeRequest<TriggerWebhookResponse>(`/webhooks/${webhookId}/trigger`, {
      method: 'POST',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Webhook ${webhookId} trigger completed`);
    }

    return result;
  }

  // SlackBot operations

  /**
   * Create a new SlackBot
   */
  async createSlackBot(data: CreateSlackBotRequest): Promise<SlackBot> {
    if (this.debug) {
      console.log('[AgentAPIProxy] Creating slackbot');
    }

    const slackbot = await this.makeRequest<SlackBot>('/slackbots', {
      method: 'POST',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Created slackbot: ${slackbot.id}`);
    }

    return slackbot;
  }

  /**
   * Get list of SlackBots
   */
  async getSlackBots(params?: SlackBotListParams): Promise<SlackBotListResponse> {
    const searchParams = new URLSearchParams();

    if (params?.status) searchParams.set('status', params.status);
    if (params?.scope) searchParams.set('scope', params.scope);
    if (params?.team_id) searchParams.set('team_id', params.team_id);
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.limit) searchParams.set('limit', params.limit.toString());

    const endpoint = `/slackbots${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const result = await this.makeRequest<SlackBot[] | SlackBotListResponse>(endpoint);

    // API returns array directly (not wrapped in object)
    if (Array.isArray(result)) {
      return { slackbots: result };
    }

    return {
      ...result,
      slackbots: result.slackbots || []
    };
  }

  /**
   * Get a specific SlackBot by ID
   */
  async getSlackBot(slackbotId: string): Promise<SlackBot> {
    return this.makeRequest<SlackBot>(`/slackbots/${slackbotId}`);
  }

  /**
   * Update a SlackBot
   */
  async updateSlackBot(slackbotId: string, data: UpdateSlackBotRequest): Promise<SlackBot> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Updating slackbot ${slackbotId}`);
    }

    const slackbot = await this.makeRequest<SlackBot>(`/slackbots/${slackbotId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Updated slackbot: ${slackbot.id}`);
    }

    return slackbot;
  }

  /**
   * Delete a SlackBot
   */
  async deleteSlackBot(slackbotId: string): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleting slackbot: ${slackbotId}`);
    }

    await this.makeRequest<void>(`/slackbots/${slackbotId}`, {
      method: 'DELETE',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleted slackbot: ${slackbotId}`);
    }
  }

  async getStorages(params: { scope: 'user' | 'team'; team_id?: string }): Promise<{ storages: import('../types/storage').Storage[]; total: number }> {
    const query = new URLSearchParams({ scope: params.scope });
    if (params.team_id) query.set('team_id', params.team_id);
    return this.makeRequest(`/storages?${query}`);
  }

  async createStorage(data: import('../types/storage').CreateStorageRequest): Promise<import('../types/storage').Storage> {
    return this.makeRequest('/storages', { method: 'POST', body: JSON.stringify(data) });
  }

  async updateStorage(id: string, data: { name: string; description?: string }): Promise<import('../types/storage').Storage> {
    return this.makeRequest(`/storages/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(data) });
  }

  async deleteStorage(id: string): Promise<void> {
    await this.makeRequest(`/storages/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  // Session Profile methods

  /**
   * Get the healthy Session Runner Pools available to the current user.
   */
  async getAvailableSessionPools(): Promise<LogicalSessionPool[]> {
    const result = await this.makeRequest<{ session_pools: LogicalSessionPool[] }>('/available-session-pools');
    return result.session_pools || [];
  }

  /**
   * Create a new Session Profile
   */
  async createSessionProfile(data: CreateSessionProfileRequest): Promise<SessionProfile> {
    if (this.debug) {
      console.log('[AgentAPIProxy] Creating session profile');
    }

    const profile = await this.makeRequest<SessionProfile>('/session-profiles', {
      method: 'POST',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Created session profile: ${profile.id}`);
    }

    return profile;
  }

  /**
   * Get list of Session Profiles
   */
  async getSessionProfiles(params?: SessionProfileListParams): Promise<SessionProfileListResponse> {
    const searchParams = new URLSearchParams();

    if (params?.scope) searchParams.set('scope', params.scope);
    if (params?.team_id) searchParams.set('team_id', params.team_id);
	if (params?.include_available_team_profiles) searchParams.set('include_available_team_profiles', 'true');

    const endpoint = `/session-profiles${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const result = await this.makeRequest<SessionProfile[] | SessionProfileListResponse>(endpoint);

    // API may return array directly (not wrapped in object)
    if (Array.isArray(result)) {
      return { session_profiles: result };
    }

    return {
      ...result,
      session_profiles: result.session_profiles || []
    };
  }

  /**
   * Preview which session profile /start would resolve for the given tags.
   * Returns the matched profile and the source that selected it.
   */
  async previewSessionProfile(params: {
    tags?: Record<string, string>;
    scope?: ResourceScope;
    team_id?: string;
  }): Promise<{ source: 'selector_tags' | 'settings_default' | 'profile_default' | 'none'; profile: SessionProfile | null }> {
    return this.makeRequest('/session-profiles/preview', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  /**
   * Get a specific Session Profile by ID
   */
  async getSessionProfile(profileId: string): Promise<SessionProfile> {
    return this.makeRequest<SessionProfile>(`/session-profiles/${profileId}`);
  }

  /**
   * Update a Session Profile
   */
  async updateSessionProfile(profileId: string, data: UpdateSessionProfileRequest): Promise<SessionProfile> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Updating session profile ${profileId}`);
    }

    const profile = await this.makeRequest<SessionProfile>(`/session-profiles/${profileId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Updated session profile: ${profile.id}`);
    }

    return profile;
  }

  /**
   * Delete a Session Profile
   */
  async deleteSessionProfile(profileId: string): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleting session profile: ${profileId}`);
    }

    await this.makeRequest<void>(`/session-profiles/${profileId}`, {
      method: 'DELETE',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleted session profile: ${profileId}`);
    }
  }

  // ============================================================
  // Sandbox Policy methods
  // ============================================================

  async createSandboxPolicy(data: CreateSandboxPolicyRequest): Promise<SandboxPolicy> {
    return this.makeRequest<SandboxPolicy>('/sandbox-policies', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getSandboxPolicies(params?: SandboxPolicyListParams): Promise<SandboxPolicyListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.scope) searchParams.set('scope', params.scope);
    if (params?.team_id) searchParams.set('team_id', params.team_id);
    const endpoint = `/sandbox-policies${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const result = await this.makeRequest<SandboxPolicy[] | SandboxPolicyListResponse>(endpoint);
    if (Array.isArray(result)) {
      return { sandbox_policies: result };
    }
    return { ...result, sandbox_policies: result.sandbox_policies || [] };
  }

  async getSandboxPolicy(policyId: string): Promise<SandboxPolicy> {
    return this.makeRequest<SandboxPolicy>(`/sandbox-policies/${policyId}`);
  }

  async updateSandboxPolicy(policyId: string, data: UpdateSandboxPolicyRequest): Promise<SandboxPolicy> {
    return this.makeRequest<SandboxPolicy>(`/sandbox-policies/${policyId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteSandboxPolicy(policyId: string): Promise<void> {
    await this.makeRequest<void>(`/sandbox-policies/${policyId}`, {
      method: 'DELETE',
    });
  }

  /** Validate or perform an ownership transfer between user/team scopes. */
  async transferResource(data: {
    resource_type: TransferableResourceType;
    resource_id: string;
    target_scope: ResourceScope;
    target_user_id?: string;
    target_team_id?: string;
    dry_run?: boolean;
  }): Promise<TransferResourceResult> {
    return this.makeRequest<TransferResourceResult>('/resources/transfer', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // ============================================================
  // API Token methods (multi-token management)
  // ============================================================

  /**
   * List API tokens for a scope. Use scope="personal" for the user's tokens,
   * or scope="team" with team_id for a team's tokens.
   */
  async getApiTokens(params: ApiTokenListParams): Promise<ApiTokenListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.scope) searchParams.set('scope', params.scope);
    if (params?.team_id) searchParams.set('team_id', params.team_id);

    const endpoint = `/api-tokens${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;
    const result = await this.makeRequest<ApiToken[] | ApiTokenListResponse>(endpoint);

    // Tolerate both wrapped ({items:[]}) and bare-array responses.
    if (Array.isArray(result)) {
      return { items: result };
    }
    return { items: result.items || [] };
  }

  /**
   * Create a new API token. The plaintext token is returned exactly once in
   * `plaintext_token` and must never be persisted by the caller.
   */
  async createApiToken(data: CreateApiTokenRequest): Promise<CreateApiTokenResponse> {
    if (this.debug) {
      // Never log the token itself; only the non-sensitive request fields.
      console.log('[AgentAPIProxy] Creating API token:', {
        name: data.name,
        scope: data.scope,
        team_id: data.team_id,
        permissions: data.permissions,
        expires_at: data.expires_at,
      });
    }

    const result = await this.makeRequest<CreateApiTokenResponse>('/api-tokens', {
      method: 'POST',
      body: JSON.stringify(data),
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Created API token: ${result.token?.id}`);
    }

    return result;
  }

  /**
   * Get metadata for a single API token. Never returns the plaintext token.
   */
  async getApiToken(tokenId: string): Promise<ApiToken> {
    return this.makeRequest<ApiToken>(`/api-tokens/${encodeURIComponent(tokenId)}`);
  }

  /**
   * Delete an API token. If the deleted token backs the current UI session,
   * subsequent requests will return 401 and the existing auth flow will
   * handle re-authentication; we do not compare plaintext tokens.
   */
  async deleteApiToken(tokenId: string): Promise<void> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleting API token: ${tokenId}`);
    }

    await this.makeRequest<void>(`/api-tokens/${encodeURIComponent(tokenId)}`, {
      method: 'DELETE',
    });

    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleted API token: ${tokenId}`);
    }
  }

  // ---------------------------------------------------------------------------
  // User-managed Files (/files)
  // ---------------------------------------------------------------------------

  /**
   * List all user-managed files
   * GET /files
   */
  async listFiles(): Promise<import('../types/user_file').FileListResponse> {
    if (this.debug) {
      console.log('[AgentAPIProxy] Listing user files');
    }
    return this.makeRequest<import('../types/user_file').FileListResponse>('/files');
  }

  /**
   * Get a single user-managed file
   * GET /files/{fileId}
   */
  async getFile(fileId: string): Promise<import('../types/user_file').UserFile> {
    return this.makeRequest<import('../types/user_file').UserFile>(`/files/${encodeURIComponent(fileId)}`);
  }

  /**
   * Create a user-managed file
   * POST /files
   */
  async createFile(data: import('../types/user_file').CreateFileRequest): Promise<import('../types/user_file').UserFile> {
    if (this.debug) {
      console.log('[AgentAPIProxy] Creating user file:', data.path);
    }
    return this.makeRequest<import('../types/user_file').UserFile>('/files', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  /**
   * Update a user-managed file
   * PUT /files/{fileId}
   */
  async updateFile(fileId: string, data: import('../types/user_file').UpdateFileRequest): Promise<import('../types/user_file').UserFile> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Updating user file: ${fileId}`);
    }
    return this.makeRequest<import('../types/user_file').UserFile>(`/files/${encodeURIComponent(fileId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  /**
   * Delete a user-managed file
   * DELETE /files/{fileId}
   */
  async deleteFile(fileId: string): Promise<{ success: boolean }> {
    if (this.debug) {
      console.log(`[AgentAPIProxy] Deleting user file: ${fileId}`);
    }
    return this.makeRequest<{ success: boolean }>(`/files/${encodeURIComponent(fileId)}`, {
      method: 'DELETE',
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // ACP (Agent Client Protocol) HTTP transport
  //
  // ACP sessions expose a minimal 2-endpoint HTTP transport instead of the
  // agentapi-compatible REST API:
  //
  //   GET  /{sessionId}/session  – session info (acpSessionId, status)
  //   POST /{sessionId}/rpc      – JSON-RPC 2.0 messages (client → agent)
  //   GET  /{sessionId}/sse      – SSE stream of JSON-RPC 2.0 messages (agent → client)
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Returns ACP session info if the session uses ACP transport, null otherwise.
   * Use this to detect whether a session is ACP-based.
   */
  async getACPSessionInfo(sessionId: string): Promise<ACPSessionInfo | null> {
    try {
      if (this.debug) {
        console.log(`[ACP] getACPSessionInfo called (proxySessionId=${sessionId})`);
      }
      const info = await this.makeRequest<ACPSessionInfo>(`/${sessionId}/session`);
      if (this.debug) {
        console.log(`[ACP] getACPSessionInfo completed (proxySessionId=${sessionId})`);
      }
      if (info?.sessionId) return info;
      return null;
    } catch {
      if (this.debug) {
        console.warn(`[ACP] getACPSessionInfo failed (proxySessionId=${sessionId})`);
      }
      return null;
    }
  }

  /**
   * Fetch message history from the ACP bridge's in-memory store.
   * When userPromptIndex is omitted, returns the current turn (latest user prompt onward).
   */
  async getACPMessageHistory(
    sessionId: string,
    _acpSessionId: string,
    userPromptIndex?: number
  ): Promise<ACPMessageHistoryResult> {
    const query = userPromptIndex !== undefined ? `?userPromptIndex=${userPromptIndex}` : '';
    const resp = await this.makeRequest<{
      messages: ACPJSONRPCMessage[];
      lastEventId?: number;
      userPromptCount?: number;
      userPromptIndex?: number;
      userPrompts?: ACPUserPromptInfo[];
    }>(`/${sessionId}/messages${query}`);

    const rawMessages = resp?.messages ?? [];
    const messages = parseACPJSONRPCMessages(rawMessages);
    if (this.debug) {
      console.log(`[ACP] getACPMessageHistory: ${messages.length} messages restored (userPromptIndex=${userPromptIndex ?? 'latest'})`);
    }

    return {
      messages,
      lastEventId: resp?.lastEventId,
      userPromptCount: resp?.userPromptCount ?? 0,
      userPromptIndex: resp?.userPromptIndex,
      userPrompts: resp?.userPrompts ?? [],
    };
  }

  /**
   * Subscribe to ACP session events via SSE at /{sessionId}/sse.
   *
   * The SSE stream emits raw JSON-RPC 2.0 messages from the ACP agent:
   *   - session/update notifications  → converted to SessionMessage via callbacks.onMessage
   *   - session/request_permission    → converted to PendingAction via callbacks.onPermission
   * Turn status is intentionally consumed from the bridge's /events endpoint,
   * not inferred from these raw protocol messages.
   *
   * Returns a subscription handle; call .close() to unsubscribe.
   */
  subscribeToACPSessionEvents(
    sessionId: string,
    acpSessionId: string,
    callbacks: ACPSessionCallbacks,
    initialLastEventId?: number,
    deferUntilHistory = false
  ): EventSubscription {
    const isUsingProxy = this.baseURL.includes('/api/v1');
    const sseUrl = isUsingProxy
      ? `/api/v1/${sessionId}/sse`
      : `${this.baseURL}/${sessionId}/sse`;

    if (this.debug) {
      console.log(`[AgentAPIProxy] ACP SSE subscribe: ${sseUrl}`);
    }

    let nextLocalId = 1;
    // Track the current streaming agent message id (for chunk accumulation).
    let streamingMsgId: number | null = null;
    let streamingUserMsgId: number | null = null;

    if (this.debug) {
      console.log(`[ACP] EventSource subscription created (url=${sseUrl}, acpSessionId=${acpSessionId})`);
    }

    return this.subscribeWithEventSource(
      sseUrl,
      {
        onOpen: () => {
          if (this.debug) {
            console.log(`[ACP] SSE connection opened (url=${sseUrl}, acpSessionId=${acpSessionId})`);
          }
          callbacks.onConnectionOpen?.();
        },
        onMessage: (event: MessageEvent) => {
          try {
        const msg: ACPJSONRPCMessage = JSON.parse(event.data);

        if (this.debug) {
          console.log('[AgentAPIProxy] ACP SSE message:', msg);
        }

        // ── session/update notification ──────────────────────────────────
        if (msg.method === 'session/update') {
          const acpParams = msg.params as { sessionId: string; update: ACPSessionUpdate; time?: string };
          const update = acpParams?.update;
          if (!update) return;

          const now = acpParams?.time || new Date().toISOString();

          switch (update.sessionUpdate) {
            case 'agent_message_chunk': {
              const text = acpExtractText(update.content);
              const image = acpExtractImage(update.content);
              if (!text && !image) return;

              // Turn status is delivered independently by the bridge's
              // authoritative /events stream.
              if (streamingMsgId !== null) {
                // Append to existing streaming message.
                if (text) callbacks.onChunk(streamingMsgId, text);
                if (image) callbacks.onImageChunk?.(streamingMsgId, image);
              } else {
                // Start a new streaming message.
                const id = nextLocalId++;
                streamingMsgId = id;
                callbacks.onMessage({
                  id,
                  role: 'agent',
                  content: text,
                  images: image ? [image] : undefined,
                  time: now,
                  type: 'normal',
                });
              }
              break;
            }

            case 'agent_thought_chunk': {
              const thought = acpExtractText(update.content);
              if (!thought) return;

              // Thought chunks always belong to the current streaming message.
              // If there is none yet, start one (content can be filled later).
              if (streamingMsgId === null) {
                const id = nextLocalId++;
                streamingMsgId = id;
                callbacks.onMessage({
                  id,
                  role: 'agent',
                  content: '',
                  thought,
                  time: now,
                  type: 'normal',
                });
              } else {
                callbacks.onThoughtChunk(streamingMsgId, thought);
              }
              break;
            }

            case 'tool_call': {
              // Finalize any streaming text before the tool call.
              streamingMsgId = null;
              const toolObj = {
                type: 'tool_use',
                // Use kind→name mapping for a proper tool name (e.g. "Bash" for "execute").
                // title often contains the full command/path text, not a short name.
                name: acpToolNameFromRawInput(update.rawInput) || acpToolDisplayName(update.kind, update.title),
                id: update.toolCallId,
                input: update.rawInput ?? {},
                title: update.title,
                locations: update.locations,
              };
              callbacks.onMessage({
                id: nextLocalId++,
                role: 'agent',
                content: JSON.stringify(toolObj),
                time: now,
                type: 'normal',
                toolUseId: update.toolCallId,
              });
              break;
            }

            case 'tool_call_update': {
              const isSuccess = update.status === 'completed' || update.status === 'success';
              const isError = update.status === 'failed' || update.status === 'error';
              // Proxy sends "running"; ACP spec also defines "in_progress"
              const isRunning = update.status === 'running' || update.status === 'in_progress';

              if (isRunning) {
                // Notify the UI so it can update the tool card's visual state.
                callbacks.onToolUpdate?.(update.toolCallId ?? '', 'in_progress');
                return;
              }

              // Step 2: rawInput/title/description patch (no completion status).
              // Note: content[] may be present here (contains description, not the result).
              // Use status as the sole discriminator — do NOT check for output.
              if (!isSuccess && !isError) {
                if (update.rawInput != null && update.toolCallId) {
                  callbacks.onToolInputUpdate?.(
                    update.toolCallId,
                    update.rawInput,
                    update.title,
                    update.locations,
                  );
                }
                return;
              }

              // Step 3: result (status = completed/failed) — prefer ACP content[] over rawOutput
              const acpText = extractACPToolContent(update.content);
              const images = extractACPToolImages(update.content);
              const resultContent = acpText || extractRawOutputText(update.rawOutput);
              callbacks.onMessage({
                id: nextLocalId++,
                role: 'tool_result',
                content: resultContent,
                images: images.length > 0 ? images : undefined,
                time: now,
                type: 'normal',
                parentToolUseId: update.toolCallId,
                status: isSuccess ? 'success' : 'error',
              });
              break;
            }

            case 'plan': {
              streamingMsgId = null;
              if (!update.entries || update.entries.length === 0) return;
              const planMD = acpPlanToMarkdown(update.entries);
              callbacks.onMessage({
                id: nextLocalId++,
                role: 'agent',
                content: planMD,
                time: now,
                type: 'plan',
              });
              break;
            }

            case 'user_message_chunk': {
              const text = acpExtractText(update.content);
              const image = acpExtractImage(update.content);
              if (!text && !image) return;
              if (image && streamingUserMsgId !== null) {
                callbacks.onImageChunk?.(streamingUserMsgId, image);
              } else {
                streamingUserMsgId = nextLocalId++;
                callbacks.onMessage({
                  id: streamingUserMsgId,
                  role: 'user',
                  content: text,
                  images: image ? [image] : undefined,
                  time: now,
                  type: 'normal',
                });
              }
              break;
            }

            case 'current_mode_update': {
              if (update.modeId) {
                callbacks.onModeUpdate?.(update.modeId);
              }
              break;
            }

            case 'available_commands_update': {
              if (update.availableCommands && Array.isArray(update.availableCommands)) {
                const commands = update.availableCommands.map(cmd => ({
                  name: cmd.name,
                  description: cmd.description,
                  hint: cmd.input?.hint,
                }));
                callbacks.onCommandsUpdate?.(commands);
              }
              break;
            }

            case 'config_option_update': {
              if (update.configOptions && Array.isArray(update.configOptions)) {
                callbacks.onConfigOptionsUpdate?.(update.configOptions);
              }
              break;
            }

            case 'agent_turn_end': {
              streamingMsgId = null;
              streamingUserMsgId = null;
              break;
            }
          }
          return;
        }

        // ── session/request_permission (agent → client RPC) ──────────────
        if (msg.method === 'session/request_permission' && msg.id != null) {
          streamingMsgId = null;
          const params = msg.params as ACPPermissionParams;
          const action: PendingAction = {
            type: 'answer_question',
            tool_use_id: params.toolCall?.toolCallId ?? '',
            content: {
              questions: [{
                question: 'Permission required',
                header: 'Permission Required',
                options: (params.options ?? []).map(o => ({
                  label: o.name || o.optionId,
                  description: o.kind ?? '',
                })),
                multiSelect: false,
              }],
            },
          };
          callbacks.onPermission(action, msg.id as number);
          return;
        }

        // ── Result of session/prompt (turn finished) ──────────────────────
        // Only a prompt result carries stopReason. Other RPC results (notably
        // permission replies) can arrive while the agent is still working and
        // must not make the UI look idle mid-turn.
        if (msg.result != null && msg.id != null) {
          const stopReason = (msg.result as { stopReason?: unknown })?.stopReason;
          if (typeof stopReason === 'string' && stopReason.length > 0) {
            streamingMsgId = null;
            streamingUserMsgId = null;
          }
          return;
        }

        // ── Error on session/prompt ───────────────────────────────────────
        if (msg.error && msg.id != null) {
          streamingMsgId = null;
          streamingUserMsgId = null;
          callbacks.onError(new Error(msg.error.message));
          return;
        }

      } catch (err) {
        if (this.debug) {
          console.error('[AgentAPIProxy] ACP SSE parse error:', err);
        }
        callbacks.onError(err instanceof Error ? err : new Error('Failed to parse ACP SSE message'));
      }
        },
        onTransientError: (event, state) => {
          if (this.debug) {
            console.warn(`[ACP] SSE transient error; browser is reconnecting (url=${sseUrl}, acpSessionId=${acpSessionId}, readyState=${state})`);
          }
          callbacks.onConnectionConnecting?.();
        },
        onReconnect: (attempt, delayMs) => {
          if (this.debug) {
            console.warn(`[ACP] SSE closed; recreating EventSource in ${delayMs}ms (url=${sseUrl}, acpSessionId=${acpSessionId}, attempt=${attempt})`);
          }
          callbacks.onConnectionConnecting?.(attempt, delayMs);
        },
        onClosed: (event, state) => {
          if (this.debug) {
            console.error(`[ACP] SSE connection permanently closed (url=${sseUrl}, acpSessionId=${acpSessionId}, readyState=${state})`);
          }
          callbacks.onConnectionClosed?.();
          callbacks.onError(new Error(`ACP SSE connection closed (readyState=${state})`));
        },
      },
      { reconnect: true, reconnectInterval: 1000 },
      initialLastEventId,
      deferUntilHistory ? { deferMessages: true, handshakeTimeoutMs: 1000 } : undefined
    );
  }

  /**
   * Opens the real ACP event subscription while history is fetched in parallel.
   * Events are buffered until resumeAfterHistory() prevents the history response
   * from overwriting updates received during bootstrap.
   */
  subscribeToACPSessionEventsForInitialization(
    sessionId: string,
    callbacks: ACPSessionCallbacks
  ): ACPInitializationSubscription {
    return this.subscribeToACPSessionEvents(sessionId, '', callbacks, undefined, true) as ACPInitializationSubscription;
  }

  /**
   * Send a session/prompt request to the ACP agent.
   * The result (stopReason) arrives asynchronously via the SSE stream.
   * @param promptId - JSON-RPC id; correlates the SSE result message.
   */
  async sendACPPrompt(
    sessionId: string,
    acpSessionId: string,
    prompt: ACPPromptContentBlock[],
    promptId: number
  ): Promise<void> {
    await this.makeRequest<unknown>(`/${sessionId}/rpc`, {
      method: 'POST',
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: promptId,
        method: 'session/prompt',
        params: {
          sessionId: acpSessionId,
          prompt,
        },
      }),
    });
  }

  /**
   * Reply to a session/request_permission RPC that arrived via SSE.
   * @param rpcId  - The JSON-RPC id from the SSE message.
   * @param optionId - The selected option id to send back.
   */
  async replyToACPPermission(
    sessionId: string,
    rpcId: number,
    optionId: string
  ): Promise<void> {
    await this.makeRequest<unknown>(`/${sessionId}/rpc`, {
      method: 'POST',
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: rpcId,
        result: {
          outcome: { outcome: 'selected', optionId },
        },
      }),
    });
  }

  /**
   * Cancel the current ACP session turn.
   */
  async cancelACPSession(sessionId: string, acpSessionId: string): Promise<void> {
    await this.makeRequest<unknown>(`/${sessionId}/rpc`, {
      method: 'POST',
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'session/cancel',
        params: { sessionId: acpSessionId },
      }),
    });
  }

  /**
   * Set an ACP session configuration option, such as the active model.
   * The ACP agent returns the complete configuration state after applying it.
   */
  async setACPSessionConfigOption(
    sessionId: string,
    acpSessionId: string,
    configId: string,
    value: string
  ): Promise<{ configOptions: ACPConfigOption[] }> {
    const response = await this.makeRequest<{
      configOptions?: ACPConfigOption[];
      result?: { configOptions?: ACPConfigOption[] };
    }>(`/${sessionId}/rpc`, {
      method: 'POST',
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method: 'session/set_config_option',
        params: {
          sessionId: acpSessionId,
          configId,
          value,
        },
      }),
    });

    return { configOptions: response.result?.configOptions ?? response.configOptions ?? [] };
  }

  async getAdminSettings(version?: number): Promise<AdminSettingsDocument> {
    const query = version ? `?version=${version}` : '';
    return this.makeRequest<AdminSettingsDocument>(`/admin/system-settings${query}`);
  }

  async updateAdminSettings(request: UpdateAdminSettingsRequest): Promise<AdminSettingsDocument> {
    return this.makeRequest<AdminSettingsDocument>('/admin/system-settings', {
      method: 'PUT',
      body: JSON.stringify(request),
    });
  }

  async listAdminSettingsVersions(): Promise<AdminSettingsVersionsResponse> {
    return this.makeRequest<AdminSettingsVersionsResponse>('/admin/system-settings/versions');
  }

  async listGitHubConnections(admin = false): Promise<GitHubConnection[]> {
    const response = await this.makeRequest<{ connections: GitHubConnection[] }>(admin ? '/admin/github-connections' : '/github-connections');
    return response.connections;
  }

  async createGitHubConnection(request: GitHubConnectionInput): Promise<GitHubConnection> {
    return this.makeRequest<GitHubConnection>('/admin/github-connections', { method: 'POST', body: JSON.stringify(request) });
  }

  async updateGitHubConnection(id: string, request: Partial<GitHubConnectionInput>): Promise<GitHubConnection> {
    return this.makeRequest<GitHubConnection>(`/admin/github-connections/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(request) });
  }

  async updateGitHubConnectionSecret(id: string, secret: NonNullable<GitHubConnectionInput['oauth_client_secret']>): Promise<GitHubConnection> {
    return this.makeRequest<GitHubConnection>(`/admin/github-connections/${encodeURIComponent(id)}/secret`, { method: 'PUT', body: JSON.stringify(secret) });
  }

  async deleteGitHubConnection(id: string): Promise<void> {
    await this.makeRequest(`/admin/github-connections/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  async testGitHubConnection(id: string): Promise<{ api_reachable: boolean; secret_resolvable: boolean }> {
    return this.makeRequest(`/admin/github-connections/${encodeURIComponent(id)}/test`, { method: 'POST' });
  }

  async updateGitHubAppPrivateKey(id: string, value: string): Promise<GitHubConnection> {
    return this.makeRequest<GitHubConnection>(`/admin/github-connections/${encodeURIComponent(id)}/github-app/private-key`, { method: 'PUT', body: JSON.stringify({ value }) });
  }

  async testGitHubApp(id: string, repository: string): Promise<{ valid: boolean; expires_at: string }> {
    return this.makeRequest(`/admin/github-connections/${encodeURIComponent(id)}/github-app/test`, { method: 'POST', body: JSON.stringify({ repository }) });
  }

  async listGitHubIdentities(): Promise<GitHubIdentitiesResponse> {
    return this.makeRequest<GitHubIdentitiesResponse>('/users/me/github-identities');
  }

  async startGitHubIdentityLink(connectionId: string, returnTo: string, callbackUrl?: string): Promise<{ authorization_url: string }> {
    return this.makeRequest<{ authorization_url: string }>('/users/me/github-identities/link', {
      method: 'POST', body: JSON.stringify({ connection_id: connectionId, return_to: returnTo, callback_url: callbackUrl }),
    });
  }

  async unlinkGitHubIdentity(identityId: string): Promise<void> {
    await this.makeRequest(`/users/me/github-identities/${encodeURIComponent(identityId)}`, { method: 'DELETE' });
  }

  async listGoogleConnections(admin = false): Promise<GoogleConnection[]> {
    const response = await this.makeRequest<{ connections: GoogleConnection[] }>(admin ? '/admin/google-connections' : '/google-connections');
    return response.connections;
  }

  async createGoogleConnection(request: GoogleConnectionInput): Promise<GoogleConnection> {
    return this.makeRequest<GoogleConnection>('/admin/google-connections', { method: 'POST', body: JSON.stringify(request) });
  }

  async updateGoogleConnection(id: string, request: Partial<GoogleConnectionInput>): Promise<GoogleConnection> {
    return this.makeRequest<GoogleConnection>(`/admin/google-connections/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(request) });
  }

  async updateGoogleConnectionSecret(id: string, secret: NonNullable<GoogleConnectionInput['oauth_client_secret']>): Promise<GoogleConnection> {
    return this.makeRequest<GoogleConnection>(`/admin/google-connections/${encodeURIComponent(id)}/secret`, { method: 'PUT', body: JSON.stringify(secret) });
  }

  async deleteGoogleConnection(id: string): Promise<void> {
    await this.makeRequest(`/admin/google-connections/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  async testGoogleConnection(id: string): Promise<{ discovery_reachable: boolean; secret_resolvable: boolean }> {
    return this.makeRequest(`/admin/google-connections/${encodeURIComponent(id)}/test`, { method: 'POST' });
  }

  async listGoogleIdentities(): Promise<GoogleIdentitiesResponse> {
    return this.makeRequest<GoogleIdentitiesResponse>('/users/me/google-identities');
  }

  async startGoogleIdentityLink(connectionId: string, returnTo: string, callbackUrl?: string): Promise<{ authorization_url: string }> {
    return this.makeRequest<{ authorization_url: string }>('/users/me/google-identities/link', {
      method: 'POST', body: JSON.stringify({ connection_id: connectionId, return_to: returnTo, callback_url: callbackUrl }),
    });
  }

  async unlinkGoogleIdentity(identityId: string): Promise<void> {
    await this.makeRequest(`/users/me/google-identities/${encodeURIComponent(identityId)}`, { method: 'DELETE' });
  }

  async listClusterSessionManagers(): Promise<ClusterSessionManager[]> {
    const result = await this.makeRequest<{ session_managers: ClusterSessionManager[] }>('/session-managers');
    return result.session_managers ?? [];
  }

  async createClusterSessionManager(name: string): Promise<{ manager: ClusterSessionManager; registration_token: string; expires_at: string }> {
    return this.makeRequest('/session-managers/registration-tokens', { method: 'POST', body: JSON.stringify({ name, scope: 'system' }) });
  }

  async deleteClusterSessionManager(managerID: string): Promise<void> {
    await this.makeRequest(`/session-managers/${encodeURIComponent(managerID)}`, { method: 'DELETE' });
  }

  async listSessionPools(): Promise<LogicalSessionPool[]> {
    const result = await this.makeRequest<{ session_pools: LogicalSessionPool[] }>('/session-pools');
    return result.session_pools ?? [];
  }

  async createSessionPool(input: Pick<LogicalSessionPool, 'name'> & Partial<Pick<LogicalSessionPool, 'labels'>>): Promise<LogicalSessionPool> {
    return this.makeRequest('/session-pools', { method: 'POST', body: JSON.stringify(input) });
  }

  async deleteSessionPool(pool: string): Promise<void> {
    await this.makeRequest(`/session-pools/${encodeURIComponent(pool)}`, { method: 'DELETE' });
  }

  async listSessionPoolSuppliers(managerID: string): Promise<SessionPoolSupplier[]> {
    const pools = await this.listSessionPools();
    const suppliers = await Promise.all(pools.map(async (pool) => {
      const result = await this.makeRequest<{ pool_suppliers: SessionPoolSupplier[] }>(`/session-pools/${encodeURIComponent(pool.name)}/suppliers`);
      return result.pool_suppliers ?? [];
    }));
    return suppliers.flat().filter((supplier) => supplier.manager_id === managerID);
  }

  async createSessionPoolSupplier(managerID: string, input: Pick<SessionPoolSupplier, 'pool' | 'min_idle' | 'max_runners'>): Promise<SessionPoolSupplier> {
    return this.makeRequest(`/session-pools/${encodeURIComponent(input.pool)}/suppliers/${encodeURIComponent(managerID)}`, { method: 'POST', body: JSON.stringify(input) });
  }

  async deleteSessionPoolSupplier(managerID: string, pool: string): Promise<void> {
    await this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/suppliers/${encodeURIComponent(managerID)}`, { method: 'DELETE' });
  }

  async listSessionPoolBindings(pool: string): Promise<SessionPoolBinding[]> {
    const result = await this.makeRequest<{ pool_bindings: SessionPoolBinding[] }>(`/session-pools/${encodeURIComponent(pool)}/bindings`);
    return result.pool_bindings ?? [];
  }

  async createSessionPoolBinding(pool: string, subjectType: 'user' | 'team' | 'all', subjectID: string, roles: 'use' | 'manage' | 'manage_and_use' | Array<'use' | 'manage'> = 'use', priority = 0, maxConcurrent = 0): Promise<SessionPoolBinding> {
    const roleInput = Array.isArray(roles) ? { roles } : { role: roles };
    return this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/bindings`, { method: 'POST', body: JSON.stringify({ subject_type: subjectType, subject_id: subjectID, ...roleInput, priority, max_concurrent: maxConcurrent }) });
  }

  async listManagedSessionPools(): Promise<LogicalSessionPool[]> {
    const result = await this.makeRequest<{ session_pools: LogicalSessionPool[] }>('/session-pools');
    return result.session_pools ?? [];
  }

  async createManagedSessionPool(input: { name: string; team_id?: string }): Promise<LogicalSessionPool> {
    return this.makeRequest('/session-pools', { method: 'POST', body: JSON.stringify(input) });
  }

  async patchManagedSessionPool(pool: string, input: { enabled?: boolean; labels?: Record<string, string> }): Promise<LogicalSessionPool> {
    return this.makeRequest(`/session-pools/${encodeURIComponent(pool)}`, { method: 'PATCH', body: JSON.stringify(input) });
  }

  async deleteManagedSessionPool(pool: string): Promise<void> {
    await this.makeRequest(`/session-pools/${encodeURIComponent(pool)}`, { method: 'DELETE' });
  }

  async listManagedSessionPoolBindings(pool: string): Promise<SessionPoolBinding[]> {
    const result = await this.makeRequest<{ pool_bindings: SessionPoolBinding[] }>(`/session-pools/${encodeURIComponent(pool)}/bindings`);
    return result.pool_bindings ?? [];
  }

  async listManagedSessionPoolSuppliers(pool: string): Promise<SessionPoolSupplier[]> {
    const result = await this.makeRequest<{ pool_suppliers: SessionPoolSupplier[] }>(`/session-pools/${encodeURIComponent(pool)}/suppliers`);
    return result.pool_suppliers ?? [];
  }

  async createManagedSessionPoolSupplier(pool: string, managerID: string, input: { min_idle?: number; max_runners?: number; enabled?: boolean }): Promise<SessionPoolSupplier> {
    return this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/suppliers/${encodeURIComponent(managerID)}`, { method: 'POST', body: JSON.stringify(input) });
  }

  async patchManagedSessionPoolSupplier(pool: string, managerID: string, input: { enabled?: boolean; draining?: boolean; min_idle?: number; max_runners?: number }): Promise<SessionPoolSupplier> {
    return this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/suppliers/${encodeURIComponent(managerID)}`, { method: 'PATCH', body: JSON.stringify(input) });
  }

  async deleteManagedSessionPoolSupplier(pool: string, managerID: string): Promise<void> {
    await this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/suppliers/${encodeURIComponent(managerID)}`, { method: 'DELETE' });
  }

  async createManagedSessionPoolBinding(pool: string, subjectType: 'user' | 'team' | 'all', subjectID: string, role: 'use' | 'manage' | 'manage_and_use', priority = 0, maxConcurrent = 0, enabled = true): Promise<SessionPoolBinding> {
    return this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/bindings`, { method: 'POST', body: JSON.stringify({ subject_type: subjectType, subject_id: subjectID, role, priority, max_concurrent: maxConcurrent, enabled }) });
  }

  async patchManagedSessionPoolBinding(pool: string, bindingID: string, input: { role?: 'use' | 'manage' | 'manage_and_use'; roles?: Array<'use' | 'manage'>; enabled?: boolean; priority?: number; max_concurrent?: number }): Promise<SessionPoolBinding> {
    return this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/bindings/${encodeURIComponent(bindingID)}`, { method: 'PATCH', body: JSON.stringify(input) });
  }

  async deleteManagedSessionPoolBinding(pool: string, bindingID: string): Promise<void> {
    await this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/bindings/${encodeURIComponent(bindingID)}`, { method: 'DELETE' });
  }

  async deleteSessionPoolBinding(pool: string, bindingID: string): Promise<void> {
    await this.makeRequest(`/session-pools/${encodeURIComponent(pool)}/bindings/${encodeURIComponent(bindingID)}`, { method: 'DELETE' });
  }

  async getSessionPoolStatus(): Promise<SessionPoolStatusResponse> {
    return this.makeRequest<SessionPoolStatusResponse>('/session-pools/status');
  }

  async getSessionPoolManagerLogs(managerID: string, tail = 200): Promise<SessionPoolLogs> {
    return this.makeRequest<SessionPoolLogs>(`/session-managers/${encodeURIComponent(managerID)}/logs?tail=${Math.min(5000, Math.max(1, tail))}`);
  }

  async getSessionPoolRunnerLogs(runnerID: string, tail = 200): Promise<SessionPoolLogs> {
    return this.makeRequest<SessionPoolLogs>(`/session-runners/${encodeURIComponent(runnerID)}/logs?tail=${Math.min(5000, Math.max(1, tail))}`);
  }

  async listAdminSessionRunners(): Promise<AdminSessionRunner[]> {
    const result = await this.makeRequest<{ session_runners: AdminSessionRunner[] }>('/admin/session-runners');
    return result.session_runners ?? [];
  }

  async getAdminSessionRunnerLogs(runnerID: string, managerID: string, tail = 200): Promise<SessionPoolLogs> {
    const params = new URLSearchParams({ manager_id: managerID, tail: String(Math.min(5000, Math.max(1, tail))) });
    return this.makeRequest<SessionPoolLogs>(`/admin/session-runners/${encodeURIComponent(runnerID)}/logs?${params}`);
  }

  async deleteAdminSessionRunner(runnerID: string, managerID: string, force = false): Promise<void> {
    const params = new URLSearchParams({ manager_id: managerID });
    if (force) params.set('force', 'true');
    await this.makeRequest(`/admin/session-runners/${encodeURIComponent(runnerID)}?${params}`, { method: 'DELETE' });
  }
}


// Utility functions to get proxy settings from browser storage
export function getAgentAPIProxyConfigFromStorage(repoFullname?: string): AgentAPIProxyClientConfig {
  // Check if we're in a browser environment
  if (typeof window === 'undefined') {
    // Server-side rendering or Node.js environment - use environment variables
    return {
      baseURL: process.env.AGENTAPI_PROXY_URL || 'http://localhost:8080',
      apiKey: process.env.AGENTAPI_API_KEY,
      timeout: parseInt(process.env.AGENTAPI_TIMEOUT || '10000'),
      maxSessions: parseInt(process.env.AGENTAPI_PROXY_MAX_SESSIONS || '10'),
      sessionTimeout: parseInt(process.env.AGENTAPI_PROXY_SESSION_TIMEOUT || '300000'),
      debug: defaultClientDebugEnabled(),
    };
  }

  try {
    // Get settings from global settings
    const globalSettings = loadFullGlobalSettings();
    const proxySettings = globalSettings.agentApiProxy || getDefaultProxySettings();

    // Add repository to history if repoFullname is provided
    if (repoFullname) {
      addRepositoryToHistory(repoFullname);
    }

    // Use proxy configuration
    const baseURL = proxySettings.enabled
      ? proxySettings.endpoint
      : `${window.location.protocol}//${window.location.host}/api/v1`;

    const timeout = proxySettings.enabled
      ? proxySettings.timeout
      : parseInt(process.env.AGENTAPI_TIMEOUT || '10000');

    return {
      baseURL,
      apiKey: proxySettings.apiKey || process.env.AGENTAPI_API_KEY,
      timeout,
      maxSessions: 10,
      sessionTimeout: 300000, // 5 minutes
      debug: defaultClientDebugEnabled(),
    };
  } catch {
    if (defaultClientDebugEnabled()) {
      console.warn('Failed to load proxy settings from storage, using fallback');
    }
    // Fallback if storage access fails
    return {
      baseURL: `${window.location.protocol}//${window.location.host}/api/v1`,
      apiKey: process.env.AGENTAPI_API_KEY,
      timeout: parseInt(process.env.AGENTAPI_TIMEOUT || '10000'),
      maxSessions: parseInt(process.env.AGENTAPI_PROXY_MAX_SESSIONS || '10'),
      sessionTimeout: parseInt(process.env.AGENTAPI_PROXY_SESSION_TIMEOUT || '300000'),
      debug: defaultClientDebugEnabled(),
    };
  }
}

// Factory function for easier client creation
export function createAgentAPIProxyClient(config: AgentAPIProxyClientConfig): AgentAPIProxyClient {
  return new AgentAPIProxyClient(config);
}

// Factory function to create client using stored settings
export function createAgentAPIProxyClientFromStorage(repoFullname?: string): AgentAPIProxyClient {
  const config = getAgentAPIProxyConfigFromStorage(repoFullname);
  return new AgentAPIProxyClient(config);
}

// Cluster administration always targets the proxy paired with this UI
// deployment. User-configured endpoints may point at a session-specific or
// external proxy and must not receive cluster-wide admin operations.
export function createCurrentDeploymentAgentAPIProxyClient(): AgentAPIProxyClient {
  const browser = typeof window !== 'undefined'
  return new AgentAPIProxyClient({
    baseURL: browser
      ? `${window.location.protocol}//${window.location.host}/api/v1`
      : process.env.AGENTAPI_PROXY_URL || 'http://localhost:8080',
    apiKey: browser ? undefined : process.env.AGENTAPI_API_KEY,
    timeout: parseInt(process.env.AGENTAPI_TIMEOUT || '10000'),
    maxSessions: 10,
    sessionTimeout: 300000,
    debug: defaultClientDebugEnabled(),
  });
}

// Default proxy client instance for convenience (uses global settings from storage)
// Synchronous version for backward compatibility
export function createDefaultAgentAPIProxyClient(): AgentAPIProxyClient {
  if (typeof window === 'undefined') {
    // Server-side - use environment variables directly
    const config = {
      baseURL: process.env.AGENTAPI_PROXY_URL || 'http://localhost:8080',
      apiKey: process.env.AGENTAPI_API_KEY,
      timeout: parseInt(process.env.AGENTAPI_TIMEOUT || '10000'),
      maxSessions: parseInt(process.env.AGENTAPI_PROXY_MAX_SESSIONS || '10'),
      sessionTimeout: parseInt(process.env.AGENTAPI_PROXY_SESSION_TIMEOUT || '300000'),
      debug: defaultClientDebugEnabled(),
    };
    return new AgentAPIProxyClient(config);
  }
  
  // Client-side - use stored settings
  const defaultProxySettings = getDefaultProxySettings();
  const config = {
    baseURL: defaultProxySettings.endpoint,
    apiKey: defaultProxySettings.apiKey,
    timeout: defaultProxySettings.timeout,
    maxSessions: parseInt(process.env.AGENTAPI_PROXY_MAX_SESSIONS || '10'),
    sessionTimeout: parseInt(process.env.AGENTAPI_PROXY_SESSION_TIMEOUT || '300000'),
    debug: defaultClientDebugEnabled(),
  };
  return new AgentAPIProxyClient(config);
}

// Default proxy client instance for convenience
export const agentAPIProxy = createDefaultAgentAPIProxyClient();

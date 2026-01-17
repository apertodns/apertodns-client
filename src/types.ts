/**
 * ApertoDNS Protocol Types
 * @author Andrea Ferro <support@apertodns.com>
 * @license MIT
 */

// ============================================================================
// Configuration Types
// ============================================================================

export interface ApertoDNSConfig {
  /** API base URL (default: https://api.apertodns.com) */
  baseUrl?: string;
  /** API token (apertodns_live_xxx or apertodns_test_xxx) */
  token: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom User-Agent header */
  userAgent?: string;
  /** Retry configuration */
  retry?: RetryConfig;
}

export interface RetryConfig {
  /** Maximum number of retries (default: 3) */
  maxRetries?: number;
  /** Initial delay between retries in ms (default: 1000) */
  retryDelay?: number;
  /** Retry on these HTTP status codes */
  retryOnStatus?: number[];
}

// ============================================================================
// Request Types
// ============================================================================

export interface UpdateRequest {
  /** Hostname to update (FQDN) */
  hostname: string;
  /** IPv4 address or "auto" for auto-detection */
  ipv4?: string | 'auto' | null;
  /** IPv6 address or "auto" for auto-detection */
  ipv6?: string | 'auto' | null;
  /** TTL in seconds (60-86400) */
  ttl?: number;
  /** TXT record for ACME DNS-01 challenges */
  txt?: TxtRecordRequest;
}

export interface TxtRecordRequest {
  /** TXT record name (e.g., "_acme-challenge") */
  name: string;
  /** TXT record value (required for 'set' action) */
  value?: string;
  /** Action: 'set' or 'delete' */
  action: 'set' | 'delete';
}

export interface BulkUpdateRequest {
  /** Array of updates */
  updates: UpdateRequest[];
  /** Default values for all updates */
  defaults?: {
    ipv4?: string | 'auto';
    ipv6?: string | 'auto';
    ttl?: number;
  };
}

export interface CreateTokenRequest {
  /** Token name/description */
  name: string;
  /** Permissions */
  permissions: TokenPermission[];
  /** Allowed hostnames (empty = all) */
  allowed_hostnames?: string[];
  /** Allowed IP ranges in CIDR notation */
  allowed_ips?: string[];
  /** Expiration date */
  expires_at?: string;
}

export interface CreateWebhookRequest {
  /** Webhook name */
  name: string;
  /** Hostname to monitor */
  hostname: string;
  /** Webhook URL (must be HTTPS) */
  url: string;
  /** Events to subscribe to */
  events: WebhookEvent[];
  /** Webhook secret (minimum 32 characters) */
  secret: string;
  /** Enable/disable webhook */
  enabled?: boolean;
  /** Retry policy */
  retry_policy?: {
    max_retries?: number;
    retry_delay_seconds?: number;
  };
}

export interface ExportRequest {
  // No fields required
}

export interface DeleteAccountRequest {
  /** Confirmation string: "DELETE_MY_ACCOUNT" */
  confirm: 'DELETE_MY_ACCOUNT';
  /** Optional feedback reason */
  reason?: string;
}

// ============================================================================
// Response Types
// ============================================================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
  meta?: ResponseMeta;
}

export interface ResponseMeta {
  request_id: string;
  processing_time_ms?: number;
  timestamp?: string;
}

export interface ApiError {
  code: ErrorCode;
  message: string;
  details?: Record<string, unknown>;
  documentation_url?: string;
  support_id?: string;
}

export interface UpdateResponse {
  hostname: string;
  ipv4: string | null;
  ipv6: string | null;
  ipv4_previous: string | null;
  ipv6_previous: string | null;
  ttl: number;
  changed: boolean;
  propagation_estimate_seconds?: number;
  updated_at: string;
}

export interface BulkUpdateResponse {
  summary: {
    total: number;
    successful: number;
    failed: number;
  };
  results: BulkUpdateResult[];
}

export interface BulkUpdateResult {
  hostname: string;
  status: 'success' | 'error';
  ipv4?: string;
  ipv6?: string;
  changed?: boolean;
  error?: {
    code: string;
    message: string;
  };
}

export interface StatusResponse {
  hostname: string;
  ipv4: string | null;
  ipv6: string | null;
  ttl: number;
  is_active: boolean;
  last_update: string;
  update_count_24h: number;
  update_count_total: number;
  created_at: string;
}

export interface DiscoveryResponse {
  protocol: string;
  protocol_version: string;
  provider: ProviderInfo;
  endpoints: EndpointsInfo;
  capabilities: CapabilitiesInfo;
  rate_limits: RateLimitsInfo;
  authentication: AuthenticationInfo;
  server_time: string;
}

export interface ProviderInfo {
  name: string;
  website: string;
  documentation: string;
  support_email: string;
  privacy_policy: string;
  terms_of_service: string;
}

export interface EndpointsInfo {
  update: string;
  bulk_update: string;
  status: string;
  webhooks: string;
  tokens: string;
  legacy_dyndns2: string;
}

export interface CapabilitiesInfo {
  ipv4: boolean;
  ipv6: boolean;
  auto_ip_detection: boolean;
  custom_ttl: boolean;
  ttl_range: { min: number; max: number; default: number };
  wildcards: boolean;
  webhooks: boolean;
  bulk_update: boolean;
  max_bulk_size: number;
  max_hostnames_per_account: number;
}

export interface RateLimitsInfo {
  update: { requests: number; window_seconds: number };
  bulk_update: { requests: number; window_seconds: number };
  status: { requests: number; window_seconds: number };
}

export interface AuthenticationInfo {
  methods: string[];
  token_prefix: string;
  token_header: string;
  api_key_header: string;
}

export interface TokenResponse {
  id: string;
  token?: string; // Only present on creation
  name: string;
  permissions: TokenPermission[];
  allowed_hostnames: string[];
  allowed_ips: string[];
  expires_at: string | null;
  created_at: string;
  last_used_at?: string;
}

export interface WebhookResponse {
  id: string;
  name: string;
  hostname: string;
  url: string;
  events: WebhookEvent[];
  enabled: boolean;
  created_at: string;
  last_triggered_at?: string;
}

export interface ExportResponse {
  export_id: string;
  status: 'processing' | 'completed' | 'failed';
  estimated_completion?: string;
  notification_email?: string;
  download_url?: string;
  expires_at?: string;
  checksum_sha256?: string;
}

export interface DeleteAccountResponse {
  deleted_at: string;
  data_retention_end: string;
  items_deleted: {
    hostnames: number;
    tokens: number;
    webhooks: number;
  };
}

// ============================================================================
// Enums and Unions
// ============================================================================

export type TokenPermission = 'update' | 'read' | 'webhooks' | 'tokens' | 'admin';

export type WebhookEvent = 'ip_changed' | 'hostname_created' | 'hostname_deleted' | 'update_failed';

export type ErrorCode =
  | 'unauthorized'
  | 'token_expired'
  | 'token_revoked'
  | 'forbidden'
  | 'hostname_forbidden'
  | 'ip_forbidden'
  | 'invalid_request'
  | 'validation_error'
  | 'invalid_hostname'
  | 'invalid_ip'
  | 'invalid_ttl'
  | 'ipv4_auto_failed'
  | 'ipv6_auto_failed'
  | 'hostname_not_found'
  | 'token_not_found'
  | 'webhook_not_found'
  | 'hostname_exists'
  | 'rate_limited'
  | 'payload_too_large'
  | 'bulk_limit_exceeded'
  | 'server_error'
  | 'dns_error'
  | 'maintenance'
  | 'timeout';

// ============================================================================
// API Keys Types (v1.2)
// ============================================================================

export type ApiKeyScope =
  | 'domains:read'
  | 'domains:write'
  | 'domains:delete'
  | 'tokens:read'
  | 'tokens:write'
  | 'tokens:delete'
  | 'records:read'
  | 'records:write'
  | 'webhooks:read'
  | 'webhooks:write'
  | 'dns:update'
  | 'profile:read'
  | 'custom-domains:read'
  | 'custom-domains:write'
  | 'custom-domains:delete'
  | 'credentials:read'
  | 'credentials:write'
  | 'credentials:delete';

export interface CreateApiKeyRequest {
  /** API key name */
  name: string;
  /** Scopes/permissions */
  scopes: ApiKeyScope[];
  /** Expiration (e.g., "30d", "365d") */
  expiresIn?: string;
}

export interface ApiKeyResponse {
  id: number;
  name: string;
  keyPrefix: string;
  scopes: ApiKeyScope[];
  rateLimit: number;
  expiresAt: string | null;
  active: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface CreateApiKeyResponse {
  id: number;
  name: string;
  key: string;
  keyPrefix: string;
  scopes: ApiKeyScope[];
  rateLimit: number;
  expiresAt: string | null;
  createdAt: string;
}

// ============================================================================
// Token Types (v1.2 - Legacy domain-bound)
// ============================================================================

export interface CreateLegacyTokenRequest {
  /** Domain ID to bind token to */
  domainId: number;
  /** Token label/description */
  label?: string;
  /** Expiration (e.g., "30d", "365d") */
  expiresIn?: string;
}

export interface LegacyTokenResponse {
  id: number;
  label: string | null;
  domainId: number;
  domainName: string | null;
  expiresAt: string | null;
  revoked: boolean;
  active: boolean;
  createdAt: string;
}

export interface CreateLegacyTokenResponse {
  id: number;
  token: string;
  label: string | null;
  domainId: number;
  domainName: string | null;
  expiresAt: string | null;
  createdAt: string;
}

export interface RegenerateTokenResponse {
  id: number;
  token: string;
  domainName: string | null;
}

// ============================================================================
// Webhook Types (v1.2)
// ============================================================================

export type WebhookEventType = 'ip_change' | 'domain_create' | 'domain_delete' | 'update_failed';

export interface CreateWebhookRequestV2 {
  /** Webhook URL (HTTPS) */
  url: string;
  /** Events to subscribe to */
  events: WebhookEventType[];
  /** HMAC secret for signature verification */
  secret?: string;
  /** Optional domain ID to filter events */
  domainId?: number | null;
}

export interface UpdateWebhookRequest {
  /** Update URL */
  url?: string;
  /** Update events */
  events?: WebhookEventType[];
  /** Enable/disable */
  active?: boolean;
  /** Update secret */
  secret?: string;
}

export interface WebhookResponseV2 {
  id: number;
  url: string;
  events: WebhookEventType[];
  domainId: number | null;
  domainName: string | null;
  active: boolean;
  lastCalled: string | null;
  lastStatus: number | null;
  failCount: number;
  createdAt: string;
  updatedAt: string;
}

// ============================================================================
// Delete Response (v1.2)
// ============================================================================

export interface DeleteResponse {
  id: number;
  deleted: boolean;
}

// ============================================================================
// Rate Limit Types
// ============================================================================

export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number;
  retryAfter?: number;
}

// ============================================================================
// Webhook Payload Types
// ============================================================================

export interface WebhookPayload {
  event: WebhookEvent;
  event_id: string;
  timestamp: string;
  webhook_id: string;
  data: WebhookEventData;
}

export interface WebhookEventData {
  hostname: string;
  ipv4_previous?: string | null;
  ipv4_current?: string | null;
  ipv6_previous?: string | null;
  ipv6_current?: string | null;
  ttl?: number;
}

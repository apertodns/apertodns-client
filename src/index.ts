/**
 * ApertoDNS Client - Universal TypeScript client for ApertoDNS Protocol v1.2.3
 *
 * @author Andrea Ferro <support@apertodns.com>
 * @license MIT
 * @see https://apertodns.com/docs
 *
 * @example
 * ```typescript
 * import { ApertoDNSClient } from 'apertodns-client';
 *
 * const client = new ApertoDNSClient({
 *   token: 'apertodns_live_xxxxxxxxxxxxxxxxxxxxxxxxxx'
 * });
 *
 * // Update a hostname with auto IP detection
 * const result = await client.update({
 *   hostname: 'myhost.apertodns.com',
 *   ipv4: 'auto'
 * });
 *
 * console.log(`Updated to ${result.ipv4}`);
 * ```
 */

// Main client
export { ApertoDNSClient } from './client';

// Types
export type {
  ApertoDNSConfig,
  RetryConfig,
  UpdateRequest,
  BulkUpdateRequest,
  CreateTokenRequest,
  CreateWebhookRequest,
  DeleteAccountRequest,
  ExportRequest,
  ApiResponse,
  ResponseMeta,
  ApiError,
  UpdateResponse,
  BulkUpdateResponse,
  BulkUpdateResult,
  StatusResponse,
  DiscoveryResponse,
  ProviderInfo,
  EndpointsInfo,
  CapabilitiesInfo,
  RateLimitsInfo,
  AuthenticationInfo,
  TokenResponse,
  WebhookResponse,
  ExportResponse,
  DeleteAccountResponse,
  RateLimitInfo,
  WebhookPayload,
  WebhookEventData,
  TokenPermission,
  WebhookEvent,
  ErrorCode,
} from './types';

// Errors
export {
  ApertoDNSError,
  AuthenticationError,
  ForbiddenError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  ServerError,
  NetworkError,
  isApertoDNSError,
  isRateLimitError,
  isNetworkError,
  isRetryableError,
} from './errors';

// Validation
export {
  isValidIPv4,
  isValidIPv6,
  isPublicIPv4,
  isPublicIPv6,
  isValidHostname,
  isValidTTL,
  isValidToken,
  isValidWebhookSecret,
  isHttpsUrl,
  validateUpdateRequest,
  type ValidationResult,
  type ValidationFieldError,
} from './validation';

// Utilities
export {
  generateToken,
  generateUUID,
  verifyWebhookSignature,
  createWebhookSignature,
  parseRateLimitHeaders,
  maskToken,
  sleep,
  calculateBackoff,
  buildUrl,
  parseTimestamp,
  formatTimestamp,
  isTokenExpired,
  normalizeHostname,
} from './utils';

/**
 * ApertoDNS Client
 * @author Andrea Ferro <support@apertodns.com>
 * @license MIT
 */

import type {
  ApertoDNSConfig,
  UpdateRequest,
  UpdateResponse,
  BulkUpdateRequest,
  BulkUpdateResponse,
  StatusResponse,
  DiscoveryResponse,
  CreateTokenRequest,
  TokenResponse,
  CreateWebhookRequest,
  WebhookResponse,
  ExportResponse,
  DeleteAccountRequest,
  DeleteAccountResponse,
  ApiResponse,
  RateLimitInfo,
  // v1.2 Management types
  CreateApiKeyRequest,
  ApiKeyResponse,
  CreateApiKeyResponse,
  CreateLegacyTokenRequest,
  LegacyTokenResponse,
  CreateLegacyTokenResponse,
  RegenerateTokenResponse,
  CreateWebhookRequestV2,
  UpdateWebhookRequest,
  WebhookResponseV2,
  DeleteResponse,
} from './types';

import {
  ApertoDNSError,
  AuthenticationError,
  ForbiddenError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  ServerError,
  NetworkError,
  isRetryableError,
} from './errors';

import { validateUpdateRequest } from './validation';
import { parseRateLimitHeaders, sleep, calculateBackoff, generateUUID, buildUrl } from './utils';

const DEFAULT_BASE_URL = 'https://api.apertodns.com';
const DEFAULT_TIMEOUT = 30000;
const DEFAULT_USER_AGENT = 'apertodns-client/1.0.0';

/**
 * ApertoDNS API Client
 *
 * @example
 * ```typescript
 * const client = new ApertoDNSClient({
 *   token: 'apertodns_live_xxxxxxxxxxxxxxxxxxxxxxxxxx'
 * });
 *
 * // Update a hostname
 * const result = await client.update({
 *   hostname: 'myhost.apertodns.com',
 *   ipv4: 'auto'
 * });
 *
 * console.log(result.ipv4); // '203.0.113.50'
 * ```
 */
interface ResolvedConfig {
  baseUrl: string;
  token: string;
  timeout: number;
  userAgent: string;
  retry: {
    maxRetries: number;
    retryDelay: number;
    retryOnStatus: number[];
  };
}

export class ApertoDNSClient {
  private readonly config: ResolvedConfig;
  private lastRateLimit: RateLimitInfo | null = null;

  constructor(config: ApertoDNSConfig) {
    if (!config.token) {
      throw new Error('Token is required');
    }

    this.config = {
      baseUrl: config.baseUrl ?? DEFAULT_BASE_URL,
      token: config.token,
      timeout: config.timeout ?? DEFAULT_TIMEOUT,
      userAgent: config.userAgent ?? DEFAULT_USER_AGENT,
      retry: {
        maxRetries: config.retry?.maxRetries ?? 3,
        retryDelay: config.retry?.retryDelay ?? 1000,
        retryOnStatus: config.retry?.retryOnStatus ?? [429, 502, 503, 504],
      },
    };
  }

  // ============================================================================
  // Core API Methods
  // ============================================================================

  /**
   * Get provider information (discovery endpoint)
   * No authentication required
   */
  async getInfo(): Promise<DiscoveryResponse> {
    const response = await this.request<DiscoveryResponse>(
      'GET',
      '/.well-known/apertodns/v1/info',
      undefined,
      { skipAuth: true }
    );
    return response;
  }

  /**
   * Update a single hostname
   */
  async update(request: UpdateRequest): Promise<UpdateResponse> {
    // Client-side validation
    const validation = validateUpdateRequest(request);
    if (!validation.valid) {
      throw new ValidationError('Validation failed', { fields: validation.errors });
    }

    const response = await this.request<UpdateResponse>(
      'POST',
      '/.well-known/apertodns/v1/update',
      request
    );
    return response;
  }

  /**
   * Update multiple hostnames in a single request
   */
  async bulkUpdate(request: BulkUpdateRequest): Promise<BulkUpdateResponse> {
    if (request.updates.length > 100) {
      throw new ValidationError('Maximum 100 hostnames per bulk update', {
        fields: [{
          field: 'updates',
          code: 'bulk_limit_exceeded',
          message: 'Maximum 100 hostnames per bulk update',
          provided: request.updates.length,
          constraints: { max: 100 },
        }],
      });
    }

    const response = await this.request<BulkUpdateResponse>(
      'POST',
      '/.well-known/apertodns/v1/bulk-update',
      request
    );
    return response;
  }

  /**
   * Get status of a hostname
   */
  async getStatus(hostname: string): Promise<StatusResponse> {
    const response = await this.request<StatusResponse>(
      'GET',
      `/.well-known/apertodns/v1/status/${encodeURIComponent(hostname)}`
    );
    return response;
  }

  // ============================================================================
  // Token Management
  // ============================================================================

  /**
   * Create a new API token
   */
  async createToken(request: CreateTokenRequest): Promise<TokenResponse> {
    const response = await this.request<TokenResponse>(
      'POST',
      '/.well-known/apertodns/v1/tokens',
      request
    );
    return response;
  }

  /**
   * List all tokens
   */
  async listTokens(): Promise<TokenResponse[]> {
    const response = await this.request<TokenResponse[]>(
      'GET',
      '/.well-known/apertodns/v1/tokens'
    );
    return response;
  }

  /**
   * Delete a token
   */
  async deleteToken(tokenId: string): Promise<void> {
    await this.request<void>(
      'DELETE',
      `/.well-known/apertodns/v1/tokens/${encodeURIComponent(tokenId)}`
    );
  }

  // ============================================================================
  // Webhook Management
  // ============================================================================

  /**
   * Create a new webhook
   */
  async createWebhook(request: CreateWebhookRequest): Promise<WebhookResponse> {
    const response = await this.request<WebhookResponse>(
      'POST',
      '/.well-known/apertodns/v1/webhooks',
      request
    );
    return response;
  }

  /**
   * List all webhooks
   */
  async listWebhooks(): Promise<WebhookResponse[]> {
    const response = await this.request<WebhookResponse[]>(
      'GET',
      '/.well-known/apertodns/v1/webhooks'
    );
    return response;
  }

  /**
   * Delete a webhook
   */
  async deleteWebhook(webhookId: string): Promise<void> {
    await this.request<void>(
      'DELETE',
      `/.well-known/apertodns/v1/webhooks/${encodeURIComponent(webhookId)}`
    );
  }

  // ============================================================================
  // API Keys Management (v1.2)
  // ============================================================================

  /**
   * List all API keys
   * Note: Full key is never returned, only keyPrefix
   */
  async listApiKeys(): Promise<ApiKeyResponse[]> {
    const response = await this.request<ApiKeyResponse[]>(
      'GET',
      '/.well-known/apertodns/v1/api-keys'
    );
    return response;
  }

  /**
   * Create a new API key
   * Warning: The full key is only returned once in this response
   */
  async createApiKey(request: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    const response = await this.request<CreateApiKeyResponse>(
      'POST',
      '/.well-known/apertodns/v1/api-keys',
      request
    );
    return response;
  }

  /**
   * Delete an API key
   */
  async deleteApiKey(id: number): Promise<DeleteResponse> {
    const response = await this.request<DeleteResponse>(
      'DELETE',
      `/.well-known/apertodns/v1/api-keys/${id}`
    );
    return response;
  }

  // ============================================================================
  // Legacy Token Management (v1.2)
  // ============================================================================

  /**
   * List all legacy tokens
   * Note: Token hash is never returned
   */
  async listLegacyTokens(): Promise<LegacyTokenResponse[]> {
    const response = await this.request<LegacyTokenResponse[]>(
      'GET',
      '/.well-known/apertodns/v1/tokens'
    );
    return response;
  }

  /**
   * Create a new legacy token (domain-bound)
   * Warning: The full token is only returned once in this response
   */
  async createLegacyToken(request: CreateLegacyTokenRequest): Promise<CreateLegacyTokenResponse> {
    const response = await this.request<CreateLegacyTokenResponse>(
      'POST',
      '/.well-known/apertodns/v1/tokens',
      request
    );
    return response;
  }

  /**
   * Regenerate a legacy token
   * Warning: The old token becomes invalid immediately
   */
  async regenerateLegacyToken(id: number): Promise<RegenerateTokenResponse> {
    const response = await this.request<RegenerateTokenResponse>(
      'POST',
      `/.well-known/apertodns/v1/tokens/${id}/regenerate`
    );
    return response;
  }

  /**
   * Delete a legacy token
   */
  async deleteLegacyToken(id: number): Promise<DeleteResponse> {
    const response = await this.request<DeleteResponse>(
      'DELETE',
      `/.well-known/apertodns/v1/tokens/${id}`
    );
    return response;
  }

  // ============================================================================
  // Webhook Management v1.2
  // ============================================================================

  /**
   * List all webhooks (v1.2 format)
   */
  async listWebhooksV2(): Promise<WebhookResponseV2[]> {
    const response = await this.request<WebhookResponseV2[]>(
      'GET',
      '/.well-known/apertodns/v1/webhooks'
    );
    return response;
  }

  /**
   * Create a new webhook (v1.2 format)
   */
  async createWebhookV2(request: CreateWebhookRequestV2): Promise<WebhookResponseV2> {
    const response = await this.request<WebhookResponseV2>(
      'POST',
      '/.well-known/apertodns/v1/webhooks',
      request
    );
    return response;
  }

  /**
   * Update a webhook
   */
  async updateWebhook(id: number, request: UpdateWebhookRequest): Promise<WebhookResponseV2> {
    const response = await this.request<WebhookResponseV2>(
      'PATCH',
      `/.well-known/apertodns/v1/webhooks/${id}`,
      request
    );
    return response;
  }

  /**
   * Delete a webhook (v1.2)
   */
  async deleteWebhookV2(id: number): Promise<DeleteResponse> {
    const response = await this.request<DeleteResponse>(
      'DELETE',
      `/.well-known/apertodns/v1/webhooks/${id}`
    );
    return response;
  }

  // ============================================================================
  // Account / GDPR
  // ============================================================================

  /**
   * Request data export (GDPR Article 20)
   */
  async requestExport(): Promise<ExportResponse> {
    const response = await this.request<ExportResponse>(
      'POST',
      '/.well-known/apertodns/v1/account/export'
    );
    return response;
  }

  /**
   * Delete account (GDPR Article 17)
   */
  async deleteAccount(request: DeleteAccountRequest): Promise<DeleteAccountResponse> {
    const response = await this.request<DeleteAccountResponse>(
      'DELETE',
      '/.well-known/apertodns/v1/account',
      request
    );
    return response;
  }

  // ============================================================================
  // Legacy DynDNS2 Support
  // ============================================================================

  /**
   * Update using legacy DynDNS2 endpoint
   * Returns the raw text response
   */
  async legacyUpdate(hostname: string, ip?: string): Promise<string> {
    const params: Record<string, string> = { hostname };
    if (ip) params.myip = ip;

    const url = buildUrl(this.config.baseUrl, '/nic/update', params);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Basic ${Buffer.from(`user:${this.config.token}`).toString('base64')}`,
          'User-Agent': this.config.userAgent,
        },
        signal: controller.signal,
      });

      const text = await response.text();
      return text.trim();
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new NetworkError('Request timeout', { isTimeout: true });
      }
      throw new NetworkError('Network error', { cause: error instanceof Error ? error : undefined });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ============================================================================
  // Rate Limit Info
  // ============================================================================

  /**
   * Get the last rate limit info from the most recent request
   */
  getRateLimitInfo(): RateLimitInfo | null {
    return this.lastRateLimit;
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private async request<T>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    path: string,
    body?: unknown,
    options?: { skipAuth?: boolean }
  ): Promise<T> {
    const url = `${this.config.baseUrl}${path}`;
    const requestId = generateUUID();

    const headers: Record<string, string> = {
      'Accept': 'application/json',
      'User-Agent': this.config.userAgent,
      'X-Request-ID': requestId,
    };

    if (!options?.skipAuth) {
      headers['Authorization'] = `Bearer ${this.config.token}`;
    }

    if (body) {
      headers['Content-Type'] = 'application/json';
    }

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.config.retry.maxRetries; attempt++) {
      try {
        const response = await this.executeRequest<T>(url, method, headers, body, requestId);
        return response;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (!isRetryableError(error) || attempt === this.config.retry.maxRetries) {
          throw error;
        }

        // Calculate backoff
        let delay = calculateBackoff(attempt, this.config.retry.retryDelay);

        // Use Retry-After header if available
        if (error instanceof RateLimitError && error.retryAfter) {
          delay = error.retryAfter * 1000;
        }

        await sleep(delay);
      }
    }

    throw lastError;
  }

  private async executeRequest<T>(
    url: string,
    method: string,
    headers: Record<string, string>,
    body: unknown,
    requestId: string
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      // Store rate limit info
      this.lastRateLimit = parseRateLimitHeaders(response.headers);

      // Handle non-JSON responses
      const contentType = response.headers.get('Content-Type');
      if (!contentType?.includes('application/json')) {
        if (response.ok && response.status === 204) {
          return undefined as T;
        }
        throw new ServerError('Invalid response format', 'server_error', response.status);
      }

      const data = await response.json() as ApiResponse<T>;

      // Handle errors
      if (!response.ok || data.status === 'error') {
        throw this.handleErrorResponse(response.status, data, requestId);
      }

      return data.data as T;
    } catch (error) {
      if (error instanceof ApertoDNSError) {
        throw error;
      }

      if (error instanceof Error && error.name === 'AbortError') {
        throw new NetworkError('Request timeout', { isTimeout: true });
      }

      throw new NetworkError('Network error', {
        cause: error instanceof Error ? error : undefined
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private handleErrorResponse(
    statusCode: number,
    response: ApiResponse<unknown>,
    requestId: string
  ): ApertoDNSError {
    const error = response.error;

    if (!error) {
      return new ServerError('Unknown error', 'server_error', statusCode, { requestId });
    }

    switch (statusCode) {
      case 401:
        return new AuthenticationError(error.message, error.code, { requestId });

      case 403:
        return new ForbiddenError(error.message, error.code, {
          details: error.details,
          requestId,
        });

      case 404:
        return new NotFoundError(error.message, error.code, { requestId });

      case 400:
        if (error.code === 'validation_error' && error.details?.fields) {
          return new ValidationError(error.message, {
            fields: error.details.fields as Array<{
              field: string;
              code: string;
              message: string;
              provided?: unknown;
              constraints?: Record<string, unknown>;
            }>,
            requestId,
          });
        }
        return ApertoDNSError.fromApiError(error, statusCode, requestId);

      case 429:
        return new RateLimitError(
          error.message,
          this.lastRateLimit ?? { limit: 0, remaining: 0, reset: 0, retryAfter: 60 },
          { requestId }
        );

      case 500:
      case 502:
      case 503:
      case 504:
        return new ServerError(error.message, error.code, statusCode, {
          supportId: error.support_id,
          requestId,
        });

      default:
        return ApertoDNSError.fromApiError(error, statusCode, requestId);
    }
  }
}

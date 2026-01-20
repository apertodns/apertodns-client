/**
 * ApertoDNS Error Classes
 * @author Andrea Ferro <support@apertodns.com>
 * @license MIT
 */

import type { ApiError, ErrorCode, RateLimitInfo } from './types';

/**
 * Base error class for ApertoDNS errors
 */
export class ApertoDNSError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;
  public readonly requestId?: string;
  public readonly supportId?: string;
  public readonly documentationUrl?: string;

  constructor(
    message: string,
    code: ErrorCode,
    statusCode: number,
    options?: {
      details?: Record<string, unknown>;
      requestId?: string;
      supportId?: string;
      documentationUrl?: string;
    }
  ) {
    super(message);
    this.name = 'ApertoDNSError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = options?.details;
    this.requestId = options?.requestId;
    this.supportId = options?.supportId;
    this.documentationUrl = options?.documentationUrl;

    // Maintain proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApertoDNSError);
    }
  }

  static fromApiError(error: ApiError, statusCode: number, requestId?: string): ApertoDNSError {
    return new ApertoDNSError(error.message, error.code, statusCode, {
      details: error.details,
      requestId,
      supportId: error.support_id,
      documentationUrl: error.documentation_url,
    });
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      details: this.details,
      requestId: this.requestId,
      supportId: this.supportId,
      documentationUrl: this.documentationUrl,
    };
  }
}

/**
 * Authentication error (401)
 */
export class AuthenticationError extends ApertoDNSError {
  constructor(message: string, code: ErrorCode = 'unauthorized', options?: { requestId?: string }) {
    super(message, code, 401, options);
    this.name = 'AuthenticationError';
  }
}

/**
 * Authorization/Forbidden error (403)
 */
export class ForbiddenError extends ApertoDNSError {
  constructor(message: string, code: ErrorCode = 'forbidden', options?: { details?: Record<string, unknown>; requestId?: string }) {
    super(message, code, 403, options);
    this.name = 'ForbiddenError';
  }
}

/**
 * Not found error (404)
 */
export class NotFoundError extends ApertoDNSError {
  constructor(message: string, code: ErrorCode = 'hostname_not_owned', options?: { requestId?: string }) {
    super(message, code, 403, options);
    this.name = 'NotFoundError';
  }
}

/**
 * Validation error (400)
 */
export class ValidationError extends ApertoDNSError {
  public readonly fields?: Array<{
    field: string;
    code: string;
    message: string;
    provided?: unknown;
    constraints?: Record<string, unknown>;
  }>;

  constructor(
    message: string,
    options?: {
      fields?: Array<{
        field: string;
        code: string;
        message: string;
        provided?: unknown;
        constraints?: Record<string, unknown>;
      }>;
      requestId?: string;
    }
  ) {
    super(message, 'validation_error', 400, { requestId: options?.requestId });
    this.name = 'ValidationError';
    this.fields = options?.fields;
  }
}

/**
 * Rate limit error (429)
 */
export class RateLimitError extends ApertoDNSError {
  public readonly rateLimitInfo: RateLimitInfo;

  constructor(message: string, rateLimitInfo: RateLimitInfo, options?: { requestId?: string }) {
    super(message, 'rate_limited', 429, {
      requestId: options?.requestId,
      details: { retry_after_seconds: rateLimitInfo.retryAfter },
    });
    this.name = 'RateLimitError';
    this.rateLimitInfo = rateLimitInfo;
  }

  get retryAfter(): number {
    return this.rateLimitInfo.retryAfter ?? 60;
  }
}

/**
 * Server error (500, 502, 503, 504)
 */
export class ServerError extends ApertoDNSError {
  constructor(
    message: string,
    code: ErrorCode = 'server_error',
    statusCode: number = 500,
    options?: { supportId?: string; requestId?: string }
  ) {
    super(message, code, statusCode, options);
    this.name = 'ServerError';
  }
}

/**
 * Network/Connection error
 */
export class NetworkError extends Error {
  public readonly cause?: Error;
  public readonly isTimeout: boolean;

  constructor(message: string, options?: { cause?: Error; isTimeout?: boolean }) {
    super(message);
    this.name = 'NetworkError';
    this.cause = options?.cause;
    this.isTimeout = options?.isTimeout ?? false;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, NetworkError);
    }
  }
}

/**
 * Type guard to check if an error is an ApertoDNS error
 */
export function isApertoDNSError(error: unknown): error is ApertoDNSError {
  return error instanceof ApertoDNSError;
}

/**
 * Type guard to check if an error is a rate limit error
 */
export function isRateLimitError(error: unknown): error is RateLimitError {
  return error instanceof RateLimitError;
}

/**
 * Type guard to check if an error is a network error
 */
export function isNetworkError(error: unknown): error is NetworkError {
  return error instanceof NetworkError;
}

/**
 * Type guard to check if an error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof RateLimitError) {
    return true;
  }
  if (error instanceof ServerError) {
    return [502, 503, 504].includes(error.statusCode);
  }
  if (error instanceof NetworkError) {
    return true;
  }
  return false;
}

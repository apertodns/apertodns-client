/**
 * Error Tests
 * @author Andrea Ferro <support@apertodns.com>
 */

import { describe, it, expect } from 'vitest';
import {
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
} from '../src/errors';

describe('ApertoDNSError', () => {
  it('should create error with all properties', () => {
    const error = new ApertoDNSError('Test error', 'server_error', 500, {
      details: { foo: 'bar' },
      requestId: 'req_123',
      supportId: 'sup_456',
    });

    expect(error.message).toBe('Test error');
    expect(error.code).toBe('server_error');
    expect(error.statusCode).toBe(500);
    expect(error.details).toEqual({ foo: 'bar' });
    expect(error.requestId).toBe('req_123');
    expect(error.supportId).toBe('sup_456');
    expect(error.name).toBe('ApertoDNSError');
  });

  it('should serialize to JSON', () => {
    const error = new ApertoDNSError('Test', 'server_error', 500);
    const json = error.toJSON();

    expect(json.name).toBe('ApertoDNSError');
    expect(json.message).toBe('Test');
    expect(json.code).toBe('server_error');
    expect(json.statusCode).toBe(500);
  });

  it('should create from API error', () => {
    const apiError = {
      code: 'validation_error' as const,
      message: 'Validation failed',
      details: { fields: [] },
      support_id: 'sup_123',
      documentation_url: 'https://docs.example.com',
    };

    const error = ApertoDNSError.fromApiError(apiError, 400, 'req_123');

    expect(error.code).toBe('validation_error');
    expect(error.message).toBe('Validation failed');
    expect(error.statusCode).toBe(400);
    expect(error.supportId).toBe('sup_123');
    expect(error.requestId).toBe('req_123');
  });
});

describe('AuthenticationError', () => {
  it('should have correct defaults', () => {
    const error = new AuthenticationError('Invalid token');

    expect(error.name).toBe('AuthenticationError');
    expect(error.code).toBe('unauthorized');
    expect(error.statusCode).toBe(401);
  });
});

describe('ForbiddenError', () => {
  it('should have correct defaults', () => {
    const error = new ForbiddenError('Access denied');

    expect(error.name).toBe('ForbiddenError');
    expect(error.code).toBe('forbidden');
    expect(error.statusCode).toBe(403);
  });
});

describe('NotFoundError', () => {
  it('should have correct defaults', () => {
    const error = new NotFoundError('Hostname not found');

    expect(error.name).toBe('NotFoundError');
    expect(error.code).toBe('hostname_not_owned');
    expect(error.statusCode).toBe(403);
  });
});

describe('ValidationError', () => {
  it('should include field errors', () => {
    const error = new ValidationError('Validation failed', {
      fields: [
        { field: 'hostname', code: 'required', message: 'Hostname is required' },
      ],
    });

    expect(error.name).toBe('ValidationError');
    expect(error.code).toBe('validation_error');
    expect(error.statusCode).toBe(400);
    expect(error.fields).toHaveLength(1);
    expect(error.fields?.[0].field).toBe('hostname');
  });
});

describe('RateLimitError', () => {
  it('should include rate limit info', () => {
    const rateLimitInfo = {
      limit: 60,
      remaining: 0,
      reset: 1234567890,
      retryAfter: 45,
    };

    const error = new RateLimitError('Rate limited', rateLimitInfo);

    expect(error.name).toBe('RateLimitError');
    expect(error.code).toBe('rate_limited');
    expect(error.statusCode).toBe(429);
    expect(error.rateLimitInfo).toEqual(rateLimitInfo);
    expect(error.retryAfter).toBe(45);
  });
});

describe('ServerError', () => {
  it('should have correct defaults', () => {
    const error = new ServerError('Internal error');

    expect(error.name).toBe('ServerError');
    expect(error.code).toBe('server_error');
    expect(error.statusCode).toBe(500);
  });

  it('should accept custom status code', () => {
    const error = new ServerError('Gateway error', 'dns_error', 502);

    expect(error.code).toBe('dns_error');
    expect(error.statusCode).toBe(502);
  });
});

describe('NetworkError', () => {
  it('should create network error', () => {
    const error = new NetworkError('Connection failed');

    expect(error.name).toBe('NetworkError');
    expect(error.message).toBe('Connection failed');
    expect(error.isTimeout).toBe(false);
  });

  it('should handle timeout', () => {
    const error = new NetworkError('Request timeout', { isTimeout: true });

    expect(error.isTimeout).toBe(true);
  });

  it('should include cause', () => {
    const cause = new Error('Original error');
    const error = new NetworkError('Network failed', { cause });

    expect(error.cause).toBe(cause);
  });
});

describe('Type Guards', () => {
  describe('isApertoDNSError', () => {
    it('should return true for ApertoDNS errors', () => {
      expect(isApertoDNSError(new ApertoDNSError('Test', 'server_error', 500))).toBe(true);
      expect(isApertoDNSError(new AuthenticationError('Test'))).toBe(true);
      expect(isApertoDNSError(new RateLimitError('Test', { limit: 60, remaining: 0, reset: 0 }))).toBe(true);
    });

    it('should return false for other errors', () => {
      expect(isApertoDNSError(new Error('Test'))).toBe(false);
      expect(isApertoDNSError(new NetworkError('Test'))).toBe(false);
      expect(isApertoDNSError(null)).toBe(false);
    });
  });

  describe('isRateLimitError', () => {
    it('should return true for rate limit errors', () => {
      expect(isRateLimitError(new RateLimitError('Test', { limit: 60, remaining: 0, reset: 0 }))).toBe(true);
    });

    it('should return false for other errors', () => {
      expect(isRateLimitError(new ApertoDNSError('Test', 'server_error', 500))).toBe(false);
    });
  });

  describe('isNetworkError', () => {
    it('should return true for network errors', () => {
      expect(isNetworkError(new NetworkError('Test'))).toBe(true);
    });

    it('should return false for other errors', () => {
      expect(isNetworkError(new ApertoDNSError('Test', 'server_error', 500))).toBe(false);
    });
  });

  describe('isRetryableError', () => {
    it('should return true for rate limit errors', () => {
      expect(isRetryableError(new RateLimitError('Test', { limit: 60, remaining: 0, reset: 0 }))).toBe(true);
    });

    it('should return true for server errors 502, 503, 504', () => {
      expect(isRetryableError(new ServerError('Test', 'dns_error', 502))).toBe(true);
      expect(isRetryableError(new ServerError('Test', 'maintenance', 503))).toBe(true);
      expect(isRetryableError(new ServerError('Test', 'timeout', 504))).toBe(true);
    });

    it('should return false for 500 server errors', () => {
      expect(isRetryableError(new ServerError('Test', 'server_error', 500))).toBe(false);
    });

    it('should return true for network errors', () => {
      expect(isRetryableError(new NetworkError('Test'))).toBe(true);
    });

    it('should return false for auth errors', () => {
      expect(isRetryableError(new AuthenticationError('Test'))).toBe(false);
    });
  });
});

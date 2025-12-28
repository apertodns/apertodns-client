/**
 * Utils Tests
 * @author Andrea Ferro <support@apertodns.com>
 */

import { describe, it, expect } from 'vitest';
import {
  generateToken,
  maskToken,
  verifyWebhookSignature,
  createWebhookSignature,
  calculateBackoff,
  buildUrl,
  isTokenExpired,
  normalizeHostname,
} from '../src/utils';

describe('Token Generation', () => {
  describe('generateToken', () => {
    it('should generate valid live token format', () => {
      const token = generateToken('live');
      expect(token).toMatch(/^apertodns_live_[A-Za-z0-9_-]{32}$/);
    });

    it('should generate valid test token format', () => {
      const token = generateToken('test');
      expect(token).toMatch(/^apertodns_test_[A-Za-z0-9_-]{32}$/);
    });

    it('should generate unique tokens', () => {
      const token1 = generateToken();
      const token2 = generateToken();
      expect(token1).not.toBe(token2);
    });
  });

  describe('maskToken', () => {
    it('should mask token correctly', () => {
      const token = 'apertodns_live_7Hqj3kL9mNpR2sT5vWxY8zA1bC4dE6fG';
      const masked = maskToken(token);
      expect(masked).toBe('apertond...E6fG');
    });

    it('should return *** for short tokens', () => {
      expect(maskToken('short')).toBe('***');
    });
  });
});

describe('Webhook Signature', () => {
  const secret = 'test-secret-minimum-32-chars-long';
  const payload = '{"event":"ip_changed"}';

  describe('createWebhookSignature', () => {
    it('should create valid signature', () => {
      const { signature, timestamp } = createWebhookSignature(payload, secret);
      expect(signature).toMatch(/^sha256=[a-f0-9]{64}$/);
      expect(timestamp).toBeGreaterThan(0);
    });
  });

  describe('verifyWebhookSignature', () => {
    it('should verify valid signature', () => {
      const { signature, timestamp } = createWebhookSignature(payload, secret);
      const isValid = verifyWebhookSignature(payload, signature, secret, timestamp);
      expect(isValid).toBe(true);
    });

    it('should reject invalid signature', () => {
      const timestamp = Math.floor(Date.now() / 1000);
      const isValid = verifyWebhookSignature(payload, 'sha256=invalid', secret, timestamp);
      expect(isValid).toBe(false);
    });

    it('should reject expired timestamp', () => {
      const oldTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
      const { signature } = createWebhookSignature(payload, secret, oldTimestamp);
      const isValid = verifyWebhookSignature(payload, signature, secret, oldTimestamp);
      expect(isValid).toBe(false);
    });

    it('should reject wrong secret', () => {
      const { signature, timestamp } = createWebhookSignature(payload, secret);
      const isValid = verifyWebhookSignature(payload, signature, 'wrong-secret-32-chars-minimum-ok', timestamp);
      expect(isValid).toBe(false);
    });
  });
});

describe('Backoff Calculation', () => {
  describe('calculateBackoff', () => {
    it('should return base delay for first attempt', () => {
      const delay = calculateBackoff(0, 1000);
      expect(delay).toBeGreaterThanOrEqual(1000);
      expect(delay).toBeLessThan(1200); // Allow for jitter
    });

    it('should increase exponentially', () => {
      const delay0 = calculateBackoff(0, 1000);
      const delay1 = calculateBackoff(1, 1000);
      const delay2 = calculateBackoff(2, 1000);

      expect(delay1).toBeGreaterThan(delay0);
      expect(delay2).toBeGreaterThan(delay1);
    });

    it('should respect max delay', () => {
      const delay = calculateBackoff(10, 1000, 5000);
      expect(delay).toBeLessThanOrEqual(5500); // Allow for jitter
    });
  });
});

describe('URL Building', () => {
  describe('buildUrl', () => {
    it('should build URL without params', () => {
      const url = buildUrl('https://api.example.com', '/path');
      expect(url).toBe('https://api.example.com/path');
    });

    it('should build URL with params', () => {
      const url = buildUrl('https://api.example.com', '/path', {
        foo: 'bar',
        num: 123
      });
      expect(url).toBe('https://api.example.com/path?foo=bar&num=123');
    });

    it('should skip undefined params', () => {
      const url = buildUrl('https://api.example.com', '/path', {
        foo: 'bar',
        skip: undefined
      });
      expect(url).toBe('https://api.example.com/path?foo=bar');
    });
  });
});

describe('Token Expiration', () => {
  describe('isTokenExpired', () => {
    it('should return false for null expiration', () => {
      expect(isTokenExpired(null)).toBe(false);
    });

    it('should return false for future expiration', () => {
      const future = new Date(Date.now() + 86400000).toISOString();
      expect(isTokenExpired(future)).toBe(false);
    });

    it('should return true for past expiration', () => {
      const past = new Date(Date.now() - 86400000).toISOString();
      expect(isTokenExpired(past)).toBe(true);
    });
  });
});

describe('Hostname Normalization', () => {
  describe('normalizeHostname', () => {
    it('should lowercase hostname', () => {
      expect(normalizeHostname('MyHost.ApertoDNS.com')).toBe('myhost.apertodns.com');
    });

    it('should trim whitespace', () => {
      expect(normalizeHostname('  myhost.apertodns.com  ')).toBe('myhost.apertodns.com');
    });
  });
});

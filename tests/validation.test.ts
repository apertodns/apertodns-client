/**
 * Validation Tests
 * @author Andrea Ferro <support@apertodns.com>
 */

import { describe, it, expect } from 'vitest';
import {
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
} from '../src/validation';

describe('IPv4 Validation', () => {
  describe('isValidIPv4', () => {
    it('should accept valid IPv4 addresses', () => {
      expect(isValidIPv4('192.168.1.1')).toBe(true);
      expect(isValidIPv4('10.0.0.1')).toBe(true);
      expect(isValidIPv4('255.255.255.255')).toBe(true);
      expect(isValidIPv4('0.0.0.0')).toBe(true);
      expect(isValidIPv4('203.0.113.50')).toBe(true);
    });

    it('should reject invalid IPv4 addresses', () => {
      expect(isValidIPv4('256.1.1.1')).toBe(false);
      expect(isValidIPv4('192.168.1')).toBe(false);
      expect(isValidIPv4('192.168.1.1.1')).toBe(false);
      expect(isValidIPv4('abc.def.ghi.jkl')).toBe(false);
      expect(isValidIPv4('')).toBe(false);
      expect(isValidIPv4('192.168.1.1/24')).toBe(false);
    });
  });

  describe('isPublicIPv4', () => {
    it('should accept public IPv4 addresses', () => {
      expect(isPublicIPv4('8.8.8.8')).toBe(true);
      expect(isPublicIPv4('1.1.1.1')).toBe(true);
      expect(isPublicIPv4('203.0.114.1')).toBe(true);
    });

    it('should reject private IPv4 addresses', () => {
      // Private ranges
      expect(isPublicIPv4('10.0.0.1')).toBe(false);
      expect(isPublicIPv4('10.255.255.255')).toBe(false);
      expect(isPublicIPv4('172.16.0.1')).toBe(false);
      expect(isPublicIPv4('172.31.255.255')).toBe(false);
      expect(isPublicIPv4('192.168.0.1')).toBe(false);
      expect(isPublicIPv4('192.168.255.255')).toBe(false);
    });

    it('should reject loopback addresses', () => {
      expect(isPublicIPv4('127.0.0.1')).toBe(false);
      expect(isPublicIPv4('127.255.255.255')).toBe(false);
    });

    it('should reject link-local addresses', () => {
      expect(isPublicIPv4('169.254.0.1')).toBe(false);
      expect(isPublicIPv4('169.254.255.255')).toBe(false);
    });

    it('should reject CGNAT addresses', () => {
      expect(isPublicIPv4('100.64.0.1')).toBe(false);
      expect(isPublicIPv4('100.127.255.255')).toBe(false);
    });

    it('should reject documentation addresses', () => {
      expect(isPublicIPv4('192.0.2.1')).toBe(false);
      expect(isPublicIPv4('198.51.100.1')).toBe(false);
      expect(isPublicIPv4('203.0.113.1')).toBe(false);
    });

    it('should reject multicast addresses', () => {
      expect(isPublicIPv4('224.0.0.1')).toBe(false);
      expect(isPublicIPv4('239.255.255.255')).toBe(false);
    });

    it('should reject reserved addresses', () => {
      expect(isPublicIPv4('240.0.0.1')).toBe(false);
      expect(isPublicIPv4('255.255.255.255')).toBe(false);
    });
  });
});

describe('IPv6 Validation', () => {
  describe('isValidIPv6', () => {
    it('should accept valid IPv6 addresses', () => {
      expect(isValidIPv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
      expect(isValidIPv6('2001:db8::1')).toBe(true);
      expect(isValidIPv6('::1')).toBe(true);
      expect(isValidIPv6('::')).toBe(true);
      expect(isValidIPv6('fe80::1')).toBe(true);
    });

    it('should reject invalid IPv6 addresses', () => {
      expect(isValidIPv6('not-an-ipv6')).toBe(false);
      expect(isValidIPv6('192.168.1.1')).toBe(false);
      expect(isValidIPv6('')).toBe(false);
    });
  });

  describe('isPublicIPv6', () => {
    it('should accept public IPv6 addresses', () => {
      expect(isPublicIPv6('2001:4860:4860::8888')).toBe(true);
      expect(isPublicIPv6('2606:4700:4700::1111')).toBe(true);
    });

    it('should reject loopback', () => {
      expect(isPublicIPv6('::1')).toBe(false);
    });

    it('should reject unspecified', () => {
      expect(isPublicIPv6('::')).toBe(false);
    });

    it('should reject link-local', () => {
      expect(isPublicIPv6('fe80::1')).toBe(false);
    });

    it('should reject unique local', () => {
      expect(isPublicIPv6('fc00::1')).toBe(false);
      expect(isPublicIPv6('fd00::1')).toBe(false);
    });

    it('should reject multicast', () => {
      expect(isPublicIPv6('ff00::1')).toBe(false);
    });

    it('should reject documentation', () => {
      expect(isPublicIPv6('2001:db8::1')).toBe(false);
    });
  });
});

describe('Hostname Validation', () => {
  describe('isValidHostname', () => {
    it('should accept valid hostnames', () => {
      expect(isValidHostname('example.com')).toBe(true);
      expect(isValidHostname('sub.example.com')).toBe(true);
      expect(isValidHostname('my-host.apertodns.com')).toBe(true);
      expect(isValidHostname('a.b.c.d.example.com')).toBe(true);
      expect(isValidHostname('host123.example.com')).toBe(true);
    });

    it('should reject hostnames without TLD', () => {
      expect(isValidHostname('localhost')).toBe(false);
      expect(isValidHostname('myhost')).toBe(false);
    });

    it('should reject hostnames over 253 characters', () => {
      const longHostname = 'a'.repeat(250) + '.com';
      expect(isValidHostname(longHostname)).toBe(false);
    });

    it('should reject labels over 63 characters', () => {
      const longLabel = 'a'.repeat(64) + '.com';
      expect(isValidHostname(longLabel)).toBe(false);
    });

    it('should reject invalid characters', () => {
      expect(isValidHostname('host_name.com')).toBe(false);
      expect(isValidHostname('host name.com')).toBe(false);
      expect(isValidHostname('host!name.com')).toBe(false);
    });

    it('should reject double dots', () => {
      expect(isValidHostname('host..example.com')).toBe(false);
    });

    it('should reject empty hostname', () => {
      expect(isValidHostname('')).toBe(false);
    });
  });
});

describe('TTL Validation', () => {
  describe('isValidTTL', () => {
    it('should accept valid TTL values', () => {
      expect(isValidTTL(60)).toBe(true);
      expect(isValidTTL(300)).toBe(true);
      expect(isValidTTL(3600)).toBe(true);
      expect(isValidTTL(86400)).toBe(true);
    });

    it('should reject TTL below minimum', () => {
      expect(isValidTTL(59)).toBe(false);
      expect(isValidTTL(0)).toBe(false);
      expect(isValidTTL(-1)).toBe(false);
    });

    it('should reject TTL above maximum', () => {
      expect(isValidTTL(86401)).toBe(false);
      expect(isValidTTL(100000)).toBe(false);
    });

    it('should reject non-integer TTL', () => {
      expect(isValidTTL(300.5)).toBe(false);
      expect(isValidTTL(NaN)).toBe(false);
    });
  });
});

describe('Token Validation', () => {
  describe('isValidToken', () => {
    it('should accept valid tokens', () => {
      expect(isValidToken('apt_live_7Hqj3kL9mNpR2sT5vWxY8zA1bC4dE6fG')).toBe(true);
      expect(isValidToken('apt_test_7Hqj3kL9mNpR2sT5vWxY8zA1bC4dE6fG')).toBe(true);
    });

    it('should reject invalid token formats', () => {
      expect(isValidToken('apt_live_short')).toBe(false);
      expect(isValidToken('invalid_token')).toBe(false);
      expect(isValidToken('')).toBe(false);
      expect(isValidToken('apt_prod_7Hqj3kL9mNpR2sT5vWxY8zA1bC4dE6fG')).toBe(false);
    });
  });
});

describe('Webhook Secret Validation', () => {
  describe('isValidWebhookSecret', () => {
    it('should accept secrets >= 32 characters', () => {
      expect(isValidWebhookSecret('a'.repeat(32))).toBe(true);
      expect(isValidWebhookSecret('a'.repeat(64))).toBe(true);
    });

    it('should reject secrets < 32 characters', () => {
      expect(isValidWebhookSecret('a'.repeat(31))).toBe(false);
      expect(isValidWebhookSecret('')).toBe(false);
    });
  });
});

describe('URL Validation', () => {
  describe('isHttpsUrl', () => {
    it('should accept HTTPS URLs', () => {
      expect(isHttpsUrl('https://example.com')).toBe(true);
      expect(isHttpsUrl('https://example.com/webhook')).toBe(true);
      expect(isHttpsUrl('https://example.com:8443/path')).toBe(true);
    });

    it('should reject HTTP URLs', () => {
      expect(isHttpsUrl('http://example.com')).toBe(false);
    });

    it('should reject invalid URLs', () => {
      expect(isHttpsUrl('not-a-url')).toBe(false);
      expect(isHttpsUrl('')).toBe(false);
    });
  });
});

describe('validateUpdateRequest', () => {
  it('should pass for valid request', () => {
    const result = validateUpdateRequest({
      hostname: 'myhost.apertodns.com',
      ipv4: 'auto',
      ttl: 300
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should fail for missing hostname', () => {
    const result = validateUpdateRequest({
      ipv4: 'auto'
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe('hostname');
  });

  it('should fail for invalid hostname', () => {
    const result = validateUpdateRequest({
      hostname: 'invalid..hostname',
      ipv4: 'auto'
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe('hostname');
  });

  it('should fail for private IP', () => {
    const result = validateUpdateRequest({
      hostname: 'myhost.apertodns.com',
      ipv4: '192.168.1.1'
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('private_ip');
  });

  it('should fail for invalid TTL', () => {
    const result = validateUpdateRequest({
      hostname: 'myhost.apertodns.com',
      ipv4: 'auto',
      ttl: 30
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe('ttl');
  });

  it('should allow "auto" for IP fields', () => {
    const result = validateUpdateRequest({
      hostname: 'myhost.apertodns.com',
      ipv4: 'auto',
      ipv6: 'auto'
    });
    expect(result.valid).toBe(true);
  });
});

/**
 * ApertoDNS Input Validation
 * @author Andrea Ferro <support@apertodns.com>
 * @license MIT
 */

// ============================================================================
// IPv4 Private Ranges (MUST Reject)
// ============================================================================

const PRIVATE_IPV4_RANGES = [
  { prefix: '0.', description: '"This" network' },
  { prefix: '10.', description: 'Private-Use' },
  { prefix: '127.', description: 'Loopback' },
  { prefix: '169.254.', description: 'Link-Local' },
  { prefix: '192.0.0.', description: 'IETF Protocol Assignments' },
  { prefix: '192.0.2.', description: 'Documentation (TEST-NET-1)' },
  { prefix: '192.168.', description: 'Private-Use' },
  { prefix: '198.18.', description: 'Benchmarking' },
  { prefix: '198.19.', description: 'Benchmarking' },
  { prefix: '198.51.100.', description: 'Documentation (TEST-NET-2)' },
  { prefix: '203.0.113.', description: 'Documentation (TEST-NET-3)' },
  { prefix: '224.', description: 'Multicast' },
  { prefix: '225.', description: 'Multicast' },
  { prefix: '226.', description: 'Multicast' },
  { prefix: '227.', description: 'Multicast' },
  { prefix: '228.', description: 'Multicast' },
  { prefix: '229.', description: 'Multicast' },
  { prefix: '230.', description: 'Multicast' },
  { prefix: '231.', description: 'Multicast' },
  { prefix: '232.', description: 'Multicast' },
  { prefix: '233.', description: 'Multicast' },
  { prefix: '234.', description: 'Multicast' },
  { prefix: '235.', description: 'Multicast' },
  { prefix: '236.', description: 'Multicast' },
  { prefix: '237.', description: 'Multicast' },
  { prefix: '238.', description: 'Multicast' },
  { prefix: '239.', description: 'Multicast' },
  { prefix: '240.', description: 'Reserved' },
  { prefix: '255.255.255.255', description: 'Limited Broadcast' },
];

// 172.16.0.0/12 and 100.64.0.0/10 need special handling
function isIn172PrivateRange(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts[0] !== 172) return false;
  return parts[1] >= 16 && parts[1] <= 31;
}

function isInCGNATRange(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts[0] !== 100) return false;
  return parts[1] >= 64 && parts[1] <= 127;
}

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate IPv4 address format
 */
export function isValidIPv4(ip: string): boolean {
  const pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return pattern.test(ip);
}

/**
 * Validate IPv6 address format
 */
export function isValidIPv6(ip: string): boolean {
  // Simplified IPv6 validation
  const pattern = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,7}:$|^(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}$|^(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}$|^(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}$|^[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6}$|^:(?::[a-fA-F0-9]{1,4}){1,7}$|^::$/;
  return pattern.test(ip);
}

/**
 * Check if IPv4 is a public address (not private/reserved)
 */
export function isPublicIPv4(ip: string): boolean {
  if (!isValidIPv4(ip)) return false;

  // Check simple prefix matches
  for (const range of PRIVATE_IPV4_RANGES) {
    if (ip.startsWith(range.prefix)) return false;
  }

  // Check 172.16.0.0/12
  if (isIn172PrivateRange(ip)) return false;

  // Check CGNAT 100.64.0.0/10
  if (isInCGNATRange(ip)) return false;

  return true;
}

/**
 * Check if IPv6 is a public address
 */
export function isPublicIPv6(ip: string): boolean {
  if (!isValidIPv6(ip)) return false;

  const normalized = ip.toLowerCase();

  // Loopback
  if (normalized === '::1') return false;

  // Unspecified
  if (normalized === '::') return false;

  // Link-local (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') ||
      normalized.startsWith('fea') || normalized.startsWith('feb')) return false;

  // Unique Local (fc00::/7)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return false;

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) return false;

  // Documentation (2001:db8::/32)
  if (normalized.startsWith('2001:db8:') || normalized.startsWith('2001:0db8:')) return false;

  return true;
}

/**
 * Validate hostname format (FQDN)
 */
export function isValidHostname(hostname: string): boolean {
  // Max 253 characters total
  if (hostname.length > 253 || hostname.length === 0) return false;

  // Split into labels
  const labels = hostname.split('.');

  // At least 2 labels (e.g., host.domain)
  if (labels.length < 2) return false;

  for (const label of labels) {
    // Each label 1-63 characters
    if (label.length < 1 || label.length > 63) return false;

    // Only alphanumeric and hyphens, no leading/trailing hyphens
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label) && label.length > 1) return false;
    if (label.length === 1 && !/^[a-zA-Z0-9]$/.test(label)) return false;
  }

  // No double dots
  if (hostname.includes('..')) return false;

  return true;
}

/**
 * Validate TTL value
 */
export function isValidTTL(ttl: number): boolean {
  return Number.isInteger(ttl) && ttl >= 60 && ttl <= 86400;
}

/**
 * Validate token format
 */
export function isValidToken(token: string): boolean {
  return /^apt_(live|test)_[A-Za-z0-9_-]{32}$/.test(token);
}

/**
 * Validate webhook secret (minimum 32 characters)
 */
export function isValidWebhookSecret(secret: string): boolean {
  return typeof secret === 'string' && secret.length >= 32;
}

/**
 * Validate URL is HTTPS
 */
export function isHttpsUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

// ============================================================================
// Validation Result Types
// ============================================================================

export interface ValidationResult {
  valid: boolean;
  errors: ValidationFieldError[];
}

export interface ValidationFieldError {
  field: string;
  code: string;
  message: string;
  provided?: unknown;
  constraints?: Record<string, unknown>;
}

/**
 * Validate an update request
 */
export function validateUpdateRequest(request: {
  hostname?: string;
  ipv4?: string | null;
  ipv6?: string | null;
  ttl?: number;
}): ValidationResult {
  const errors: ValidationFieldError[] = [];

  // Hostname is required
  if (!request.hostname) {
    errors.push({
      field: 'hostname',
      code: 'required',
      message: 'Hostname is required',
    });
  } else if (!isValidHostname(request.hostname)) {
    errors.push({
      field: 'hostname',
      code: 'invalid_format',
      message: 'Hostname must be a valid FQDN',
      provided: request.hostname,
    });
  }

  // IPv4 validation (if provided and not "auto")
  if (request.ipv4 && request.ipv4 !== 'auto') {
    if (!isValidIPv4(request.ipv4)) {
      errors.push({
        field: 'ipv4',
        code: 'invalid_format',
        message: 'Invalid IPv4 address format',
        provided: request.ipv4,
      });
    } else if (!isPublicIPv4(request.ipv4)) {
      errors.push({
        field: 'ipv4',
        code: 'private_ip',
        message: 'IPv4 address must be a public address',
        provided: request.ipv4,
      });
    }
  }

  // IPv6 validation (if provided and not "auto")
  if (request.ipv6 && request.ipv6 !== 'auto') {
    if (!isValidIPv6(request.ipv6)) {
      errors.push({
        field: 'ipv6',
        code: 'invalid_format',
        message: 'Invalid IPv6 address format',
        provided: request.ipv6,
      });
    } else if (!isPublicIPv6(request.ipv6)) {
      errors.push({
        field: 'ipv6',
        code: 'private_ip',
        message: 'IPv6 address must be a public address',
        provided: request.ipv6,
      });
    }
  }

  // TTL validation (if provided)
  if (request.ttl !== undefined && !isValidTTL(request.ttl)) {
    errors.push({
      field: 'ttl',
      code: 'out_of_range',
      message: 'TTL must be between 60 and 86400 seconds',
      provided: request.ttl,
      constraints: { min: 60, max: 86400 },
    });
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

# apertodns-client

Universal TypeScript client for ApertoDNS Protocol v1.0

[![npm version](https://img.shields.io/npm/v/apertodns-client.svg)](https://www.npmjs.com/package/apertodns-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![ApertoDNS Protocol v1.0](https://img.shields.io/badge/ApertoDNS_Protocol-v1.0-blue)](https://apertodns.com/protocol)

## Installation

```bash
npm install apertodns-client
```

## Quick Start

```typescript
import { ApertoDNSClient } from 'apertodns-client';

const client = new ApertoDNSClient({
  token: 'apt_live_xxxxxxxxxxxxxxxxxxxxxxxxxx'
});

// Update a hostname with auto IP detection
const result = await client.update({
  hostname: 'myhost.apertodns.com',
  ipv4: 'auto'
});

console.log(`Updated to ${result.ipv4}`);
```

## Features

- Full ApertoDNS Protocol v1.0 support
- TypeScript-first with complete type definitions
- Automatic retries with exponential backoff
- Rate limit handling
- Client-side validation
- Webhook signature verification
- Legacy DynDNS2 support
- Zero dependencies (except Node.js built-ins)

## API Reference

### Constructor

```typescript
const client = new ApertoDNSClient({
  // Required: Your API token
  token: 'apt_live_xxx',

  // Optional: API base URL (default: https://api.apertodns.com)
  baseUrl: 'https://api.apertodns.com',

  // Optional: Request timeout in ms (default: 30000)
  timeout: 30000,

  // Optional: Custom User-Agent
  userAgent: 'MyApp/1.0.0',

  // Optional: Retry configuration
  retry: {
    maxRetries: 3,
    retryDelay: 1000,
    retryOnStatus: [429, 502, 503, 504]
  }
});
```

### Update Methods

#### Single Update

```typescript
const result = await client.update({
  hostname: 'myhost.apertodns.com',
  ipv4: 'auto',        // 'auto' | IP address | null
  ipv6: 'auto',        // 'auto' | IP address | null
  ttl: 300             // 60-86400 seconds
});

console.log(result);
// {
//   hostname: 'myhost.apertodns.com',
//   ipv4: '203.0.113.50',
//   ipv6: '2001:db8::1',
//   ipv4_previous: '203.0.113.49',
//   ipv6_previous: null,
//   ttl: 300,
//   changed: true,
//   updated_at: '2025-01-01T12:00:00.000Z'
// }
```

#### Bulk Update

```typescript
const result = await client.bulkUpdate({
  updates: [
    { hostname: 'host1.apertodns.com', ipv4: 'auto' },
    { hostname: 'host2.apertodns.com', ipv4: '203.0.113.100' },
    { hostname: 'host3.apertodns.com', ipv4: 'auto', ttl: 600 }
  ],
  defaults: {
    ttl: 300
  }
});

console.log(result.summary);
// { total: 3, successful: 3, failed: 0 }
```

#### Legacy DynDNS2

```typescript
const response = await client.legacyUpdate('myhost.apertodns.com');
console.log(response); // 'good 203.0.113.50'
```

### Status

```typescript
const status = await client.getStatus('myhost.apertodns.com');

console.log(status);
// {
//   hostname: 'myhost.apertodns.com',
//   ipv4: '203.0.113.50',
//   ipv6: '2001:db8::1',
//   ttl: 300,
//   is_active: true,
//   last_update: '2025-01-01T12:00:00.000Z',
//   update_count_24h: 5,
//   update_count_total: 1250,
//   created_at: '2024-01-15T10:00:00.000Z'
// }
```

### Discovery

```typescript
const info = await client.getInfo(); // No auth required

console.log(info.provider.name);     // 'ApertoDNS'
console.log(info.capabilities.ipv6); // true
```

### Token Management

```typescript
// Create token
const token = await client.createToken({
  name: 'Home Router',
  permissions: ['update', 'read'],
  allowed_hostnames: ['myhost.apertodns.com'],
  expires_at: '2025-12-31T23:59:59Z'
});

console.log(token.token); // 'apt_live_xxx' - Save this immediately!

// List tokens
const tokens = await client.listTokens();

// Delete token
await client.deleteToken('tok_xxx');
```

### Webhook Management

```typescript
// Create webhook
const webhook = await client.createWebhook({
  name: 'IP Change Notification',
  hostname: 'myhost.apertodns.com',
  url: 'https://my-server.com/webhook',
  events: ['ip_changed'],
  secret: 'my-secret-minimum-32-characters-long'
});

// List webhooks
const webhooks = await client.listWebhooks();

// Delete webhook
await client.deleteWebhook('wh_xxx');
```

### GDPR / Account

```typescript
// Request data export
const exportRequest = await client.requestExport();
console.log(exportRequest.export_id);

// Delete account
const result = await client.deleteAccount({
  confirm: 'DELETE_MY_ACCOUNT',
  reason: 'No longer needed'
});
```

## Error Handling

```typescript
import {
  ApertoDNSClient,
  ApertoDNSError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  isRateLimitError
} from 'apertodns-client';

try {
  await client.update({ hostname: 'myhost.apertodns.com', ipv4: 'auto' });
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error('Invalid token');
  } else if (error instanceof RateLimitError) {
    console.error(`Rate limited. Retry after ${error.retryAfter} seconds`);
  } else if (error instanceof ValidationError) {
    console.error('Validation failed:', error.fields);
  } else if (error instanceof ApertoDNSError) {
    console.error(`Error ${error.code}: ${error.message}`);
  }
}
```

## Webhook Signature Verification

```typescript
import { verifyWebhookSignature } from 'apertodns-client';

// In your webhook handler
app.post('/webhook', (req, res) => {
  const payload = JSON.stringify(req.body);
  const signature = req.headers['x-apertodns-signature'];
  const timestamp = parseInt(req.headers['x-apertodns-timestamp'], 10);

  const isValid = verifyWebhookSignature(
    payload,
    signature,
    'your-webhook-secret',
    timestamp
  );

  if (!isValid) {
    return res.status(401).send('Invalid signature');
  }

  // Process webhook...
  res.status(200).send('OK');
});
```

## Validation Utilities

```typescript
import {
  isValidHostname,
  isValidIPv4,
  isPublicIPv4,
  isValidToken,
  validateUpdateRequest
} from 'apertodns-client';

// Check hostname
isValidHostname('myhost.apertodns.com'); // true
isValidHostname('invalid..hostname');     // false

// Check IP
isValidIPv4('203.0.113.50');     // true
isPublicIPv4('192.168.1.1');     // false (private)

// Validate full request
const result = validateUpdateRequest({
  hostname: 'myhost.apertodns.com',
  ipv4: '192.168.1.1'
});

if (!result.valid) {
  console.log(result.errors);
  // [{ field: 'ipv4', code: 'private_ip', message: '...' }]
}
```

## Rate Limit Info

```typescript
// After any request
const rateLimitInfo = client.getRateLimitInfo();

if (rateLimitInfo) {
  console.log(`${rateLimitInfo.remaining}/${rateLimitInfo.limit} requests remaining`);
  console.log(`Resets at ${new Date(rateLimitInfo.reset * 1000)}`);
}
```

## Requirements

- Node.js 16+
- Native `fetch` support (Node.js 18+ or polyfill)

## License

MIT - Andrea Ferro <support@apertodns.com>

## Links

- [ApertoDNS](https://apertodns.com)
- [Protocol Specification](https://apertodns.com/docs/protocol)
- [API Documentation](https://apertodns.com/docs/api)
- [GitHub](https://github.com/apertodns/apertodns-client)

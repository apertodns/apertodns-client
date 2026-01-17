# apertodns-client

Universal TypeScript client for ApertoDNS Protocol v1.3.0

[![npm version](https://img.shields.io/npm/v/apertodns-client.svg)](https://www.npmjs.com/package/apertodns-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![ApertoDNS Protocol v1.3.0](https://img.shields.io/badge/ApertoDNS_Protocol-v1.3.0-blue)](https://apertodns.com/protocol)

## Installation

```bash
npm install apertodns-client
```

## Quick Start

```typescript
import { ApertoDNSClient } from 'apertodns-client';

const client = new ApertoDNSClient({
  token: 'apertodns_live_xxxxxxxxxxxxxxxxxxxxxxxxxx'
});

// Update a hostname with auto IP detection
const result = await client.update({
  hostname: 'myhost.apertodns.com',
  ipv4: 'auto'
});

console.log(`Updated to ${result.ipv4}`);
```

## Features

- Full ApertoDNS Protocol v1.2.3 support
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
  token: 'apertodns_live_xxx',

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

#### TXT Records (ACME DNS-01)

Set and delete TXT records for Let's Encrypt DNS-01 challenges:

```typescript
// Set TXT record for certificate validation
await client.setTxt(
  'example.apertodns.com',
  '_acme-challenge',
  'gfj9Xq...validation-token'
);

// Delete TXT record after certificate issuance
await client.deleteTxt('example.apertodns.com', '_acme-challenge');

// Or use update() with txt option for more control
const result = await client.update({
  hostname: 'example.apertodns.com',
  txt: {
    name: '_acme-challenge',
    value: 'validation-token',
    action: 'set'  // or 'delete'
  }
});
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

### Health Check

```typescript
const health = await client.getHealth(); // No auth required

console.log(health.status);    // 'healthy'
console.log(health.uptime);    // seconds since start
console.log(health.timestamp); // ISO timestamp
```

### List Domains

```typescript
const domains = await client.listDomains();

domains.forEach(d => {
  console.log(`${d.hostname}: ${d.ipv4 || 'no IPv4'}`);
});
// Output:
// myhost.apertodns.com: 203.0.113.50
// other.apertodns.com: 198.51.100.10
```

### API Keys Management (v1.2)

```typescript
// List API keys (full key never returned, only prefix)
const keys = await client.listApiKeys();

// Create API key - SAVE THE KEY IMMEDIATELY!
const newKey = await client.createApiKey({
  name: 'My Script',
  scopes: ['domains:read', 'dns:update'],
  expiresIn: '30d'  // optional
});
console.log(newKey.key); // 'apertodns_live_xxx' - Only shown once!

// Delete API key
await client.deleteApiKey(123);
```

**Available Scopes:**
- `domains:read`, `domains:write`, `domains:delete`
- `tokens:read`, `tokens:write`, `tokens:delete`
- `records:read`, `records:write`
- `webhooks:read`, `webhooks:write`
- `dns:update`, `profile:read`
- `custom-domains:read`, `custom-domains:write`, `custom-domains:delete`
- `credentials:read`, `credentials:write`, `credentials:delete`

### Token Management (v1.2)

Legacy domain-bound tokens for DynDNS compatibility:

```typescript
// List tokens
const tokens = await client.listLegacyTokens();

// Create token - SAVE IMMEDIATELY!
const token = await client.createLegacyToken({
  domainId: 123,
  label: 'Home Router',
  expiresIn: '365d'
});
console.log(token.token); // Only shown once!

// Regenerate token (invalidates old one)
const newToken = await client.regenerateLegacyToken(456);

// Delete token
await client.deleteLegacyToken(456);
```

### Webhook Management (v1.2)

```typescript
// List webhooks
const webhooks = await client.listWebhooksV2();

// Create webhook
const webhook = await client.createWebhookV2({
  url: 'https://example.com/webhook',
  events: ['ip_change', 'domain_create'],
  secret: 'my-32-character-minimum-secret!!'
});

// Update webhook
await client.updateWebhook(123, {
  active: false,
  events: ['ip_change']
});

// Delete webhook
await client.deleteWebhookV2(123);
```

**Available Events:** `ip_change`, `domain_create`, `domain_delete`, `update_failed`

### Webhook Management (Legacy v1.0)

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

> Note: GDPR endpoints are ApertoDNS-specific (`/api/*`), not part of the protocol standard.

```typescript
// Request data export (GET /api/export)
const exportData = await client.requestExport();
console.log(exportData.user.email);
console.log(exportData.domains.length);

// Delete account (POST /api/delete-account)
const result = await client.deleteAccount({
  confirmation: 'DELETE_MY_ACCOUNT'  // Required confirmation string
});
console.log(result.deletedAt);
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

## Note on Terminology

This client maintains compatibility with the DynDNS2 protocol (`/nic/update`), which is a de facto industry standard used by routers, NAS devices, and DDNS clients worldwide. DynDNS® is a registered trademark of Oracle Corporation. ApertoDNS is not affiliated with or endorsed by Oracle or Dyn.

## License

MIT - Andrea Ferro <support@apertodns.com>

## Links

- [ApertoDNS](https://apertodns.com)
- [Protocol Specification](https://apertodns.com/docs/protocol)
- [API Documentation](https://apertodns.com/docs/api)
- [GitHub](https://github.com/apertodns/apertodns-client)

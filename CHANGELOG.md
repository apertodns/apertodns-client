# Changelog

All notable changes to the ApertoDNS Client will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-01-17

### Added

- **TXT Record Support** for ACME DNS-01 challenges
  - `setTxt(hostname, name, value)` - Set a TXT record for DNS-01 validation
  - `deleteTxt(hostname, name)` - Delete a TXT record after certificate issuance
  - `TxtRecordRequest` type for TXT operations
  - `txt` field added to `UpdateRequest` type

### Fixed

- `update()` validation no longer rejects documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x)
  - Server handles IP validation, client only validates format
  - Enables testing with RFC 5737 documentation addresses

---

## [1.3.2] - 2026-01-15

### Added

- `ipv4_auto_failed` error code - returned when IPv4 auto-detection fails (client on IPv6)
- `ipv6_auto_failed` error code - returned when IPv6 auto-detection fails (client on IPv4)

---

## [1.3.0] - 2026-01-01

### Fixed

- **BREAKING**: Fixed API response format to match IETF specification
  - `ApiResponse.status` (string) → `ApiResponse.success` (boolean)
  - Error detection now uses `success === false` instead of `status === 'error'`
- Client now correctly handles API responses per protocol v1.2

### Changed

- Updated `ApiResponse<T>` interface: `success: boolean` replaces `status: string`

---

## [1.2.1] - 2025-12-29

### Documentation

- Added `getHealth()` and `listDomains()` examples to README
- Clarified GDPR endpoints are ApertoDNS-specific (`/api/*`)
- Fixed GDPR example: `confirm` → `confirmation`

---

## [1.2.0] - 2025-12-29

### Added

- `getHealth()` - Get server health status
- `listDomains()` - List all domains for authenticated user

### Fixed

- GDPR endpoints now use correct paths:
  - `requestExport()` → GET /api/export
  - `deleteAccount()` → POST /api/delete-account

---

## [1.1.3] - 2025-12-29

### Added

- Terminology disclaimer for DynDNS2 compatibility

---

## [1.1.2] - 2025-12-29

### Changed

- Updated README with v1.2 API documentation
- Added examples for API Keys, Tokens, and Webhooks management
- Updated protocol version badge to v1.2

---

## [1.1.1] - 2025-12-29

### Changed

- Renamed scope `dyndns:update` → `dns:update` (ApertoDNS is a new protocol, not DynDNS)

---

## [1.1.0] - 2025-12-29

### Added

- **API Keys Management**
  - `listApiKeys()` - List all API keys (keyPrefix only, no full keys)
  - `createApiKey()` - Create new API key with scopes
  - `deleteApiKey()` - Delete an API key

- **Legacy Token Management**
  - `listLegacyTokens()` - List all domain-bound tokens
  - `createLegacyToken()` - Create new token for a domain
  - `regenerateLegacyToken()` - Regenerate token (invalidates old)
  - `deleteLegacyToken()` - Delete a token

- **Webhook Management v1.2**
  - `listWebhooksV2()` - List webhooks with v1.2 response format
  - `createWebhookV2()` - Create webhook with events array
  - `updateWebhook()` - Update webhook (PATCH)
  - `deleteWebhookV2()` - Delete webhook with confirmation response

- **New Types**
  - `ApiKeyScope` - All available API key scopes
  - `ApiKeyResponse`, `CreateApiKeyResponse` - API key types
  - `LegacyTokenResponse`, `CreateLegacyTokenResponse`, `RegenerateTokenResponse` - Token types
  - `WebhookResponseV2`, `CreateWebhookRequestV2`, `UpdateWebhookRequest` - Webhook v1.2 types
  - `WebhookEventType` - Webhook event types
  - `DeleteResponse` - Standard delete response

### Security

- API keys: Full key returned only on creation
- Tokens: Token hash never exposed in list responses
- Webhooks: Secret never returned in responses

---

## [1.0.1] - 2025-12-28

### Fixed

- Minor bug fixes

---

## [1.0.0] - 2025-01-01

### Added

- Initial release of ApertoDNS Client
- Core methods: `update()`, `bulkUpdate()`, `getStatus()`, `getInfo()`
- Token management: `createToken()`, `listTokens()`, `deleteToken()`
- Webhook management: `createWebhook()`, `listWebhooks()`, `deleteWebhook()`
- GDPR methods: `requestExport()`, `deleteAccount()`
- Legacy DynDNS2 support: `legacyUpdate()`
- Full TypeScript support with complete type definitions
- Automatic retry with exponential backoff
- Rate limit handling

---

[1.2.0]: https://github.com/apertodns/apertodns-client/releases/tag/v1.2.0
[1.1.0]: https://github.com/apertodns/apertodns-client/releases/tag/v1.1.0
[1.0.1]: https://github.com/apertodns/apertodns-client/releases/tag/v1.0.1
[1.0.0]: https://github.com/apertodns/apertodns-client/releases/tag/v1.0.0

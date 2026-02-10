# CHANNEL_HUB_V1 (B8)

## Added endpoint

- `POST /v1/channel/inbound`

## Current B8 behavior

This is a contract-ready Hub ingress with safe stub routing:

1. Validates auth/signature/time skew.
2. Validates required schema fields.
3. Enforces idempotency by `requestId` (TTL cache).
4. Returns deterministic stub errors until Edge routing is implemented:
   - `TENANT_NOT_MAPPED` (when `tenantChannelId` missing)
   - `EDGE_UNAVAILABLE` (default stub response)

## Headers expected

- `X-Timestamp`
- `X-Channel-Signature` (`sha256=<hmac>`)

Note: HMAC uses `BRIDGE_TOKEN` as temporary shared secret in B8.

## Env knobs

- `CHANNEL_REQUEST_ID_TTL_MS` (default 300000)
- `CHANNEL_MAX_CLOCK_SKEW_SEC` (default 300)

## Next (B9/B10)

- Replace stub with real edge registry/dispatch.
- Keep same response contract and error codes.

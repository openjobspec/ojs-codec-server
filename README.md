# OJS Codec Server

Standalone HTTP service that provides AES-256-GCM encryption and decryption endpoints for OJS dashboard integration.

The Codec Server enables Admin UI / dashboards to decode encrypted job payloads by proxying through this service. It is intentionally separate from the backend — backends never see plaintext.

```
Dashboard → GET /ojs/v1/admin/jobs/{id} → Backend (returns encrypted args)
         → POST /codec/decode           → Codec Server (returns plaintext)
         → Displays plaintext to authorized user
```

## Quick Start

```bash
# Generate a 32-byte AES key
export OJS_CODEC_KEY=$(openssl rand -hex 32)

# Build and run
make run
```

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `OJS_CODEC_KEY` | Yes* | — | Hex-encoded 32-byte AES-256 key |
| `OJS_CODEC_KEY_ID` | No | `primary` | Key ID label for `OJS_CODEC_KEY` |
| `OJS_CODEC_KEYS` | Yes* | — | Comma-separated `id:hexkey` pairs for key rotation |
| `OJS_CODEC_PORT` | No | `8089` | HTTP listen port |

\* At least one of `OJS_CODEC_KEY` or `OJS_CODEC_KEYS` is required.

### Key Rotation

Supply multiple keys so old jobs encrypted with rotated keys remain decodable:

```bash
export OJS_CODEC_KEY=<current-key-hex>
export OJS_CODEC_KEY_ID=key-2026-03
export OJS_CODEC_KEYS="key-2026-02:<old-key-hex>"
```

New encryptions use the key from `OJS_CODEC_KEY`; decryptions look up the key by the `ojs_key_id` in the payload metadata.

## API

### POST /codec/encode

Encrypts each payload with the current key.

**Request:**
```json
{
  "payloads": [
    { "data": "eyJjYXJkIjoiNDExMTExMTExMTExMTExMSJ9" }
  ]
}
```

**Response:**
```json
{
  "payloads": [
    {
      "data": "base64-of-nonce-ciphertext-tag...",
      "metadata": {
        "ojs_codec": "aes-256-gcm",
        "ojs_key_id": "primary"
      }
    }
  ]
}
```

### POST /codec/decode

Decrypts each payload using the key ID from its metadata. Payloads without `ojs_codec` metadata pass through unchanged.

**Request:**
```json
{
  "payloads": [
    {
      "data": "base64-of-nonce-ciphertext-tag...",
      "metadata": {
        "ojs_codec": "aes-256-gcm",
        "ojs_key_id": "primary"
      }
    }
  ]
}
```

**Response:**
```json
{
  "payloads": [
    { "data": "eyJjYXJkIjoiNDExMTExMTExMTExMTExMSJ9" }
  ]
}
```

### GET /health

```json
{ "status": "ok" }
```

## Build

```bash
make build          # Build binary to bin/ojs-codec-server
make test           # Run tests with race detector
make lint           # go vet
make docker-build   # Build Docker image
```

## Docker

```bash
docker build -t ojs-codec-server .
docker run -p 8089:8089 \
  -e OJS_CODEC_KEY=$(openssl rand -hex 32) \
  ojs-codec-server
```

## Security Notes

- **HTTPS required in production.** Run behind a TLS-terminating reverse proxy or load balancer.
- **Authentication.** The spec requires authentication (JWT recommended). Add an auth middleware or API gateway in front of this service for production use.
- **Key storage.** Use a secret manager (Vault, AWS Secrets Manager, GCP Secret Manager) instead of environment variables in production.
- **No external dependencies.** Uses only Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/rand`).

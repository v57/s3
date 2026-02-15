# s3-server

A minimal, local S3-compatible server written in Bun. It stores objects on disk and supports:
- `GET` object
- `HEAD` object (size/metadata)
- `PUT` object
- `DELETE` object
- `ListObjectsV2`
- SigV4 auth (header and presigned URLs)

## Quick Start

```bash
bun i
bun server
```

By default the server listens on `http://localhost:9000` and stores data under your current directory.

## Configuration

Set these environment variables before starting the server:
- `PORT` (default `9000`)
- `S3_DATA_DIR` (default `.`)
- `S3_ACCESS_KEY_ID` (default `random generated`)
- `S3_SECRET_ACCESS_KEY` (default `random generated`)
- `S3_SESSION_TOKEN` (optional)
- `S3_MAX_BODY_BYTES` (default `unlimited`)
- `S3_MAX_TIME_SKEW_SECONDS` (default `unlimited`)

Example:
```bash
S3_ACCESS_KEY_ID=local-key \
S3_SECRET_ACCESS_KEY=local-secret \
S3_DATA_DIR=/tmp/s3-data \
PORT=8000 \
bun server
```

## Use in Bun

### You can start the server directly
```ts
import { S3Server } from "./S3Server";

await new S3Server({
  port: 9000,
  path: '~/storage',
  key: 'local-key',
  secret: 'local-secret',
}).start()
```

### Or use it inside your Bun.serve
```ts
import { S3Server } from "./S3Server";

const s3 = new S3Server({
  path: '~/storage',
  key: 'local-key',
  secret: 'local-secret',
})
Bun.serve({
  port: 9000,
  fetch(request: Request) {
    return s3.fetch(request)
  },
})

```

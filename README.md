# S3 Server

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
You can also pass a storage path positionally and flags such as `--port`, for example:

```bash
bun server ~/storage --port 9002
```

Run `bun server --help` to see the full CLI usage.

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

When using the library directly, `path` is an optional fallback root. You can also
provide explicit paths for individual buckets with `bucketPaths`; buckets without
an entry will be rejected when no fallback `path` is set. Paths starting with `~/`
are expanded against `Bun.env.HOME`.

## Use in Bun

### You can start the server directly
```ts
import { S3Server } from 's3'

await new S3Server({
  port: 9000,
  key: 'local-key',
  secret: 'local-secret',
  bucketPaths: {
    photos: '~/storage/photos',
    backups: '~/storage/backups',
  },
}).start()
```

### Or use it inside your Bun.serve
```ts
import { S3Server } from 's3'

const s3 = new S3Server({
  key: 'local-key',
  secret: 'local-secret',
  bucketPaths: {
    hub: '~/storage/hub',
  },
})
Bun.serve({
  port: 9000,
  fetch(request: Request) {
    return s3.fetch(request)
  },
})

```

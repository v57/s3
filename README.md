<h1>
  <img alt="Containerization logo" src="./icon.png" width="70" valign="middle">
  &nbsp;s3 server
</h1>
A minimal, local S3-compatible server written in Bun. It stores objects on disk and supports:
- `GET` object
- `HEAD` object (size/metadata)
- `PUT` object
- `DELETE` object
- `ListObjectsV2`
- SigV4 auth (header and presigned URLs)

## Role in Hub

`s3` is not a Hub service: it never connects to a hub and has no Hub API, permissions or approval. It is the S3
server [hub-s3-local](https://github.com/v57/hub-s3-local) runs inside its process to share a folder (`~/Hub/Files`
by default) as the bucket `hub`. hub-s3-local starts it with random keys and hands out presigned links to it, and the
Hub network sees only hub-s3-local's `s3/*` paths. [hub-s3](https://github.com/v57/hub-s3) doesn't use it: it fronts
an existing S3 provider. To use the server in another Bun project:

```bash
bun add v57/s3
```

The server binds `0.0.0.0` unless `host` (`--host`) says otherwise, and every request needs a SigV4 signature from
its key and secret. An upload's signature is checked before its body is read (a header-signed upload must send
`x-amz-content-sha256`, and its body is compared with that hash after), so an unsigned request can't make the server
buffer a body.

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

## Testing

```bash
bun i
bun test
```

`index.test.ts` starts a server on port 19997 over a temporary folder and drives it with Bun's `S3Client` (auth,
objects, deletes, listings with delimiters, bucket paths, `~/` expansion). `server.test.ts` covers the CLI's argument parsing.

## Swift server (`S3ServerSwift`)

An interchangeable, dependency-free Swift implementation lives in its own repository,
[S3ServerSwift](https://github.com/v57/S3ServerSwift) (macOS 13+, Swift 6). It uses only system frameworks
(Foundation, Network, CryptoKit, Security) and reproduces this server's S3 behavior: SigV4 header/presigned auth,
path-style and virtual-host bucket addressing, safe filesystem path handling, PUT/GET/HEAD/DELETE, ListObjectsV2, and
the same client-observable error XML.

## Verification

The shared TypeScript contract suite runs the same cases against both backends. `test:swift` builds the `Server`
executable of `../S3ServerSwift` (a checkout next to this one; `S3_SWIFT_SERVER_BIN` points at another build):

```bash
bun run test:bun        # Bun reference (index.test.ts, server.test.ts)
bun run test:swift      # build Server + contract suite + CLI process tests
bun run test:contracts  # both
```

## Intentional S3 non-goals

Multipart upload, ranged GET, versioning, ACLs, bucket create/delete, and TLS are
not implemented in either backend. The HTTP transport supports keep-alive for
sequential requests (as the Bun S3Client uses across PUT/GET), but does not
support HTTP pipelining of multiple in-flight requests on one connection.

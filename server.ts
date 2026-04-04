#!/usr/bin/env bun
import { randomBytes } from 'crypto'
import { parseArgs } from 'util'
import { S3Server } from '.'

function parseInteger(value: string | undefined, fallback: number) {
  const parsed = Number.parseInt(value ?? '', 10)
  return Number.isFinite(parsed) ? parsed : fallback
}

function parseBucketPaths(rawBucketPaths: string | string[] | undefined) {
  const entries = Array.isArray(rawBucketPaths) ? rawBucketPaths : rawBucketPaths ? [rawBucketPaths] : []
  const bucketPaths: Record<string, string> = {}
  for (const entry of entries) {
    const separatorIndex = entry.indexOf('=')
    if (separatorIndex <= 0 || separatorIndex === entry.length - 1) {
      throw new Error(`invalid bucket path "${entry}". Use bucket=/some/path`)
    }
    const bucket = entry.slice(0, separatorIndex)
    const bucketPath = entry.slice(separatorIndex + 1)
    bucketPaths[bucket] = bucketPath
  }
  return bucketPaths
}

export function buildServerHelpText() {
  return `Usage:
  bun server [path] [options]

Options:
  --help, -h                  Show this help message
  --host <host>               Bind host (default 0.0.0.0)
  --port <port>               Bind port (default 9000)
  --path <path>               Default storage root
  --key <key>                 Access key ID
  --secret <secret>           Secret access key
  --session-token <token>     Session token
  --max-body-bytes <bytes>    Maximum upload size
  --max-time-skew-seconds <s> Maximum allowed time skew
  --bucket-path <bucket=path> Bucket-specific storage path; repeatable

Examples:
  bun server ~/storage --port 9002
  bun server --path ~/storage --bucket-path photos=~/photos
`
}

export type ParsedServerArgs =
  | {
      help: true
      usage: string
    }
  | {
      help: false
      options: {
        host?: string
        port: number
        path: string
        bucketPaths: Record<string, string>
        key: string
        secret: string
        sessionToken: string | null
        maxSize: number
        maxTimeSkewSeconds: number
      }
    }

export function parseServerOptions(argv = process.argv.slice(2)): ParsedServerArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      help: { type: 'boolean', short: 'h' },
      host: { type: 'string' },
      port: { type: 'string' },
      path: { type: 'string' },
      key: { type: 'string' },
      secret: { type: 'string' },
      'session-token': { type: 'string' },
      'max-body-bytes': { type: 'string' },
      'max-time-skew-seconds': { type: 'string' },
      'bucket-path': { type: 'string', multiple: true },
    },
  })

  if (values.help) {
    return { help: true, usage: buildServerHelpText() }
  }

  const explicitPath = typeof values.path === 'string' ? values.path : positionals[0]
  return {
    help: false,
    options: {
      host: typeof values.host === 'string' ? values.host : undefined,
      port: parseInteger(typeof values.port === 'string' ? values.port : Bun.env.PORT, 9000),
      path: explicitPath ?? Bun.env.S3_DATA_DIR ?? '.',
      bucketPaths: parseBucketPaths(values['bucket-path']),
      key: typeof values.key === 'string' ? values.key : Bun.env.S3_ACCESS_KEY_ID ?? Bun.env.AWS_ACCESS_KEY_ID ?? randomBytes(16).toString('hex'),
      secret: typeof values.secret === 'string' ? values.secret : Bun.env.S3_SECRET_ACCESS_KEY ?? Bun.env.AWS_SECRET_ACCESS_KEY ?? randomBytes(16).toString('hex'),
      sessionToken:
        typeof values['session-token'] === 'string' ? values['session-token'] : Bun.env.S3_SESSION_TOKEN ?? Bun.env.AWS_SESSION_TOKEN ?? null,
      maxSize: parseInteger(
        typeof values['max-body-bytes'] === 'string' ? values['max-body-bytes'] : Bun.env.S3_MAX_BODY_BYTES,
        0,
      ),
      maxTimeSkewSeconds: parseInteger(
        typeof values['max-time-skew-seconds'] === 'string' ? values['max-time-skew-seconds'] : Bun.env.S3_MAX_TIME_SKEW_SECONDS,
        0,
      ),
    },
  }
}

if (import.meta.main) {
  const cli = parseServerOptions()
  if (cli.help) {
    console.log(cli.usage)
    process.exit(0)
  }
  await new S3Server(cli.options).start(true)
}

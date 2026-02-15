import { randomBytes } from 'crypto'
import { S3Server } from '.'

const config = {
  port: Number.parseInt(process.env.PORT ?? '', 10) || 9000,
  path: process.argv[2] ?? process.env.S3_DATA_DIR ?? '.',
  key: process.env.S3_ACCESS_KEY_ID ?? process.env.AWS_ACCESS_KEY_ID ?? randomBytes(16).toString('hex'),
  secret: process.env.S3_SECRET_ACCESS_KEY ?? process.env.AWS_SECRET_ACCESS_KEY ?? randomBytes(16).toString('hex'),
  sessionToken: process.env.S3_SESSION_TOKEN ?? process.env.AWS_SESSION_TOKEN ?? null,
  maxBodyBytes: Number.parseInt(process.env.S3_MAX_BODY_BYTES ?? '0', 10) || 0,
  maxTimeSkewSeconds: Number.parseInt(process.env.S3_MAX_TIME_SKEW_SECONDS ?? '0', 10) || 0,
}
await new S3Server(config).start(true)

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

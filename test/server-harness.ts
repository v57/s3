import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'

export type ServerBackend = 'bun' | 'swift'

export type TestServerOptions = {
  backend?: ServerBackend
  host?: string
  port?: number
  path?: string | null
  bucketPaths?: Record<string, string>
  key?: string
  secret?: string
  sessionToken?: string
  maxBodyBytes?: number
  maxTimeSkewSeconds?: number
  environment?: Record<string, string>
}

export type TestServer = {
  backend: ServerBackend
  baseUrl: string
  key: string
  secret: string
  port: number
  storageDirectory: string
  stop(): Promise<void>
}

const DEFAULT_KEY = 'testkey'
const DEFAULT_SECRET = 'testsecret'

export async function reservePort(host = '127.0.0.1') {
  const reservation = Bun.listen({
    hostname: host,
    port: 0,
    socket: {
      data() {},
    },
  })
  const port = reservation.port
  reservation.stop(true)
  return port
}

export async function startTestServer(options: TestServerOptions = {}): Promise<TestServer> {
  const backend = options.backend ?? parseBackend(Bun.env.S3_TEST_SERVER)
  const host = options.host ?? '127.0.0.1'
  const port = options.port ?? (await reservePort(host))
  const storageDirectory = await mkdtemp(path.join(tmpdir(), `s3-${backend}-contract-`))
  const root = options.path === undefined ? storageDirectory : options.path
  const key = options.key ?? DEFAULT_KEY
  const secret = options.secret ?? DEFAULT_SECRET
  const args = [
    '--host',
    host,
    '--port',
    String(port),
    '--key',
    key,
    '--secret',
    secret,
  ]
  if (root !== null) args.push('--path', root)
  if (options.sessionToken !== undefined) args.push('--session-token', options.sessionToken)
  if (options.maxBodyBytes !== undefined) args.push('--max-body-bytes', String(options.maxBodyBytes))
  if (options.maxTimeSkewSeconds !== undefined) {
    args.push('--max-time-skew-seconds', String(options.maxTimeSkewSeconds))
  }
  for (const [bucket, bucketPath] of Object.entries(options.bucketPaths ?? {})) {
    args.push('--bucket-path', `${bucket}=${bucketPath}`)
  }

  const command =
    backend === 'bun'
      ? [process.execPath, path.join(import.meta.dir, '..', 'server.ts'), ...args]
      : [resolveSwiftServerBinary(), ...args]
  const child = Bun.spawn(command, {
    cwd: path.join(import.meta.dir, '..'),
    env: {
      ...process.env,
      ...(root === null ? { S3_DATA_DIR: '' } : {}),
      ...options.environment,
    },
    stdout: 'pipe',
    stderr: 'pipe',
  })
  const stdout = new Response(child.stdout).text()
  const stderr = new Response(child.stderr).text()

  try {
    await waitUntilReady(`http://${host}:${port}`, child, 5_000)
  } catch (error) {
    child.kill()
    await child.exited
    const output = `${await stdout}\n${await stderr}`.trim()
    await rm(storageDirectory, { recursive: true, force: true })
    throw new Error(`${String(error)}\ncommand: ${command.join(' ')}\n${output}`)
  }

  let stopped = false
  return {
    backend,
    baseUrl: `http://${host}:${port}`,
    key,
    secret,
    port,
    storageDirectory,
    async stop() {
      if (stopped) return
      stopped = true
      child.kill('SIGTERM')
      await child.exited
      await rm(storageDirectory, { recursive: true, force: true })
    },
  }
}

function parseBackend(value: string | undefined): ServerBackend {
  if (value === undefined || value === '' || value === 'bun') return 'bun'
  if (value === 'swift') return 'swift'
  throw new Error(`Unsupported S3_TEST_SERVER "${value}"; expected bun or swift`)
}

function resolveSwiftServerBinary() {
  const configured = Bun.env.S3_SWIFT_SERVER_BIN
  if (configured) return path.resolve(configured)
  return path.join(import.meta.dir, '..', '..', 'S3ServerSwift', '.build', 'release', 'Server')
}

async function waitUntilReady(baseUrl: string, child: Bun.Subprocess, timeoutMilliseconds: number) {
  const deadline = Date.now() + timeoutMilliseconds
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited with status ${child.exitCode}`)
    try {
      const response = await fetch(baseUrl, { signal: AbortSignal.timeout(250) })
      if (response.status > 0) return
    } catch {}
    await Bun.sleep(20)
  }
  throw new Error(`server did not become ready within ${timeoutMilliseconds}ms`)
}

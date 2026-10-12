import { describe, test, expect, beforeAll } from 'bun:test'
import { mkdtemp, rm, readdir } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'

const SERVER_BIN = process.env.S3_SWIFT_SERVER_BIN
  ? path.resolve(process.env.S3_SWIFT_SERVER_BIN)
  : path.join(import.meta.dir, '..', 'S3ServerSwift', '.build', 'release', 'Server')

let binExists = false

beforeAll(async () => {
  binExists = await Bun.file(SERVER_BIN).exists()
})

describe('Server executable', () => {
  test('help exits zero and prints usage without binding', async () => {
    if (!binExists) return
    const proc = Bun.spawn([SERVER_BIN, '--help'], { stdout: 'pipe', stderr: 'pipe' })
    const [stdout, exitCode] = await Promise.all([new Response(proc.stdout).text(), proc.exited])
    expect(exitCode).toBe(0)
    expect(stdout).toContain('Usage:')
    expect(stdout).toContain('--bucket-path')
  })

  test('short help exits zero', async () => {
    if (!binExists) return
    const proc = Bun.spawn([SERVER_BIN, '-h'], { stdout: 'pipe', stderr: 'pipe' })
    const [stdout, exitCode] = await Promise.all([new Response(proc.stdout).text(), proc.exited])
    expect(exitCode).toBe(0)
    expect(stdout).toContain('Usage:')
  })

  test('unknown option fails with nonzero exit and diagnostic', async () => {
    if (!binExists) return
    const proc = Bun.spawn([SERVER_BIN, '--nope'], { stdout: 'pipe', stderr: 'pipe' })
    const [stderr, exitCode] = await Promise.all([new Response(proc.stderr).text(), proc.exited])
    expect(exitCode).not.toBe(0)
    expect(stderr).toContain('Unknown option')
  })

  test('missing flag value fails with nonzero exit', async () => {
    if (!binExists) return
    const proc = Bun.spawn([SERVER_BIN, '--port'], { stdout: 'pipe', stderr: 'pipe' })
    const [stderr, exitCode] = await Promise.all([new Response(proc.stderr).text(), proc.exited])
    expect(exitCode).not.toBe(0)
    expect(stderr).toContain('argument missing')
  })

  test('malformed bucket path fails with nonzero exit', async () => {
    if (!binExists) return
    const proc = Bun.spawn([SERVER_BIN, '--bucket-path', 'no-equals'], { stdout: 'pipe', stderr: 'pipe' })
    const [stderr, exitCode] = await Promise.all([new Response(proc.stderr).text(), proc.exited])
    expect(exitCode).not.toBe(0)
    expect(stderr).toContain('invalid bucket path')
  })

  test('startup logs credentials, directory, and listening URL', async () => {
    if (!binExists) return
    const storageDir = await mkdtemp(path.join(tmpdir(), 's3-cli-log-'))
    const port = 19555
    const child = Bun.spawn(
      [
        SERVER_BIN,
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
        '--key',
        'cli-key',
        '--secret',
        'cli-secret',
        '--path',
        storageDir,
      ],
      { stdout: 'pipe', stderr: 'pipe' },
    )
    const outputPromise = new Response(child.stdout).text()
    try {
      // Wait for the listener to come up, then terminate; the process flushes
      // its startup log on bind and exits cleanly on SIGTERM.
      await waitForPort(`http://127.0.0.1:${port}`)
      child.kill('SIGTERM')
      const exitCode = await child.exited
      expect(exitCode).toBe(0)
      const output = await outputPromise
      expect(output).toContain('Access Key: cli-key')
      expect(output).toContain('Secret Key: cli-secret')
      expect(output).toContain(`Directory: ${storageDir}`)
      expect(output).toContain(`http://127.0.0.1:${port}`)
    } finally {
      child.kill()
      await rm(storageDir, { recursive: true, force: true })
    }
  })

  test('SIGTERM stops the server cleanly', async () => {
    if (!binExists) return
    const storageDir = await mkdtemp(path.join(tmpdir(), 's3-cli-sig-'))
    const child = Bun.spawn(
      [SERVER_BIN, '--host', '127.0.0.1', '--port', '19556', '--key', 'k', '--secret', 's', '--path', storageDir],
      { stdout: 'pipe', stderr: 'pipe' },
    )
    try {
      await waitForPort('http://127.0.0.1:19556')
      child.kill('SIGTERM')
      const exitCode = await child.exited
      expect(exitCode).toBe(0)
    } finally {
      child.kill()
      await rm(storageDir, { recursive: true, force: true })
    }
  })

  test('root directory is created on startup', async () => {
    if (!binExists) return
    const parent = await mkdtemp(path.join(tmpdir(), 's3-cli-root-'))
    const root = path.join(parent, 'nested', 'root')
    const port = 19557
    const child = Bun.spawn(
      [SERVER_BIN, '--host', '127.0.0.1', '--port', String(port), '--key', 'k', '--secret', 's', '--path', root],
      { stdout: 'pipe', stderr: 'pipe' },
    )
    try {
      await waitForPort(`http://127.0.0.1:${port}`)
      expect(await Bun.file(path.join(root, '.keep')).exists()).toBe(false)
      expect((await readdir(parent)).length).toBeGreaterThan(0)
    } finally {
      child.kill('SIGTERM')
      await child.exited
      await rm(parent, { recursive: true, force: true })
    }
  })
})

async function waitForPort(url: string) {
  const deadline = Date.now() + 5000
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(250) })
      if (res.status > 0) return
    } catch {}
    await Bun.sleep(20)
  }
  throw new Error(`server did not become ready at ${url}`)
}

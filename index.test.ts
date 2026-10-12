import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { S3Server } from '.'
import { S3Client } from 'bun'
import type { Server } from 'bun'
import { lstat, mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'

const KEY = 'testkey'
const SECRET = 'testsecret'
const PORT = 19997
const BUCKET = 'testbucket'
const BASE_URL = `http://localhost:${PORT}`

let client: S3Client
let tmpDir: string
let server: Server<unknown>

beforeAll(async () => {
  tmpDir = await mkdtemp(path.join(tmpdir(), 's3-test-'))
  server = await new S3Server({ key: KEY, secret: SECRET, port: PORT, path: tmpDir }).start()
  client = new S3Client({
    accessKeyId: KEY,
    secretAccessKey: SECRET,
    bucket: BUCKET,
    endpoint: BASE_URL,
  })
})

afterAll(async () => {
  server.stop()
  await rm(tmpDir, { recursive: true, force: true })
})

describe('auth', () => {
  test('rejects unauthenticated request', async () => {
    const res = await fetch(`${BASE_URL}/${BUCKET}/test.txt`)
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('AccessDenied')
  })

  test('rejects wrong credentials', async () => {
    const bad = new S3Client({
      accessKeyId: 'wrong',
      secretAccessKey: 'wrong',
      bucket: BUCKET,
      endpoint: BASE_URL,
    })
    await expect(bad.list()).rejects.toThrow()
  })
})

describe('PUT / GET', () => {
  test('custom multi-label authority remains path-style', () => {
    const parsed = (new S3Server({ key: KEY, secret: SECRET }) as any).parseBucketAndKey(
      new URL('http://s3-owner.v1-network.hub.invalid/hub/folder/object.txt'),
    )
    expect(parsed).toEqual({ bucket: 'hub', key: 'folder/object.txt' })
  })

  test('roundtrip text object', async () => {
    await Bun.write(client.file('hello.txt'), 'hello world')
    expect(await client.file('hello.txt').text()).toBe('hello world')
  })

  test('roundtrip binary object', async () => {
    const data = new Uint8Array([10, 20, 30])
    await Bun.write(client.file('bytes.bin'), data)
    expect(new Uint8Array(await client.file('bytes.bin').arrayBuffer())).toEqual(data)
  })

  test('overwrite replaces content', async () => {
    await Bun.write(client.file('overwrite.txt'), 'first')
    await Bun.write(client.file('overwrite.txt'), 'second')
    expect(await client.file('overwrite.txt').text()).toBe('second')
  })

  test('GET missing object throws', async () => {
    await expect(client.file('nonexistent-xyz.txt').text()).rejects.toThrow()
  })
})

describe('DELETE', () => {
  test('deletes existing object', async () => {
    await Bun.write(client.file('to-delete.txt'), 'gone')
    await client.delete('to-delete.txt')
    await expect(client.file('to-delete.txt').text()).rejects.toThrow()
  })

  test('error on missing object', async () => {
    await expect(client.delete('no-such-key-xyz.txt')).rejects.toThrow()
  })
})

describe('LIST', () => {
  test('empty bucket has keyCount 0', async () => {
    const emptyClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: 'emptybucket',
      endpoint: BASE_URL,
    })
    const result = await emptyClient.list()
    expect(result.keyCount).toBe(0)
    expect(result.isTruncated).toBe(false)
  })

  test('lists uploaded objects', async () => {
    await Bun.write(client.file('ls/a.txt'), 'a')
    await Bun.write(client.file('ls/b.txt'), 'b')
    const result = await client.list({ prefix: 'ls/' })
    expect(result.keyCount).toBeGreaterThanOrEqual(2)
  })

  test('prefix filters results', async () => {
    await Bun.write(client.file('pfx/one.txt'), '1')
    await Bun.write(client.file('other/two.txt'), '2')
    const result = await client.list({ prefix: 'pfx/' })
    expect(result.contents?.every(c => c.key.startsWith('pfx/'))).toBe(true)
  })

  test('max-keys limits and truncates', async () => {
    for (let i = 0; i < 5; i++) {
      await Bun.write(client.file(`maxkeys/f${i}.txt`), `${i}`)
    }
    const result = await client.list({ prefix: 'maxkeys/', maxKeys: 2 })
    expect(result.contents?.length).toBeLessThanOrEqual(2)
    expect(result.isTruncated).toBe(true)
  })
})

describe('LIST delimiter', () => {
  // Structure under 'delim/' prefix:
  //   root.txt
  //   dir1/
  //     file1.txt
  //     subdir/
  //       file2.txt
  //   dir2/
  //     file3.txt
  beforeEach(async () => {
    await Bun.write(client.file('delim/root.txt'), 'root')
    await Bun.write(client.file('delim/dir1/file1.txt'), 'file1')
    await Bun.write(client.file('delim/dir1/subdir/file2.txt'), 'file2')
    await Bun.write(client.file('delim/dir2/file3.txt'), 'file3')
  })

  test('groups top-level dirs into commonPrefixes', async () => {
    const result = await client.list({ prefix: 'delim/', delimiter: '/' })
    expect(result.contents?.map(c => c.key)).toEqual(['delim/root.txt'])
    expect(result.commonPrefixes?.map(p => p.prefix)).toEqual(['delim/dir1/', 'delim/dir2/'])
  })

  test('keyCount includes contents and commonPrefixes', async () => {
    const result = await client.list({ prefix: 'delim/', delimiter: '/' })
    expect(result.keyCount).toBe((result.contents?.length ?? 0) + (result.commonPrefixes?.length ?? 0))
  })

  test('delimiter with deeper prefix', async () => {
    const result = await client.list({ prefix: 'delim/dir1/', delimiter: '/' })
    expect(result.contents?.map(c => c.key)).toEqual(['delim/dir1/file1.txt'])
    expect(result.commonPrefixes?.map(p => p.prefix)).toEqual(['delim/dir1/subdir/'])
  })

  test('no delimiter returns all files flat', async () => {
    const result = await client.list({ prefix: 'delim/' })
    expect(result.keyCount).toBeGreaterThanOrEqual(4)
    expect(result.commonPrefixes).toBeUndefined()
  })

  test('delimiter at root with no prefix', async () => {
    const result = await client.list({ delimiter: '/' })
    // All keys are under directories, so no root-level files in testbucket
    expect(result.commonPrefixes?.some(p => p.prefix === 'delim/')).toBe(true)
    expect(result.contents?.some(c => c.key.includes('/'))).toBe(false)
  })
})

describe('bucket paths', () => {
  const SECONDARY_PORT = 19998
  const ALPHA_BUCKET = 'alpha'
  const BETA_BUCKET = 'beta'
  const MISSING_BUCKET = 'gamma'
  const SECONDARY_BASE_URL = `http://localhost:${SECONDARY_PORT}`

  let secondaryServer: Server<unknown>
  let secondaryTmpDir: string
  let alphaClient: S3Client
  let betaClient: S3Client
  let missingClient: S3Client

  beforeAll(async () => {
    secondaryTmpDir = await mkdtemp(path.join(tmpdir(), 's3-bucket-paths-'))
    secondaryServer = await new S3Server({
      key: KEY,
      secret: SECRET,
      port: SECONDARY_PORT,
      bucketPaths: {
        [ALPHA_BUCKET]: path.join(secondaryTmpDir, ALPHA_BUCKET),
        [BETA_BUCKET]: path.join(secondaryTmpDir, BETA_BUCKET),
      },
    }).start()
    alphaClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: ALPHA_BUCKET,
      endpoint: SECONDARY_BASE_URL,
    })
    betaClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: BETA_BUCKET,
      endpoint: SECONDARY_BASE_URL,
    })
    missingClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: MISSING_BUCKET,
      endpoint: SECONDARY_BASE_URL,
    })
  })

  afterAll(async () => {
    secondaryServer.stop()
    await rm(secondaryTmpDir, { recursive: true, force: true })
  })

  test('uses only explicitly configured bucket paths when no default path is set', async () => {
    await Bun.write(alphaClient.file('nested/alpha.txt'), 'alpha')
    await Bun.write(betaClient.file('nested/beta.txt'), 'beta')

    expect(await alphaClient.file('nested/alpha.txt').text()).toBe('alpha')
    expect(await betaClient.file('nested/beta.txt').text()).toBe('beta')

    const alphaListing = await alphaClient.list({ prefix: 'nested/' })
    const betaListing = await betaClient.list({ prefix: 'nested/' })

    expect(alphaListing.contents?.map(item => item.key)).toEqual(['nested/alpha.txt'])
    expect(betaListing.contents?.map(item => item.key)).toEqual(['nested/beta.txt'])
  })

  test('rejects buckets without a configured path', async () => {
    await expect(missingClient.list()).rejects.toThrow(/NoSuchBucket|Bucket not configured/)
  })
})

describe('home path expansion', () => {
  const HOME_PORT = 19999
  const HOME_BUCKET = 'home-bucket'
  const HOME_BASE_URL = `http://localhost:${HOME_PORT}`

  let originalHome: string | undefined
  let homeDir: string
  let homeServer: Server<unknown>
  let homeClient: S3Client

  beforeAll(async () => {
    originalHome = Bun.env.HOME
    homeDir = await mkdtemp(path.join(tmpdir(), 's3-home-'))
    Bun.env.HOME = homeDir

    homeServer = await new S3Server({
      key: KEY,
      secret: SECRET,
      port: HOME_PORT,
      path: '~/fallback',
      bucketPaths: {
        [HOME_BUCKET]: '~/bucket-data',
      },
    }).start()
    homeClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: HOME_BUCKET,
      endpoint: HOME_BASE_URL,
    })
  })

  afterAll(async () => {
    homeServer.stop()
    if (originalHome === undefined) {
      delete Bun.env.HOME
    } else {
      Bun.env.HOME = originalHome
    }
    await rm(homeDir, { recursive: true, force: true })
  })

  test('expands tilde-prefixed configured paths against Bun.env.HOME', async () => {
    expect((await lstat(path.join(homeDir, 'fallback'))).isDirectory()).toBe(true)
    expect((await lstat(path.join(homeDir, 'bucket-data'))).isDirectory()).toBe(true)

    await Bun.write(homeClient.file('nested/file.txt'), 'hello home')
    expect(await homeClient.file('nested/file.txt').text()).toBe('hello home')
  })
})

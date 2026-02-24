import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { S3Server } from '.'
import { S3Client } from 'bun'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'

const KEY = 'testkey'
const SECRET = 'testsecret'
const PORT = 19997
const BUCKET = 'testbucket'
const BASE_URL = `http://localhost:${PORT}`

let client: S3Client
let tmpDir: string

beforeAll(async () => {
  tmpDir = await mkdtemp(path.join(tmpdir(), 's3-test-'))
  const server = new S3Server({ key: KEY, secret: SECRET, port: PORT, path: tmpDir })
  await server.start()
  client = new S3Client({
    accessKeyId: KEY,
    secretAccessKey: SECRET,
    bucket: BUCKET,
    endpoint: BASE_URL,
  })
})

afterAll(async () => {
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

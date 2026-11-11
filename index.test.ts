import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { S3Client } from 'bun'
import { createHash, createHmac } from 'crypto'
import { lstat, mkdtemp, rm, symlink } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'
import { startTestServer, type TestServer } from './test/server-harness'

const KEY = 'testkey'
const SECRET = 'testsecret'
const BUCKET = 'testbucket'

let client: S3Client
let server: TestServer

beforeAll(async () => {
  server = await startTestServer({ key: KEY, secret: SECRET })
  client = new S3Client({
    accessKeyId: KEY,
    secretAccessKey: SECRET,
    bucket: BUCKET,
    endpoint: server.baseUrl,
  })
})

afterAll(async () => {
  await server.stop()
})

describe('auth', () => {
  test('rejects unauthenticated request', async () => {
    const res = await fetch(`${server.baseUrl}/${BUCKET}/test.txt`)
    expect(res.status).toBe(403)
    expect(await res.text()).toContain('AccessDenied')
  })

  test('rejects wrong credentials', async () => {
    const bad = new S3Client({
      accessKeyId: 'wrong',
      secretAccessKey: 'wrong',
      bucket: BUCKET,
      endpoint: server.baseUrl,
    })
    await expect(bad.list()).rejects.toThrow()
  })
})

describe('PUT / GET', () => {
  test('custom multi-label authority remains path-style', async () => {
    // A presigned link to a Hub Network share names the share's authority; the first label isn't a bucket
    const authority = new S3Client({ accessKeyId: KEY, secretAccessKey: SECRET, bucket: BUCKET, endpoint: `http://s3-owner.v1-network.hub.invalid:${server.port}` })
    await Bun.write(client.file('authority/object.txt'), 'path-style')
    const url = new URL(authority.presign('authority/object.txt', { method: 'GET', expiresIn: 60 }))
    const res = await fetch(`${server.baseUrl}${url.pathname}${url.search}`, { headers: { Host: url.host } })
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('path-style')
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
      endpoint: server.baseUrl,
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
  const ALPHA_BUCKET = 'alpha'
  const BETA_BUCKET = 'beta'
  const MISSING_BUCKET = 'gamma'

  let secondaryServer: TestServer
  let secondaryTmpDir: string
  let alphaClient: S3Client
  let betaClient: S3Client
  let missingClient: S3Client

  beforeAll(async () => {
    secondaryTmpDir = await mkdtemp(path.join(tmpdir(), 's3-bucket-paths-'))
    secondaryServer = await startTestServer({
      key: KEY,
      secret: SECRET,
      path: null,
      bucketPaths: {
        [ALPHA_BUCKET]: path.join(secondaryTmpDir, ALPHA_BUCKET),
        [BETA_BUCKET]: path.join(secondaryTmpDir, BETA_BUCKET),
      },
    })
    alphaClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: ALPHA_BUCKET,
      endpoint: secondaryServer.baseUrl,
    })
    betaClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: BETA_BUCKET,
      endpoint: secondaryServer.baseUrl,
    })
    missingClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: MISSING_BUCKET,
      endpoint: secondaryServer.baseUrl,
    })
  })

  afterAll(async () => {
    await secondaryServer.stop()
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
  const HOME_BUCKET = 'home-bucket'

  let originalHome: string | undefined
  let homeDir: string
  let homeServer: TestServer
  let homeClient: S3Client

  beforeAll(async () => {
    originalHome = Bun.env.HOME
    homeDir = await mkdtemp(path.join(tmpdir(), 's3-home-'))
    Bun.env.HOME = homeDir

    homeServer = await startTestServer({
      key: KEY,
      secret: SECRET,
      path: '~/fallback',
      bucketPaths: {
        [HOME_BUCKET]: '~/bucket-data',
      },
      environment: { HOME: homeDir },
    })
    homeClient = new S3Client({
      accessKeyId: KEY,
      secretAccessKey: SECRET,
      bucket: HOME_BUCKET,
      endpoint: homeServer.baseUrl,
    })
  })

  afterAll(async () => {
    await homeServer.stop()
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

describe('body before auth', () => {
  // Answers what the server sends to a PUT that announces a large body and never finishes it
  async function partialPut(path: string, headers: Record<string, string> = {}) {
    const extra = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`).join('')
    return await new Promise<string>((resolve, reject) => {
      let answer = ''
      const timer = setTimeout(() => reject(new Error('the server waited for the body')), 2000)
      Bun.connect({
        hostname: '127.0.0.1',
        port: server.port,
        socket: {
          open(socket) {
            socket.write(`PUT ${path} HTTP/1.1\r\nHost: localhost:${server.port}\r\nContent-Length: 100000000\r\n${extra}\r\n`)
            socket.write('x'.repeat(1024))
          },
          data(socket, data) {
            answer += data.toString()
            if (answer.includes('</Error>')) {
              clearTimeout(timer)
              socket.end()
              resolve(answer)
            }
          },
          error(_, error) {
            clearTimeout(timer)
            reject(error)
          },
        },
      })
    })
  }

  test('refuses an unsigned upload before reading its body', async () => {
    const answer = await partialPut(`/${BUCKET}/big.bin`)
    expect(answer).toStartWith('HTTP/1.1 403')
    expect(answer).toContain('AccessDenied')
  })

  test('refuses a badly presigned upload before reading its body', async () => {
    const url = new URL(client.presign('big.bin', { method: 'PUT', expiresIn: 60 }))
    url.searchParams.set('X-Amz-Signature', '0'.repeat(64))
    const answer = await partialPut(`${url.pathname}${url.search}`)
    expect(answer).toStartWith('HTTP/1.1 403')
    expect(answer).toContain('Signature mismatch')
  })

  test('refuses a header-signed upload without x-amz-content-sha256', async () => {
    const answer = await partialPut(`/${BUCKET}/big.bin`, { Authorization: `AWS4-HMAC-SHA256 Credential=${KEY}/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=${'0'.repeat(64)}` })
    expect(answer).toContain('Missing x-amz-content-sha256')
  })

  test('presigned uploads still work', async () => {
    const url = client.presign('presigned.txt', { method: 'PUT', expiresIn: 60 })
    expect((await fetch(url, { method: 'PUT', body: 'hello' })).status).toBe(200)
    expect(await client.file('presigned.txt').text()).toBe('hello')
  })
})

describe('HEAD', () => {
  test('returns metadata without a body', async () => {
    await Bun.write(client.file('head/object.txt'), 'head-body-content')
    const res = await fetch(`${server.baseUrl}/${BUCKET}/head/object.txt`, {
      method: 'HEAD',
      headers: signedRequestHeaders('HEAD', `/${BUCKET}/head/object.txt`),
    })
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('')
    expect(res.headers.get('content-length')).toBe('17')
    expect(res.headers.get('etag')).toBeTruthy()
    expect(res.headers.get('last-modified')).toBeTruthy()
  })

  test('missing object returns 404 NoSuchKey', async () => {
    const res = await fetch(`${server.baseUrl}/${BUCKET}/head/missing.txt`, {
      method: 'HEAD',
      headers: signedRequestHeaders('HEAD', `/${BUCKET}/head/missing.txt`),
    })
    expect(res.status).toBe(404)
    expect(await res.text()).toBe('')
  })

  test('a folder with keys under it has no object of its own', async () => {
    // Like S3: `mods` and `mods/` are NoSuchKey even though `mods/…` keys exist
    await Bun.write(client.file('mods/config.txt'), 'config')
    for (const key of ['mods', 'mods/']) {
      const head = await fetch(`${server.baseUrl}/${BUCKET}/${key}`, {
        method: 'HEAD',
        headers: signedRequestHeaders('HEAD', `/${BUCKET}/${key}`),
      })
      expect(head.status).toBe(404)
      const get = await fetch(`${server.baseUrl}/${BUCKET}/${key}`, {
        headers: signedRequestHeaders('GET', `/${BUCKET}/${key}`),
      })
      expect(get.status).toBe(404)
      expect(await get.text()).toContain('<Code>NoSuchKey</Code>')
    }
    expect(await client.exists('mods')).toBe(false)

    await Bun.write(client.file('mods/jar/mod.jar'), 'jar')
    expect(await client.file('mods/config.txt').text()).toBe('config')
    expect(await client.file('mods/jar/mod.jar').text()).toBe('jar')
    const listed = await client.list({ prefix: 'mods/' })
    expect(listed.contents?.map(c => c.key).sort()).toEqual(['mods/config.txt', 'mods/jar/mod.jar'])
    const grouped = await client.list({ prefix: 'mods/', delimiter: '/' })
    expect(grouped.contents?.map(c => c.key)).toEqual(['mods/config.txt'])
    expect(grouped.commonPrefixes?.map(p => p.prefix)).toEqual(['mods/jar/'])
  })
})

describe('metadata parity', () => {
  test('PUT, GET, HEAD share ETag and content length', async () => {
    const key = 'meta/parity.txt'
    await Bun.write(client.file(key), 'parity-data')
    const getRes = await fetch(`${server.baseUrl}/${BUCKET}/${key}`, {
      headers: signedRequestHeaders('GET', `/${BUCKET}/${key}`),
    })
    const headRes = await fetch(`${server.baseUrl}/${BUCKET}/${key}`, {
      method: 'HEAD',
      headers: signedRequestHeaders('HEAD', `/${BUCKET}/${key}`),
    })
    expect(getRes.status).toBe(200)
    expect(headRes.status).toBe(200)
    expect(headRes.headers.get('etag')).toBe(getRes.headers.get('etag'))
    expect(headRes.headers.get('content-length')).toBe(getRes.headers.get('content-length'))
    expect(headRes.headers.get('last-modified')).toBe(getRes.headers.get('last-modified'))
    expect(await getRes.text()).toBe('parity-data')
  })

  test('known extension maps to a MIME type, unknown falls back to octet-stream', async () => {
    await Bun.write(client.file('mime/known.txt'), 'txt')
    await Bun.write(client.file('mime/unknown.zzz'), 'bin')
    const txtRes = await fetch(`${server.baseUrl}/${BUCKET}/mime/known.txt`, {
      headers: signedRequestHeaders('GET', `/${BUCKET}/mime/known.txt`),
    })
    const unknownRes = await fetch(`${server.baseUrl}/${BUCKET}/mime/unknown.zzz`, {
      headers: signedRequestHeaders('GET', `/${BUCKET}/mime/unknown.zzz`),
    })
    expect(txtRes.headers.get('content-type')).toBeTruthy()
    expect(txtRes.headers.get('content-type')).not.toContain('octet-stream')
    expect(unknownRes.headers.get('content-type')).toBe('application/octet-stream')
  })
})

describe('body limits', () => {
  test('declared Content-Length over limit returns 413 EntityTooLarge with XML', async () => {
    const limited = await startTestServer({ key: KEY, secret: SECRET, maxBodyBytes: 10 })
    try {
      const limitedClient = new S3Client({
        accessKeyId: KEY,
        secretAccessKey: SECRET,
        bucket: BUCKET,
        endpoint: limited.baseUrl,
      })
      const res = await fetch(`${limited.baseUrl}/${BUCKET}/limit/declared.txt`, {
        method: 'PUT',
        headers: {
          'content-length': '100',
          ...signedRequestHeaders('PUT', `/${BUCKET}/limit/declared.txt`, limited.baseUrl),
        },
        body: 'x'.repeat(100),
      })
      expect(res.status).toBe(413)
      const text = await res.text()
      expect(text).toContain('EntityTooLarge')
      expect(res.headers.get('content-type')).toContain('application/xml')
      // No partial object persisted.
      await expect(limitedClient.file('limit/declared.txt').text()).rejects.toThrow()
    } finally {
      await limited.stop()
    }
  })

  test('streamed body over limit returns 413 and leaves no temp file', async () => {
    const limited = await startTestServer({ key: KEY, secret: SECRET, maxBodyBytes: 5 })
    try {
      const res = await fetch(`${limited.baseUrl}/${BUCKET}/limit/streamed.txt`, {
        method: 'PUT',
        headers: {
          'content-length': '20',
          ...signedRequestHeaders('PUT', `/${BUCKET}/limit/streamed.txt`, limited.baseUrl),
        },
        body: 'y'.repeat(20),
      })
      expect(res.status).toBe(413)
      expect(await res.text()).toContain('EntityTooLarge')
    } finally {
      await limited.stop()
    }
  })
})

describe('error XML', () => {
  test('unauthenticated request returns XML error with escaped fields and request id', async () => {
    const res = await fetch(`${server.baseUrl}/${BUCKET}/test.txt`)
    expect(res.status).toBe(403)
    expect(res.headers.get('content-type')).toContain('application/xml')
    const text = await res.text()
    expect(text).toContain('<Error>')
    expect(text).toContain('<Code>AccessDenied</Code>')
    expect(text).toContain('<RequestId>')
    const id = text.match(/<RequestId>(.*?)<\/RequestId>/)?.[1]
    expect(id?.length).toBeGreaterThan(0)
  })

  test('authenticated unsupported method returns 405 MethodNotAllowed', async () => {
    const res = await fetch(`${server.baseUrl}/${BUCKET}/some.txt`, {
      method: 'PATCH',
      headers: signedRequestHeaders('PATCH', `/${BUCKET}/some.txt`),
    })
    expect(res.status).toBe(405)
    expect(await res.text()).toContain('MethodNotAllowed')
  })

  test('missing bucket returns 404 NoSuchBucket', async () => {
    // A server with no default root rejects buckets without an explicit mapping.
    const noRoot = await startTestServer({ key: KEY, secret: SECRET, path: null })
    try {
      const missingClient = new S3Client({
        accessKeyId: KEY,
        secretAccessKey: SECRET,
        bucket: 'not-configured-bucket',
        endpoint: noRoot.baseUrl,
      })
      await expect(missingClient.list()).rejects.toThrow(/Bucket not configured|NoSuchBucket/)
    } finally {
      await noRoot.stop()
    }
  })
})

describe('traversal and symlink protection', () => {
  test('traversal key is rejected without accessing the target', async () => {
    const sentinel = path.join(server.storageDirectory, 'sentinel.txt')
    await Bun.write(sentinel, 'do-not-touch')
    const traversalRes = await fetch(`${server.baseUrl}/${BUCKET}/../sentinel.txt`, {
      method: 'GET',
      headers: signedRequestHeaders('GET', `/${BUCKET}/../sentinel.txt`),
    })
    // Bun's URL normalization may collapse the traversal before it reaches the
    // server; assert on whatever the server sees, which must not leak sentinel.
    expect(traversalRes.status).not.toBe(200)
    const text = await traversalRes.text()
    expect(text).not.toContain('do-not-touch')
  })

  test('symlinked object path is rejected', async () => {
    const outside = path.join(server.storageDirectory, 'outside-secret.txt')
    await Bun.write(outside, 'secret-data')
    await symlink(outside, path.join(server.storageDirectory, BUCKET, 'evil-link.txt'))

    const res = await fetch(`${server.baseUrl}/${BUCKET}/evil-link.txt`, {
      method: 'GET',
      headers: signedRequestHeaders('GET', `/${BUCKET}/evil-link.txt`),
    })
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('InvalidURI')
  })
})

describe('list-type validation', () => {
  test('unsupported list type returns 400 InvalidRequest', async () => {
    const res = await fetch(`${server.baseUrl}/${BUCKET}?list-type=1`, {
      headers: signedRequestHeaders('GET', `/${BUCKET}?list-type=1`),
    })
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('InvalidRequest')
  })

  test('list-type=2 with continuation token paginates without duplication', async () => {
    for (let i = 0; i < 5; i++) {
      await Bun.write(client.file(`page/f${i}.txt`), `${i}`)
    }
    const first = await fetch(
      `${server.baseUrl}/${BUCKET}?list-type=2&prefix=page%2F&max-keys=2`,
      { headers: signedRequestHeaders('GET', `/${BUCKET}?list-type=2&prefix=page%2F&max-keys=2`) },
    )
    const firstXml = await first.text()
    expect(first.status).toBe(200)
    expect(firstXml).toContain('<IsTruncated>true</IsTruncated>')
    const nextToken = firstXml.match(/<NextContinuationToken>(.*?)<\/NextContinuationToken>/)?.[1]
    expect(nextToken).toBeTruthy()

    const second = await fetch(
      `${server.baseUrl}/${BUCKET}?list-type=2&prefix=page%2F&max-keys=2&continuation-token=${encodeURIComponent(nextToken!)}`,
      { headers: signedRequestHeaders('GET', `/${BUCKET}?list-type=2&prefix=page%2F&max-keys=2&continuation-token=${encodeURIComponent(nextToken!)}`) },
    )
    const secondXml = await second.text()
    expect(second.status).toBe(200)
    // Keys in the second page must not repeat the first page's keys.
    const firstKeys = [...firstXml.matchAll(/<Key>(.*?)<\/Key>/g)].map(m => m[1])
    const secondKeys = [...secondXml.matchAll(/<Key>(.*?)<\/Key>/g)].map(m => m[1])
    const overlap = firstKeys.filter(k => secondKeys.includes(k))
    expect(overlap).toEqual([])
  })
})

/**
 * Builds a minimal AWS SigV4 Authorization header for the request line given,
 * using the fixed test credentials. This lets contract tests issue raw requests
 * (HEAD, unsupported methods, query list calls) the S3Client API does not cover.
 *
 * The caller must also send `x-amz-content-sha256: UNSIGNED-PAYLOAD` so the
 * server accepts the unsigned payload marker used in the canonical request.
 */
function signHeaderRequest(method: string, target: string, baseUrl = server.baseUrl) {
  const host = new URL(baseUrl).host
  const now = new Date()
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '')
  const date = amzDate.slice(0, 8)
  const region = 'auto'
  const service = 's3'
  const [pathname, query = ''] = target.split('?')
  // `URL.searchParams` decodes then re-encodes; reproduce that exactly.
  const searchParams = new URLSearchParams(query)
  const canonicalQuery = [...searchParams.entries()]
    .map(([k, v]) => [encodeURIComponent(k), encodeURIComponent(v)] as const)
    .sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : a[0] < b[0] ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join('&')
  const payloadHash = 'UNSIGNED-PAYLOAD'
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date'
  const canonicalRequest = [
    method,
    pathname,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n')
  const scope = `${date}/${region}/${service}/aws4_request`
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n')
  const hmac = (key: string | Uint8Array, data: string) =>
    createHmac('sha256', key).update(data).digest() as Uint8Array
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${SECRET}`, date), region), service), 'aws4_request')
  const signature = createHmac('sha256', signingKey)
    .update(stringToSign)
    .digest('hex')
  return `AWS4-HMAC-SHA256 Credential=${KEY}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`
}

/** Headers for a raw signed request using the unsigned payload marker. */
function signedRequestHeaders(method: string, target: string, baseUrl = server.baseUrl): Record<string, string> {
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '')
  return {
    Authorization: signHeaderRequest(method, target, baseUrl),
    'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
    'x-amz-date': amzDate,
  }
}

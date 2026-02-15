import { lstat, mkdir, readdir, rename, stat, unlink } from 'fs/promises'
import { createHash, createHmac, timingSafeEqual } from 'crypto'
import path from 'path'
import type { HeadersInit, Server } from 'bun'

export type S3ServerOptions = {
  port?: number
  path: string
  key: string
  secret: string
  sessionToken?: string | null
  maxSize?: number
  maxTimeSkewSeconds?: number
}

type ObjectInfo = {
  key: string
  size: number
  lastModified: string
  etag: string
}

export class S3Server {
  private server: Server<unknown> | null = null
  private readonly options: S3ServerOptions

  constructor(options: S3ServerOptions) {
    const maxBodyBytes = Number.isFinite(options.maxSize ?? NaN) ? Math.max(0, options.maxSize as number) : 0
    const maxTimeSkewSeconds = Number.isFinite(options.maxTimeSkewSeconds ?? NaN)
      ? Math.max(0, options.maxTimeSkewSeconds as number)
      : 0
    this.options = {
      ...options,
      path: path.isAbsolute(options.path) ? options.path : path.resolve(process.cwd(), options.path),
      sessionToken: options.sessionToken ?? null,
      maxSize: maxBodyBytes,
      maxTimeSkewSeconds,
    }
  }

  async start(log: boolean = false) {
    await mkdir(this.options.path, { recursive: true })
    this.server = Bun.serve({
      port: this.options.port ?? 9000,
      hostname: '0.0.0.0',
      fetch: this.fetch,
    })
    if (log) {
      console.log(`Access Key: ${this.options.key}`)
      console.log(`Secret Key: ${this.options.secret}`)
      console.log(`Directory: ${this.options.path}`)
      console.log(`http://localhost:${this.server.port}`)
    }
    return this.server
  }

  get port() {
    return this.server?.port ?? this.options.port
  }

  private xmlEscape(value: string) {
    return value
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&apos;')
  }

  private xmlResponse(body: string, status = 200, headers?: HeadersInit) {
    const merged = new Headers(headers)
    merged.set('Content-Type', 'application/xml; charset=utf-8')
    return new Response(body, { status, headers: merged })
  }

  private s3Error(code: string, message: string, status = 400) {
    const body = `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>${this.xmlEscape(code)}</Code>
  <Message>${this.xmlEscape(message)}</Message>
  <RequestId>${Bun.randomUUIDv7()}</RequestId>
</Error>`
    return this.xmlResponse(body, status)
  }

  private sha256Hex(data: Uint8Array | string) {
    return createHash('sha256').update(data).digest('hex')
  }

  private hmacSha256(key: string | Buffer, data: string) {
    return createHmac('sha256', key).update(data).digest()
  }

  private encodeRfc3986(value: string) {
    return encodeURIComponent(value).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
  }

  private canonicalUri(pathname: string) {
    if (!pathname) return '/'
    const segments = pathname.split('/').map(segment => {
      if (segment === '') return ''
      try {
        return this.encodeRfc3986(decodeURIComponent(segment))
      } catch {
        throw new Error('invalid path encoding')
      }
    })
    const joined = segments.join('/')
    return joined.startsWith('/') ? joined : `/${joined}`
  }

  private canonicalQuery(url: URL, excludeKeys?: Set<string>) {
    const pairs: Array<[string, string]> = []
    for (const [key, value] of url.searchParams) {
      if (excludeKeys?.has(key)) continue
      pairs.push([this.encodeRfc3986(key), this.encodeRfc3986(value)])
    }
    pairs.sort((a, b) => {
      if (a[0] === b[0]) {
        return a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0
      }
      return a[0] < b[0] ? -1 : 1
    })
    return pairs.map(([key, value]) => `${key}=${value}`).join('&')
  }

  private normalizeHeaderValue(value: string) {
    return value.trim().replace(/\s+/g, ' ')
  }

  private canonicalHeaders(req: Request, signedHeaders: string[], url: URL) {
    let output = ''
    for (const header of signedHeaders) {
      let value: string | null
      if (header === 'host') {
        value = req.headers.get('host') ?? url.host
      } else {
        value = req.headers.get(header)
      }
      if (value === null) return null
      output += `${header}:${this.normalizeHeaderValue(value)}\n`
    }
    return output
  }

  private parseAuthorizationHeader(header: string) {
    if (!header.startsWith('AWS4-HMAC-SHA256 ')) {
      throw new Error('unsupported authorization scheme')
    }
    const params: Record<string, string> = {}
    const rest = header.slice('AWS4-HMAC-SHA256 '.length)
    for (const part of rest.split(',')) {
      const trimmed = part.trim()
      if (!trimmed) continue
      const eqIndex = trimmed.indexOf('=')
      if (eqIndex === -1) continue
      const key = trimmed.slice(0, eqIndex)
      const value = trimmed.slice(eqIndex + 1)
      params[key] = value
    }
    if (!params.Credential || !params.SignedHeaders || !params.Signature) {
      throw new Error('missing authorization fields')
    }
    return {
      credential: params.Credential,
      signedHeaders: params.SignedHeaders,
      signature: params.Signature,
    }
  }

  private parseCredential(credential: string) {
    const parts = credential.split('/')
    if (parts.length !== 5) throw new Error('invalid credential scope')
    const [accessKeyId, date, region, service, terminal] = parts
    if (terminal !== 'aws4_request') {
      throw new Error('invalid credential terminator')
    }
    return {
      accessKeyId,
      date,
      region,
      service,
      scope: `${date}/${region}/${service}/aws4_request`,
    }
  }

  private parseAmzDate(value: string) {
    if (!value || value.length < 15) throw new Error('invalid x-amz-date')
    const year = Number.parseInt(value.slice(0, 4), 10)
    const month = Number.parseInt(value.slice(4, 6), 10) - 1
    const day = Number.parseInt(value.slice(6, 8), 10)
    const hour = Number.parseInt(value.slice(9, 11), 10)
    const minute = Number.parseInt(value.slice(11, 13), 10)
    const second = Number.parseInt(value.slice(13, 15), 10)
    const timestamp = Date.UTC(year, month, day, hour, minute, second)
    if (!Number.isFinite(timestamp)) throw new Error('invalid x-amz-date')
    return timestamp
  }

  private async readBodyWithLimit(req: Request, limitBytes: number) {
    if (!req.body) return new Uint8Array()
    const effectiveLimit = Number.isFinite(limitBytes) && limitBytes > 0 ? limitBytes : Number.POSITIVE_INFINITY
    const reader = req.body.getReader()
    const chunks: Uint8Array[] = []
    let total = 0
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      if (!value) continue
      total += value.byteLength
      if (total > effectiveLimit) {
        throw new Error('payload too large')
      }
      chunks.push(value)
    }
    const buffer = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      buffer.set(chunk, offset)
      offset += chunk.byteLength
    }
    return buffer
  }

  private getPayloadHash(req: Request, payloadBytes: Uint8Array | null, isPresigned: boolean) {
    if (isPresigned) return 'UNSIGNED-PAYLOAD'
    const headerHash = req.headers.get('x-amz-content-sha256')
    if (headerHash) {
      if (headerHash === 'UNSIGNED-PAYLOAD' || headerHash === 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD') {
        return headerHash
      }
      const actualHash = this.sha256Hex(payloadBytes ?? new Uint8Array())
      if (headerHash.toLowerCase() !== actualHash) {
        throw new Error('payload hash mismatch')
      }
      return headerHash.toLowerCase()
    }
    return this.sha256Hex(payloadBytes ?? new Uint8Array())
  }

  private verifySignature(req: Request, url: URL, payloadBytes: Uint8Array | null) {
    const presignedAlgorithm = url.searchParams.get('X-Amz-Algorithm')
    const isPresigned = Boolean(presignedAlgorithm)
    let credentialStr: string
    let signedHeadersStr: string
    let signature: string
    let amzDate: string
    let expiresIn: number | null = null

    if (isPresigned) {
      if (presignedAlgorithm !== 'AWS4-HMAC-SHA256') {
        return this.s3Error('AccessDenied', 'Unsupported signature algorithm', 403)
      }
      credentialStr = url.searchParams.get('X-Amz-Credential') ?? ''
      signedHeadersStr = url.searchParams.get('X-Amz-SignedHeaders') ?? ''
      signature = url.searchParams.get('X-Amz-Signature') ?? ''
      amzDate = url.searchParams.get('X-Amz-Date') ?? ''
      const expiresRaw = url.searchParams.get('X-Amz-Expires') ?? ''
      expiresIn = Number.parseInt(expiresRaw, 10)
      if (!Number.isFinite(expiresIn)) {
        return this.s3Error('AccessDenied', 'Invalid presign expiration', 403)
      }
    } else {
      const authHeader = req.headers.get('authorization')
      if (!authHeader) {
        return this.s3Error('AccessDenied', 'Missing authorization', 403)
      }
      let parsed: { credential: string; signedHeaders: string; signature: string }
      try {
        parsed = this.parseAuthorizationHeader(authHeader)
      } catch (err) {
        return this.s3Error('AccessDenied', (err as Error).message, 403)
      }
      credentialStr = parsed.credential
      signedHeadersStr = parsed.signedHeaders
      signature = parsed.signature
      amzDate = req.headers.get('x-amz-date') ?? ''
      if (!amzDate) {
        return this.s3Error('AccessDenied', 'Missing x-amz-date', 403)
      }
    }

    let credential: ReturnType<S3Server['parseCredential']>
    try {
      credential = this.parseCredential(credentialStr)
    } catch (err) {
      return this.s3Error('AccessDenied', (err as Error).message, 403)
    }

    if (!credential.date || !credential.region) {
      return this.s3Error('AccessDenied', 'Invalid credential scope', 403)
    }

    if (credential.accessKeyId !== this.options.key) {
      return this.s3Error('AccessDenied', 'Invalid access key', 403)
    }

    if (credential.service !== 's3') {
      return this.s3Error('AccessDenied', 'Invalid service', 403)
    }

    if (this.options.sessionToken) {
      const token = req.headers.get('x-amz-security-token') ?? url.searchParams.get('X-Amz-Security-Token')
      if (!token || token !== this.options.sessionToken) {
        return this.s3Error('AccessDenied', 'Invalid session token', 403)
      }
    }

    let requestTimestamp: number
    try {
      requestTimestamp = this.parseAmzDate(amzDate)
    } catch (err) {
      return this.s3Error('AccessDenied', (err as Error).message, 403)
    }

    const amzDateShort = amzDate.slice(0, 8)
    if (credential.date !== amzDateShort) {
      return this.s3Error('AccessDenied', 'Credential date mismatch', 403)
    }

    if (isPresigned) {
      const expiresAt = requestTimestamp + (expiresIn ?? 0) * 1000
      if (Date.now() > expiresAt) {
        return this.s3Error('AccessDenied', 'Presigned URL expired', 403)
      }
    } else if (this.options.maxTimeSkewSeconds && this.options.maxTimeSkewSeconds > 0) {
      const skewMs = Math.abs(Date.now() - requestTimestamp)
      if (skewMs > this.options.maxTimeSkewSeconds * 1000) {
        return this.s3Error('RequestTimeTooSkewed', 'Request time too skewed', 403)
      }
    }

    const signedHeaders = signedHeadersStr
      .split(';')
      .map(header => header.trim().toLowerCase())
      .filter(Boolean)
    if (signedHeaders.length === 0) {
      return this.s3Error('AccessDenied', 'Missing signed headers', 403)
    }
    if (!signedHeaders.includes('host')) {
      return this.s3Error('AccessDenied', 'Signed headers must include host', 403)
    }

    const canonicalHeaderString = this.canonicalHeaders(req, signedHeaders, url)
    if (!canonicalHeaderString) {
      return this.s3Error('AccessDenied', 'Signed header missing', 403)
    }

    let canonicalPath: string
    try {
      canonicalPath = this.canonicalUri(url.pathname)
    } catch (err) {
      return this.s3Error('AccessDenied', (err as Error).message, 403)
    }

    const canonicalQueryString = this.canonicalQuery(url, isPresigned ? new Set(['X-Amz-Signature']) : undefined)

    let payloadHash: string
    try {
      payloadHash = this.getPayloadHash(req, payloadBytes, isPresigned)
    } catch (err) {
      return this.s3Error('AccessDenied', (err as Error).message, 403)
    }

    const canonicalRequest = [
      req.method,
      canonicalPath,
      canonicalQueryString,
      canonicalHeaderString,
      signedHeaders.join(';'),
      payloadHash,
    ].join('\n')

    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credential.scope, this.sha256Hex(canonicalRequest)].join('\n')

    const signingKey = this.hmacSha256(
      this.hmacSha256(
        this.hmacSha256(this.hmacSha256(`AWS4${this.options.secret}`, credential.date), credential.region),
        credential.service,
      ),
      'aws4_request',
    )
    const computedSignature = this.hmacSha256(signingKey, stringToSign).toString('hex').toLowerCase()
    const providedSignature = signature.toLowerCase()
    if (computedSignature.length !== providedSignature.length) {
      return this.s3Error('AccessDenied', 'Signature mismatch', 403)
    }
    const computedBytes = Buffer.from(computedSignature, 'hex')
    const providedBytes = Buffer.from(providedSignature, 'hex')
    if (computedBytes.length !== providedBytes.length || computedBytes.length === 0) {
      return this.s3Error('AccessDenied', 'Signature mismatch', 403)
    }
    if (!timingSafeEqual(computedBytes, providedBytes)) {
      return this.s3Error('AccessDenied', 'Signature mismatch', 403)
    }

    return null
  }

  private normalizeKey(key: string) {
    if (!key || !key.trim()) throw new Error('key is required')
    return key.replaceAll('\\', '/')
  }

  private resolveBucketPath(bucket: string) {
    const bucketPath = path.resolve(this.options.path, bucket)
    if (bucketPath !== this.options.path && !bucketPath.startsWith(this.options.path + path.sep)) {
      throw new Error('bucket escapes data directory')
    }
    return bucketPath
  }

  private resolveObjectPath(bucket: string, key: string) {
    const bucketPath = this.resolveBucketPath(bucket)
    const resolved = path.resolve(bucketPath, key)
    if (resolved !== bucketPath && !resolved.startsWith(bucketPath + path.sep)) {
      throw new Error('key escapes bucket directory')
    }
    return resolved
  }

  private async assertNoSymlinkInPath(bucketPath: string, filePath: string) {
    const relative = path.relative(bucketPath, filePath)
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error('key escapes bucket directory')
    }
    const bucketStats = await lstat(bucketPath).catch(() => null)
    if (bucketStats?.isSymbolicLink()) {
      throw new Error('bucket path is a symlink')
    }
    const parts = relative.split(path.sep).filter(Boolean)
    let current = bucketPath
    for (const part of parts) {
      current = path.join(current, part)
      const stats = await lstat(current).catch(() => null)
      if (!stats) break
      if (stats.isSymbolicLink()) {
        throw new Error('symlink not allowed in object path')
      }
    }
  }

  private parseBucketFromHost(req: Request) {
    const host = req.headers.get('host')
    if (!host) return null
    const hostname = host.split(':')[0] ?? ''
    const parts = hostname.split('.')
    if (parts.length <= 1) return null
    const bucket = parts[0]
    return bucket && bucket !== 'localhost' ? bucket : null
  }

  private parseBucketAndKey(req: Request, url: URL) {
    const hostBucket = this.parseBucketFromHost(req)
    const parts = url.pathname.split('/').filter(Boolean)
    let bucket = parts.at(0)
    if (!bucket) return { bucket: hostBucket, key: null }
    try {
      bucket = decodeURIComponent(bucket)
    } catch {
      throw new Error('invalid bucket encoding')
    }

    if (hostBucket && bucket !== hostBucket) {
      bucket = hostBucket
      const rawKey = parts.join('/')
      let key: string | null = null
      try {
        key = decodeURIComponent(rawKey)
      } catch {
        throw new Error('invalid key encoding')
      }
      if (!bucket.trim()) return { bucket: null, key: null }
      if (bucket.includes('/') || bucket.includes('\\')) {
        throw new Error('invalid bucket')
      }
      return { bucket, key }
    }

    let key: string | null = null
    if (parts.length > 1) {
      const rawKey = parts.slice(1).join('/')
      try {
        key = decodeURIComponent(rawKey)
      } catch {
        throw new Error('invalid key encoding')
      }
    }

    if (!bucket.trim()) return { bucket: null, key: null }
    if (bucket.includes('/') || bucket.includes('\\')) {
      throw new Error('invalid bucket')
    }
    return { bucket, key }
  }

  private toPosix(filePath: string) {
    return filePath.split(path.sep).join('/')
  }

  private etagForStats(stats: Awaited<ReturnType<typeof stat>>) {
    const hash = createHash('md5').update(`${stats.size}:${stats.mtimeMs}`).digest('hex')
    return `"${hash}"`
  }

  private async listObjects(bucket: string, prefix: string | null, maxKeys: number, continuationToken: string | null) {
    const bucketPath = this.resolveBucketPath(bucket)
    const results: ObjectInfo[] = []
    let hitLimit = false
    let seenContinuation = !continuationToken

    const walk = async (dir: string) => {
      if (hitLimit) return
      let entries = await readdir(dir, { withFileTypes: true }).catch(() => [])
      entries = entries.sort((a, b) => a.name.localeCompare(b.name))
      for (const entry of entries) {
        if (hitLimit) return
        const fullPath = path.join(dir, entry.name)
        if (entry.isDirectory()) {
          await walk(fullPath)
          continue
        }
        if (!entry.isFile()) continue
        const rel = path.relative(bucketPath, fullPath)
        const key = this.toPosix(rel)
        if (prefix && !key.startsWith(prefix)) continue
        if (!seenContinuation) {
          if (key <= continuationToken!) {
            continue
          }
          seenContinuation = true
        }
        const stats = await stat(fullPath)
        results.push({
          key,
          size: stats.size,
          lastModified: stats.mtime.toISOString(),
          etag: this.etagForStats(stats),
        })
        if (results.length >= maxKeys) {
          hitLimit = true
          return
        }
      }
    }

    await walk(bucketPath)
    return {
      objects: results,
      isTruncated: hitLimit,
      nextToken: hitLimit ? (results.at(results.length - 1)?.key ?? null) : null,
    }
  }

  private listXml(
    bucket: string,
    prefix: string | null,
    objects: ObjectInfo[],
    maxKeys: number,
    isTruncated: boolean,
    continuationToken: string | null,
    nextToken: string | null,
    listType: string | null,
  ) {
    const contents = objects
      .map(
        obj => `
  <Contents>
    <Key>${this.xmlEscape(obj.key)}</Key>
    <LastModified>${this.xmlEscape(obj.lastModified)}</LastModified>
    <ETag>${this.xmlEscape(obj.etag)}</ETag>
    <Size>${obj.size}</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>`,
      )
      .join('')

    const continuationXml =
      listType === '2' && continuationToken
        ? `
  <ContinuationToken>${this.xmlEscape(continuationToken)}</ContinuationToken>`
        : ''
    const nextTokenXml =
      listType === '2' && isTruncated && nextToken
        ? `
  <NextContinuationToken>${this.xmlEscape(nextToken)}</NextContinuationToken>`
        : ''

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>${this.xmlEscape(bucket)}</Name>
  <Prefix>${this.xmlEscape(prefix ?? '')}</Prefix>
  <KeyCount>${objects.length}</KeyCount>
  <MaxKeys>${maxKeys}</MaxKeys>
  <IsTruncated>${isTruncated ? 'true' : 'false'}</IsTruncated>${continuationXml}${nextTokenXml}${contents}
</ListBucketResult>`

    return this.xmlResponse(body)
  }

  fetch = async (req: Request) => {
    const url = new URL(req.url)
    let bucket: string | null
    let key: string | null
    let payloadBytes: Uint8Array | null = null

    const expectsBody = req.method === 'PUT' || req.method === 'POST'
    if (expectsBody) {
      const contentLength = req.headers.get('content-length')
      const maxBodyBytes = this.options.maxSize ?? 0
      if (contentLength) {
        const parsed = Number.parseInt(contentLength, 10)
        if (Number.isFinite(parsed) && maxBodyBytes > 0 && parsed > maxBodyBytes) {
          return this.s3Error('EntityTooLarge', 'Payload too large', 413)
        }
      }
      try {
        payloadBytes = await this.readBodyWithLimit(req, maxBodyBytes)
      } catch (err) {
        if ((err as Error).message === 'payload too large') {
          return this.s3Error('EntityTooLarge', 'Payload too large', 413)
        }
        return this.s3Error('InternalError', (err as Error).message, 500)
      }
    }

    const authError = this.verifySignature(req, url, payloadBytes)
    if (authError) return authError

    try {
      ;({ bucket, key } = this.parseBucketAndKey(req, url))
    } catch (err) {
      return this.s3Error('InvalidURI', (err as Error).message, 400)
    }

    if (!bucket) {
      return this.s3Error('NoSuchBucket', 'Bucket not specified', 404)
    }

    if (!key && req.method === 'GET') {
      const listType = url.searchParams.get('list-type')
      if (listType && listType !== '2') {
        return this.s3Error('InvalidRequest', 'Unsupported list type', 400)
      }
      const prefix = url.searchParams.get('prefix')
      const rawMaxKeys = url.searchParams.get('max-keys')
      const parsedMaxKeys = rawMaxKeys ? Number.parseInt(rawMaxKeys, 10) : NaN
      const maxKeys = Number.isFinite(parsedMaxKeys) && parsedMaxKeys > 0 ? Math.min(parsedMaxKeys, 1000) : 1000
      const continuationToken = listType === '2' ? (url.searchParams.get('continuation-token') ?? null) : null
      const { objects, isTruncated, nextToken } = await this.listObjects(bucket, prefix, maxKeys, continuationToken)
      return this.listXml(bucket, prefix, objects, maxKeys, isTruncated, continuationToken, nextToken, listType)
    }

    if (!key) {
      return this.s3Error('InvalidRequest', 'Key is required', 400)
    }

    let filePath: string
    try {
      filePath = this.resolveObjectPath(bucket, this.normalizeKey(key))
    } catch (err) {
      return this.s3Error('InvalidURI', (err as Error).message, 400)
    }
    const bucketPath = this.resolveBucketPath(bucket)
    try {
      await this.assertNoSymlinkInPath(bucketPath, filePath)
    } catch (err) {
      return this.s3Error('InvalidURI', (err as Error).message, 400)
    }

    if (req.method === 'PUT') {
      await mkdir(path.dirname(filePath), { recursive: true })
      const tmpPath = `${filePath}.upload-${Bun.randomUUIDv7()}`
      try {
        await Bun.write(tmpPath, payloadBytes ?? '')
        try {
          await rename(tmpPath, filePath)
        } catch {
          await unlink(filePath).catch(() => null)
          await rename(tmpPath, filePath)
        }
        return new Response(null, {
          status: 200,
          headers: { ETag: this.etagForStats(await stat(filePath)) },
        })
      } catch (err) {
        await unlink(tmpPath).catch(() => null)
        return this.s3Error('InternalError', (err as Error).message, 500)
      }
    }

    if (req.method === 'HEAD') {
      const stats = await stat(filePath).catch(() => null)
      if (!stats) return this.s3Error('NoSuchKey', 'Object not found', 404)
      return new Response(null, {
        status: 200,
        headers: {
          'Content-Length': stats.size.toString(),
          'Last-Modified': stats.mtime.toUTCString(),
          ETag: this.etagForStats(stats),
        },
      })
    }

    if (req.method === 'GET') {
      const stats = await stat(filePath).catch(() => null)
      if (!stats) return this.s3Error('NoSuchKey', 'Object not found', 404)
      const file = Bun.file(filePath)
      return new Response(file, {
        status: 200,
        headers: {
          'Content-Length': stats.size.toString(),
          'Last-Modified': stats.mtime.toUTCString(),
          ETag: this.etagForStats(stats),
          'Content-Type': file.type || 'application/octet-stream',
        },
      })
    }

    if (req.method === 'DELETE') {
      const removed = await unlink(filePath)
        .then(() => true)
        .catch(() => false)
      if (!removed) return this.s3Error('NoSuchKey', 'Object not found', 404)
      return new Response(null, { status: 204 })
    }

    return this.s3Error('MethodNotAllowed', 'Unsupported method', 405)
  }
}

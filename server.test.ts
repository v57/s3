import { describe, expect, test } from 'bun:test'
import { buildServerHelpText, parseServerOptions } from './server'

describe('parseServerOptions', () => {
  test('supports positional path and flags', () => {
    const options = parseServerOptions(['~/storage', '--port', '9002'])
    expect(options.help).toBe(false)
    if (options.help) return
    expect(options.options.path).toBe('~/storage')
    expect(options.options.port).toBe(9002)
  })

  test('supports explicit path and repeated bucket paths', () => {
    const options = parseServerOptions([
      '--path',
      '~/fallback',
      '--bucket-path',
      'alpha=~/alpha',
      '--bucket-path',
      'beta=/tmp/beta',
    ])
    expect(options.help).toBe(false)
    if (options.help) return
    expect(options.options.path).toBe('~/fallback')
    expect(options.options.bucketPaths).toEqual({
      alpha: '~/alpha',
      beta: '/tmp/beta',
    })
  })

  test('supports help flag', () => {
    const options = parseServerOptions(['--help'])
    expect(options.help).toBe(true)
    if (!options.help) return
    expect(options.usage).toContain('bun server [path] [options]')
    expect(options.usage).toContain('--bucket-path <bucket=path>')
  })

  test('supports short help flag', () => {
    const options = parseServerOptions(['-h'])
    expect(options.help).toBe(true)
  })

  test('exports a help text', () => {
    expect(buildServerHelpText()).toContain('Examples:')
  })
})

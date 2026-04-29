/**
 * Server-side Knuckles client for a Next.js App Router app.
 *
 * Construct once and reuse — the JWKS cache and the keep-alive
 * connection pool both want a long-lived instance.
 *
 * Treat the secret as a server-only env var. Never put `KNUCKLES_*`
 * vars in `NEXT_PUBLIC_*` and never import this file from a client
 * component.
 */

import { KnucklesClient } from '@knuckles/client'

let _client: KnucklesClient | undefined

export function knuckles(): KnucklesClient {
  if (_client === undefined) {
    _client = new KnucklesClient({
      baseUrl: required('KNUCKLES_URL'),
      clientId: required('KNUCKLES_CLIENT_ID'),
      clientSecret: required('KNUCKLES_CLIENT_SECRET'),
    })
  }
  return _client
}

function required(name: string): string {
  const value = process.env[name]
  if (!value) throw new Error(`Missing required env var: ${name}`)
  return value
}

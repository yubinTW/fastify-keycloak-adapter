# Fastify-Keycloak-Adapter

[![Node.js CI](https://github.com/yubinTW/fastify-keycloak-adapter/actions/workflows/node.js.yml/badge.svg)](https://github.com/yubinTW/fastify-keycloak-adapter/actions/workflows/node.js.yml)
[![NPM version](https://img.shields.io/npm/v/fastify-keycloak-adapter.svg?style=flat)](https://www.npmjs.com/package/fastify-keycloak-adapter)

`fastify-keycloak-adapter` is a keycloak adapter for a Fastify app.

## Install

https://www.npmjs.com/package/fastify-keycloak-adapter

```
npm i fastify-keycloak-adapter
```

```
yarn add fastify-keycloak-adapter
```

## Fastify Version

- Fastify 4 -> `npm i fastify-keycloak-adapter`
- Fastify 3 -> `npm i fastify-keycloak-adapter@0.6.3` (deprecated)

## Usage

```typescript
import fastify from 'fastify'
import keycloak, { KeycloakOptions } from 'fastify-keycloak-adapter'

const server = fastify()

const opts: KeycloakOptions = {
  appOrigin: 'http://localhost:8888',
  keycloakSubdomain: 'keycloak.yourcompany.com/auth/realms/realm01',
  clientId: 'client01',
  clientSecret: 'client01secret'
}

server.register(keycloak, opts)
```

## Configuration

- `appOrigin` app url, used for redirect to the app when user login successfully (required)

- `keycloakSubdomain` keycloak subdomain, endpoint of a realm resource (required)

- `useHttps` set true if keycloak server uses `https` (optional, defaults to `false`)

- `clientId` client id (required)

- `clientSecret` client secret (required)

- `scope` client scope of keycloak (optional, string[], defaults to `['openid']`)

- `callback` Relative or absolute URL to receive the response data (optional, defaults to `/`)

- `retries` The number of times to retry before failing. (optional, number, defaults to 3)

- `logoutEndpoint` route path of doing logout (optional, defaults to `/logout`)

- `excludedPatterns` string array for non-authorized urls (optional, support `?`, `*` and `**` wildcards)

- `autoRefreshToken` set true for refreshing token automatically when token has expired (optional, defaults to `false`)

- `disableCookiePlugin` set true if your application register the [fastify-cookie](https://github.com/fastify/fastify-cookie) plugin itself. Otherwise **fastify-cookie** will be registered by this plugin, because it's mandatory. (optional, defaults to `false`)

- `disableSessionPlugin` set true if your application register the [fastify-session](https://github.com/fastify/fastify-session) plugin itself. Otherwise **fastify-session** will be registered by this plugin, because it's mandatory. (optional, defaults to `false`)

- `userPayloadMapper(userPayload)` defined the fields of `fastify.session.user` (optional)

- `unauthorizedHandler(request, reply)` is a function to customize the handling (e.g. the response) of unauthorized requests (optional)

## Configuration example

```typescript
import keycloak, { KeycloakOptions, UserInfo } from 'fastify-keycloak-adapter'
import fastify, { FastifyInstance } from 'fastify'

const server: FastifyInstance = fastify()

const opts: KeycloakOptions = {
  appOrigin: 'http://localhost:8888',
  keycloakSubdomain: 'keycloak.mycompany.com/auth/realms/myrealm',
  useHttps: false,
  clientId: 'myclient01',
  clientSecret: 'myClientSecret',
  logoutEndpoint: '/logout',
  excludedPatterns: ['/metrics', '/manifest.json', '/api/todos/**'],
  callback: '/hello'
}

server.register(keycloak, opts)
```

## Set userPayloadMapper

defined the fields of `fastify.session.user`, use the payload from JWT token

use `DefaultToken` in default case

or you should define the type by yourself, in case the keycloak server has custom payload

```typescript
import { KeycloakOptions, DefaultToken } from 'fastify-keycloak-adapter'

const userPayloadMapper = (tokenPayload: unknown) => ({
  account: (tokenPayload as DefaultToken).preferred_username,
  name: (tokenPayload as DefaultToken).name
})

const opts: KeycloakOptions = {
  // ...
  userPayloadMapper: userPayloadMapper
}
```

## Set unauthorizedHandler

Provides a custom handler for unauthorized requests.

```typescript
import { FastifyReply, FastifyRequest } from 'fastify'
import { KeycloakOptions } from 'fastify-keycloak-adapter'

const unauthorizedHandler = (request: FastifyRequest, reply: FastifyReply) => {
  reply.status(401).send(`Invalid request`)
}

const opts: KeycloakOptions = {
  // ...
  unauthorizedHandler: unauthorizedHandler
}
```

## Disable mandatory plugin registration

Use the options to disable the cookie and session plugin registration, in case you want to initialize the plugins yourself, to provide your own set of configurations for these plugins.

```typescript
import fastify from 'fastify'
import fastifyCookie from '@fastify/cookie'
import session from '@fastify/session'
import keycloak, { KeycloakOptions } from 'fastify-keycloak-adapter'

const server = fastify()

server.register(fastifyCookie)
server.register(session, {
  secret: '<SOME_SECRET>',
  cookie: {
    secure: false
  }
})

const opts: KeycloakOptions = {
  // ...
  disableCookiePlugin: true,
  disableSessionPlugin: true
}
server.register(keycloak, opts)
```

## Get login user

use `request.session.user`

```typescript
server.get('/users/me', async (request, reply) => {
  const user = request.session.user
  return reply.status(200).send({ user })
})
```

# License

[MIT License](LICENSE)

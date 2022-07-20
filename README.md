# Fastify-Keycloak-Adapter

a keycloak adapter for Fastify app

## Install

https://www.npmjs.com/package/fastify-keycloak-adapter

```
npm i fastify-keycloak-adapter
```

## Fastify Version

- Fastify 4 -> `npm i fastify-keycloak-adapter`
- Fastify 3 -> `npm i fastify-keycloak-adapter@0.6.3`

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

- `logoutEndpoint` route path of doing logout (optional, defaults to `/logout`)

- `excludedPatterns` string array for non-authorized urls (optional, support `?`, `*` and `**` wildcards)
- `userPayloadMapper` defined the fields of `fastify.session.user` (optional)

- `unauthorizedHandler(request, reply)` is a function to customize the handling (e.g. the response) of unauthorized requests (invalid auth token)

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
  excludedPatterns: ['/metrics', '/api/todos/**']
}

server.register(keycloak, opts)
```

## Set userPayloadMapper

defined the fields of `fastify.session.user`, you can set value from `UserInfo`

```typescript
import { KeycloakOptions, UserInfo } from 'fastify-keycloak-adapter'

const userPayloadMapper = (userPayload: UserInfo) => ({
  account: userPayload.preferred_username,
  name: userPayload.name
})

const opts: KeycloakOptions = {
  // ...
  userPayloadMapper: userPayloadMapper
}
```

## Set unauthorizedHandler

Provides a custom handler for unauthorized requests.

```typescript
import { FastifyReply, FastifyRequest } from 'fastify';
import { KeycloakOptions } from 'fastify-keycloak-adapter'

const unauthorizedHandler = (request: FastifyRequest, reply: FastifyReply) => {
  reply.status(401).send(`Invalid request`);
};

const opts: KeycloakOptions = {
  // ...
  unauthorizedHandler: unauthorizedHandler
}
```

## Get login user

use `request.session.user`

```typescript
server.get('/users/me', async (request, reply) => {
  const user = request.session.user
  return reply.status(200).send({ user })
})
```

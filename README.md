# Fastify-Keycloak-Adapter

## Install

https://www.npmjs.com/package/fastify-keycloak-adapter

```
npm i fastify-keycloak-adapter
```

## Usage

```typescript
import keycloak, { KeycloakOptions } from 'fastify-keycloak-adapter'

const opts: KeycloakOptions = {
  appOrigin: process.env.APP_ORIGIN,
  keycloakSubdomain: process.env.KEYCLOAK_SUBDOMAIN,
  clientId: process.env.KEYCLOAK_CLIENT_ID,
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET
}

fastify.register(keycloak, opts)
```

## Configuration

- `appOrigin` app url, used for redirect to the app when user login successfully (required)

- `keycloakSubdomain` keycloak subdomain, endpoint of a realm resource (required)

- `clientId` client id (required)

- `clientSecret` client secret (required)

- `logoutEndpoint` route path of doing logout (optional, defaults to `/logout`)

- `excludedPatterns` string array for non-authorized urls (optional, support  `?`, `*` and `**` wildcards)

## Configuration example

```typescript
const opts: KeycloakOptions = {
  appOrigin: 'http://localhost:8888',
  keycloakSubdomain: 'keycloak.mycompany.com/auth/realms/myrealm',
  clientId: 'myclient01',
  clientSecret: 'myClientSecret',
  logoutEndpoint: '/logout',
  excludedPatterns: [
    '/metrics',
    '/api/todos/**'
  ]
}
```
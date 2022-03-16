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
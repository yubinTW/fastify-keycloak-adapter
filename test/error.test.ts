import { FastifyInstance } from 'fastify'
import { afterAll, beforeAll, describe, it } from 'vitest'

import { KeycloakOptions } from '../src/keycloak'
import { serverOf, serverStart } from './server'

describe('Error behavior', () => {
  const server: FastifyInstance = serverOf()

  beforeAll(async () => {})

  afterAll(async () => {})

  it.fails('should error, when given an invalid appOrigin', async () => {
    const keycloakOptions: KeycloakOptions = {
      appOrigin: 'localhost:8888',
      keycloakSubdomain: `localhost:8080/auth/realms/demo`,
      clientId: 'client01',
      clientSecret: 'client01secret'
    }

    await serverStart(server, 8888, keycloakOptions)
    await server.ready()
  })

  it.fails('should error, when given an invalid keycloakSubdomain', async () => {
    const keycloakOptions: KeycloakOptions = {
      appOrigin: 'http://localhost:8888',
      keycloakSubdomain: `localhost:8080/auth/realms/demo/`,
      clientId: 'client01',
      clientSecret: 'client01secret'
    }

    await serverStart(server, 8888, keycloakOptions)
    await server.ready()
  })
})

import { FastifyInstance } from 'fastify'
import { KeycloakContainer, StartedKeycloakContainer } from 'testcontainers-keycloak'
import { describe, beforeAll, afterAll, expect, it } from 'vitest'
import { KeycloakOptions } from '../keycloak'
import { startFastify } from './server'

describe('server with keycloak testing', () => {
  const serverPort = 8888
  let keycloak: StartedKeycloakContainer
  let keycloakOptions: KeycloakOptions

  beforeAll(async () => {
    const keycloakPort = 8080

    keycloak = await new KeycloakContainer()
      .withStartupTimeout(600_000)
      .withAdminUsername('admin')
      .withAdminPassword('admin')
      .withExposedPorts(keycloakPort)
      .start()

    await keycloak.configCredentials('master', 'admin', 'admin')

    await keycloak.createRealm('demo')
    await keycloak.createUser('demo', 'user01', 'yubin', 'hsu', true)
    await keycloak.setUserPassword('demo', 'user01', 'user01password')
    await keycloak.createClient(
      'demo',
      'client01',
      'client01secret',
      [`http://localhost:${serverPort}/*`],
      [`http://localhost:${serverPort}`]
    )

    keycloakOptions = {
      appOrigin: `http://localhost:${serverPort}`,
      keycloakSubdomain: `${keycloak.getHost()}:${keycloak.getMappedPort(keycloakPort)}/auth/realms/demo`,
      clientId: 'client01',
      clientSecret: 'client01secret'
    }
  })

  afterAll(async () => {
    await keycloak.stop()
  })

  describe('minimal plugin configuration', () => {
    let server: FastifyInstance

    beforeAll(async () => {
      server = await startFastify(serverPort, keycloakOptions)
      await server.ready()
    })

    afterAll(async () => {
      await server.close()
    })

    it('should return 302, when send a request to an endpoint', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/ping'
      })
      expect(response.statusCode).toBe(302)
    })

    it('should return 401 and "Unauthorized", when send a request to an endpoint without a valid token', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/ping',
        headers: { authorization: `Bearer fakeToken` }
      })
      expect(response.statusCode).toBe(401)
      expect(response.body).toBe('Unauthorized')
    })

    it('should return 200, when send a request to an endpoint with a valid token', async () => {
      const token = await keycloak.getAccessToken('demo', 'user01', 'user01password', 'client01', 'client01secret')
      const response = await server.inject({
        method: 'GET',
        url: '/ping',
        headers: { authorization: `Bearer ${token}` }
      })
      expect(response.statusCode).toBe(200)
    })

    it('should return default userPayload', async () => {
      const token = await keycloak.getAccessToken('demo', 'user01', 'user01password', 'client01', 'client01secret')
      const response = await server.inject({
        method: 'GET',
        url: '/me',
        headers: { authorization: `Bearer ${token}` }
      })
      expect(response.statusCode).toBe(200)
      const {
        user: { account }
      } = JSON.parse(response.body)
      expect(account).toBe('user01')
    })
  })

  describe('custom user payload mapping configuration', () => {
    let server: FastifyInstance

    beforeAll(async () => {
      server = await startFastify(serverPort, {
        ...keycloakOptions,
        userPayloadMapper: (userPayload) => ({
          username: userPayload.preferred_username
        })
      })
      await server.ready()
    })

    afterAll(async () => {
      await server.close()
    })

    it('should return custom userPayload', async () => {
      const token = await keycloak.getAccessToken('demo', 'user01', 'user01password', 'client01', 'client01secret')
      const response = await server.inject({
        method: 'GET',
        url: '/me',
        headers: { authorization: `Bearer ${token}` }
      })
      expect(response.statusCode).toBe(200)
      const {
        user: { username }
      } = JSON.parse(response.body)
      expect(username).toBe('user01')
    })
  })

  describe('custom unauthorized handler configuration', () => {
    let server: FastifyInstance

    beforeAll(async () => {
      server = await startFastify(serverPort, {
        ...keycloakOptions,
        unauthorizedHandler: (_request, reply) => {
          reply.status(403).send(`Forbidden`)
        }
      })
      await server.ready()
    })

    afterAll(async () => {
      await server.close()
    })

    it('should return custom unauthorized reply, when send a request to an endpoint without a valid token', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/ping',
        headers: { authorization: `Bearer fakeToken` }
      })
      expect(response.statusCode).toBe(403)
      expect(response.body).toBe('Forbidden')
    })
  })
})

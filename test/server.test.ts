import { FastifyInstance, FastifyRequest } from 'fastify'
import { KeycloakContainer, StartedKeycloakContainer } from 'testcontainers-keycloak'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { KeycloakOptions } from '../src/keycloak'
import { serverOf, serverStart } from './server'

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
    const server: FastifyInstance = serverOf()

    beforeAll(async () => {
      await serverStart(server, serverPort, keycloakOptions)
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
    const server: FastifyInstance = serverOf()

    type MyToken = {
      preferred_username: Readonly<string>
      deptname: Readonly<string>
    }

    const userPayload = (tokenPayload: unknown) => ({
      username: (tokenPayload as MyToken).preferred_username,
      deptName: (tokenPayload as MyToken).deptname
    })

    beforeAll(async () => {
      await serverStart(server, serverPort, {
        ...keycloakOptions,
        userPayloadMapper: userPayload
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
    const server: FastifyInstance = serverOf()

    beforeAll(async () => {
      await serverStart(server, serverPort, {
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

  describe('add bypassFn configuration', () => {
    const server: FastifyInstance = serverOf()

    const bypassFn = (request: FastifyRequest) => {
      return request.headers.password === 'sesame'
    }

    beforeAll(async () => {
      await serverStart(server, serverPort, {
        ...keycloakOptions,
        bypassFn,
      })
      await server.ready()
    })

    afterAll(async () => {
      await server.close()
    })

    it('should return 200, cause bypassFn returned true', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/ping',
        headers: {
          authorization: `Bearer fakeToken`,
          password: 'sesame'
        }
      })
      expect(response.statusCode).toBe(200)
    })

    it('should return 401, cause bypassFn returned false', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/ping',
        headers: {
          authorization: `Bearer fakeToken`,
          password: 'mellon'
        }
      })
      expect(response.statusCode).toBe(401)
      expect(response.body).toBe('Unauthorized')
    })
  })


  describe('add async bypassFn configuration', () => {
    const server: FastifyInstance = serverOf()

    const bypassFn = (request: FastifyRequest) => new Promise<boolean>((resolve) => {
      setTimeout(() => {
        resolve(request.headers.password === 'sesame')
      }, 100)
    })

    beforeAll(async () => {
      await serverStart(server, serverPort, {
        ...keycloakOptions,
        bypassFn,
      })
      await server.ready()
    })

    afterAll(async () => {
      await server.close()
    })

    it('should return 200, cause bypassFn returned true', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/ping',
        headers: {
          authorization: `Bearer fakeToken`,
          password: 'sesame'
        }
      })
      expect(response.statusCode).toBe(200)
    })

    it('should return 401, cause bypassFn returned false', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/ping',
        headers: {
          authorization: `Bearer fakeToken`,
          password: 'mellon'
        }
      })
      expect(response.statusCode).toBe(401)
      expect(response.body).toBe('Unauthorized')
    })
  })
})

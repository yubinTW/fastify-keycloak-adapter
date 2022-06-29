import { FastifyInstance } from 'fastify'
import { KeycloakContainer, StartedKeycloakContainer } from 'testcontainers-keycloak'
import { KeycloakOptions } from '../keycloak'
import { startFastify } from './server'

describe('server with keycloak testing', () => {
  let server: FastifyInstance
  let keycloak: StartedKeycloakContainer

  beforeAll(async () => {
    keycloak = await new KeycloakContainer()
      .withAdminUsername('admin')
      .withAdminPassword('admin')
      .withExposedPorts(8080)
      .start()

    await keycloak.configCredentials('master', 'admin', 'admin')

    await keycloak.createRealm('demo')
    await keycloak.createUser('demo', 'user01', 'yubin', 'hsu', true)
    await keycloak.setUserPassword('demo', 'user01', 'user01password')
    await keycloak.createClient(
      'demo',
      'client01',
      'client01secret',
      ['http://localhost:8888/*'],
      ['http://localhost:8888']
    )

    const keycloakOptions: KeycloakOptions = {
      appOrigin: 'http://localhost:8888',
      keycloakSubdomain: `${keycloak.getHost()}:${keycloak.getMappedPort(8080)}/auth/realms/demo`,
      clientId: 'client01',
      clientSecret: 'client01secret'
    }

    server = await startFastify(8888, keycloakOptions)
    await server.ready()
  })

  afterAll(async () => {
    await server.close()
    await keycloak.stop()
  })

  it('should return 302, when send a request to an endpoint', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/ping'
    })
    expect(response.statusCode).toBe(302)
  })

  it('should return 401, when send a request to an endpoint without a valid token', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/ping',
      headers: { authorization: `Bearer fakeToken` }
    })
    expect(response.statusCode).toBe(401)
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
})

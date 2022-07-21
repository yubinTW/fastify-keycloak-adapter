import { FastifyInstance } from 'fastify'
import { KeycloakOptions } from '../keycloak'
import { startFastify } from './server'

describe('Error behavior', () => {
  let server: FastifyInstance

  beforeAll(async () => {})

  afterAll(async () => {})

  it('should error, when given an invalid appOrigin', async () => {
    const keycloakOptions: KeycloakOptions = {
      appOrigin: 'localhost:8888',
      keycloakSubdomain: `localhost:8080/auth/realms/demo`,
      clientId: 'client01',
      clientSecret: 'client01secret'
    }

    try {
      server = await startFastify(8888, keycloakOptions)
      await server.ready()
      fail()
    } catch (error) {
      expect(error).toBeTruthy()
    }
  })

  it('should error, when given an invalid keycloakSubdomain', async () => {
    const keycloakOptions: KeycloakOptions = {
      appOrigin: 'http://localhost:8888',
      keycloakSubdomain: `localhost:8080/auth/realms/demo/`,
      clientId: 'client01',
      clientSecret: 'client01secret'
    }

    try {
      server = await startFastify(8888, keycloakOptions)
      await server.ready()
      fail()
    } catch (error) {
      expect(error).toBeTruthy()
    }
  })
})

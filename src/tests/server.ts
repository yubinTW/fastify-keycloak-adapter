import fastify, { FastifyInstance } from 'fastify'
import keycloak, { KeycloakOptions } from '../keycloak'

const startFastify = async (port: number, keycloakOptions: KeycloakOptions) => {
  const server: FastifyInstance = fastify()

  server.get('/ping', async (request, reply) => {
    return reply.status(200).send({ msg: 'pong' })
  })

  await server.register(keycloak, keycloakOptions)

  await server.listen(port)

  return server
}

export { startFastify }

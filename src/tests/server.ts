import fastify, { FastifyInstance } from 'fastify'
import keycloak, { KeycloakOptions } from '../keycloak'

const startFastify = async (port: number, keycloakOptions: KeycloakOptions) => {
  const server: FastifyInstance = fastify()

  server.get('/ping', async (request, reply) => {
    return reply.status(200).send({ msg: 'pong' })
  })

  server.get('/me', async (request, reply) => {
    const user = request.session.user
    return reply.status(200).send({ user })
  })

  await server.register(keycloak, keycloakOptions)

  await server.listen({
    port: port
  })

  return server
}

export { startFastify }

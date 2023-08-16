import fastify, { FastifyInstance } from 'fastify'

import keycloak, { KeycloakOptions } from '../src/keycloak'

export const serverOf: () => FastifyInstance = () => fastify()

export const serverStart: (
  server: FastifyInstance,
  port: number,
  keycloakOptions: KeycloakOptions
) => Promise<FastifyInstance> = async (server, port, keycloakOptions) => {
  server.get('/ping', async (_request, reply) => {
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

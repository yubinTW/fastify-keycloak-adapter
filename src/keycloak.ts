import fastifyPlugin from 'fastify-plugin'
import cookie from 'fastify-cookie'
import session from '@fastify/session'
import grant, { GrantResponse, GrantSession } from 'grant'
import jwt from 'fastify-jwt'
import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify'
import * as B from 'fp-ts/boolean'
import * as E from 'fp-ts/Either'
import * as O from 'fp-ts/Option'
import { pipe } from 'fp-ts/function'
import { inspect } from 'util'
import axios from 'axios'

declare module 'fastify' {
  interface Session {
    grant: GrantSession
    user: unknown
  }
}

type WellWknownConfiguration = {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint: string
}

export type KeycloakOptions = {
  appOrigin?: string
  keycloakSubdomain?: string
  clientId?: string
  clientSecret?: string
}

export default fastifyPlugin(async (fastify: FastifyInstance, opts: KeycloakOptions) => {
  fastify.register(cookie)

  fastify.register(session, {
    secret: new Array(32).fill('a').join(''),
    cookie: { secure: false }
  })

  const getWellKnownConfiguration = async (url: string) => {
    const response = await axios.get<WellWknownConfiguration>(url)
    return response.data
  }

  const keycloakConfiguration = await getWellKnownConfiguration(
    `http://${opts.keycloakSubdomain}/.well-known/openid-configuration`
  )

  fastify.register(
    grant.fastify()({
      defaults: {
        origin: opts.appOrigin,
        transport: 'session'
      },
      keycloak: {
        key: opts.clientId,
        secret: opts.clientSecret,
        oauth: 2,
        authorize_url: keycloakConfiguration.authorization_endpoint,
        access_url: keycloakConfiguration.token_endpoint,
        callback: '/',
        scope: ['openid'],
        nonce: true
      }
    })
  )

  const realmResponse = await axios.get(`http://${opts.keycloakSubdomain}`)
  const publicKey: string = realmResponse.data['public_key']

  const secretPublicKey = `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`

  fastify.register(jwt, {
    secret: {
      private: 'dummyprivate',
      public: secretPublicKey
    },
    verify: { algorithms: ['RS256'] }
  })

  function getGrantFromSession(request: FastifyRequest): E.Either<Error, GrantSession> {
    return pipe(
      request.session.grant,
      O.fromNullable,
      O.match(
        () => E.left(new Error(`grant not found in session`)),
        () => E.right(request.session.grant)
      )
    )
  }

  function getResponseFromGrant(grant: GrantSession): E.Either<Error, GrantResponse> {
    return pipe(
      grant.response,
      O.fromNullable,
      O.match(
        () => E.left(new Error(`response not found in grant`)),
        (response) => E.right(response)
      )
    )
  }

  function getIdtokenFromResponse(response: GrantResponse): E.Either<Error, string> {
    return pipe(
      response.id_token,
      O.fromNullable,
      O.match(
        () => E.left(new Error(`id_token not found in response with response: ${response}`)),
        (id_token) => E.right(id_token)
      )
    )
  }

  function verifyIdtoken(idToken: string): E.Either<Error, string> {
    return E.tryCatch(
      () => fastify.jwt.verify(idToken),
      (e) => new Error(`Failed to verify id_token: ${e}`)
    )
  }

  function decodedTokenToJson(decodedToken: string): E.Either<Error, any> {
    return E.tryCatch(
      () => JSON.parse(JSON.stringify(decodedToken)),
      (e) => new Error(`Failed to parsing json from decodedToken: ${e}`)
    )
  }

  function authentication(request: FastifyRequest): E.Either<Error, any> {
    return pipe(
      getGrantFromSession(request),
      E.chain(getResponseFromGrant),
      E.chain(getIdtokenFromResponse),
      E.chain(verifyIdtoken),
      E.chain(decodedTokenToJson)
    )
  }

  const getBearerTokenFromRequest = (request: FastifyRequest): O.Option<string> => {
    return pipe(
      request.headers.authorization,
      O.fromNullable,
      O.map((str) => str.substring(7))
    )
  }

  const verifyJwtToken = (token: string): E.Either<Error, string> => {
    return E.tryCatch(
      () => fastify.jwt.verify(token),
      (e) => new Error(`Failed to verify token: ${e}`)
    )
  }

  const grantRoutes = ['/connect/:provider', '/connect/:provider/:override']

  const isGrantRoute = (request: FastifyRequest) => grantRoutes.includes(request.routerPath)

  const userPayloadMapper = (userPayload: any) => ({
    account: userPayload.preferred_username,
    name: userPayload.name
  })

  fastify.addHook('preValidation', (request: FastifyRequest, reply: FastifyReply, done) => {
    pipe(
      request,
      isGrantRoute,
      B.match(
        () => {
          pipe(
            request,
            getBearerTokenFromRequest,
            O.match(
              () => {
                pipe(
                  authentication(request),
                  E.fold(
                    (e) => {
                      request.log.debug(`${e}`)
                      reply.redirect(`${opts.appOrigin}/connect/keycloak`)
                    },
                    (decodedJson) => {
                      request.session.user = userPayloadMapper(decodedJson)
                      request.log.debug(`${inspect(request.session.user, false, null)}`)
                    }
                  )
                )
              },
              (bearerToken) => {
                pipe(
                  bearerToken,
                  verifyJwtToken,
                  E.chain(decodedTokenToJson),
                  E.fold(
                    (e) => {
                      request.log.debug(`${e}`)
                      reply.redirect(process.env.APP_ORIGIN + '/connect/keycloak')
                    },
                    (decodedJson) => {
                      request.session.user = userPayloadMapper(decodedJson)
                      request.log.debug(`${inspect(request.session.user, false, null)}`)
                    }
                  )
                )
              }
            )
          )
        },
        () => {}
      )
    )
    done()
  })

  fastify.get('/logout', async (request, reply) => {
    pipe(
      request.session.user,
      O.fromNullable,
      O.match(
        () => {
          reply.redirect('/')
        },
        () => {
          request.destroySession((err) => {
            if (err) {
              return reply.status(500).send({ msg: `Internal Server Error: ${err}` })
            }
            reply.redirect(`${keycloakConfiguration.end_session_endpoint}?redirect_uri=${opts.appOrigin}`)
          })
        }
      )
    )
  })

  fastify.log.info(`Keycloak registered successfully!`)
  return fastify
})

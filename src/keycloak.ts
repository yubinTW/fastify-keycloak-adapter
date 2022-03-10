import fastifyPlugin from 'fastify-plugin'
import cookie from 'fastify-cookie'
import session from '@fastify/session'
import grant, { GrantResponse, GrantSession } from 'grant'
import jwt from 'fastify-jwt'
import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify'
import * as B from 'fp-ts/boolean'
import * as E from 'fp-ts/Either'
import * as O from 'fp-ts/Option'
import * as TE from 'fp-ts/TaskEither'
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

type RealmResponse = {
  realm: string
  public_key: string
}

export type KeycloakOptions = {
  appOrigin?: string
  keycloakSubdomain?: string
  clientId?: string
  clientSecret?: string
  logoutEndpoint?: string
}

export default fastifyPlugin(async (fastify: FastifyInstance, opts: KeycloakOptions) => {
  function getWellKnownConfiguration(url: string) {
    return TE.tryCatch(
      () => axios.get<WellWknownConfiguration>(url),
      (e) => new Error(`Failed to get openid configuration: ${e}`)
    )
  }

  const keycloakConfiguration = await pipe(
    `http://${opts.keycloakSubdomain}/.well-known/openid-configuration`,
    getWellKnownConfiguration,
    TE.map((response) => response.data)
  )()

  function registerDependentPlugin(config: WellWknownConfiguration) {
    fastify.register(cookie)

    fastify.register(session, {
      secret: new Array(32).fill('a').join(''),
      cookie: { secure: false }
    })

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
          authorize_url: config.authorization_endpoint,
          access_url: config.token_endpoint,
          callback: '/',
          scope: ['openid'],
          nonce: true
        }
      })
    )
  }

  pipe(
    keycloakConfiguration,
    E.match(
      (error) => {
        fastify.log.error(`Failed to get openid-configuration: ${error}`)
      },
      (config) => {
        registerDependentPlugin(config)
      }
    )
  )

  function getRealmResponse(url: string) {
    return TE.tryCatch(
      () => axios.get<RealmResponse>(url),
      (e) => new Error(`${e}`)
    )
  }

  const secretPublicKey = await pipe(
    `http://${opts.keycloakSubdomain}`,
    getRealmResponse,
    TE.map((response) => response.data),
    TE.map((realmResponse) => realmResponse.public_key),
    TE.map((publicKey) => `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`)
  )()

  pipe(
    secretPublicKey,
    E.match(
      (e) => {
        fastify.log.error(`Failed to get public key: ${e}`)
      },
      (publicKey) => {
        fastify.register(jwt, {
          secret: {
            private: 'dummyprivate',
            public: publicKey
          },
          verify: { algorithms: ['RS256'] }
        })
      }
    )
  )

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

  function getBearerTokenFromRequest(request: FastifyRequest): O.Option<string> {
    return pipe(
      request.headers.authorization,
      O.fromNullable,
      O.map((str) => str.substring(7))
    )
  }

  function verifyJwtToken(token: string): E.Either<Error, string> {
    return E.tryCatch(
      () => fastify.jwt.verify(token),
      (e) => new Error(`Failed to verify token: ${e}`)
    )
  }

  const grantRoutes = ['/connect/:provider', '/connect/:provider/:override']

  function isGrantRoute(request: FastifyRequest): boolean {
    return grantRoutes.includes(request.routerPath)
  }

  const userPayloadMapper = (userPayload: any) => ({
    account: userPayload.preferred_username,
    name: userPayload.name
  })

  function authenticationByGrant(request: FastifyRequest, reply: FastifyReply) {
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
  }

  function authenticationByToken(request: FastifyRequest, reply: FastifyReply, bearerToken: string) {
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
                authenticationByGrant(request, reply)
              },
              (bearerToken) => {
                authenticationByToken(request, reply, bearerToken)
              }
            )
          )
        },
        () => {}
      )
    )
    done()
  })

  function logout(request: FastifyRequest, reply: FastifyReply) {
    request.destroySession((error) => {
      pipe(
        error,
        O.fromNullable,
        O.match(
          () => {
            pipe(
              keycloakConfiguration,
              E.map((config) => reply.redirect(`${config.end_session_endpoint}?redirect_uri=${opts.appOrigin}`))
            )
          },
          (e) => {
            request.log.error(`Failed to logout: ${e}`)
            reply.status(500).send({ msg: `Internal Server Error: ${e}` })
          }
        )
      )
    })
  }

  const logoutEndpoint = opts.logoutEndpoint ?? '/logout'

  fastify.get(logoutEndpoint, async (request, reply) => {
    pipe(
      request.session.user,
      O.fromNullable,
      O.match(
        () => {
          reply.redirect('/')
        },
        () => {
          logout(request, reply)
        }
      )
    )
  })

  fastify.log.info(`Keycloak registered successfully!`)
  return fastify
})

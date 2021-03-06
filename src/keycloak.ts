import fastifyPlugin from 'fastify-plugin'
import cookie from '@fastify/cookie'
import session from '@fastify/session'
import grant, { GrantResponse, GrantSession } from 'grant'
import jwt from '@fastify/jwt'
import { FastifyRequest, FastifyReply, FastifyInstance } from 'fastify'
import * as B from 'fp-ts/boolean'
import * as E from 'fp-ts/Either'
import * as O from 'fp-ts/Option'
import * as TE from 'fp-ts/TaskEither'
import { pipe } from 'fp-ts/function'
import * as t from 'io-ts'
import { inspect } from 'util'
import axios from 'axios'
import axiosRetry from 'axios-retry'
import wcmatch from 'wildcard-match'

declare module 'fastify' {
  interface Session {
    grant: GrantSession
    user: unknown
  }
}

type WellKnownConfiguration = {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint: string
}

type RealmResponse = {
  realm: string
  public_key: string
}

export type UserInfo = {
  email_verified: Readonly<boolean>
  name: Readonly<string>
  preferred_username: Readonly<string>
  given_name: Readonly<string>
  family_name: Readonly<string>
}

const AppOriginCodec = new t.Type<string, string, unknown>(
  'AppOrigin',
  (input: unknown): input is string => typeof input === 'string',
  (input, context) =>
    typeof input === 'string' &&
    (input.startsWith('http://') || input.startsWith('https://')) &&
    input.endsWith('/') === false
      ? t.success(input)
      : t.failure(input, context),
  (a) => t.identity(a)
)

const KeycloakSubdomainCodec = new t.Type<string, string, unknown>(
  'KeycloakSubdomain',
  (input: unknown): input is string => typeof input === 'string',
  (input, context) =>
    typeof input === 'string' &&
    input.length > 0 &&
    input.startsWith('http://') === false &&
    input.startsWith('https://') === false &&
    input.endsWith('/') === false
      ? t.success(input)
      : t.failure(input, context),
  (a) => t.identity(a)
)

const requiredOptions = t.type({
  appOrigin: t.readonly(AppOriginCodec),
  keycloakSubdomain: t.readonly(KeycloakSubdomainCodec),
  clientId: t.readonly(t.string),
  clientSecret: t.readonly(t.string)
})

const partialOptions = t.partial({
  useHttps: t.readonly(t.boolean),
  logoutEndpoint: t.readonly(t.string),
  excludedPatterns: t.readonly(t.array(t.string)),
  scope: t.array(t.readonly(t.string)),
  disableCookiePlugin: t.readonly(t.boolean),
  disableSessionPlugin: t.readonly(t.boolean),
  retries: t.readonly(t.number)
})

const KeycloakOptions = t.intersection([requiredOptions, partialOptions])

export type KeycloakOptions = t.TypeOf<typeof KeycloakOptions> & {
  userPayloadMapper?: (userPayload: UserInfo) => {}
  unauthorizedHandler?: (request: FastifyRequest, reply: FastifyReply) => void
}

function getWellKnownConfiguration(url: string) {
  return TE.tryCatch(
    () => axios.get<WellKnownConfiguration>(url),
    (e) => new Error(`${e}`)
  )
}

function validAppOrigin(opts: KeycloakOptions): E.Either<Error, KeycloakOptions> {
  return pipe(
    opts.appOrigin,
    AppOriginCodec.decode,
    E.match(
      (_) => E.left(new Error(`Invalid appOrigin: ${opts.appOrigin}`)),
      (_) => E.right(opts)
    )
  )
}

function validKeycloakSubdomain(opts: KeycloakOptions): E.Either<Error, KeycloakOptions> {
  return pipe(
    opts.keycloakSubdomain,
    KeycloakSubdomainCodec.decode,
    E.match(
      (_) => E.left(new Error(`Invalid keycloakSubdomain: ${opts.keycloakSubdomain}`)),
      (_) => E.right(opts)
    )
  )
}

export default fastifyPlugin(async (fastify: FastifyInstance, opts: KeycloakOptions) => {
  axiosRetry(axios, {
    retries: opts.retries ? opts.retries : 3,
    retryDelay: axiosRetry.exponentialDelay,
    onRetry: (retryCount, error, _requestConfig) => {
      fastify.log.error(`Retry #${retryCount} ${error.message}`)
    }
  })

  pipe(
    opts,
    validAppOrigin,
    E.chain(validKeycloakSubdomain),
    E.match(
      (e) => {
        fastify.log.error(`${e}`)
        throw new Error(e.message)
      },
      (_) => {
        fastify.log.debug(`Keycloak Options valid successfully! ${inspect(opts, false, null)}`)
      }
    )
  )

  const protocol = opts.useHttps ? 'https://' : 'http://'

  const keycloakConfiguration = await pipe(
    `${protocol}${opts.keycloakSubdomain}/.well-known/openid-configuration`,
    getWellKnownConfiguration,
    TE.map((response) => response.data)
  )()

  function registerDependentPlugin(config: WellKnownConfiguration) {
    if (!opts.disableCookiePlugin) {
      fastify.register(cookie)
    }

    if (!opts.disableSessionPlugin) {
      fastify.register(session, {
        secret: new Array(32).fill('a').join(''),
        cookie: { secure: false }
      })
    }

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
          scope: opts.scope ?? ['openid'],
          nonce: true
        }
      })
    )
  }

  pipe(
    keycloakConfiguration,
    E.match(
      (error) => {
        fastify.log.fatal(`Failed to get openid-configuration: ${error}`)
        throw new Error(`Failed to get openid-configuration: ${error}`)
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
    `${protocol}${opts.keycloakSubdomain}`,
    getRealmResponse,
    TE.map((response) => response.data),
    TE.map((realmResponse) => realmResponse.public_key),
    TE.map((publicKey) => `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`)
  )()

  pipe(
    secretPublicKey,
    E.match(
      (e) => {
        fastify.log.fatal(`Failed to get public key: ${e}`)
        throw new Error(`Failed to get public key: ${e}`)
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

  const userPayloadMapper = pipe(
    opts.userPayloadMapper,
    O.fromNullable,
    O.match(
      () => (userPayload: UserInfo) => ({
        account: userPayload.preferred_username,
        name: userPayload.name
      }),
      (a) => a
    )
  )

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

  const unauthorizedHandler = pipe(
    opts.unauthorizedHandler,
    O.fromNullable,
    O.match(
      () => (_request: FastifyRequest, reply: FastifyReply) => {
        reply.status(401).send(`Unauthorized`)
      },
      (a) => a
    )
  )

  function authenticationByToken(request: FastifyRequest, reply: FastifyReply, bearerToken: string) {
    pipe(
      bearerToken,
      verifyJwtToken,
      E.chain(decodedTokenToJson),
      E.fold(
        (e) => {
          request.log.debug(`${e}`)
          unauthorizedHandler(request, reply)
        },
        (decodedJson) => {
          request.session.user = userPayloadMapper(decodedJson)
          request.log.debug(`${inspect(request.session.user, false, null)}`)
        }
      )
    )
  }

  const matchers = pipe(
    opts.excludedPatterns?.map((pattern) => wcmatch(pattern)),
    O.fromNullable
  )

  function filterExcludedPattern(request: FastifyRequest) {
    return pipe(
      matchers,
      O.map((matchers) => matchers.filter((matcher) => matcher(request.url))),
      O.map((matchers) => matchers.length > 0),
      O.match(
        () => O.of(request),
        (b) =>
          pipe(
            b,
            B.match(
              () => O.of(request),
              () => O.none
            )
          )
      )
    )
  }

  function filterGrantRoute(request: FastifyRequest) {
    return pipe(
      request,
      O.fromPredicate((request) => !isGrantRoute(request))
    )
  }

  fastify.addHook('preValidation', (request: FastifyRequest, reply: FastifyReply, done) => {
    pipe(
      request,
      filterGrantRoute,
      O.chain(filterExcludedPattern),
      O.map((request) =>
        pipe(
          request,
          getBearerTokenFromRequest,
          O.match(
            () => authenticationByGrant(request, reply),
            (bearerToken) => authenticationByToken(request, reply, bearerToken)
          )
        )
      )
    )
    done()
  })

  function logout(request: FastifyRequest, reply: FastifyReply) {
    request.session.destroy((error) => {
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

import fastify, { FastifyInstance, FastifyRequest } from 'fastify'
import { expect } from 'tstyche'
import fastifyOauth2, {
  FastifyOAuth2Options,
  Credentials,
  OAuth2Namespace,
  OAuth2Token,
  ProviderConfiguration,
  UserInfoExtraOptions
} from '.'
import type { ModuleOptions } from 'simple-oauth2'

/**
 * Preparing some data for testing.
 */
const auth = fastifyOauth2.GOOGLE_CONFIGURATION
const scope = ['r_emailaddress', 'r_basicprofile']
const tags = ['oauth2', 'oauth']
const credentials: Credentials = {
  client: {
    id: 'test_id',
    secret: 'test_secret',
  },
  auth,
}

const simpleOauth2Options: ModuleOptions = {
  client: {
    id: 'test_id',
    secret: 'test_secret',
  },
  auth,
}

const OAuth2NoneOptional: FastifyOAuth2Options = {
  name: 'testOAuthName',
  credentials,
  callbackUri: 'http://localhost/testOauth/callback'
}

const OAuth2Options: FastifyOAuth2Options = {
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  generateStateFunction: function () {
    expect(this).type.toBe<FastifyInstance>()
    return 'test'
  },
  checkStateFunction: function () {
    expect(this).type.toBe<FastifyInstance>()
    return true
  },
  startRedirectPath: '/login/testOauth',
  cookie: {
    secure: true,
    sameSite: 'none'
  },
  redirectStateCookieName: 'redirect-state-cookie',
  verifierCookieName: 'verifier-cookie',
}

expect<FastifyOAuth2Options>().type.toBeAssignableFrom({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  pkce: 'S256' as const
})

expect<FastifyOAuth2Options>().type.toBeAssignableFrom({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: (req: FastifyRequest) => `${req.protocol}://${req.hostname}/callback`,
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  pkce: 'S256' as const
})

expect<FastifyOAuth2Options>().type.toBeAssignableFrom({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  discovery: { issuer: 'https://idp.mycompany.com' }
})

expect<FastifyOAuth2Options>().type.not.toBeAssignableFrom({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  discovery: { issuer: 1 }
})

expect<FastifyOAuth2Options>().type.toBeAssignableFrom({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  pkce: 'plain' as const
})

expect<FastifyOAuth2Options>()
  .type.not.toBeAssignableFrom({
    name: 'testOAuthName',
    scope,
    credentials,
    callbackUri: 'http://localhost/testOauth/callback',
    callbackUriParams: {},
    generateStateFunction: () => {},
    checkStateFunction: () => {},
    startRedirectPath: '/login/testOauth',
    pkce: 'SOMETHING' as const
  })

const server = fastify()

server.register(fastifyOauth2, OAuth2NoneOptional)
server.register(fastifyOauth2, OAuth2Options)

server.register(fastifyOauth2, {
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  checkStateFunction: () => true,
})

expect(server.register).type.not.toBeCallableWith(fastifyOauth2, {
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  checkStateFunction: () => true,
  startRedirectPath: 2
})

declare module 'fastify' {
  interface FastifyInstance {
    testOAuthName: OAuth2Namespace;
  }
}

/**
 * Actual testing.
 */
expect(auth).type.toBe<ProviderConfiguration>()
expect(scope).type.toBe<string[]>()
expect(tags).type.toBe<string[]>()
expect(credentials).type.toBe<Credentials>()

// Ensure duplicated simple-oauth2 are compatible with simple-oauth2
expect({ auth: { tokenHost: '' }, ...credentials }).type.toBeAssignableTo<ModuleOptions<string>>()
expect(auth).type.toBeAssignableTo<ModuleOptions['auth']>()

// Ensure published types of simple-oauth2 are accepted
expect(simpleOauth2Options).type.toBeAssignableTo<Credentials>()
expect(simpleOauth2Options.auth).type.toBeAssignableTo<ProviderConfiguration>()

expect(fastifyOauth2).type.not.toBeCallableWith()
expect(fastifyOauth2).type.not.toBeCallableWith(server, {}, () => {})

expect(fastifyOauth2.DISCORD_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.FACEBOOK_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.GITHUB_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.GITLAB_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.GOOGLE_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.LINKEDIN_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(
  fastifyOauth2.MICROSOFT_CONFIGURATION
).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.SPOTIFY_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(
  fastifyOauth2.VKONTAKTE_CONFIGURATION
).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.TWITCH_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.VATSIM_CONFIGURATION).type.toBe<ProviderConfiguration>()
expect(
  fastifyOauth2.VATSIM_DEV_CONFIGURATION
).type.toBe<ProviderConfiguration>()
expect(
  fastifyOauth2.EPIC_GAMES_CONFIGURATION
).type.toBe<ProviderConfiguration>()
expect(fastifyOauth2.YANDEX_CONFIGURATION).type.toBe<ProviderConfiguration>()

server.get('/testOauth/callback', async (request, reply) => {
  expect(server.oauth2TestOAuthName).type.toBe<OAuth2Namespace | undefined>()

  expect(server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)).type.toBe<Promise<OAuth2Token>>()

  expect(server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, reply)).type.toBe<Promise<OAuth2Token>>()

  expect(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, (_err: any, _t: OAuth2Token): void => {
    })
  ).type.toBe<void>()

  expect(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, reply, (_err: any, _t: OAuth2Token): void => {
    })
  ).type.toBe<void>()

  const token = await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)
  if (token.token.refresh_token) {
    expect(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.token, {})
    ).type.toBe<Promise<OAuth2Token>>()

    expect(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(
        token.token,
        {},
        (_err: any, _t: OAuth2Token): void => {
        }
      )
    ).type.toBe<void>()

    expect(server.testOAuthName.revokeToken(token.token, 'access_token', undefined)).type.toBe<Promise<void>>()

    expect(server.testOAuthName.revokeToken).type.not.toBeCallableWith(
      token.token,
      'test',
      undefined
    )
    expect(
      server.testOAuthName.revokeToken(token.token, 'refresh_token', undefined, (_err: any): void => {
      })
    ).type.toBe<void>()

    expect(server.testOAuthName.revokeToken).type.not.toBeCallableWith(
      token.token,
      'test',
      undefined,
      (_err: any): void => {}
    )
    expect(server.testOAuthName.revokeToken).type.not.toBeCallableWith(token.token, 'test', undefined)

    expect(server.testOAuthName.revokeAllToken(token.token, undefined)).type.not.toBe<void>()

    expect(server.testOAuthName.revokeAllToken(token.token, undefined)).type.toBe<Promise<void>>()

    expect(server.testOAuthName.revokeAllToken(token.token, undefined, (_err: any): void => {
    })).type.toBe<void>()

    expect(server.testOAuthName.revokeToken).type.not.toBeCallableWith(
      token.token,
      'access_token',
      undefined,
      undefined
    )

    expect(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.token, {})
    ).type.toBe<Promise<OAuth2Token>>()

    expect(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(
        token.token,
        {},
        (_err: any, _t: OAuth2Token): void => {}
      )
    ).type.toBe<void>()
  }

  expect(server.testOAuthName.generateAuthorizationUri(request, reply)).type.toBe<Promise<string>>()
  expect(server.testOAuthName.generateAuthorizationUri(request, reply, (_err) => {})).type.toBe<void>()

  // BEGIN userinfo tests
  expect(server.testOAuthName.userinfo(token.token)).type.toBe<Promise<Object>>()
  expect(server.testOAuthName.userinfo(token.token.access_token)).type.toBe<Promise<Object>>()
  expect(server.testOAuthName.userinfo(token.token.access_token, () => {})).type.toBe<void>()
  expect(server.testOAuthName.userinfo(token.token.access_token, undefined, () => {})).type.toBe<void>()

  expect<UserInfoExtraOptions>().type.toBeAssignableFrom({ method: 'GET' as const, params: {}, via: 'header' as const })
  expect<UserInfoExtraOptions>().type.toBeAssignableFrom({ method: 'POST' as const, params: { a: 1 }, via: 'header' as const })
  expect<UserInfoExtraOptions>().type.toBeAssignableFrom({ via: 'body' as const })
  expect<UserInfoExtraOptions>().type.not.toBeAssignableFrom({
    via: 'donkey' as const
  })
  expect<UserInfoExtraOptions>().type.not.toBeAssignableFrom({
    something: 1
  })
  // END userinfo tests

  expect(
    server.testOAuthName.generateAuthorizationUri(request, reply)
  ).type.toBe<Promise<string>>()

  expect(
    server.testOAuthName.generateAuthorizationUri
  ).type.not.toBeCallableWith(request)

  return {
    access_token: token.token.access_token,
  }
})

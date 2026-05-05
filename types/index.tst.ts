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

expect({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  pkce: 'S256'
} as const).type.toBeAssignableTo<FastifyOAuth2Options>()

expect({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: (req: FastifyRequest) => `${req.protocol}://${req.hostname}/callback`,
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  pkce: 'S256'
} as const).type.toBeAssignableTo<FastifyOAuth2Options>()

expect({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  discovery: { issuer: 'https://idp.mycompany.com' }
} as const).type.toBeAssignableTo<FastifyOAuth2Options>()

expect({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  discovery: { issuer: 1 }
}).type.not.toBeAssignableTo<FastifyOAuth2Options>()

expect({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  startRedirectPath: '/login/testOauth',
  pkce: 'plain'
} as const).type.toBeAssignableTo<FastifyOAuth2Options>()

expect({
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  generateStateFunction: () => {
  },
  checkStateFunction: () => {
  },
  startRedirectPath: '/login/testOauth',
  pkce: 'SOMETHING'
}).type.not.toBeAssignableTo<FastifyOAuth2Options>()

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

// @ts-expect-error!
server.register(fastifyOauth2, {
  name: 'testOAuthName',
  scope,
  credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  checkStateFunction: () => true,
  startRedirectPath: 2,
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

// @ts-expect-error!
fastifyOauth2()

// @ts-expect-error!
fastifyOauth2(server, {}, () => {})

expect(fastifyOauth2.DISCORD_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.FACEBOOK_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.GITHUB_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.GITLAB_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.GOOGLE_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.LINKEDIN_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.MICROSOFT_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.SPOTIFY_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.VKONTAKTE_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.TWITCH_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.VATSIM_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.VATSIM_DEV_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.EPIC_GAMES_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()
expect(fastifyOauth2.YANDEX_CONFIGURATION).type.toBeAssignableTo<ProviderConfiguration>()

server.get('/testOauth/callback', async (request, reply) => {
  expect(server.testOAuthName).type.toBe<OAuth2Namespace>()
  expect(server.oauth2TestOAuthName).type.toBe<OAuth2Namespace | undefined>()

  expect(await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)).type.toBe<OAuth2Token>()
  expect(server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)).type.toBe<Promise<OAuth2Token>>()

  expect(await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, reply)).type.toBe<OAuth2Token>()
  expect(server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, reply)).type.toBe<Promise<OAuth2Token>>()

  expect(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, (_err: any, _t: OAuth2Token): void => {
    })
  ).type.toBe<void>()

  expect(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, reply, (_err: any, _t: OAuth2Token): void => {
    })
  ).type.toBe<void>()

  expect(
    await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)
  ).type.not.toBe<void>()

  expect(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(
      request,
      (_err: any, _t: OAuth2Token): void => {}
    )
  ).type.not.toBe<OAuth2Token>()

  expect(server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)).type.not.toBe<void>()

  const token = await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)
  if (token.token.refresh_token) {
    expect(
      await server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.token, {})
    ).type.toBe<OAuth2Token>()

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

    expect(server.testOAuthName.revokeToken(token.token, 'access_token', undefined)).type.not.toBe<void>()

    expect(server.testOAuthName.revokeToken(token.token, 'access_token', undefined)).type.toBe<Promise<void>>()

    // @ts-expect-error!
    server.testOAuthName.revokeToken(token.token, 'test', undefined)

    expect(
      server.testOAuthName.revokeToken(token.token, 'refresh_token', undefined, (_err: any): void => {
      })
    ).type.toBe<void>()

    // @ts-expect-error!
    server.testOAuthName.revokeToken(token.token, 'test', undefined, (_err: any): void => {})

    // @ts-expect-error!
    server.testOAuthName.revokeToken(token.token, 'access_token', undefined, undefined)

    expect(server.testOAuthName.revokeAllToken(token.token, undefined)).type.not.toBe<void>()

    expect(server.testOAuthName.revokeAllToken(token.token, undefined)).type.toBe<Promise<void>>()

    expect(server.testOAuthName.revokeAllToken(token.token, undefined, (_err: any): void => {
    })).type.toBe<void>()

    // @ts-expect-error!
    server.testOAuthName.revokeAllToken(token.token, undefined, undefined)

    expect(await server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.token, {})).type.not.toBe<void>()

    expect(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(
        token.token,
        {},
        (_err: any, _t: OAuth2Token): void => {
        }
      )
    ).type.not.toBe<OAuth2Token>()

    expect(server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.token, {})).type.not.toBe<void>()
  }

  expect(server.testOAuthName.generateAuthorizationUri(request, reply)).type.toBe<Promise<string>>()
  expect(server.testOAuthName.generateAuthorizationUri(request, reply, (_err) => {})).type.toBe<void>()

  // BEGIN userinfo tests
  expect(server.testOAuthName.userinfo(token.token)).type.toBe<Promise<Object>>()
  expect(server.testOAuthName.userinfo(token.token.access_token)).type.toBe<Promise<Object>>()
  expect(await server.testOAuthName.userinfo(token.token.access_token)).type.toBe<Object>()
  expect(server.testOAuthName.userinfo(token.token.access_token, () => {})).type.toBe<void>()
  expect(server.testOAuthName.userinfo(token.token.access_token, undefined, () => {})).type.toBe<void>()

  expect({ method: 'GET', params: {}, via: 'header' } as const).type.toBeAssignableTo<UserInfoExtraOptions>()
  expect({ method: 'POST', params: { a: 1 }, via: 'header' } as const).type.toBeAssignableTo<UserInfoExtraOptions>()
  expect({ via: 'body' } as const).type.toBeAssignableTo<UserInfoExtraOptions>()

  expect({ via: 'donkey' }).type.not.toBeAssignableTo<UserInfoExtraOptions>()
  expect({ something: 1 }).type.not.toBeAssignableTo<UserInfoExtraOptions>()
  // END userinfo tests

  expect(await server.testOAuthName.generateAuthorizationUri(request, reply)).type.toBe<string>()

  // @ts-expect-error!
  server.testOAuthName.generateAuthorizationUri(request)

  return {
    access_token: token.token.access_token,
  }
})

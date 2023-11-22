'use strict'

const t = require('tap')
const nock = require('nock')
const createFastify = require('fastify')
const crypto = require('node:crypto')
const fastifyOauth2 = require('..')

nock.disableNetConnect()

function makeRequests (t, fastify, userAgentHeaderMatcher, pkce, discoveryHost, omitCodeChallenge, discoveryHostOptions = {}) {
  let discoveryScope
  if (discoveryHost) {
    const METADATA_BODY = {
      authorization_endpoint: 'https://github.com/login/oauth/access_token',
      token_endpoint: 'https://github.com/login/oauth/access_token',
      revocation_endpoint: 'https://github.com/login/oauth/access_token',
      code_challenge_methods_supported: omitCodeChallenge ? null : pkce === 'S256' ? ['S256', 'plain'] : pkce === 'plain' ? ['plain'] : null
    }
    discoveryScope = nock(discoveryHost)
      .matchHeader('User-Agent', userAgentHeaderMatcher || 'fastify-oauth2')
      .get('/.well-known/openid-configuration')

    if (discoveryHostOptions.error) {
      discoveryScope = discoveryScope.replyWithError(discoveryHostOptions.error)
    } else {
      discoveryScope = discoveryScope.reply(200, discoveryHostOptions.badJSON ? '####$$%' : METADATA_BODY)
    }
  }

  fastify.listen({ port: 0 }, function (err) {
    if (discoveryHostOptions.badJSON) {
      t.equal(err.message, 'Unexpected token \'#\', "####$$%" is not valid JSON')
      discoveryScope?.done()
      t.end()
      return
    }

    if (discoveryHostOptions.error) {
      t.equal(err.message, 'Problem calling discovery endpoint. See innerError for details.')
      t.equal(err.innerError.code, 'ETIMEDOUT')
      discoveryScope?.done()
      t.end()
      return
    }

    t.error(err, 'not expecting error here!')

    fastify.inject({
      method: 'GET',
      url: '/login/github'
    }, function (err, responseStart) {
      t.error(err)

      t.equal(responseStart.statusCode, 302)

      const { searchParams } = new URL(responseStart.headers.location)
      const [state, codeChallengeMethod, codeChallenge] = ['state', 'code_challenge_method', 'code_challenge'].map(k => searchParams.get(k))

      t.ok(state)
      if (pkce) {
        t.strictSame(codeChallengeMethod, pkce, 'pkce method must match')
        t.ok(codeChallenge, 'code challenge is present')
      }

      const RESPONSE_BODY = {
        access_token: 'my-access-token',
        refresh_token: 'my-refresh-token',
        token_type: 'Bearer',
        expires_in: '240000'
      }

      const RESPONSE_BODY_REFRESHED = {
        access_token: 'my-access-token-refreshed',
        refresh_token: 'my-refresh-token-refreshed',
        token_type: 'Bearer',
        expires_in: '240000'
      }

      const githubScope = nock('https://github.com')
        .matchHeader('Authorization', 'Basic bXktY2xpZW50LWlkOm15LXNlY3JldA==')
        .matchHeader('User-Agent', userAgentHeaderMatcher || 'fastify-oauth2')
        .post('/login/oauth/access_token', 'grant_type=authorization_code&code=my-code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback' + (pkce ? '&code_verifier=myverifier' : ''))
        .reply(200, RESPONSE_BODY)
        .post('/login/oauth/access_token', 'grant_type=refresh_token&refresh_token=my-refresh-token')
        .reply(200, RESPONSE_BODY_REFRESHED)

      fastify.inject({
        method: 'GET',
        url: '/?code=my-code&state=' + state,
        cookies: {
          'oauth2-redirect-state': state,
          'oauth2-code-verifier': pkce ? 'myverifier' : undefined
        }
      }, function (err, responseEnd) {
        t.error(err)

        t.equal(responseEnd.statusCode, 200)
        t.strictSame(JSON.parse(responseEnd.payload), RESPONSE_BODY_REFRESHED)

        githubScope.done()
        discoveryScope?.done()
        t.end()
      })
    })
  })
}

t.test('fastify-oauth2', t => {
  t.test('callback', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications']
    })

    fastify.get('/', function (request, reply) {
      if (this.githubOAuth2 !== this.oauth2GithubOAuth2) {
        throw new Error('Expected oauth2GithubOAuth2 to match githubOAuth2')
      }
      this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, (err, result) => {
        if (err) throw err

        // attempts to refresh the token
        this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token, undefined, (err, result) => {
          if (err) throw err

          const newToken = result

          reply.send({
            access_token: newToken.token.access_token,
            refresh_token: newToken.token.refresh_token,
            expires_in: newToken.token.expires_in,
            token_type: newToken.token.token_type
          })
        })
      })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify)
  })

  t.test('promise', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications']
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify)
  })

  t.test('wrong state', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: '/callback'
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)
        .catch(e => {
          reply.code(400)
          return e.message
        })
    })

    t.teardown(fastify.close.bind(fastify))

    fastify.inject({
      method: 'GET',
      url: '/?code=my-code&state=wrong-state'
    }, function (err, responseEnd) {
      t.error(err)

      t.equal(responseEnd.statusCode, 400)
      t.strictSame(responseEnd.payload, 'Invalid state')

      t.end()
    })
  })

  t.test('custom user-agent', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      userAgent: 'test/1.2.3'
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, 'test/1.2.3')
  })

  t.test('overridden user-agent', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION,
        http: {
          headers: {
            'User-Agent': 'foo/4.5.6'
          }
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      userAgent: 'test/1.2.3'
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, /^foo\/4\.5\.6$/)
  })

  t.test('disabled user-agent', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      userAgent: false
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, userAgent => userAgent === undefined)
  })

  t.test('pkce.plain', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      pkce: 'plain'
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, 'plain')
  })

  t.test('pkce.S256', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      pkce: 'S256'
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, 'S256')
  })

  t.test('discovery with S256 - automatic', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      discovery: {
        issuer: 'https://github.com'
      }
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, 'S256', 'https://github.com')
  })

  t.test('discovery with plain - automatic', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      discovery: {
        issuer: 'https://github.com'
      }
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, 'plain', 'https://github.com')
  })

  t.test('discovery with no code challenge method - explicitly set instead', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      pkce: 'S256',
      discovery: {
        issuer: 'https://github.com'
      }
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, 'S256', 'https://github.com', true)
  })

  t.test('discovery with S256 - automatic, supported full discovery URL', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      discovery: {
        issuer: 'https://github.com/.well-known/openid-configuration'
      }
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, undefined, 'https://github.com')
  })

  t.test('discovery with S256 - automatic, supported deep mount without a trailing slash', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      discovery: {
        issuer: 'https://github.com/deepmount' // no trailin slash
      }
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, undefined, 'https://github.com/deepmount') // no trailin slash
  })

  t.test('discovery - supports HTTP', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      discovery: {
        issuer: 'http://github.com'
      }
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, undefined, 'http://github.com')
  })

  t.test('discovery - supports omitting user agent', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      discovery: {
        issuer: 'http://github.com'
      },
      userAgent: false
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, userAgent => userAgent === undefined, undefined, 'http://github.com')
  })

  t.test('discovery - failed gracefully when discovery host gives bad data', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      discovery: {
        issuer: 'http://github.com'
      }
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, undefined, 'http://github.com', undefined, { badJSON: true })
  })

  t.test('discovery - failed gracefully when discovery host errs with ETIMEDOUT or similar', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        }
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications'],
      discovery: {
        issuer: 'http://github.com'
      }
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.token)
        })
        .then(token => {
          return {
            access_token: token.token.access_token,
            refresh_token: token.token.refresh_token,
            expires_in: token.token.expires_in,
            token_type: token.token.token_type
          }
        })
    })

    t.teardown(fastify.close.bind(fastify))

    makeRequests(t, fastify, undefined, undefined, 'http://github.com', undefined, { error: { code: 'ETIMEDOUT' } })
  })

  t.end()
})

t.test('options.name should be a string', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2)
    .ready(err => {
      t.strictSame(err.message, 'options.name should be a string')
    })
})

t.test('options.credentials should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name'
  })
    .ready(err => {
      t.strictSame(err.message, 'options.credentials should be an object')
    })
})

t.test('options.callbackUri should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    }
  })
    .ready(err => {
      t.strictSame(err.message, 'options.callbackUri should be a string')
    })
})

t.test('options.callbackUriParams should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    callbackUriParams: 1
  })
    .ready(err => {
      t.strictSame(err.message, 'options.callbackUriParams should be a object')
    })
})

t.test('options.callbackUriParams', t => {
  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    startRedirectPath: '/login/github',
    callbackUri: '/callback',
    callbackUriParams: {
      access_type: 'offline'
    },
    scope: ['notifications']
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.listen({ port: 0 }, function (err) {
    t.error(err)

    fastify.inject({
      method: 'GET',
      url: '/login/github'
    }, function (err, responseStart) {
      t.error(err)

      t.equal(responseStart.statusCode, 302)
      const matched = responseStart.headers.location.match(/https:\/\/github\.com\/login\/oauth\/authorize\?response_type=code&client_id=my-client-id&access_type=offline&redirect_uri=%2Fcallback&scope=notifications&state=(.*)/)
      t.ok(matched)
      t.end()
    })
  })
})

t.test('options.tokenRequestParams should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    tokenRequestParams: 1
  })
    .ready(err => {
      t.strictSame(err.message, 'options.tokenRequestParams should be a object')
    })
})

t.test('options.tokenRequestParams', t => {
  t.plan(2)

  const fastify = createFastify({ logger: { level: 'silent' } })
  const oAuthCode = '123456789'

  fastify.register(fastifyOauth2, {
    name: 'githubOAuth2',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    startRedirectPath: '/login/github',
    callbackUri: 'http://localhost:3000/callback',
    generateStateFunction: function () {
      return 'dummy'
    },
    checkStateFunction: function (state, callback) {
      callback()
    },
    tokenRequestParams: {
      param1: '123'
    },
    scope: ['notifications']
  })

  const githubScope = nock('https://github.com')
    .post(
      '/login/oauth/access_token',
      'grant_type=authorization_code&param1=123&code=123456789&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback',
      {
        reqheaders: {
          authorization: 'Basic bXktY2xpZW50LWlkOm15LXNlY3JldA=='
        }
      }
    )
    .reply(200, {})

  fastify.get('/callback', function (request, reply) {
    return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)
      .catch(e => {
        reply.code(400)
        return e.message
      })
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.listen({ port: 0 }, function (err) {
    t.error(err)

    fastify.inject({
      method: 'GET',
      url: '/callback?code=' + oAuthCode
    }, function (err) {
      t.error(err)

      githubScope.done()
    })
  })
})

t.test('options.generateStateFunction with request', t => {
  t.plan(5)
  const fastify = createFastify()

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    startRedirectPath: '/login/github',
    callbackUri: '/callback',
    generateStateFunction: (request) => {
      t.ok(request, 'the request param has been set')
      return request.query.code
    },
    checkStateFunction: () => true,
    scope: ['notifications']
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.listen({ port: 0 }, function (err) {
    t.error(err)

    fastify.inject({
      method: 'GET',
      url: '/login/github',
      query: { code: 'generated_code' }
    }, function (err, responseStart) {
      t.error(err)
      t.equal(responseStart.statusCode, 302)
      const matched = responseStart.headers.location.match(/https:\/\/github\.com\/login\/oauth\/authorize\?response_type=code&client_id=my-client-id&redirect_uri=%2Fcallback&scope=notifications&state=generated_code/)
      t.ok(matched)
    })
  })
})

t.test('generateAuthorizationUri redirect with request object', t => {
  const fastify = createFastify()

  fastify.register(fastifyOauth2, {
    name: 'theName',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    generateStateFunction: (request) => {
      t.ok(request, 'the request param has been set')
      return request.query.code
    },
    checkStateFunction: () => true,
    scope: ['notifications']
  })

  fastify.get('/gh', function (request, reply) {
    const redirectUrl = this.theName.generateAuthorizationUri(request, reply)
    return reply.redirect(redirectUrl)
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.inject({
    method: 'GET',
    url: '/gh',
    query: { code: 'generated_code' }
  }, function (err, responseStart) {
    t.error(err)
    t.equal(responseStart.statusCode, 302)
    const matched = responseStart.headers.location.match(/https:\/\/github\.com\/login\/oauth\/authorize\?response_type=code&client_id=my-client-id&redirect_uri=%2Fcallback&scope=notifications&state=generated_code/)
    t.ok(matched)
    t.end()
  })
})

t.test('options.generateStateFunction should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    generateStateFunction: 42
  })
    .ready(err => {
      t.strictSame(err.message, 'options.generateStateFunction should be a function')
    })
})

t.test('options.checkStateFunction should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    generateStateFunction: () => { },
    checkStateFunction: 42
  })
    .ready(err => {
      t.strictSame(err.message, 'options.checkStateFunction should be a function')
    })
})

t.test('options.startRedirectPath should be a string', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    startRedirectPath: 42
  })
    .ready(err => {
      t.strictSame(err.message, 'options.startRedirectPath should be a string')
    })
})

t.test('options.generateStateFunction ^ options.checkStateFunction', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    checkStateFunction: () => { }
  })
    .ready(err => {
      t.strictSame(err.message, 'options.checkStateFunction and options.generateStateFunction have to be given')
    })
})

t.test('options.tags should be a array', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    tags: 'invalid tags'
  })
    .ready(err => {
      t.strictSame(err.message, 'options.tags should be a array')
    })
})

t.test('options.schema should be a object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    schema: 1
  })
    .ready(err => {
      t.strictSame(err.message, 'options.schema should be a object')
    })
})

t.test('options.cookie should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    cookie: 1
  })
    .ready(err => {
      t.strictSame(err.message, 'options.cookie should be an object')
    })
})

t.test('options.userAgent should be a string', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    userAgent: 1
  })
    .ready(err => {
      t.strictSame(err.message, 'options.userAgent should be a string')
    })
})

t.test('options.pkce', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    pkce: {}
  })
    .ready(err => {
      t.strictSame(err.message, 'options.pkce should be one of "S256" | "plain" when used')
    })
})

t.test('options.discovery should be object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    discovery: 'string'
  })
    .ready(err => {
      t.strictSame(err.message, 'options.discovery should be an object')
    })
})

t.test('options.discovery.issuer should be URL', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    discovery: {
      issuer: {}
    }
  })
    .ready(err => {
      t.strictSame(err.message, 'options.discovery.issuer should be a URL in string format')
    })
})

t.test('credentials.auth should not be provided when discovery is used', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    discovery: {
      issuer: 'https://valid.iss'
    }
  })
    .ready(err => {
      t.strictSame(err.message, 'when options.discovery.issuer is configured, credentials.auth should not be used')
    })
})

t.test('options.schema', t => {
  const fastify = createFastify({ logger: { level: 'silent' }, exposeHeadRoutes: false })

  fastify.addHook('onRoute', function (routeOptions) {
    t.strictSame(routeOptions.schema, { tags: ['oauth2', 'oauth'] })
    t.end()
  })

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    startRedirectPath: '/login/github',
    callbackUri: '/callback',
    callbackUriParams: {
      access_type: 'offline'
    },
    scope: ['notifications'],
    schema: {
      tags: ['oauth2', 'oauth']
    }
  })

  fastify.ready()
})

t.test('already decorated', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify
    .decorate('githubOAuth2', false)
    .register(fastifyOauth2, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.GITHUB_CONFIGURATION
      },
      callbackUri: '/callback'
    })
    .ready(err => {
      t.strictSame(err.message, 'The decorator \'githubOAuth2\' has already been added!')
    })
})

t.test('preset configuration generate-callback-uri-params', t => {
  t.plan(3)

  t.test('array scope', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'the-name',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.APPLE_CONFIGURATION,
        options: {
          authorizationMethod: 'body'
        }
      },
      startRedirectPath: '/login/apple',
      callbackUri: '/callback',
      scope: ['email']
    })

    t.teardown(fastify.close.bind(fastify))

    fastify.listen({ port: 0 }, function (err) {
      t.error(err)

      fastify.inject({
        method: 'GET',
        url: '/login/apple'
      }, function (err, responseStart) {
        t.error(err)

        t.equal(responseStart.statusCode, 302)
        const matched = responseStart.headers.location.match(/https:\/\/appleid\.apple\.com\/auth\/authorize\?response_type=code&client_id=my-client-id&response_mode=form_post&redirect_uri=%2Fcallback&scope=email&state=(.*)/)
        t.ok(matched)
        t.end()
      })
    })
  })

  t.test('string scope', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'the-name',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.APPLE_CONFIGURATION,
        options: {
          authorizationMethod: 'body'
        }
      },
      startRedirectPath: '/login/apple',
      callbackUri: '/callback',
      scope: 'name'
    })

    t.teardown(fastify.close.bind(fastify))

    fastify.listen({ port: 0 }, function (err) {
      t.error(err)

      fastify.inject({
        method: 'GET',
        url: '/login/apple'
      }, function (err, responseStart) {
        t.error(err)

        t.equal(responseStart.statusCode, 302)
        const matched = responseStart.headers.location.match(/https:\/\/appleid\.apple\.com\/auth\/authorize\?response_type=code&client_id=my-client-id&response_mode=form_post&redirect_uri=%2Fcallback&scope=name&state=(.*)/)
        t.ok(matched)
        t.end()
      })
    })
  })

  t.test('no scope', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(fastifyOauth2, {
      name: 'the-name',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: fastifyOauth2.APPLE_CONFIGURATION,
        options: {
          authorizationMethod: 'body'
        }
      },
      startRedirectPath: '/login/apple',
      callbackUri: '/callback',
      scope: ''
    })

    t.teardown(fastify.close.bind(fastify))

    fastify.listen({ port: 0 }, function (err) {
      t.error(err)

      fastify.inject({
        method: 'GET',
        url: '/login/apple'
      }, function (err, responseStart) {
        t.error(err)

        t.equal(responseStart.statusCode, 302)
        const matched = responseStart.headers.location.match(/https:\/\/appleid\.apple\.com\/auth\/authorize\?response_type=code&client_id=my-client-id&redirect_uri=%2Fcallback&scope=&state=(.*)/)
        t.ok(matched)
        t.end()
      })
    })
  })
})

t.test('preset configuration generate-callback-uri-params', t => {
  t.plan(56)

  const presetConfigs = [
    'FACEBOOK_CONFIGURATION',
    'GITHUB_CONFIGURATION',
    'GITLAB_CONFIGURATION',
    'LINKEDIN_CONFIGURATION',
    'GOOGLE_CONFIGURATION',
    'MICROSOFT_CONFIGURATION',
    'VKONTAKTE_CONFIGURATION',
    'SPOTIFY_CONFIGURATION',
    'DISCORD_CONFIGURATION',
    'TWITCH_CONFIGURATION',
    'VATSIM_CONFIGURATION',
    'VATSIM_DEV_CONFIGURATION',
    'EPIC_GAMES_CONFIGURATION',
    'YANDEX_CONFIGURATION'
  ]

  for (const configName of presetConfigs) {
    t.ok(fastifyOauth2[configName])
    t.equal(typeof fastifyOauth2[configName].tokenHost, 'string')
    t.equal(typeof fastifyOauth2[configName].tokenPath, 'string')
    t.equal(typeof fastifyOauth2[configName].authorizePath, 'string')
  }
})

t.test('revoke token for gitlab with callback', (t) => {
  t.plan(3)
  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'gitlabOAuth2',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITLAB_CONFIGURATION
    },
    startRedirectPath: '/login/gitlab',
    callbackUri: 'http://localhost:3000/callback',
    scope: ['user']
  })

  fastify.get('/', function (request, reply) {
    this.gitlabOAuth2.revokeToken({
      access_token: 'testToken',
      token_type: 'access_token'
    }, 'access_token', undefined, (err) => {
      if (err) throw err
      reply.send('ok')
    })
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.listen({ port: 0 }, function (err) {
    t.error(err)

    const gitlabRevoke = nock('https://gitlab.com')
      .post('/oauth/revoke', 'token=testToken&token_type_hint=access_token')
      .reply(200, { status: 'ok' })

    fastify.inject({
      method: 'GET',
      url: '/'
    }, function (err, responseStart) {
      t.error(err, 'No error should be thrown')
      t.equal(responseStart.statusCode, 200)
      gitlabRevoke.done()

      t.end()
    })
  })
})

t.test('revoke token for gitlab promisify', (t) => {
  t.plan(3)
  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'gitlabOAuth2',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITLAB_CONFIGURATION
    },
    startRedirectPath: '/login/gitlab',
    callbackUri: 'http://localhost:3000/callback',
    scope: ['user']
  })

  fastify.get('/', function (request, reply) {
    return this.gitlabOAuth2.revokeToken({
      access_token: 'testToken',
      token_type: 'access_token'
    }, 'access_token', undefined).then(() => {
      return reply.send('ok')
    }).catch((e) => {
      throw e
    })
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.listen({ port: 0 }, function (err) {
    t.error(err)

    const gitlabRevoke = nock('https://gitlab.com')
      .post('/oauth/revoke', 'token=testToken&token_type_hint=access_token')
      .reply(200, { status: 'ok' })

    fastify.inject({
      method: 'GET',
      url: '/'
    }, function (err, responseStart) {
      t.error(err, 'No error should be thrown')
      t.equal(responseStart.statusCode, 200)
      gitlabRevoke.done()

      t.end()
    })
  })
})

t.test('revoke all token for gitlab promisify', (t) => {
  t.plan(3)
  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'gitlabOAuth2',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITLAB_CONFIGURATION
    },
    startRedirectPath: '/login/gitlab',
    callbackUri: 'http://localhost:3000/callback',
    scope: ['user']
  })

  fastify.get('/', function (request, reply) {
    return this.gitlabOAuth2.revokeAllToken({
      access_token: 'testToken',
      token_type: 'access_token',
      refresh_token: 'refreshToken'
    }, undefined).then(() => {
      return reply.send('ok')
    }).catch((e) => {
      throw e
    })
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.listen({ port: 0 }, function (err) {
    t.error(err)

    const gitlabRevoke = nock('https://gitlab.com')
      .post('/oauth/revoke', 'token=testToken&token_type_hint=access_token')
      .reply(200, { status: 'ok' })
      .post('/oauth/revoke', 'token=refreshToken&token_type_hint=refresh_token')
      .reply(200, { status: 'ok' })

    fastify.inject({
      method: 'GET',
      url: '/'
    }, function (err, responseStart) {
      t.error(err, 'No error should be thrown')
      t.equal(responseStart.statusCode, 200)
      gitlabRevoke.done()

      t.end()
    })
  })
})

t.test('revoke all token for linkedin callback', (t) => {
  t.plan(3)
  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(fastifyOauth2, {
    name: 'linkedinOAuth2',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.LINKEDIN_CONFIGURATION
    },
    startRedirectPath: '/login/gitlab',
    callbackUri: 'http://localhost:3000/callback',
    scope: ['user']
  })

  fastify.get('/', function (request, reply) {
    return this.linkedinOAuth2.revokeAllToken({
      access_token: 'testToken',
      token_type: 'access_token',
      refresh_token: 'refreshToken'
    }, undefined, (err) => {
      if (err) throw err
      return reply.send('ok')
    })
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.listen({ port: 0 }, function (err) {
    t.error(err)

    const gitlabRevoke = nock('https://www.linkedin.com')
      .post('/oauth/v2/revoke', 'token=testToken&token_type_hint=access_token')
      .reply(200, { status: 'ok' })
      .post('/oauth/v2/revoke', 'token=refreshToken&token_type_hint=refresh_token')
      .reply(200, { status: 'ok' })

    fastify.inject({
      method: 'GET',
      url: '/'
    }, function (err, responseStart) {
      t.error(err, 'No error should be thrown')
      t.equal(responseStart.statusCode, 200)
      gitlabRevoke.done()

      t.end()
    })
  })
})

t.test('options.generateStateFunction with signing key', t => {
  t.plan(5)
  const fastify = createFastify()

  const hmacKey = 'hello'
  const expectedState = crypto.createHmac('sha1', hmacKey).update('foo').digest('hex')

  fastify.register(require('@fastify/cookie'))

  fastify.register(fastifyOauth2, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: fastifyOauth2.GITHUB_CONFIGURATION
    },
    startRedirectPath: '/login/github',
    callbackUri: '/callback',
    generateStateFunction: (request) => {
      const state = crypto.createHmac('sha1', hmacKey).update(request.headers.foo).digest('hex')
      t.ok(request, 'the request param has been set')
      return state
    },
    checkStateFunction: (request) => {
      const generatedState = crypto.createHmac('sha1', hmacKey).update(request.headers.foo).digest('hex')
      return generatedState === request.query.state
    },
    scope: ['notifications']
  })

  t.teardown(fastify.close.bind(fastify))

  fastify.listen({ port: 0 }, function (err) {
    t.error(err)
    fastify.inject({
      method: 'GET',
      url: '/login/github',
      query: { code: expectedState },
      headers: { foo: 'foo' }
    }, function (err, responseStart) {
      t.error(err)
      t.equal(responseStart.statusCode, 302)
      const matched = responseStart.headers.location.match(/https:\/\/github\.com\/login\/oauth\/authorize\?response_type=code&client_id=my-client-id&redirect_uri=%2Fcallback&scope=notifications&state=1e864fbd840212c1ed9ce60175d373f3a48681b2/)
      t.ok(matched)
    })
  })
})

'use strict'

const t = require('tap')
const nock = require('nock')
const createFastify = require('fastify')

const oauthPlugin = require('./index')

nock.disableNetConnect()

function makeRequests (t, fastify) {
  fastify.listen(0, function (err) {
    t.error(err)

    fastify.inject({
      method: 'GET',
      url: '/login/github'
    }, function (err, responseStart) {
      t.error(err)

      t.equal(responseStart.statusCode, 302)
      const matched = responseStart.headers.location.match(/https:\/\/github\.com\/login\/oauth\/authorize\?response_type=code&client_id=my-client-id&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=notifications&state=(.*)/)
      t.ok(matched)
      const state = matched[1]
      t.ok(state)

      const RESPONSE_BODY = {
        access_token: 'my-access-token',
        refresh_token: 'my-refresh-token',
        token_type: 'bearer',
        expires_in: '240000'
      }

      const RESPONSE_BODY_REFRESHED = {
        access_token: 'my-access-token-refreshed',
        refresh_token: 'my-refresh-token-refreshed',
        token_type: 'bearer',
        expires_in: '240000'
      }

      const githubScope = nock('https://github.com')
        .post('/login/oauth/access_token', 'code=my-code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&grant_type=authorization_code&client_id=my-client-id&client_secret=my-secret')
        .reply(200, RESPONSE_BODY)
        .post('/login/oauth/access_token', 'grant_type=refresh_token&refresh_token=my-refresh-token&client_id=my-client-id&client_secret=my-secret')
        .reply(200, RESPONSE_BODY_REFRESHED)

      fastify.inject({
        method: 'GET',
        url: '/?code=my-code&state=' + state
      }, function (err, responseEnd) {
        t.error(err)

        t.equal(responseEnd.statusCode, 200)
        t.strictSame(JSON.parse(responseEnd.payload), RESPONSE_BODY_REFRESHED)

        githubScope.done()

        t.end()
      })
    })
  })
}

t.test('fastify-oauth2', t => {
  t.test('callback', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(oauthPlugin, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: oauthPlugin.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications']
    })

    fastify.get('/', function (request, reply) {
      this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, (err, result) => {
        if (err) throw err

        // attempts to refresh the token
        this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.refresh_token, undefined, (err, result) => {
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

    t.tearDown(fastify.close.bind(fastify))

    makeRequests(t, fastify)
  })

  t.test('promise', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(oauthPlugin, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: oauthPlugin.GITHUB_CONFIGURATION
      },
      startRedirectPath: '/login/github',
      callbackUri: 'http://localhost:3000/callback',
      scope: ['notifications']
    })

    fastify.get('/', function (request, reply) {
      return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)
        .then(result => {
          // attempts to refresh the token
          return this.githubOAuth2.getNewAccessTokenUsingRefreshToken(result.refresh_token)
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

    t.tearDown(fastify.close.bind(fastify))

    makeRequests(t, fastify)
  })

  t.test('wrong state', t => {
    const fastify = createFastify({ logger: { level: 'silent' } })

    fastify.register(oauthPlugin, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: oauthPlugin.GITHUB_CONFIGURATION
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

    t.tearDown(fastify.close.bind(fastify))

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

  t.end()
})

t.test('options.name should be a string', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(oauthPlugin)
    .ready(err => {
      t.strictSame(err.message, 'options.name should be a string')
    })
})

t.test('options.credentials should be and object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(oauthPlugin, {
    name: 'the-name'
  })
    .ready(err => {
      t.strictSame(err.message, 'options.credentials should be an object')
    })
})

t.test('options.callbackUri should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(oauthPlugin, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: oauthPlugin.GITHUB_CONFIGURATION
    }
  })
    .ready(err => {
      t.strictSame(err.message, 'options.callbackUri should be a string')
    })
})

t.test('options.callbackUriParams should be an object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(oauthPlugin, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: oauthPlugin.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    callbackUriParams: 1
  })
    .ready(err => {
      t.strictSame(err.message, 'options.callbackUriParams should be a object')
    })
})

t.test('options.callbackUriParams', t => {
  const fastify = createFastify({ logger: true })

  fastify.register(oauthPlugin, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: oauthPlugin.GITHUB_CONFIGURATION
    },
    startRedirectPath: '/login/github',
    callbackUri: '/callback',
    callbackUriParams: {
      access_type: 'offline'
    },
    scope: ['notifications']
  })

  t.tearDown(fastify.close.bind(fastify))

  fastify.listen(0, function (err) {
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

t.test('options.generateStateFunction should be and object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(oauthPlugin, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: oauthPlugin.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    generateStateFunction: 42
  })
    .ready(err => {
      t.strictSame(err.message, 'options.generateStateFunction should be a function')
    })
})

t.test('options.checkStateFunction should be and object', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(oauthPlugin, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: oauthPlugin.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    generateStateFunction: () => {},
    checkStateFunction: 42
  })
    .ready(err => {
      t.strictSame(err.message, 'options.checkStateFunction should be a function')
    })
})

t.test('options.startRedirectPath should be a string', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(oauthPlugin, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: oauthPlugin.GITHUB_CONFIGURATION
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

  fastify.register(oauthPlugin, {
    name: 'the-name',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: oauthPlugin.GITHUB_CONFIGURATION
    },
    callbackUri: '/callback',
    checkStateFunction: () => {}
  })
    .ready(err => {
      t.strictSame(err.message, 'options.checkStateFunction and options.generateStateFunction have to be given')
    })
})

t.test('already decorated', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify
    .decorate('githubOAuth2', false)
    .register(oauthPlugin, {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: oauthPlugin.GITHUB_CONFIGURATION
      },
      callbackUri: '/callback'
    })
    .ready(err => {
      t.strictSame(err.message, 'FST_ERR_DEC_ALREADY_PRESENT: The decorator \'githubOAuth2\' has already been added!')
    })
})

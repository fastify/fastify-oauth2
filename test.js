'use strict'

const t = require('tap')
const nock = require('nock')
const createFastify = require('fastify')

const oauthPlugin = require('./index')

nock.disableNetConnect()

t.test('fastify-oauth2', t => {
  t.plan(2)

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
    this.getAccessTokenFromAuthorizationCodeFlow(request, (err, result) => {
      if (err) throw err

      const token = this.githubOAuth2.accessToken.create(result)
      reply.send({
        access_token: token.token.access_token,
        refresh_token: token.token.refresh_token,
        expires_in: token.token.expires_in,
        token_type: token.token.token_type
      })
    })
  })

  t.tearDown(fastify.close.bind(fastify))

  fastify.listen(0, function (err) {
    t.error(err)

    t.test('ok', t => {
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

        const githubScope = nock('https://github.com')
          .post('/login/oauth/access_token', 'code=my-code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&grant_type=authorization_code&client_id=my-client-id&client_secret=my-secret')
          .reply(200, RESPONSE_BODY)

        fastify.inject({
          method: 'GET',
          url: '/?code=my-code&state=' + state
        }, function (err, responseEnd) {
          t.error(err)

          t.equal(responseEnd.statusCode, 200)
          t.strictSame(JSON.parse(responseEnd.payload), RESPONSE_BODY)

          githubScope.done()

          t.end()
        })
      })
    })
  })
})

t.test('options.name is required', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(require('./index'))
    .ready(err => {
      t.strictSame(err.message, 'options.name is required')
    })
})

t.test('already decorated', t => {
  t.plan(1)

  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify
    .decorate('githubOAuth2', false)
    .register(require('./index'), {
      name: 'githubOAuth2',
      credentials: {
        client: {
          id: 'my-client-id',
          secret: 'my-secret'
        },
        auth: oauthPlugin.GITHUB_CONFIGURATION
      }
    })
    .ready(err => {
      t.strictSame(err.message, 'The decorator \'githubOAuth2\' has been already added!')
    })
})

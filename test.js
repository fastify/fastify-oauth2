'use strict'

const t = require('tap')
const nock = require('nock')
const createFastify = require('fastify')

const oauthPlugin = require('./index')

nock.disableNetConnect()

t.test('fastify-githubOAuth2', t => {
  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(oauthPlugin, {
    name: 'githubOAuth2',
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: oauthPlugin.GITHUB_CONFIGURATION
    }
  })

  fastify.get('/login/github', function (request, reply) {
    const authorizationUri = this.githubOAuth2.authorizationCode.authorizeURL({
      redirect_uri: 'http://localhost:3000/callback',
      scope: 'notifications',
      state: '3(#0/!~'
    })
    reply.redirect(authorizationUri)
  })
  fastify.get('/', function (request, reply) {
    const code = request.query.code

    return this.githubOAuth2.authorizationCode.getToken({ code })
      .then(result => {
        const token = this.githubOAuth2.accessToken.create(result)
        return {
          access_token: token.token.access_token,
          refresh_token: token.token.refresh_token,
          expires_in: token.token.expires_in,
          token_type: token.token.token_type
        }
      })
  })

  t.test('ok', t => {
    t.plan(4)

    return fastify.inject({
      method: 'GET',
      url: '/login/github'
    })
      .then(responseStart => {
        t.equal(responseStart.statusCode, 302)
        t.equal(responseStart.headers.location, 'https://github.com/login/oauth/authorize?response_type=code&client_id=my-client-id&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=notifications&state=3(%230%2F!~')

        const RESPONSE_BODY = {
          access_token: 'my-access-token',
          refresh_token: 'my-refresh-token',
          token_type: 'bearer',
          expires_in: '240000'
        }

        const githubScope = nock('https://github.com')
          .post('/login/oauth/access_token', 'code=my-code&grant_type=authorization_code&client_id=my-client-id&client_secret=my-secret')
          .reply(200, RESPONSE_BODY)

        return fastify.inject({
          method: 'GET',
          url: '/?code=my-code'
        })
          .then(responseEnd => {
            t.equal(responseEnd.statusCode, 200)
            t.strictSame(JSON.parse(responseEnd.payload), RESPONSE_BODY)

            githubScope.done()
          })
      })
  })

  t.end()
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

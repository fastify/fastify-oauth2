'use strict'

const t = require('tap')
const nock = require('nock')
const createFastify = require('fastify')

nock.disableNetConnect()

t.test('fastify-oauth2', t => {
  const fastify = createFastify({ logger: { level: 'silent' } })

  fastify.register(require('./index'), {
    credentials: {
      client: {
        id: 'my-client-id',
        secret: 'my-secret'
      },
      auth: {
        tokenHost: 'https://github.com',
        tokenPath: '/login/oauth/access_token',
        authorizePath: '/login/oauth/authorize'
      }
    }
  })

  fastify.get('/login/github', function (request, reply) {
    const authorizationUri = this.oauth2.authorizationCode.authorizeURL({
      redirect_uri: 'http://localhost:3000/callback',
      scope: 'notifications',
      state: '3(#0/!~'
    })
    reply.redirect(authorizationUri)
  })
  fastify.get('/', async function (request, reply) {
    const code = request.query.code

    const result = await this.oauth2.authorizationCode.getToken({ code })
    const token = this.oauth2.accessToken.create(result)
    return reply.send({
      access_token: token.token.access_token,
      refresh_token: token.token.refresh_token,
      expires_in: token.token.expires_in,
      token_type: token.token.token_type
    })
  })

  t.test('ok', async t => {
    t.plan(4)

    const responseStart = await fastify.inject({
      method: 'GET',
      url: '/login/github'
    })

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

    const responseEnd = await fastify.inject({
      method: 'GET',
      url: '/?code=my-code'
    })

    t.equal(responseEnd.statusCode, 200)
    t.strictSame(JSON.parse(responseEnd.payload), RESPONSE_BODY)

    githubScope.done()
  })

  t.end()
})

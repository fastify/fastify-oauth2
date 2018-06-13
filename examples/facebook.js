'use strict'

const fastify = require('fastify')({ logger: { level: 'trace' } })
const got = require('got')

const oauthPlugin = require('../')

fastify.register(oauthPlugin, {
  name: 'facebookOAuth2',
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.FACEBOOK_CONFIGURATION
  }
})

fastify.get('/login/facebook', function (request, reply) {
  const authorizationUri = this.facebookOAuth2.authorizationCode.authorizeURL({
    redirect_uri: 'http://localhost:3000/',
    state: '3(#0/!~'
  })
  reply.redirect(authorizationUri)
})
fastify.get('/', async function (request, reply) {
  const code = request.query.code

  try {
    const result = await this.facebookOAuth2.authorizationCode.getToken({
      code: code,
      redirect_uri: 'http://localhost:3000/'
    })
    const meResponse = await got('https://graph.facebook.com/v3.0/me', {
      headers: {
        Authorization: 'Bearer ' + result.access_token
      },
      json: true
    })
    return meResponse.body
  } catch (e) {
    console.log(e)
    throw e
  }
})

fastify.listen(3000)

'use strict'

const fastify = require('fastify')({ logger: { level: 'trace' } })

// const oauthPlugin = require('@fastify/oauth2')
const oauthPlugin = require('..')

fastify.register(oauthPlugin, {
  name: 'kakaoOAuth2',
  // See Kakao Login documentation for scope options:
  // https://developers.kakao.com/docs/latest/en/kakaologin/rest-api#request-code
  scope: ['profile_nickname', 'account_email'],
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.KAKAO_CONFIGURATION
  },
  startRedirectPath: '/login/kakao',
  callbackUri: 'http://localhost:3000/login/kakao/callback'
})

fastify.get('/login/kakao/callback', async function (request, reply) {
  const { token } = await this.kakaoOAuth2.getAccessTokenFromAuthorizationCodeFlow(
    request,
    reply
  )

  reply.send({ access_token: token.access_token })
})

fastify.listen({ port: 3000 })

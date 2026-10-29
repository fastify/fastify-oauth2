'use strict'

const fastify = require('fastify')({ logger: { level: 'trace' } })

// const oauthPlugin = require('@fastify/oauth2')
const oauthPlugin = require('..')

fastify.register(oauthPlugin, {
  name: 'kakaoOAuth2',
  scope: ['profile_nickname'],
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.KAKAO_CONFIGURATION,
    options: {
      authorizationMethod: 'body'
    }
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

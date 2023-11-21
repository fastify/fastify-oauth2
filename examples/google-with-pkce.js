'use strict'

const fastify = require('fastify')({ logger: { level: 'trace' } })
const sget = require('simple-get')

const cookieOpts = {
  // domain: 'localhost',
  path: '/',
  secure: true,
  sameSite: 'lax',
  httpOnly: true
}

// const oauthPlugin = require('fastify-oauth2')
fastify.register(require('@fastify/cookie'), {
  secret: ['my-secret'],
  parseOptions: cookieOpts
})

const oauthPlugin = require('..')
fastify.register(oauthPlugin, {
  name: 'googleOAuth2',
  scope: ['openid', 'profile', 'email'],
  credentials: {
    client: {
      id: process.env.CLIENT_ID,
      secret: process.env.CLIENT_SECRET
    },
    auth: oauthPlugin.GOOGLE_CONFIGURATION
  },
  startRedirectPath: '/login/google',
  callbackUri: 'http://localhost:3000/interaction/callback/google',
  cookie: cookieOpts,
  pkce: 'S256' // "plain" is also supported in this library, see your own provider's .well-known/openid-configuration endpoint (if it's exposed) to understand which methods are supported
})

fastify.get('/interaction/callback/google', function (request, reply) {
  // Note that in this example a "reply" is also passed, it's so that code verifier cookie can be cleaned before
  // token is requested from token endpoint
  this.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, reply, (err, result) => {
    if (err) {
      reply.send(err)
      return
    }

    sget.concat({
      url: 'https://www.googleapis.com/oauth2/v2/userinfo',
      method: 'GET',
      headers: {
        Authorization: 'Bearer ' + result.token.access_token
      },
      json: true
    }, function (err, res, data) {
      if (err) {
        reply.send(err)
        return
      }
      reply.send(data)
    })
  })
})

fastify.listen({ port: 3000 })
fastify.log.info('go to http://localhost:3000/login/google')

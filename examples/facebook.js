'use strict'

const fastify = require('fastify')({ logger: { level: 'trace' } })
const sget = require('simple-get')

// const oauthPlugin = require('fastify-oauth2')
const oauthPlugin = require('..')

fastify.register(oauthPlugin, {
  name: 'facebookOAuth2',
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.FACEBOOK_CONFIGURATION
  },
  startRedirectPath: '/login/facebook',
  callbackUri: 'http://localhost:3000/login/facebook/callback'
})

fastify.get('/login/facebook/callback', function (request, reply) {
  this.facebookOAuth2.getAccessTokenFromAuthorizationCodeFlow(request, (err, result) => {
    if (err) {
      reply.send(err)
      return
    }

    sget.concat({
      url: 'https://graph.facebook.com/v6.0/me',
      method: 'GET',
      headers: {
        Authorization: 'Bearer ' + result.access_token
      },
      json: true
    }, function (err, _res, data) {
      if (err) {
        reply.send(err)
        return
      }
      reply.send(data)
    })
  })
})

fastify.listen({ port: 3000 })

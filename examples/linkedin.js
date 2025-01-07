'use strict'

const fastify = require('fastify')({ logger: { level: 'trace' } })
const sget = require('simple-get')

// const oauthPlugin = require('fastify-oauth2')
const oauthPlugin = require('..')

fastify.register(oauthPlugin, {
  name: 'linkedinOAuth2',
  scope: ['profile', 'email', 'openid'],
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.LINKEDIN_CONFIGURATION
  },
  tokenRequestParams: {
    client_id: '<CLIENT_ID>',
    client_secret: '<CLIENT_SECRET>'
  },
  startRedirectPath: '/login/linkedin',
  callbackUri: 'http://localhost:3000/login/linkedin/callback'
})

fastify.get('/login/linkedin/callback', function (request, reply) {
  this.linkedinOAuth2.getAccessTokenFromAuthorizationCodeFlow(
    request,
    (err, result) => {
      if (err) {
        reply.send(err)
        return
      }

      sget.concat(
        {
          url: 'https://api.linkedin.com/v2/userinfo',
          method: 'GET',
          headers: {
            Authorization: 'Bearer ' + result.token.access_token
          },
          json: true
        },
        function (err, _res, data) {
          if (err) {
            reply.send(err)
            return
          }
          reply.send(data)
        }
      )
    }
  )
})

fastify.listen({ port: 3000 })

'use strict'

// This example assumes the use of the npm package apple-signin in your code.
// This library is not included with fastify-oauth2. If you wish to implement
// the verification part of Apple's Sign In REST API yourself,
// look at https://github.com/Techofficer/node-apple-signin to see how they did
// it, or look at https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api
// for more details on how to do it from scratch.

const fastify = require('fastify')({ logger: { level: 'trace' } })
const appleSignin = require('apple-signin')

// const oauthPlugin = require('fastify-oauth2')
const oauthPlugin = require('..')

const CLIENT_ID = '<CLIENT_ID>'

fastify.register(oauthPlugin, {
  name: 'appleOAuth2',
  credentials: {
    client: {
      id: CLIENT_ID,
      // See https://github.com/Techofficer/node-apple-signin/blob/master/source/index.js
      // for how to create the secret.
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.APPLE_CONFIGURATION
  },
  startRedirectPath: '/login/apple',
  callbackUri: 'http://localhost:3000/login/apple/callback'
})

fastify.get('/login/apple/callback', function (request, reply) {
  this.appleOAuth2.getAccessTokenFromAuthorizationCodeFlow(
    request,
    (err, result) => {
      if (err) {
        reply.send(err)
        return
      }

      appleSignin.verifyIdToken(
        result.id_token,
        CLIENT_ID
      )
        .then(payload => {
          // Find all the available fields (like email) in
          // https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
          const userAppleId = payload.sub

          reply.send(userAppleId)
        })
        .catch(err => {
          // Token is not verified
          reply.send(err)
        })
    }
  )
})

fastify.listen(3000)

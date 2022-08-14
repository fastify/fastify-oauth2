'use strict'

const fastify = require('fastify')({ logger: { level: 'trace' } })
const sget = require('simple-get')

// const oauthPlugin = require('fastify-oauth2')
const oauthPlugin = require('..')

fastify.register(oauthPlugin, {
  name: 'githubOAuth2',
  scope: [],
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.GITHUB_CONFIGURATION
  },
  startRedirectPath: '/login/github',
  callbackUri: 'http://localhost:3000/login/github/callback'
})

let refreshToken = ''

fastify.get('/login/github/callback', function (request, reply) {
  this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(
    request,
    (err, result) => {
      if (err) {
        reply.send(err)
        return
      }

      refreshToken = result.token.refresh_token

      sget.concat(
        {
          url: 'https://api.github.com/user',
          method: 'GET',
          headers: {
            Authorization: 'token ' + result.token.access_token
          },
          json: true
        },
        function (err, res, data) {
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

fastify.get('/login/github/verifyAccessToken', function (request, reply) {
  const { accessToken } = request.query
  sget.concat(
    {
      url: 'https://api.github.com/applications/<CLIENT_ID>/token',
      method: 'POST',
      headers: {
        Authorization:
          'Basic ' +
          Buffer.from('<CLIENT_ID>' + ':' + '<CLIENT_SECRET').toString(
            'base64'
          )
      },
      body: JSON.stringify({ access_token: accessToken }),
      json: true
    },
    function (err, res, data) {
      if (err) {
        reply.send(err)
        return
      }
      reply.send(data)
    }
  )
})

fastify.get('/login/github/refreshToken', function (request, reply) {
  // this.githubOAuth2.getAccessTokenFromRefreshToken(refresh_token, {}, (err, result) => {})

  sget.concat(
    {
      url: 'https://github.com/login/oauth/access_token',
      method: 'POST',
      form: {
        refresh_token: refreshToken
      },
      json: true
    },
    function (err, res, data) {
      if (err) {
        reply.send(err)
        return
      }
      reply.send(data)
    }
  )
})

fastify.listen({ port: 3000 })

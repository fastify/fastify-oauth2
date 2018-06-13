'use strict'

const fp = require('fastify-plugin')
const oauth2Module = require('simple-oauth2')

const oauthPlugin = fp(function (fastify, options, next) {
  if (!options.name) return next(new Error('options.name is required'))

  const oauth2 = oauth2Module.create(options.credentials)

  fastify.decorate(options.name, oauth2)

  next()
})

oauthPlugin.FACEBOOK_CONFIGURATION = {
  authorizeHost: 'https://facebook.com',
  authorizePath: '/v3.0/dialog/oauth',
  tokenHost: 'https://graph.facebook.com',
  tokenPath: '/v3.0/oauth/access_token'
}

oauthPlugin.GITHUB_CONFIGURATION = {
  tokenHost: 'https://github.com',
  tokenPath: '/login/oauth/access_token',
  authorizePath: '/login/oauth/authorize'
}

module.exports = oauthPlugin

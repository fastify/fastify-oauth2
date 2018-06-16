'use strict'

const fp = require('fastify-plugin')
const oauth2Module = require('simple-oauth2')
const defaultState = require('crypto').randomBytes(10).toString('hex')

function defaultGenerateStateFunction () {
  return defaultState
}

function defaultCheckStateFunction (state, callback) {
  if (state === defaultState) {
    callback()
    return
  }
  callback(new Error('Invalid state'))
}

const oauthPlugin = fp(function (fastify, options, next) {
  if (!options.name) return next(new Error('options.name is required'))

  const name = options.name
  const credentials = options.credentials
  const callbackUri = options.callbackUri
  const scope = options.scope
  const generateStateFunction = options.generateStateFunction || defaultGenerateStateFunction
  const checkStateFunction = options.checkStateFunction || defaultCheckStateFunction
  const startRedirectPath = options.startRedirectPath

  function startRedirectHandler (request, reply) {
    const state = generateStateFunction()

    const authorizationUri = this[name].authorizationCode.authorizeURL({
      redirect_uri: callbackUri,
      scope: scope,
      state: state
    })
    reply.redirect(authorizationUri)
  }

  const cbk = function (o, code, callback) {
    return o.authorizationCode.getToken({
      code: code,
      redirect_uri: callbackUri
    }, callback)
  }

  function getAccessTokenFromAuthorizationCodeFlow (request, callback) {
    const code = request.query.code
    const state = request.query.state
    const fastify = this

    checkStateFunction(state, function (err) {
      if (err) {
        callback(err)
        return
      }
      cbk(fastify[name], code, callback)
    })
  }

  const oauth2 = oauth2Module.create(credentials)

  if (startRedirectPath) {
    fastify.get(startRedirectPath, startRedirectHandler)
    fastify.decorate('getAccessTokenFromAuthorizationCodeFlow', getAccessTokenFromAuthorizationCodeFlow)
  }

  try {
    fastify.decorate(name, oauth2)
  } catch (e) {
    next(e)
    return
  }

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

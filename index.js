'use strict'

const defaultState = require('crypto').randomBytes(10).toString('hex')

const fp = require('fastify-plugin')
const oauth2Module = require('simple-oauth2')

const promisify = require('util').promisify || require('es6-promisify').promisify

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
  if (typeof options.name !== 'string') {
    return next(new Error('options.name should be a string'))
  }
  if (typeof options.credentials !== 'object') {
    return next(new Error('options.credentials should be an object'))
  }
  if (typeof options.callbackUri !== 'string') {
    return next(new Error('options.callbackUri should be a string'))
  }
  if (options.callbackUriParams && typeof options.callbackUriParams !== 'object') {
    return next(new Error('options.callbackUriParams should be a object'))
  }
  if (options.generateStateFunction && typeof options.generateStateFunction !== 'function') {
    return next(new Error('options.generateStateFunction should be a function'))
  }
  if (options.checkStateFunction && typeof options.checkStateFunction !== 'function') {
    return next(new Error('options.checkStateFunction should be a function'))
  }
  if (options.startRedirectPath && typeof options.startRedirectPath !== 'string') {
    return next(new Error('options.startRedirectPath should be a string'))
  }
  if (!options.generateStateFunction ^ !options.checkStateFunction) {
    return next(new Error('options.checkStateFunction and options.generateStateFunction have to be given'))
  }

  const name = options.name
  const credentials = options.credentials
  const callbackUri = options.callbackUri
  const callbackUriParams = options.callbackUriParams || {}
  const scope = options.scope
  const generateStateFunction = options.generateStateFunction || defaultGenerateStateFunction
  const checkStateFunction = options.checkStateFunction || defaultCheckStateFunction
  const startRedirectPath = options.startRedirectPath

  function startRedirectHandler (request, reply) {
    const state = generateStateFunction()
    const urlOptions = Object.assign({}, callbackUriParams, {
      redirect_uri: callbackUri,
      scope: scope,
      state: state
    })

    const authorizationUri = this[name].oauth2.authorizationCode.authorizeURL(urlOptions)
    reply.redirect(authorizationUri)
  }

  const cbk = function (o, code, callback) {
    return o.oauth2.authorizationCode.getToken({
      code: code,
      redirect_uri: callbackUri
    }, callback)
  }

  function getAccessTokenFromAuthorizationCodeFlowCallbacked (request, callback) {
    const code = request.query.code
    const state = request.query.state

    checkStateFunction(state, function (err) {
      if (err) {
        callback(err)
        return
      }
      cbk(fastify[name], code, callback)
    })
  }
  const getAccessTokenFromAuthorizationCodeFlowPromisified = promisify(getAccessTokenFromAuthorizationCodeFlowCallbacked)

  function getAccessTokenFromAuthorizationCodeFlow (request, callback) {
    if (!callback) {
      return getAccessTokenFromAuthorizationCodeFlowPromisified(request)
    }
    getAccessTokenFromAuthorizationCodeFlowCallbacked(request, callback)
  }

  function getNewAccessTokenUsingRefreshTokenCallbacked (refreshToken, params, callback) {
    const accessToken = fastify[name].oauth2.accessToken.create({ refresh_token: refreshToken })
    accessToken.refresh(params, callback)
  }
  const getNewAccessTokenUsingRefreshTokenPromisified = promisify(getNewAccessTokenUsingRefreshTokenCallbacked)

  function getNewAccessTokenUsingRefreshToken (refreshToken, params, callback) {
    if (!callback) {
      return getNewAccessTokenUsingRefreshTokenPromisified(refreshToken, params)
    }
    getNewAccessTokenUsingRefreshTokenCallbacked(refreshToken, params, callback)
  }

  const oauth2 = oauth2Module.create(credentials)

  if (startRedirectPath) {
    fastify.get(startRedirectPath, startRedirectHandler)
  }

  try {
    fastify.decorate(name, {
      oauth2: oauth2,
      getAccessTokenFromAuthorizationCodeFlow,
      getNewAccessTokenUsingRefreshToken
    })
  } catch (e) {
    next(e)
    return
  }

  next()
})

oauthPlugin.FACEBOOK_CONFIGURATION = {
  authorizeHost: 'https://facebook.com',
  authorizePath: '/v6.0/dialog/oauth',
  tokenHost: 'https://graph.facebook.com',
  tokenPath: '/v6.0/oauth/access_token'
}

oauthPlugin.GITHUB_CONFIGURATION = {
  tokenHost: 'https://github.com',
  tokenPath: '/login/oauth/access_token',
  authorizePath: '/login/oauth/authorize'
}

oauthPlugin.LINKEDIN_CONFIGURATION = {
  authorizeHost: 'https://www.linkedin.com',
  authorizePath: '/oauth/v2/authorization',
  tokenHost: 'https://www.linkedin.com',
  tokenPath: '/oauth/v2/accessToken'
}

oauthPlugin.GOOGLE_CONFIGURATION = {
  authorizeHost: 'https://accounts.google.com',
  authorizePath: '/o/oauth2/v2/auth',
  tokenHost: 'https://www.googleapis.com',
  tokenPath: '/oauth2/v4/token'
}

oauthPlugin.MICROSOFT_CONFIGURATION = {
  authorizeHost: 'https://login.microsoftonline.com',
  authorizePath: '/common/oauth2/v2.0/authorize',
  tokenHost: 'https://login.microsoftonline.com',
  tokenPath: '/common/oauth2/v2.0/token'
}

oauthPlugin.VKONTAKTE_CONFIGURATION = {
  authorizeHost: 'https://oauth.vk.com',
  authorizePath: '/authorize',
  tokenHost: 'https://oauth.vk.com',
  tokenPath: '/access_token'
}

oauthPlugin.SPOTIFY_CONFIGURATION = {
  authorizeHost: 'https://accounts.spotify.com',
  authorizePath: '/authorize',
  tokenHost: 'https://accounts.spotify.com',
  tokenPath: '/api/token'
}

module.exports = oauthPlugin

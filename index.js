'use strict'

const crypto = require('crypto')

const fp = require('fastify-plugin')
const { AuthorizationCode } = require('simple-oauth2')
const kGenerateCallbackUriParams = Symbol.for('fastify-oauth2.generate-callback-uri-params')

const promisify = require('util').promisify
const callbackify = require('util').callbackify

function defaultGenerateStateFunction () {
  return crypto.randomBytes(16).toString('base64url')
}

function defaultCheckStateFunction (request, callback) {
  const state = request.query.state
  const stateCookie = request.cookies['oauth2-redirect-state']
  if (stateCookie && state === stateCookie) {
    callback()
    return
  }
  callback(new Error('Invalid state'))
}

function defaultGenerateCallbackUriParams (callbackUriParams) {
  return callbackUriParams
}

function fastifyOauth2 (fastify, options, next) {
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
  if (options.tokenRequestParams && typeof options.tokenRequestParams !== 'object') {
    return next(new Error('options.tokenRequestParams should be a object'))
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
  if (options.tags && !Array.isArray(options.tags)) {
    return next(new Error('options.tags should be a array'))
  }
  if (options.schema && typeof options.schema !== 'object') {
    return next(new Error('options.schema should be a object'))
  }

  if (!fastify.hasReplyDecorator('cookie')) {
    fastify.register(require('@fastify/cookie'))
  }

  const name = options.name
  const credentials = options.credentials
  const callbackUri = options.callbackUri
  const callbackUriParams = options.callbackUriParams || {}
  const tokenRequestParams = options.tokenRequestParams || {}
  const scope = options.scope
  const generateStateFunction = options.generateStateFunction || defaultGenerateStateFunction
  const checkStateFunction = options.checkStateFunction || defaultCheckStateFunction
  const generateCallbackUriParams = (credentials.auth && credentials.auth[kGenerateCallbackUriParams]) || defaultGenerateCallbackUriParams
  const startRedirectPath = options.startRedirectPath
  const tags = options.tags || []
  const schema = options.schema || { tags }

  function generateAuthorizationUri (request, reply) {
    const state = generateStateFunction(request)

    reply.setCookie('oauth2-redirect-state', state, {
      httpOnly: true,
      sameSite: 'lax'
    })

    const urlOptions = Object.assign({}, generateCallbackUriParams(callbackUriParams, request, scope, state), {
      redirect_uri: callbackUri,
      scope,
      state
    })

    return oauth2.authorizeURL(urlOptions)
  }

  function startRedirectHandler (request, reply) {
    const authorizationUri = generateAuthorizationUri(request, reply)

    reply.redirect(authorizationUri)
  }

  const cbk = function (o, code, callback) {
    const body = Object.assign({}, tokenRequestParams, {
      code,
      redirect_uri: callbackUri
    })

    return callbackify(o.oauth2.getToken.bind(o.oauth2, body))(callback)
  }

  function getAccessTokenFromAuthorizationCodeFlowCallbacked (request, callback) {
    const code = request.query.code

    checkStateFunction(request, function (err) {
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
    const accessToken = fastify[name].oauth2.createToken(refreshToken)
    callbackify(accessToken.refresh.bind(accessToken, params))(callback)
  }
  const getNewAccessTokenUsingRefreshTokenPromisified = promisify(getNewAccessTokenUsingRefreshTokenCallbacked)

  function getNewAccessTokenUsingRefreshToken (refreshToken, params, callback) {
    if (!callback) {
      return getNewAccessTokenUsingRefreshTokenPromisified(refreshToken, params)
    }
    getNewAccessTokenUsingRefreshTokenCallbacked(refreshToken, params, callback)
  }
  const oauth2 = new AuthorizationCode(credentials)

  if (startRedirectPath) {
    fastify.get(startRedirectPath, { schema }, startRedirectHandler)
  }

  try {
    fastify.decorate(name, {
      oauth2,
      getAccessTokenFromAuthorizationCodeFlow,
      getNewAccessTokenUsingRefreshToken,
      generateAuthorizationUri
    })
  } catch (e) {
    next(e)
    return
  }

  next()
}

fastifyOauth2.APPLE_CONFIGURATION = {
  authorizeHost: 'https://appleid.apple.com',
  authorizePath: '/auth/authorize',
  tokenHost: 'https://appleid.apple.com',
  tokenPath: '/auth/token',
  // kGenerateCallbackUriParams is used for dedicated behavior for each OAuth2.0 provider
  // It can update the callbackUriParams based on requestObject, scope and state
  //
  // Symbol used in here because we would not like the user to modify this behavior and
  // do not want to mess up with property name collision
  [kGenerateCallbackUriParams]: function (callbackUriParams, requestObject, scope, state) {
    const stringifyScope = Array.isArray(scope) ? scope.join(' ') : scope
    // This behavior is not documented on Apple Developer Docs but it display through runtime error.
    // Related Docs: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms
    // Related Issue: https://github.com/fastify/fastify-oauth2/issues/116
    //
    // `response_mode` must be `form_post` when scope include `email` or `name`
    if (stringifyScope.includes('email') || stringifyScope.includes('name')) {
      callbackUriParams.response_mode = 'form_post'
    }
    return callbackUriParams
  }
}

fastifyOauth2.FACEBOOK_CONFIGURATION = {
  authorizeHost: 'https://facebook.com',
  authorizePath: '/v6.0/dialog/oauth',
  tokenHost: 'https://graph.facebook.com',
  tokenPath: '/v6.0/oauth/access_token'
}

fastifyOauth2.GITHUB_CONFIGURATION = {
  tokenHost: 'https://github.com',
  tokenPath: '/login/oauth/access_token',
  authorizePath: '/login/oauth/authorize'
}

fastifyOauth2.GITLAB_CONFIGURATION = {
  authorizeHost: 'https://gitlab.com',
  authorizePath: '/oauth/authorize',
  tokenHost: 'https://gitlab.com',
  tokenPath: '/oauth/token'
}

fastifyOauth2.LINKEDIN_CONFIGURATION = {
  authorizeHost: 'https://www.linkedin.com',
  authorizePath: '/oauth/v2/authorization',
  tokenHost: 'https://www.linkedin.com',
  tokenPath: '/oauth/v2/accessToken'
}

fastifyOauth2.GOOGLE_CONFIGURATION = {
  authorizeHost: 'https://accounts.google.com',
  authorizePath: '/o/oauth2/v2/auth',
  tokenHost: 'https://www.googleapis.com',
  tokenPath: '/oauth2/v4/token'
}

fastifyOauth2.MICROSOFT_CONFIGURATION = {
  authorizeHost: 'https://login.microsoftonline.com',
  authorizePath: '/common/oauth2/v2.0/authorize',
  tokenHost: 'https://login.microsoftonline.com',
  tokenPath: '/common/oauth2/v2.0/token'
}

fastifyOauth2.VKONTAKTE_CONFIGURATION = {
  authorizeHost: 'https://oauth.vk.com',
  authorizePath: '/authorize',
  tokenHost: 'https://oauth.vk.com',
  tokenPath: '/access_token'
}

fastifyOauth2.SPOTIFY_CONFIGURATION = {
  authorizeHost: 'https://accounts.spotify.com',
  authorizePath: '/authorize',
  tokenHost: 'https://accounts.spotify.com',
  tokenPath: '/api/token'
}

fastifyOauth2.DISCORD_CONFIGURATION = {
  authorizeHost: 'https://discord.com',
  authorizePath: '/api/oauth2/authorize',
  tokenHost: 'https://discord.com',
  tokenPath: '/api/oauth2/token'
}

fastifyOauth2.TWITCH_CONFIGURATION = {
  authorizeHost: 'https://id.twitch.tv',
  authorizePath: '/oauth2/authorize',
  tokenHost: 'https://id.twitch.tv',
  tokenPath: '/oauth2/token'
}

fastifyOauth2.VATSIM_CONFIGURATION = {
  authorizeHost: 'https://auth.vatsim.net',
  authorizePath: '/oauth/authorize',
  tokenHost: 'https://auth.vatsim.net',
  tokenPath: '/oauth/token'
}

fastifyOauth2.VATSIM_DEV_CONFIGURATION = {
  authorizeHost: 'https://auth-dev.vatsim.net',
  authorizePath: '/oauth/authorize',
  tokenHost: 'https://auth-dev.vatsim.net',
  tokenPath: '/oauth/token'
}

fastifyOauth2.EPIC_GAMES_CONFIGURATION = {
  authorizeHost: 'https://www.epicgames.com',
  authorizePath: '/id/authorize',
  tokenHost: 'https://api.epicgames.dev',
  tokenPath: '/epic/oauth/v1/token'
}

module.exports = fp(fastifyOauth2, {
  fastify: '4.x',
  name: '@fastify/oauth2'
})
module.exports.default = fastifyOauth2
module.exports.fastifyOauth2 = fastifyOauth2

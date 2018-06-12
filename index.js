'use strict'

const fp = require('fastify-plugin')
const oauth2Module = require('simple-oauth2')

module.exports = fp(function (fastify, options, next) {
  const oauth2 = oauth2Module.create(options.credentials)

  fastify.decorate('oauth2', oauth2)

  next()
})

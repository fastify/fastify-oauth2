# fastify-oauth2

Wrap around [`simple-oauth2`](https://github.com/lelylan/simple-oauth2) library.

## Install

```
npm i --save fastify-oauth2
```

## Usage

```js
const fastify = require('fastify')({ logger: { level: 'trace' } })
const oauthPlugin = require('fastify-oauth2')

// Register the plugin
fastify.register(oauthPlugin, {
  name: 'facebookOAuth2',
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.FACEBOOK_CONFIGURATION
    // auth: oauthPlugin.GITHUB_CONFIGURATION
  }
})

// Register the handler for the initial redirection
fastify.get('/login/facebook', function (request, reply) {
  const authorizationUri = this.facebookOAuth2.authorizationCode.authorizeURL({
    redirect_uri: 'http://localhost:3000/',
    state: 'my-state'
  })
  reply.redirect(authorizationUri)
})

// Exchange the code with the access_token
fastify.get('/', async function (request, reply) {
  const code = request.query.code

  const result = await this.facebookOAuth2.authorizationCode.getToken({
    code: code,
    redirect_uri: 'http://localhost:3000/'
  })
  console.log(result.access_token)
})

```

## Example

See [facebook example](./examples/facebook.js) for an example.

## Reference

This fastify plugin decorates the fastify instance with the [`simple-oauth2`](https://github.com/lelylan/simple-oauth2)
instance.

## License

Licensed under [MIT](./LICENSE).

*NB:* See [`simple-oauth2`](https://github.com/lelylan/simple-oauth2) license too

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


fastify.register(oauthPlugin, {
  name: 'facebookOAuth2',
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.FACEBOOK_CONFIGURATION
  },
  // register a fastify url to start the redirect flow
  startRedirectPath: '/login/facebook',
  // facebook redirect here after the user login
  callbackUri: 'http://localhost:3000/login/facebook/callback'
})

fastify.get('/login/facebook/callback', async function (request, reply) {
  const result = await this.getAccessTokenFromAuthorizationCodeFlow(request)

  console.log(result.access_token)

  // if later you need to refresh the token you can use
  // this.getNewAccessTokenWithRefreshToken(result.refresh_token)

  reply.send({ access_token: result.access_token })
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

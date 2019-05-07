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
  const result = await this.facebookOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)

  console.log(result.access_token)

  reply.send({ access_token: result.access_token })
})

fastify.register(oauthPlugin, {
	name: 'githubOAuth2',
	credentials: {
	  client: {
	    id: 'my-client-id',
	    secret: 'my-secret'
    },
	  auth: oauthPlugin.GITHUB_CONFIGURATION
	},
	startRedirectPath: '/login/github',
	callbackUri: 'http://localhost:3000/login/github/callback',
	scope: ['notifications']
})

fastify.get('/login/github/callback', function (request, reply) {
	return this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)
	  .then(result => {
	    const token = this.githubOAuth2.accessToken.create(result)
	    return {
        access_token: token.token.access_token,
	      refresh_token: token.token.refresh_token,
	      expires_in: token.token.expires_in,
	      token_type: token.token.token_type
	    }
	  })
})

```

## Example

See [facebook example](./examples/facebook.js) for an example.

## Reference

This fastify plugin decorates the fastify instance with the [`simple-oauth2`](https://github.com/lelylan/simple-oauth2)
instance using the name attribute, so when you register a plugin like `fastify.register(oauthPlugin, {name: 'foo'})` you'll have access to the
[helpers](https://github.com/lelylan/simple-oauth2#helpers) through
`fastify.foo.<helpers>`

## License

Licensed under [MIT](./LICENSE).

*NB:* See [`simple-oauth2`](https://github.com/lelylan/simple-oauth2) license too

# fastify-oauth2

![CI workflow](https://github.com/fastify/fastify-oauth2/workflows/CI%20workflow/badge.svg)

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
  const token = await this.facebookOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)

  console.log(token.access_token)

  // if later you need to refresh the token you can use
  // const newToken = await this.getNewAccessTokenUsingRefreshToken(token.refresh_token)

  reply.send({ access_token: token.access_token })
})
```

### Preset configurations

You can choose some default setup to assign to `auth` option.

- `APPLE_CONFIGURATION`
- `FACEBOOK_CONFIGURATION`
- `GITHUB_CONFIGURATION`
- `LINKEDIN_CONFIGURATION`
- `GOOGLE_CONFIGURATION`
- `MICROSOFT_CONFIGURATION`
- `VKONTAKTE_CONFIGURATION`
- `SPOTIFY_CONFIGURATION`

### Custom configuration

Of course you can set the OAUTH endpoints by yourself if a preset is not in our module:

```js
fastify.register(oauthPlugin, {
  name: 'customOauth2',
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: {
      authorizeHost: 'https://my-site.com',
      authorizePath: '/authorize',
      tokenHost: 'https://token.my-site.com',
      tokenPath: '/api/token'
    }
  },
  startRedirectPath: '/login',
  callbackUri: 'http://localhost:3000/login/callback'
})
```

## Set custom state

The `generateStateFunction` accepts a function to generate the `state` parameter for the OAUTH flow. This function receives the Fastify's `request` object as parameter.
When you set it, it is required to provide the function `checkStateFunction` also in order to validate the states generated.

```js
  const validStates = new Set()

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
    callbackUri: 'http://localhost:3000/login/facebook/callback',
    // custom function to generate the state
    generateStateFunction: (request) => {
      const state = request.query.customCode
      validStates.add(state)
      return state
    },
    // custom function to check the state is valid
    checkStateFunction: (returnedState, callback) => {
      if (validStates.has(returnedState)) {
        callback()
        return
      }
      callback(new Error('Invalid state'))
    }
  })
```

## Example

See the [`example/`](./examples/) folder for more example.

## Reference

This fastify plugin decorates the fastify instance with the [`simple-oauth2`](https://github.com/lelylan/simple-oauth2)
instance inside a **namespace** specified by the property `name`.

E.g. For `name: 'customOauth2'`, the `simple-oauth2` instance will become accessible like this:

`fastify.customOauth2.oauth2`

In this manner we are able to register multiple OAuth providers and each OAuth providers `simple-oauth2` instance will live in it's own **namespace**.

E.g.

- `fastify.facebook.oauth2`
- `fastify.github.oauth2`
- `fastify.spotify.oauth2`
- `fastify.vkontakte.oauth2`

Assuming we have registered multiple OAuth providers like this:

- `fastify.register(oauthPlugin, { name: 'facebook', { ... } // facebooks credentials, startRedirectPath, callbackUri etc )`
- `fastify.register(oauthPlugin, { name: 'github', { ... } // githubs credentials, startRedirectPath, callbackUri etc )`
- `fastify.register(oauthPlugin, { name: 'spotify', { ... } // spotifys credentials, startRedirectPath, callbackUri etc )`
- `fastify.register(oauthPlugin, { name: 'vkontakte', { ... } // vkontaktes credentials, startRedirectPath, callbackUri etc )`

## Utilities

This fastify plugin adds 3 utility decorators to your fastify instance using the same **namespace**:

- `getAccessTokenFromAuthorizationCodeFlow(request, callback)`: A function that uses the Authorization code flow to fetch an OAuth2 token using the data in the last request of the flow. If the callback is not passed it will return a promise. The object resulting from the callback call or the promise resolution is a *token response* object containing the following keys:
  - `access_token`
  - `refresh_token` (optional, only if the `offline scope` was originally requested)
  - `token_type` (generally `'bearer'`)
  - `expires_in` (number of seconds for the token to expire, e.g. `240000`)
- `getNewAccessTokenUsingRefreshToken(refreshToken, params, callback)`: A function that takes a refresh token and retrieves a new *token response* object. This is generally useful with background processing workers to re-issue a new token when the original token has expired. The `params` argument is optional and it's an object that can be used to pass in extra parameters to the refresh request (e.g. a stricter set of scopes). If the callback is not passed this function will return a promise. The object resulting from the callback call or the promise resolution is a new *token response* object (see fields above).
- `generateAuthorizationUri(requestObject)`: A function that returns the authorization uri. This is generally useful when you want to handle the redirect yourself in a specific route. The `requestObject` argument passes the request object to the `generateStateFunction`). You **don't** need to declare a `startRedirectPath` if you use this approach. Example of how you would use it:

```js
fastify.get('/external', { /* Hooks can be used here */ }, async (req, reply) => {
  const authorizationEndpoint = fastify.customOAuth2.generateAuthorizationUri(req);
  reply.redirect(authorizationEndpoint)
});
```

E.g. For `name: 'customOauth2'`, the helpers `getAccessTokenFromAuthorizationCodeFlow` and `getNewAccessTokenUsingRefreshToken` will become accessible like this:

- `fastify.customOauth2.getAccessTokenFromAuthorizationCodeFlow`
- `fastify.customOauth2.getNewAccessTokenUsingRefreshToken`

## Usage with Typescript

Type definitions are provided with package. Decoration are applied during runtime and are based on auth configuration name. One solution is leverage typescript declaration merging to add type-safe namespace.

In project declarations files .d.ts

```ts
import { OAuth2Namespace } from 'fastify-oauth2';

declare module 'fastify' {
  interface FastifyInstance {
    facebookOAuth2: OAuth2Namespace;
    myCustomOAuth2: OAuth2Namespace;
  }
}
```

## License

Licensed under [MIT](./LICENSE).

*NB:* See [`simple-oauth2`](https://github.com/lelylan/simple-oauth2) license too

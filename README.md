# @fastify/oauth2

![CI](https://github.com/fastify/fastify-oauth2/workflows/CI/badge.svg)
[![NPM version](https://img.shields.io/npm/v/@fastify/oauth2.svg?style=flat)](https://www.npmjs.com/package/@fastify/oauth2)
[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](https://standardjs.com/)

Wrapper around the [`simple-oauth2`](https://github.com/lelylan/simple-oauth2) library.

v4.x of this module support Fastify v3.x
[v3.x](https://github.com/fastify/fastify-oauth2/tree/3.x) of this module support Fastify v2.x

## Install

```
npm i @fastify/oauth2
```

## Usage

```js
const fastify = require('fastify')({ logger: { level: 'trace' } })
const oauthPlugin = require('@fastify/oauth2')

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
  const { token } = await this.facebookOAuth2.getAccessTokenFromAuthorizationCodeFlow(request)

  console.log(token.access_token)

  // if later you need to refresh the token you can use
  // const { token: newToken } = await this.getNewAccessTokenUsingRefreshToken(token)

  reply.send({ access_token: token.access_token })
})
```

### Usage with `@fastify/cookie`

Since v7.2.0, `@fastify/oauth2` requires the use of cookies to securely implement the OAuth2 exchange. Therefore, if you need `@fastify/cookie` yourself,
you will need to register it  _before_ `@fastify/oauth2`.

```js
const fastify = require('fastify')({ logger: { level: 'trace' } })
const oauthPlugin = require('@fastify/oauth2')

fastify.register(require('@fastify/cookie'), cookieOptions)
fastify.register(oauthPlugin, oauthOptions)
```

Cookies are by default `httpOnly`, `sameSite: Lax`. If this does not suit your use case, it is possible to override the default cookie settings by providing options in the configuration object, for example

```js
fastify.register(oauthPlugin, {
  ...,
  cookie: {
    secure: true,
    sameSite: 'none'
  }
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
- `DISCORD_CONFIGURATION`
- `TWITCH_CONFIGURATION`
- `VATSIM_CONFIGURATION`
- `VATSIM_DEV_CONFIGURATION`
- `EPIC_GAMES_CONFIGURATION`

### Custom configuration

Of course, you can set the OAUTH endpoints by yourself if a preset is not in our module:

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
  callbackUri: 'http://localhost:3000/login/callback',
  callbackUriParams: {
    exampleParam: 'example param value'
  }
})
```

### Schema configuration

You can specify your own schema for the `startRedirectPath` end-point. It allows you to create a well-documented document when using `@fastify/swagger` together.
Note: `schema` option will override the `tags` option without merging them.

```js
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
  // add tags for the schema
  tags: ['facebook', 'oauth2'],
  // add schema
  schema: {
    tags: ['facebook', 'oauth2'] // this will take the precedence
  }
})
```

## Set custom state

The `generateStateFunction` accepts a function to generate the `state` parameter for the OAUTH flow. This function receives the Fastify instance's `request` object as parameter.
The `state` parameter will be also set into a `httpOnly`, `sameSite: Lax` cookie.
When you set it, it is required to provide the function `checkStateFunction` in order to validate the states generated.

```js
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
      request.session.state = state
      return state
    },
    // custom function to check the state is valid
    checkStateFunction: (request, callback) => {
      if (request.query.state === request.session.state) {
        callback()
        return
      }
      callback(new Error('Invalid state'))
    }
  })
```

## Set custom callbackUri Parameters

The `callbackUriParams` accepts an object that will be translated to query parameters for the callback OAUTH flow. The default value is {}.

```js
fastify.register(oauthPlugin, {
  name: 'googleOAuth2',
  scope: ['profile', 'email'],
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>',
    },
    auth: oauthPlugin.GOOGLE_CONFIGURATION,
  },
  startRedirectPath: '/login/google',
  callbackUri: 'http://localhost:3000/login/google/callback',
  callbackUriParams: {
    // custom query param that will be passed to callbackUri
    access_type: 'offline', // will tell Google to send a refreshToken too
  },
});
```

## Set custom tokenRequest body Parameters

The `tokenRequestParams` parameter accepts an object that will be translated to additional parameters in the POST body
when requesting access tokens via the service’s token endpoint.

## Examples

See the [`example/`](./examples/) folder for more examples.

## Reference

This Fastify plugin decorates the fastify instance with the [`simple-oauth2`](https://github.com/lelylan/simple-oauth2)
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

- `getAccessTokenFromAuthorizationCodeFlow(request, callback)`: A function that uses the Authorization code flow to fetch an OAuth2 token using the data in the last request of the flow. If the callback is not passed it will return a promise. The callback call or promise resolution returns an [AccessToken](https://github.com/lelylan/simple-oauth2/blob/master/API.md#accesstoken) object, which has an `AccessToken.token` property with the following keys:
  - `access_token`
  - `refresh_token` (optional, only if the `offline scope` was originally requested, as seen in the callbackUriParams example)
  - `token_type` (generally `'Bearer'`)
  - `expires_in` (number of seconds for the token to expire, e.g. `240000`)
- `getNewAccessTokenUsingRefreshToken(Token, params, callback)`: A function that takes a `AccessToken`-Object as `Token` and retrieves a new `AccessToken`-Object. This is generally useful with background processing workers to re-issue a new AccessToken when the previous AccessToken has expired. The `params` argument is optional and it is an object that can be used to pass in additional parameters to the refresh request (e.g. a stricter set of scopes). If the callback is not passed this function will return a Promise. The object resulting from the callback call or the resolved Promise is a new `AccessToken` object (see above). Example of how you would use it for `name:googleOAuth2`:
```js
fastify.googleOAuth2.getNewAccessTokenUsingRefreshToken(currentAccessToken, (err, newAccessToken) => {
   // Handle the new accessToken
});
```

- `generateAuthorizationUri(requestObject, replyObject)`: A function that returns the authorization uri. This is generally useful when you want to handle the redirect yourself in a specific route. The `requestObject` argument passes the request object to the `generateStateFunction`). You **do not** need to declare a `startRedirectPath` if you use this approach. Example of how you would use it:

```js
fastify.get('/external', { /* Hooks can be used here */ }, async (req, reply) => {
  const authorizationEndpoint = fastify.customOAuth2.generateAuthorizationUri(req, reply);
  reply.redirect(authorizationEndpoint)
});
```

E.g. For `name: 'customOauth2'`, the helpers `getAccessTokenFromAuthorizationCodeFlow` and `getNewAccessTokenUsingRefreshToken` will become accessible like this:

- `fastify.customOauth2.getAccessTokenFromAuthorizationCodeFlow`
- `fastify.customOauth2.getNewAccessTokenUsingRefreshToken`

## Usage with TypeScript

Type definitions are provided with the package. Decorations are applied during runtime and are based on auth configuration name. One solution is to leverage TypeScript declaration merging to add type-safe namespace. Make sure you have `@types/node` installed for this to work correctly.

In project declarations files .d.ts

```ts
import { OAuth2Namespace } from '@fastify/oauth2';

declare module 'fastify' {
  interface FastifyInstance {
    facebookOAuth2: OAuth2Namespace;
    myCustomOAuth2: OAuth2Namespace;
  }
}
```

## Provider Quirks

The following providers require additional work to be set up correctly.   

### Twitch

Twitch requires that the request for a token in the oauth2 flow contains the `client_id` and `client_secret` properties in `tokenRequestParams`:

```js
fastify.register(oauthPlugin, {
  name: 'twitchOauth2',
  credentials: {
    client: {
      id: '<CLIENT_ID>',
      secret: '<CLIENT_SECRET>'
    },
    auth: oauthPlugin.TWITCH_CONFIGURATION
  },
  tokenRequestParams: {
    client_id: '<CLIENT_ID>',
    client_secret: '<CLIENT_SECRET>',
  },
  // register a fastify url to start the redirect flow
  startRedirectPath: '/login/twitch',
  // twitch redirect here after the user login
  callbackUri: 'http://localhost:3000/login/twitch/callback'
})
```

## License

Licensed under [MIT](./LICENSE).

*NB* See [`simple-oauth2`](https://github.com/lelylan/simple-oauth2) license too

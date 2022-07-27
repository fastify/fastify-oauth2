import fastify from 'fastify';
import { expectAssignable, expectError, expectType } from 'tsd';
import fastifyOauth2, { Credentials, OAuth2Namespace, OAuth2Token, ProviderConfiguration } from '../..';

/**
 * Preparing some data for testing.
 */
const auth = fastifyOauth2.GOOGLE_CONFIGURATION;
const scope = ['r_emailaddress', 'r_basicprofile'];
const tags = ['oauth2', 'oauth'];
const credentials = {
  client: {
    id: 'test_id',
    secret: 'test_secret',
  },
  auth: auth,
};
const OAuth2Options = {
  name: 'testOAuthName',
  scope: scope,
  credentials: credentials,
  callbackUri: 'http://localhost/testOauth/callback',
  callbackUriParams: {},
  generateStateFunction: () => {},
  checkStateFunction: () => {},
  startRedirectPath: '/login/testOauth',
};

const server = fastify();

server.register(fastifyOauth2, OAuth2Options);

declare module 'fastify' {
  // Developers need to define this in their code like they have to do with all decorators.
  interface FastifyInstance {
    testOAuthName: OAuth2Namespace;
  }
}

/**
 * Actual testing.
 */
expectType<ProviderConfiguration>(auth);
expectType<string[]>(scope);
expectType<string[]>(tags);
expectType<Credentials>(credentials);

expectError(fastifyOauth2()); // error because missing required arguments
expectError(fastifyOauth2(server, {}, () => {})); // error because missing required options

expectAssignable<ProviderConfiguration>(fastifyOauth2.DISCORD_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.FACEBOOK_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.GITHUB_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.GOOGLE_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.LINKEDIN_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.MICROSOFT_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.SPOTIFY_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.VKONTAKTE_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.TWITCH_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.VATSIM_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.VATSIM_DEV_CONFIGURATION);
expectAssignable<ProviderConfiguration>(fastifyOauth2.EPIC_GAMES_CONFIGURATION);

server.get('/testOauth/callback', async request => {
  expectType<OAuth2Namespace>(server.testOAuthName);

  expectType<OAuth2Token>(await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request));
  expectType<Promise<OAuth2Token>>(server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request));
  expectType<void>(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, (err: any, t: OAuth2Token): void => {}),
  );

  expectError<void>(await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)); // error because Promise should not return void
  expectError<OAuth2Token>(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, (err: any, t: OAuth2Token): void => {}),
  ); // error because non-Promise function call should return void and have a callback argument
  expectError<void>(server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)); // error because function call does not pass a callback as second argument.

  const token = await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request);
  if (token.refresh_token) {
    expectType<OAuth2Token>(
      await server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.refresh_token, {}),
    );
    expectType<Promise<OAuth2Token>>(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.refresh_token, {}),
    );
    expectType<void>(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(
        token.refresh_token,
        {},
        (err: any, t: OAuth2Token): void => { },
      ),
    );

    expectError<void>(await server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.refresh_token, {})); // error because Promise should not return void
    expectError<OAuth2Token>(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(
        token.refresh_token,
        {},
        (err: any, t: OAuth2Token): void => { },
      ),
    ); // error because non-Promise function call should return void and have a callback argument
    expectError<void>(server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.refresh_token, {})); // error because function call does not pass a callback as second argument.
  }

  expectType<string>(server.testOAuthName.generateAuthorizationUri(request));

  return {
    access_token: token.access_token,
  };
});

import * as fastify from 'fastify';
import * as fastifyOauth2 from '.';
import { expectType, expectError, expectAssignable } from 'tsd';

/**
 * Preparing some data for testing.
 */
const auth = fastifyOauth2.GOOGLE_CONFIGURATION;
const scope = ['r_emailaddress', 'r_basicprofile'];
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
    testOAuthName: fastifyOauth2.OAuth2Namespace;
  }
}

/**
 * Actual testing.
 */
expectType<fastifyOauth2.ProviderConfiguration>(auth);
expectType<string[]>(scope);
expectType<fastifyOauth2.Credentials>(credentials);
expectType<fastifyOauth2.Credentials>(credentials);

expectType<void>(fastifyOauth2(server, OAuth2Options, () => {}));
expectError(fastifyOauth2()); // error because missing required arguments
expectError(fastifyOauth2(server, {}, () => {})); // error because missing required plugin options

expectAssignable<fastifyOauth2.ProviderConfiguration>(fastifyOauth2.FACEBOOK_CONFIGURATION);
expectAssignable<fastifyOauth2.ProviderConfiguration>(fastifyOauth2.GITHUB_CONFIGURATION);
expectAssignable<fastifyOauth2.ProviderConfiguration>(fastifyOauth2.GOOGLE_CONFIGURATION);
expectAssignable<fastifyOauth2.ProviderConfiguration>(fastifyOauth2.LINKEDIN_CONFIGURATION);
expectAssignable<fastifyOauth2.ProviderConfiguration>(fastifyOauth2.MICROSOFT_CONFIGURATION);
expectAssignable<fastifyOauth2.ProviderConfiguration>(fastifyOauth2.SPOTIFY_CONFIGURATION);
expectAssignable<fastifyOauth2.ProviderConfiguration>(fastifyOauth2.VKONTAKTE_CONFIGURATION);

server.get('/testOauth/callback', async request => {
  expectType<fastifyOauth2.OAuth2Namespace>(server.testOAuthName);

  const token = await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request);
  expectType<fastifyOauth2.OAuth2Token>(token);
  expectType<void>(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, (t: fastifyOauth2.OAuth2Token): void => {}),
  );

  expectError<void>(await server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)); // error because Promise should not return void
  expectError<fastifyOauth2.OAuth2Token>(
    server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request, (t: fastifyOauth2.OAuth2Token): void => {}),
  ); // error because non-Promise function call should return void and have a callback argument
  expectError<void>(server.testOAuthName.getAccessTokenFromAuthorizationCodeFlow(request)); // error because function call does not pass a callback as second argument.

  if (token.refresh_token) {
    expectType<fastifyOauth2.OAuth2Token>(
      await server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.refresh_token, {}),
    );
    expectType<void>(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(
        token.refresh_token,
        {},
        (t: fastifyOauth2.OAuth2Token): void => {},
      ),
    );

    expectError<void>(await server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.refresh_token, {})); // error because Promise should not return void
    expectError<fastifyOauth2.OAuth2Token>(
      server.testOAuthName.getNewAccessTokenUsingRefreshToken(
        token.refresh_token,
        {},
        (t: fastifyOauth2.OAuth2Token): void => {},
      ),
    ); // error because non-Promise function call should return void and have a callback argument
    expectError<void>(server.testOAuthName.getNewAccessTokenUsingRefreshToken(token.refresh_token, {})); // error because function call does not pass a callback as second argument.
  }

  return {
    access_token: token.access_token,
  };
});

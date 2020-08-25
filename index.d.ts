import { FastifyRequest, FastifyInstance, RawServerBase, RawRequestDefaultExpression, RawReplyDefaultExpression, FastifyError } from 'fastify';

declare function fastifyOauth2 (
  instance: FastifyInstance,
  opts: fastifyOauth2.FastifyOAuth2Options,
  next: (err?: FastifyError) => void
): void;

declare namespace fastifyOauth2 {
  const APPLE_CONFIGURATION: ProviderConfiguration;
  const FACEBOOK_CONFIGURATION: ProviderConfiguration;
  const GITHUB_CONFIGURATION: ProviderConfiguration;
  const LINKEDIN_CONFIGURATION: ProviderConfiguration;
  const GOOGLE_CONFIGURATION: ProviderConfiguration;
  const MICROSOFT_CONFIGURATION: ProviderConfiguration;
  const SPOTIFY_CONFIGURATION: ProviderConfiguration;
  const VKONTAKTE_CONFIGURATION: ProviderConfiguration;

  interface OAuth2Token {
    token_type: 'bearer';
    access_token: string;
    refresh_token?: string;
    expires_in: number;
  }

  interface OAuth2Namespace {
    getAccessTokenFromAuthorizationCodeFlow(
      request: FastifyRequest,
    ): Promise<OAuth2Token>;

    getAccessTokenFromAuthorizationCodeFlow(
      request: FastifyRequest,
      callback: (token: OAuth2Token) => void,
    ): void;

    getNewAccessTokenUsingRefreshToken(
      refreshToken: string,
      params: Object,
      callback: (token: OAuth2Token) => void,
    ): void;

    getNewAccessTokenUsingRefreshToken(refreshToken: string, params: Object): Promise<OAuth2Token>;
  }

  interface ProviderConfiguration {
    authorizeHost: string;
    authorizePath: string;
    tokenHost: string;
    tokenPath: string;
  }

  interface Credentials {
    client: {
      id: string;
      secret: string;
    };
    auth: ProviderConfiguration;
  }

  interface FastifyOAuth2Options {
    name: string;
    scope: string[];
    credentials: Credentials;
    callbackUri: string;
    callbackUriParams?: Object;
    generateStateFunction?: Function;
    checkStateFunction?: Function;
    startRedirectPath: string;
    tags?: string[];
    schema?: object;
  }
}

export = fastifyOauth2;

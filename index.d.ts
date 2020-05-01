import * as fastify from 'fastify';
import * as http from 'http';

declare function fastifyOauth2(
  instance: fastify.FastifyInstance<http.Server, http.IncomingMessage, http.ServerResponse>,
  options: fastifyOauth2.FastifyOAuth2Options,
  callback: (err?: fastify.FastifyError) => void
): void;

declare namespace fastifyOauth2 {
  const FACEBOOK_CONFIGURATION: ProviderConfiguration;
  const GITHUB_CONFIGURATION: ProviderConfiguration;
  const LINKEDIN_CONFIGURATION: ProviderConfiguration;
  const GOOGLE_CONFIGURATION: ProviderConfiguration;
  const MICROSOFT_CONFIGURATION: ProviderConfiguration;
  const SPOTIFY_CONFIGURATION: ProviderConfiguration;
  const VKONTAKTE_CONFIGURATION: ProviderConfiguration;

  interface OAuth2Token{
    token_type: 'bearer';
    access_token: string;
    refresh_token?: string;
    expires_in: number
  }

  interface OAuth2Namespace{
    getAccessTokenFromAuthorizationCodeFlow(
      request: fastify.FastifyRequest<http.IncomingMessage>,
    ): Promise<OAuth2Token>

    getAccessTokenFromAuthorizationCodeFlow(
      request: fastify.FastifyRequest<http.IncomingMessage>,
      callback: (token: OAuth2Token) => void
    ): void

    getNewAccessTokenUsingRefreshToken(
      refreshToken: string,
      params: Object,
      callback: (token: OAuth2Token) => void
    ): void

    getNewAccessTokenUsingRefreshToken(
      refreshToken: string,
      params: Object,
    ): Promise<OAuth2Token>
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
  }
}

export = fastifyOauth2;

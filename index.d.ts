import * as fastify from 'fastify';
import * as http from 'http';


export interface OAuth2Token{
  token_type: 'bearer';
  access_token: string;
  refresh_token?: string;
  expires_in: number
}

export interface OAuth2Namespace{
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

export interface ProviderConfiguration {
  authorizeHost: string;
  authorizePath: string;
  tokenHost: string;
  tokenPath: string;
}

export interface Credentials {
  client: {
    id: string;
    secret: string;
  };
  auth: ProviderConfiguration;
}

export interface FastifyOAuth2Options {
  name: string;
  scope: string[];
  credentials: Credentials;
  callbackUri: string;
  callbackUriParams?: Object;
  generateStateFunction?: Function;
  checkStateFunction?: Function;
  startRedirectPath: string;
}


declare function fastifyOauth2(
  instance: fastify.FastifyInstance<http.Server, http.IncomingMessage, http.ServerResponse>,
  options: FastifyOAuth2Options,
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
}

export default fastifyOauth2;



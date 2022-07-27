import { FastifyPluginCallback, FastifyRequest } from 'fastify';

interface FastifyOAuth2 {
  APPLE_CONFIGURATION: ProviderConfiguration;
  DISCORD_CONFIGURATION: ProviderConfiguration;
  FACEBOOK_CONFIGURATION: ProviderConfiguration;
  GITHUB_CONFIGURATION: ProviderConfiguration;
  LINKEDIN_CONFIGURATION: ProviderConfiguration;
  GOOGLE_CONFIGURATION: ProviderConfiguration;
  MICROSOFT_CONFIGURATION: ProviderConfiguration;
  SPOTIFY_CONFIGURATION: ProviderConfiguration;
  VKONTAKTE_CONFIGURATION: ProviderConfiguration;
  TWITCH_CONFIGURATION: ProviderConfiguration;
  VATSIM_CONFIGURATION: ProviderConfiguration;
  VATSIM_DEV_CONFIGURATION: ProviderConfiguration;
  EPIC_GAMES_CONFIGURATION: ProviderConfiguration;
}

export const fastifyOauth2: FastifyPluginCallback<FastifyOAuth2Options> & FastifyOAuth2

export interface FastifyOAuth2Options {
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

export interface OAuth2Token {
  token_type: 'bearer';
  access_token: string;
  refresh_token?: string;
  expires_in: number;
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

export interface OAuth2Namespace {
  getAccessTokenFromAuthorizationCodeFlow(
    request: FastifyRequest,
  ): Promise<OAuth2Token>;

  getAccessTokenFromAuthorizationCodeFlow(
    request: FastifyRequest,
    callback: (err: any, token: OAuth2Token) => void,
  ): void;

  getNewAccessTokenUsingRefreshToken(
    refreshToken: string,
    params: Object,
    callback: (err: any, token: OAuth2Token) => void,
  ): void;

  getNewAccessTokenUsingRefreshToken(refreshToken: string, params: Object): Promise<OAuth2Token>;

  generateAuthorizationUri(
    request: FastifyRequest,
  ): string;
}

export default fastifyOauth2;

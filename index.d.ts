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

export interface Token {  
  token_type: 'bearer';
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  expires_at: Date;
}

export interface OAuth2Token {
  /**
   * Immutable object containing the token object provided while constructing a new access token instance.
   * This property will usually have the schema as specified by RFC6750,
   * but the exact properties may vary between authorization servers.
   */
  token: Token;

  /**
   * Determines if the current access token is definitely expired or not
   * @param expirationWindowSeconds Window of time before the actual expiration to refresh the token. Defaults to 0.
   */
  expired(expirationWindowSeconds?: number): boolean;

  /** Refresh the access token */
  refresh(params?: {}): Promise<AccessToken>;

  /** Revoke access or refresh token */
  revoke(tokenType: TokenType): Promise<void>;

  /** Revoke both the existing access and refresh tokens */
  revokeAll(): Promise<void>;
}

export interface ProviderConfiguration {
  /** String used to set the host to request the tokens to. Required. */
  tokenHost: string;
  /** String path to request an access token. Default to /oauth/token. */
  tokenPath?: string | undefined;
  /** String path to revoke an access token. Default to /oauth/revoke. */
  revokePath?: string | undefined;
  /** String used to set the host to request an "authorization code". Default to the value set on auth.tokenHost. */
  authorizeHost?: string | undefined;
  /** String path to request an authorization code. Default to /oauth/authorize. */
  authorizePath?: string | undefined;
}

export interface Credentials {
  client: {
      /** Service registered client id. Required. */
      id: string;
      /** Service registered client secret. Required. */
      secret: string;
      /** Parameter name used to send the client secret. Default to client_secret. */
      secretParamName?: string | undefined;
      /** Parameter name used to send the client id. Default to client_id. */
      idParamName?: string | undefined;
  };
  auth: ProviderConfiguration;
  /**
   * Used to set global options to the internal http library (wreck).
   * All options except baseUrl are allowed
   * Defaults to header.Accept = "application/json"
   */
  http?: {} | undefined;
  options?: {
      /** Format of data sent in the request body. Defaults to form. */
      bodyFormat?: "json" | "form" | undefined;
      /**
       * Indicates the method used to send the client.id/client.secret authorization params at the token request.
       * If set to body, the bodyFormat option will be used to format the credentials.
       * Defaults to header
       */
      authorizationMethod?: "header" | "body" | undefined;
  } | undefined;
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

  getNewAccessTokenUsingRefreshToken(refreshToken: Token, params: Object): Promise<OAuth2Token>;

  generateAuthorizationUri(
    request: FastifyRequest,
  ): string;
}

export default fastifyOauth2;

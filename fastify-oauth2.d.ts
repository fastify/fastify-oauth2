import { FastifyInstance, FastifyRequest, FastifyReply, FastifyError } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http';
import * as oauthPlugin from './index';

declare module 'fastify' {
  interface FastifyInstance<
    HttpServer = Server,
    HttpRequest = IncomingMessage,
    HttpResponse = ServerResponse
  > {
    getAccessTokenFromAuthorizationCodeFlow: oauthPlugin.getAccessTokenFromAuthorizationCodeFlow;
    getNewAccessTokenUsingRefreshToken: oauthPlugin.getNewAccessTokenUsingRefreshToken;
  }
}

declare module 'fastify-oauth2' {
  import { FastifyInstance, FastifyRequest, FastifyReply, FastifyError } from 'fastify';
  import { Server, IncomingMessage, ServerResponse } from 'http';

  function oauthPlugin(
    fastify: FastifyInstance<Server, IncomingMessage, ServerResponse>,
    options: Object,
    next: (err?: FastifyError) => void
  ): void;

  namespace oauthPlugin {

    function startRedirectHandler (request: FastifyRequest<IncomingMessage>, reply: FastifyReply<ServerResponse>): void

    function getAccessTokenFromAuthorizationCodeFlow(request: FastifyRequest<IncomingMessage>, callback?: (err?: FastifyError) => void): void | Promise<Object>

    function getAccessTokenFromAuthorizationCodeFlowCallbacked (request: FastifyRequest<IncomingMessage>, callback: (err?: FastifyError) => void): Promise<Object>

    function getNewAccessTokenUsingRefreshToken(refreshToken: string, params: Object, callback?: (err?: FastifyError) => void): any

    function getNewAccessTokenUsingRefreshTokenCallbacked(refreshToken: string, params: Object, callback: (err?: FastifyError) => void): any

    type options = {
      name: string;
      scope: String[];
      credentials: Credentials;
      callbackUri: string;
      callbackUriParams: Object;
      generateStateFunction: Function;
      checkStateFunction: Function;
      startRedirectPath: string;
    };

    type Configuration = {
      authorizeHost: string;
      authorizePath: string;
      tokenHost: string;
      tokenPath: string;
    };

    type Credentials = {
      client: {
        id: string;
        secret: string;
      };
      auth: {
        authorizeHost: string;
        authorizePath: string;
        tokenHost: string;
        tokenPath: string;
      };
    };

    const oauth2: any;

    const FACEBOOK_CONFIGURATION: Configuration;
    const GITHUB_CONFIGURATION: Configuration;
    const LINKEDIN_CONFIGURATION: Configuration;
    const GOOGLE_CONFIGURATION: Configuration;
    const MICROSOFT_CONFIGURATION: Configuration;
    const SPOTIFY_CONFIGURATION: Configuration;
    const VKONTAKTE_CONFIGURATION: Configuration;
  }

  export = oauthPlugin;
}
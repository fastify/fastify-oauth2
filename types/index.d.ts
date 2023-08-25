import type { FastifyPluginCallback, FastifyReply, FastifyRequest } from 'fastify';
import type { CookieSerializeOptions } from "@fastify/cookie";
import type { ModuleOptions } from 'simple-oauth2';

interface FastifyOauth2 extends FastifyPluginCallback<fastifyOauth2.FastifyOAuth2Options> {
    APPLE_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    DISCORD_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    FACEBOOK_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    GITHUB_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    GITLAB_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    LINKEDIN_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    GOOGLE_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    MICROSOFT_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    SPOTIFY_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    VKONTAKTE_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    TWITCH_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    VATSIM_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    VATSIM_DEV_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
    EPIC_GAMES_CONFIGURATION: fastifyOauth2.ProviderConfiguration;
}

declare namespace fastifyOauth2 {
  export interface FastifyOAuth2Options {
    name: string;
    scope?: string[];
    credentials: Credentials;
    callbackUri: string;
    callbackUriParams?: Object;
    tokenRequestParams?: Object;
    generateStateFunction?: Function;
    checkStateFunction?: Function;
    startRedirectPath?: string;
    tags?: string[];
    schema?: object;
    cookie?: CookieSerializeOptions;
  }

    export type TToken = 'access_token' | 'refresh_token'

    export interface Token {
        token_type: 'Bearer';
        access_token: string;
        refresh_token?: string;
        id_token?: string;
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
        refresh(params?: {}): Promise<OAuth2Token>;

        /** Revoke access or refresh token */
        revoke(tokenType: 'access_token' | 'refresh_token'): Promise<void>;

        /** Revoke both the existing access and refresh tokens */
        revokeAll(): Promise<void>;
    }

    // Can't extend ModuleOptions["auth"] directly
    type SimpleOauth2ProviderConfiguration = ModuleOptions["auth"];
    // Kept for backwards compatibility
    export interface ProviderConfiguration extends SimpleOauth2ProviderConfiguration {}

    // Kept for backwards compatibility
    export interface Credentials extends ModuleOptions<string> {
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
            refreshToken: Token,
            params: Object,
            callback: (err: any, token: OAuth2Token) => void,
        ): void;

        getNewAccessTokenUsingRefreshToken(refreshToken: Token, params: Object): Promise<OAuth2Token>;

        generateAuthorizationUri(
            request: FastifyRequest,
            reply: FastifyReply,
        ): string;

        revokeToken(
            revokeToken: Token,
            tokenType: TToken,
            httpOptions: Object | undefined,
            callback: (err: any) => void
        ): void

        revokeToken(revokeToken: Token, tokenType: TToken, httpOptions: Object | undefined): Promise<void>

        revokeAllToken(
            revokeToken: Token,
            httpOptions: Object | undefined,
            callback: (err: any) => void
        ): void;

        revokeAllToken(revokeToken: Token, httpOptions: Object | undefined): Promise<void>
    }

    export const fastifyOauth2: FastifyOauth2
    export {fastifyOauth2 as default}
}

declare function fastifyOauth2(...params: Parameters<FastifyOauth2>): ReturnType<FastifyOauth2>

export = fastifyOauth2

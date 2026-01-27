import { Logger } from '@nestjs/common';
import type { HttpResponse } from '../mcp/interfaces/http-adapter.interface';
import type { OAuthEndpointConfiguration, OAuthModuleOptions, OAuthUserProfile } from './providers/oauth-provider.interface';
import { ClientService } from './services/client.service';
import { JwtTokenService, TokenPair } from './services/jwt-token.service';
import { OAuthStrategyService } from './services/oauth-strategy.service';
import type { IOAuthStore } from './stores/oauth-store.interface';
interface OAuthCallbackRequest {
    user?: {
        profile: OAuthUserProfile;
        accessToken: string;
        provider: string;
    };
    headers: Record<string, string | string[] | undefined>;
    cookies?: Record<string, string | undefined>;
    [key: string]: any;
}
interface RequestWithRawBody {
    headers: Record<string, string | string[] | undefined>;
    body?: any;
    rawBody?: Buffer;
    textBody?: string;
    cookies?: Record<string, string | undefined>;
    [key: string]: any;
}
export declare function createMcpOAuthController(endpoints?: OAuthEndpointConfiguration, options?: {
    disableWellKnownProtectedResourceMetadata?: boolean;
    disableWellKnownAuthorizationServerMetadata?: boolean;
}, authModuleId?: string): {
    new (options: OAuthModuleOptions, store: IOAuthStore, jwtTokenService: JwtTokenService, clientService: ClientService, oauthStrategyService: OAuthStrategyService): {
        readonly logger: Logger;
        readonly serverUrl: string;
        readonly isProduction: boolean;
        readonly options: OAuthModuleOptions;
        readonly strategyName: string;
        readonly store: IOAuthStore;
        readonly jwtTokenService: JwtTokenService;
        readonly clientService: ClientService;
        readonly oauthStrategyService: OAuthStrategyService;
        parseRequestBody(body: any, req?: RequestWithRawBody): Record<string, any>;
        captureRawBodyAsync(req: RequestWithRawBody): Promise<void>;
        getProtectedResourceMetadata(): {
            authorization_servers: string[];
            resource: string;
            scopes_supported: string[];
            bearer_methods_supported: string[];
            mcp_versions_supported: string[];
        };
        getAuthorizationServerMetadata(): {
            issuer: string;
            authorization_endpoint: string;
            token_endpoint: string;
            registration_endpoint: string;
            response_types_supported: string[];
            response_modes_supported: string[];
            grant_types_supported: string[];
            token_endpoint_auth_methods_supported: string[];
            scopes_supported: string[];
            revocation_endpoint: string;
            code_challenge_methods_supported: string[];
        };
        registerClient(registrationDto: any): Promise<import("./stores/oauth-store.interface").OAuthClient>;
        authorize(query: any, req: any, res: any): Promise<void>;
        handleProviderCallback(req: OAuthCallbackRequest, res: any): Promise<void>;
        processAuthenticationSuccess(req: OAuthCallbackRequest, res: any, adaptedRes?: HttpResponse): Promise<void>;
        exchangeToken(body: any, req: RequestWithRawBody, res: any): Promise<TokenPair>;
        processTokenExchange(parsedBody: Record<string, any>, req: RequestWithRawBody): Promise<TokenPair>;
        extractClientCredentials(req: RequestWithRawBody, body: any): {
            client_id: string;
            client_secret?: string;
        };
        validateClientAuthentication(client: any, clientCredentials: {
            client_id: string;
            client_secret?: string;
        }): void;
        handleAuthorizationCodeGrant(code: string, code_verifier: string, _redirect_uri: string, clientCredentials: {
            client_id: string;
            client_secret?: string;
        }): Promise<TokenPair>;
        handleRefreshTokenGrant(refresh_token: string, clientCredentials: {
            client_id: string;
            client_secret?: string;
        }): Promise<TokenPair>;
        validatePKCE(code_verifier: string, code_challenge: string, method: string): boolean;
    };
};
export {};
//# sourceMappingURL=mcp-oauth.controller.d.ts.map
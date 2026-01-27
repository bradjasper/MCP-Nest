import { CanActivate, ExecutionContext } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { JwtPayload, JwtTokenService } from '../services/jwt-token.service';
import type { IOAuthStore } from '../stores/oauth-store.interface';
import type { McpOptions } from '../../mcp';
export interface AuthenticatedRequest {
    headers: {
        authorization?: string;
        [key: string]: string | string[] | undefined;
    };
    user?: JwtPayload;
    [key: string]: any;
}
export declare class McpAuthJwtGuard implements CanActivate {
    private readonly jwtTokenService;
    private readonly store;
    private readonly moduleRef;
    private readonly options?;
    constructor(jwtTokenService: JwtTokenService | null, store: IOAuthStore | null, moduleRef: ModuleRef, options?: McpOptions | undefined);
    canActivate(context: ExecutionContext): Promise<boolean>;
    private extractTokenFromHeader;
}
//# sourceMappingURL=jwt-auth.guard.d.ts.map
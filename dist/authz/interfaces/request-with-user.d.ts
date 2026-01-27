import type { JwtPayload } from '../services/jwt-token.service';
export type McpUserPayload = JwtPayload & {
    name?: string;
    username?: string;
    email?: string;
    displayName?: string;
    avatarUrl?: string;
};
export interface McpRequestWithUser {
    headers: Record<string, string | string[] | undefined>;
    user: McpUserPayload;
    body?: any;
    query?: Record<string, any>;
    params?: Record<string, string>;
    cookies?: Record<string, string | undefined>;
    [key: string]: any;
}
//# sourceMappingURL=request-with-user.d.ts.map
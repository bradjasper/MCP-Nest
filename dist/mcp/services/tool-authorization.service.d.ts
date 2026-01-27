import { DiscoveredTool } from './mcp-registry.service';
import { ToolMetadata, SecurityScheme } from '../decorators/tool.decorator';
import { JwtPayload } from '../../authz/services/jwt-token.service';
export declare class ToolAuthorizationService {
    generateSecuritySchemes(tool: DiscoveredTool<ToolMetadata>, moduleHasGuards: boolean): SecurityScheme[];
    canAccessTool(user: JwtPayload | undefined, tool: DiscoveredTool<ToolMetadata>, moduleHasGuards: boolean, allowUnauthenticatedAccess?: boolean): boolean;
    validateToolAccess(user: JwtPayload | undefined, tool: DiscoveredTool<ToolMetadata>, moduleHasGuards: boolean, allowUnauthenticatedAccess?: boolean): void;
    private hasRequiredScopes;
    private hasRequiredRoles;
}
//# sourceMappingURL=tool-authorization.service.d.ts.map
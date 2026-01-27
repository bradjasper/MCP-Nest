import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ModuleRef } from '@nestjs/core';
import { McpRegistryService } from '../mcp-registry.service';
import { McpHandlerBase } from './mcp-handler.base';
import { HttpRequest } from '../../interfaces/http-adapter.interface';
import { ToolAuthorizationService } from '../tool-authorization.service';
import type { McpOptions } from '../../interfaces/mcp-options.interface';
export declare class McpToolsHandler extends McpHandlerBase {
    private readonly mcpModuleId;
    private readonly options;
    private readonly authService;
    private readonly moduleHasGuards;
    constructor(moduleRef: ModuleRef, registry: McpRegistryService, mcpModuleId: string, options: McpOptions, authService: ToolAuthorizationService);
    private buildDefaultContentBlock;
    private formatToolResult;
    registerHandlers(mcpServer: McpServer, httpRequest: HttpRequest): void;
}
//# sourceMappingURL=mcp-tools.handler.d.ts.map
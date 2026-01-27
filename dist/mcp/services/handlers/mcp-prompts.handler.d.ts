import { ModuleRef } from '@nestjs/core';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpRegistryService } from '../mcp-registry.service';
import { McpHandlerBase } from './mcp-handler.base';
import { HttpRequest } from '../../interfaces/http-adapter.interface';
import type { McpOptions } from '../../interfaces';
export declare class McpPromptsHandler extends McpHandlerBase {
    private readonly mcpModuleId;
    constructor(moduleRef: ModuleRef, registry: McpRegistryService, mcpModuleId: string, options?: McpOptions);
    registerHandlers(mcpServer: McpServer, httpRequest: HttpRequest): void;
}
//# sourceMappingURL=mcp-prompts.handler.d.ts.map
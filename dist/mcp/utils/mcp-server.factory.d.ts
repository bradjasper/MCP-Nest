import { McpOptions } from '../interfaces';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpRegistryService } from '../services/mcp-registry.service';
import { Logger } from '@nestjs/common';
export declare function createMcpServer(mcpModuleId: string, registry: McpRegistryService, options: McpOptions, logger: Logger): McpServer;
//# sourceMappingURL=mcp-server.factory.d.ts.map
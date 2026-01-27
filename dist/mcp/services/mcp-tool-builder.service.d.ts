import { DynamicToolDefinition, DynamicToolHandler } from '../interfaces/dynamic-tool.interface';
import { McpRegistryService } from './mcp-registry.service';
import type { McpOptions } from '../interfaces';
export declare const DYNAMIC_TOOL_HANDLER_TOKEN: unique symbol;
export declare class McpToolBuilder {
    private readonly registry;
    private readonly mcpModuleId;
    private readonly options;
    private readonly logger;
    constructor(registry: McpRegistryService, mcpModuleId: string, options: McpOptions);
    registerTool(definition: DynamicToolDefinition): void;
    getHandler(toolName: string): DynamicToolHandler | undefined;
    static getHandlerByModuleId(mcpModuleId: string, toolName: string): DynamicToolHandler | undefined;
}
//# sourceMappingURL=mcp-tool-builder.service.d.ts.map
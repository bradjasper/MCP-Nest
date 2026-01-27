"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var McpToolBuilder_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.McpToolBuilder = exports.DYNAMIC_TOOL_HANDLER_TOKEN = void 0;
const common_1 = require("@nestjs/common");
const zod_1 = require("zod");
const mcp_registry_service_1 = require("./mcp-registry.service");
const mcp_logger_factory_1 = require("../utils/mcp-logger.factory");
exports.DYNAMIC_TOOL_HANDLER_TOKEN = Symbol('DYNAMIC_TOOL_HANDLER');
const globalHandlers = new Map();
let McpToolBuilder = McpToolBuilder_1 = class McpToolBuilder {
    constructor(registry, mcpModuleId, options) {
        this.registry = registry;
        this.mcpModuleId = mcpModuleId;
        this.options = options;
        this.logger = (0, mcp_logger_factory_1.createMcpLogger)(McpToolBuilder_1.name, this.options);
        if (!globalHandlers.has(mcpModuleId)) {
            globalHandlers.set(mcpModuleId, new Map());
        }
    }
    registerTool(definition) {
        this.logger.debug(`Registering dynamic tool: ${definition.name}`);
        const moduleHandlers = globalHandlers.get(this.mcpModuleId);
        moduleHandlers.set(definition.name, definition.handler);
        const parameters = definition.parameters ?? zod_1.z.object({});
        const metadata = {
            name: definition.name,
            description: definition.description,
            parameters,
            outputSchema: definition.outputSchema,
            annotations: definition.annotations,
            _meta: definition._meta,
            isPublic: definition.isPublic,
            requiredScopes: definition.requiredScopes,
            requiredRoles: definition.requiredRoles,
        };
        this.registry.registerDynamicTool(this.mcpModuleId, {
            type: 'tool',
            metadata,
            providerClass: exports.DYNAMIC_TOOL_HANDLER_TOKEN,
            methodName: definition.name,
        });
    }
    getHandler(toolName) {
        return globalHandlers.get(this.mcpModuleId)?.get(toolName);
    }
    static getHandlerByModuleId(mcpModuleId, toolName) {
        return globalHandlers.get(mcpModuleId)?.get(toolName);
    }
};
exports.McpToolBuilder = McpToolBuilder;
exports.McpToolBuilder = McpToolBuilder = McpToolBuilder_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, common_1.Inject)('MCP_MODULE_ID')),
    __param(2, (0, common_1.Inject)('MCP_OPTIONS')),
    __metadata("design:paramtypes", [mcp_registry_service_1.McpRegistryService, String, Object])
], McpToolBuilder);
//# sourceMappingURL=mcp-tool-builder.service.js.map
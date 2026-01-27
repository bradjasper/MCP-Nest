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
var McpToolsHandler_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.McpToolsHandler = void 0;
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const mcp_registry_service_1 = require("../mcp-registry.service");
const mcp_handler_base_1 = require("./mcp-handler.base");
const tool_authorization_service_1 = require("../tool-authorization.service");
const zod_json_schema_compat_js_1 = require("@modelcontextprotocol/sdk/server/zod-json-schema-compat.js");
const zod_compat_js_1 = require("@modelcontextprotocol/sdk/server/zod-compat.js");
const mcp_tool_builder_service_1 = require("../mcp-tool-builder.service");
let McpToolsHandler = McpToolsHandler_1 = class McpToolsHandler extends mcp_handler_base_1.McpHandlerBase {
    constructor(moduleRef, registry, mcpModuleId, options, authService) {
        super(moduleRef, registry, McpToolsHandler_1.name, options);
        this.mcpModuleId = mcpModuleId;
        this.options = options;
        this.authService = authService;
        this.moduleHasGuards =
            this.options.guards !== undefined && this.options.guards.length > 0;
    }
    buildDefaultContentBlock(result) {
        return [
            {
                type: 'text',
                text: JSON.stringify(result),
            },
        ];
    }
    formatToolResult(result, outputSchema) {
        if (result && typeof result === 'object' && Array.isArray(result.content)) {
            return result;
        }
        if (outputSchema) {
            const validation = outputSchema.safeParse(result);
            if (!validation.success) {
                throw new types_js_1.McpError(types_js_1.ErrorCode.InternalError, `Tool result does not match outputSchema: ${validation.error.message}`);
            }
            return {
                structuredContent: result,
                content: this.buildDefaultContentBlock(result),
            };
        }
        return {
            content: this.buildDefaultContentBlock(result),
        };
    }
    registerHandlers(mcpServer, httpRequest) {
        if (this.registry.getTools(this.mcpModuleId).length === 0) {
            this.logger.debug('No tools registered, skipping tool handlers');
            return;
        }
        mcpServer.server.setRequestHandler(types_js_1.ListToolsRequestSchema, () => {
            const user = httpRequest.raw
                ? httpRequest.raw.user
                : undefined;
            const allTools = this.registry.getTools(this.mcpModuleId);
            const effectiveModuleHasGuards = httpRequest.raw
                ? this.moduleHasGuards
                : false;
            const allowUnauthenticatedAccess = this.options.allowUnauthenticatedAccess ?? false;
            const authorizedTools = allTools.filter((tool) => this.authService.canAccessTool(user, tool, effectiveModuleHasGuards, allowUnauthenticatedAccess));
            const tools = authorizedTools.map((tool) => {
                const toolSchema = {
                    name: tool.metadata.name,
                    description: tool.metadata.description,
                    annotations: tool.metadata.annotations,
                    _meta: tool.metadata._meta,
                };
                const securitySchemes = this.authService.generateSecuritySchemes(tool, effectiveModuleHasGuards);
                if (securitySchemes.length > 0) {
                    toolSchema['securitySchemes'] = securitySchemes;
                    toolSchema._meta = {
                        ...toolSchema._meta,
                        securitySchemes,
                    };
                }
                const normalizedInputParameters = (0, zod_compat_js_1.normalizeObjectSchema)(tool.metadata.parameters);
                if (normalizedInputParameters) {
                    toolSchema['inputSchema'] = (0, zod_json_schema_compat_js_1.toJsonSchemaCompat)(normalizedInputParameters);
                }
                const normalizedOutputSchema = (0, zod_compat_js_1.normalizeObjectSchema)(tool.metadata.outputSchema);
                if (normalizedOutputSchema) {
                    const outputSchema = (0, zod_json_schema_compat_js_1.toJsonSchemaCompat)(normalizedOutputSchema);
                    const jsonSchema = {
                        ...outputSchema,
                        type: 'object',
                    };
                    toolSchema['outputSchema'] = jsonSchema;
                }
                return toolSchema;
            });
            return {
                tools,
            };
        });
        mcpServer.server.setRequestHandler(types_js_1.CallToolRequestSchema, async (request) => {
            this.logger.debug('CallToolRequestSchema is being called');
            const toolInfo = this.registry.findTool(this.mcpModuleId, request.params.name);
            if (!toolInfo) {
                throw new types_js_1.McpError(types_js_1.ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
            }
            const user = httpRequest.raw
                ? httpRequest.raw.user
                : undefined;
            const effectiveModuleHasGuards = httpRequest.raw
                ? this.moduleHasGuards
                : false;
            const allowUnauthenticatedAccess = this.options.allowUnauthenticatedAccess ?? false;
            this.authService.validateToolAccess(user, toolInfo, effectiveModuleHasGuards, allowUnauthenticatedAccess);
            try {
                if (toolInfo.metadata.parameters) {
                    const validation = toolInfo.metadata.parameters.safeParse(request.params.arguments || {});
                    if (!validation.success) {
                        const issues = validation.error.issues
                            .map((issue) => {
                            const path = issue.path.length > 0 ? issue.path.join('.') : '';
                            const location = path ? `[${path}]: ` : '';
                            return `${location}${issue.message}`;
                        })
                            .join('; ');
                        return {
                            content: [
                                {
                                    type: 'text',
                                    text: `Invalid parameters: ${issues}`,
                                },
                            ],
                            isError: true,
                        };
                    }
                    request.params.arguments = validation.data;
                }
                const contextId = core_1.ContextIdFactory.getByRequest(httpRequest);
                this.moduleRef.registerRequestByContextId(httpRequest, contextId);
                const context = this.createContext(mcpServer, request);
                let result;
                if (toolInfo.providerClass === mcp_tool_builder_service_1.DYNAMIC_TOOL_HANDLER_TOKEN) {
                    const handler = mcp_tool_builder_service_1.McpToolBuilder.getHandlerByModuleId(this.mcpModuleId, request.params.name);
                    if (!handler) {
                        throw new types_js_1.McpError(types_js_1.ErrorCode.MethodNotFound, `Handler not found for dynamic tool: ${request.params.name}`);
                    }
                    result = await handler(request.params.arguments || {}, context, httpRequest.raw);
                }
                else {
                    const toolInstance = await this.moduleRef.resolve(toolInfo.providerClass, contextId, { strict: false });
                    if (!toolInstance) {
                        throw new types_js_1.McpError(types_js_1.ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
                    }
                    result = await toolInstance[toolInfo.methodName].call(toolInstance, request.params.arguments, context, httpRequest.raw);
                }
                const transformedResult = this.formatToolResult(result, toolInfo.metadata.outputSchema);
                this.logger.debug(transformedResult, 'CallToolRequestSchema result');
                return transformedResult;
            }
            catch (error) {
                this.logger.error(error);
                if (error instanceof types_js_1.McpError) {
                    throw error;
                }
                return {
                    content: [{ type: 'text', text: error.message }],
                    isError: true,
                };
            }
        });
    }
};
exports.McpToolsHandler = McpToolsHandler;
exports.McpToolsHandler = McpToolsHandler = McpToolsHandler_1 = __decorate([
    (0, common_1.Injectable)({ scope: common_1.Scope.REQUEST }),
    __param(2, (0, common_1.Inject)('MCP_MODULE_ID')),
    __param(3, (0, common_1.Inject)('MCP_OPTIONS')),
    __metadata("design:paramtypes", [core_1.ModuleRef,
        mcp_registry_service_1.McpRegistryService, String, Object, tool_authorization_service_1.ToolAuthorizationService])
], McpToolsHandler);
//# sourceMappingURL=mcp-tools.handler.js.map
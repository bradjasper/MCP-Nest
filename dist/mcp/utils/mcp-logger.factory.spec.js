"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("@nestjs/common");
const mcp_logger_factory_1 = require("./mcp-logger.factory");
describe('McpLoggerFactory', () => {
    describe('createMcpLogger', () => {
        it('should create standard logger when no options provided', () => {
            const logger = (0, mcp_logger_factory_1.createMcpLogger)('TestContext', undefined);
            expect(logger).toBeInstanceOf(common_1.Logger);
        });
        it('should create standard logger when logging is undefined', () => {
            const options = {
                name: 'test',
                version: '1.0.0',
            };
            const logger = (0, mcp_logger_factory_1.createMcpLogger)('TestContext', options);
            expect(logger).toBeInstanceOf(common_1.Logger);
        });
        it('should create no-op logger when logging is false', () => {
            const options = {
                name: 'test',
                version: '1.0.0',
                logging: false,
            };
            const logger = (0, mcp_logger_factory_1.createMcpLogger)('TestContext', options);
            expect(logger).toBeInstanceOf(common_1.Logger);
            expect(() => {
                logger.log('test message');
                logger.error('test error');
                logger.warn('test warning');
                logger.debug('test debug');
                logger.verbose('test verbose');
            }).not.toThrow();
        });
        it('should create filtered logger with specified levels', () => {
            const options = {
                name: 'test',
                version: '1.0.0',
                logging: {
                    level: ['error', 'warn'],
                },
            };
            const logger = (0, mcp_logger_factory_1.createMcpLogger)('TestContext', options);
            expect(logger).toBeInstanceOf(common_1.Logger);
            expect(() => {
                logger.log('test message');
                logger.error('test error');
                logger.warn('test warning');
                logger.debug('test debug');
                logger.verbose('test verbose');
            }).not.toThrow();
        });
        it('should create logger with all log levels when specified', () => {
            const options = {
                name: 'test',
                version: '1.0.0',
                logging: {
                    level: ['log', 'error', 'warn', 'debug', 'verbose'],
                },
            };
            const logger = (0, mcp_logger_factory_1.createMcpLogger)('TestContext', options);
            expect(logger).toBeInstanceOf(common_1.Logger);
        });
        it('should handle empty level array gracefully', () => {
            const options = {
                name: 'test',
                version: '1.0.0',
                logging: {
                    level: [],
                },
            };
            const logger = (0, mcp_logger_factory_1.createMcpLogger)('TestContext', options);
            expect(logger).toBeInstanceOf(common_1.Logger);
            expect(() => {
                logger.log('test message');
                logger.error('test error');
                logger.warn('test warning');
                logger.debug('test debug');
                logger.verbose('test verbose');
            }).not.toThrow();
        });
    });
    describe('FilteredLogger behavior', () => {
        it('should only call parent logger methods for enabled levels', () => {
            const options = {
                name: 'test',
                version: '1.0.0',
                logging: {
                    level: ['error', 'warn'],
                },
            };
            const logSpy = jest.spyOn(common_1.Logger.prototype, 'log').mockImplementation();
            const errorSpy = jest
                .spyOn(common_1.Logger.prototype, 'error')
                .mockImplementation();
            const warnSpy = jest.spyOn(common_1.Logger.prototype, 'warn').mockImplementation();
            const debugSpy = jest
                .spyOn(common_1.Logger.prototype, 'debug')
                .mockImplementation();
            const verboseSpy = jest
                .spyOn(common_1.Logger.prototype, 'verbose')
                .mockImplementation();
            const logger = (0, mcp_logger_factory_1.createMcpLogger)('TestContext', options);
            logger.log('log message');
            logger.error('error message');
            logger.warn('warn message');
            logger.debug('debug message');
            logger.verbose('verbose message');
            expect(errorSpy).toHaveBeenCalled();
            expect(warnSpy).toHaveBeenCalled();
            logSpy.mockRestore();
            errorSpy.mockRestore();
            warnSpy.mockRestore();
            debugSpy.mockRestore();
            verboseSpy.mockRestore();
        });
    });
    describe('NoOpLogger behavior', () => {
        it('should not call parent logger methods when logging is disabled', () => {
            const options = {
                name: 'test',
                version: '1.0.0',
                logging: false,
            };
            const logSpy = jest.spyOn(common_1.Logger.prototype, 'log').mockImplementation();
            const errorSpy = jest
                .spyOn(common_1.Logger.prototype, 'error')
                .mockImplementation();
            const warnSpy = jest.spyOn(common_1.Logger.prototype, 'warn').mockImplementation();
            const debugSpy = jest
                .spyOn(common_1.Logger.prototype, 'debug')
                .mockImplementation();
            const verboseSpy = jest
                .spyOn(common_1.Logger.prototype, 'verbose')
                .mockImplementation();
            const logger = (0, mcp_logger_factory_1.createMcpLogger)('TestContext', options);
            logger.log('log message');
            logger.error('error message');
            logger.warn('warn message');
            logger.debug('debug message');
            logger.verbose('verbose message');
            logSpy.mockRestore();
            errorSpy.mockRestore();
            warnSpy.mockRestore();
            debugSpy.mockRestore();
            verboseSpy.mockRestore();
        });
    });
});
//# sourceMappingURL=mcp-logger.factory.spec.js.map
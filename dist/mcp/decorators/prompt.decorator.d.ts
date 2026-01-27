import { ZodObject, ZodType } from 'zod';
type PromptArgsRawShape = {
    [k: string]: ZodType;
};
export interface PromptMetadata {
    name: string;
    description: string;
    parameters?: ZodObject<PromptArgsRawShape>;
}
export interface PromptOptions {
    name?: string;
    description: string;
    parameters?: ZodObject<PromptArgsRawShape>;
}
export declare const Prompt: (options: PromptOptions) => import("@nestjs/common").CustomDecorator<string>;
export {};
//# sourceMappingURL=prompt.decorator.d.ts.map
interface FastifyRequest {
    url: string;
    method: string;
    headers: Record<string, string | string[]>;
    query: Record<string, any>;
    body: any;
    params: Record<string, string>;
    routeOptions?: any;
    cookies?: Record<string, string>;
}
interface FastifyReply {
    status(code: number): this;
    send(payload: any): Promise<void>;
    header(name: string, value: string | string[]): this;
    sent: boolean;
    raw: any;
    setCookie?(name: string, value: string, options?: any): this;
    clearCookie?(name: string, options?: any): this;
    redirect(statusCode: number, url: string): this;
    redirect(url: string): this;
}
import { HttpAdapter, HttpRequest, HttpResponse } from '../interfaces/http-adapter.interface';
export declare class FastifyHttpAdapter implements HttpAdapter {
    adaptRequest(req: FastifyRequest): HttpRequest;
    adaptResponse(res: FastifyReply): HttpResponse;
}
export {};
//# sourceMappingURL=fastify-http.adapter.d.ts.map
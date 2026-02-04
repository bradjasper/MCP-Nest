"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FastifyHttpAdapter = void 0;
class FastifyHttpAdapter {
    adaptRequest(req) {
        const cookies = req.cookies;
        const raw = req.raw;
        if (req.user && raw) {
            raw.user = req.user;
        }
        return {
            url: req.url,
            method: req.method,
            headers: req.headers,
            query: req.query,
            body: req.body,
            params: req.params,
            get: (name) => {
                const value = req.headers[name.toLowerCase()];
                return Array.isArray(value) ? value[0] : value;
            },
            cookies,
            getCookie: (name) => cookies?.[name],
            raw: req.raw,
        };
    }
    adaptResponse(res) {
        return {
            status: (code) => {
                res.status(code);
                return this.adaptResponse(res);
            },
            json: (body) => {
                void res.send(body);
                return this.adaptResponse(res);
            },
            send: (body) => {
                void res.send(body);
                return this.adaptResponse(res);
            },
            write: (chunk) => {
                void res.raw.write(chunk);
            },
            setHeader: (name, value) => {
                res.header(name, value);
            },
            get headersSent() {
                return res.sent;
            },
            get writable() {
                return !res.sent;
            },
            get closed() {
                return res.sent;
            },
            on: (event, listener) => {
                res.raw.on(event, listener);
            },
            setCookie: (name, value, options) => {
                if (res.setCookie) {
                    res.setCookie(name, value, options);
                }
            },
            clearCookie: (name, options) => {
                if (res.clearCookie) {
                    res.clearCookie(name, options);
                }
            },
            redirect: (url) => {
                res.redirect(302, url);
            },
            raw: res.raw,
        };
    }
}
exports.FastifyHttpAdapter = FastifyHttpAdapter;
//# sourceMappingURL=fastify-http.adapter.js.map
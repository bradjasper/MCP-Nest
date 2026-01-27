"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExpressHttpAdapter = void 0;
class ExpressHttpAdapter {
    adaptRequest(req) {
        const cookies = req.cookies;
        return {
            url: req.url,
            method: req.method,
            headers: req.headers,
            query: req.query,
            body: req.body,
            params: req.params,
            get: (name) => req.get(name),
            cookies,
            getCookie: (name) => cookies?.[name],
            raw: req,
        };
    }
    adaptResponse(res) {
        return {
            status: (code) => {
                res.status(code);
                return this.adaptResponse(res);
            },
            json: (body) => {
                res.json(body);
                return this.adaptResponse(res);
            },
            send: (body) => {
                res.send(body);
                return this.adaptResponse(res);
            },
            write: (chunk) => res.write(chunk),
            setHeader: (name, value) => res.setHeader(name, value),
            get headersSent() {
                return res.headersSent;
            },
            get writable() {
                return res.writable;
            },
            get closed() {
                return res.destroyed || res.writableEnded;
            },
            on: (event, listener) => {
                res.on(event, listener);
            },
            setCookie: (name, value, options) => {
                res.cookie(name, value, options || {});
            },
            clearCookie: (name, options) => {
                res.clearCookie(name, options || {});
            },
            redirect: (url) => {
                res.redirect(url);
            },
            raw: res,
        };
    }
}
exports.ExpressHttpAdapter = ExpressHttpAdapter;
//# sourceMappingURL=express-http.adapter.js.map
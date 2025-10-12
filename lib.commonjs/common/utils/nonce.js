"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getNonce = getNonce;
function getNonce() {
    const now = new Date();
    return now.getTime() * 10000 + 40;
}
//# sourceMappingURL=nonce.js.map
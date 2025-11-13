"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TextToImage = void 0;
const extractor_1 = require("./extractor");
class TextToImage extends extractor_1.Extractor {
    svcInfo;
    constructor(svcInfo) {
        super();
        this.svcInfo = svcInfo;
    }
    getSvcInfo() {
        return Promise.resolve(this.svcInfo);
    }
    async getInputCount(content) {
        if (!content) {
            return 0;
        }
        const utf8Encoder = new TextEncoder();
        const encoded = utf8Encoder.encode(content);
        return encoded.length;
    }
    async getOutputCount(content) {
        if (!content) {
            return 0;
        }
        const utf8Encoder = new TextEncoder();
        const encoded = utf8Encoder.encode(content);
        return encoded.length;
    }
}
exports.TextToImage = TextToImage;
//# sourceMappingURL=textToImage.js.map
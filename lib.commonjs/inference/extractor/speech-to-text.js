"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpeechToText = void 0;
const extractor_1 = require("./extractor");
class SpeechToText extends extractor_1.Extractor {
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
exports.SpeechToText = SpeechToText;
//# sourceMappingURL=speech-to-text.js.map
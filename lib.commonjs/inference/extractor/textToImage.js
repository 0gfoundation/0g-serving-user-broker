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
        // For text-to-image, parse the request payload to extract 'n' value
        if (!content) {
            return 1; // Default to 1 image if no content
        }
        try {
            const payload = JSON.parse(content);
            // Extract 'n' (number of images) from the payload
            if (payload && payload.n !== undefined) {
                const n = typeof payload.n === 'string' ? parseInt(payload.n, 10) : payload.n;
                return typeof n === 'number' && !isNaN(n) ? n : 1;
            }
            return 1; // Default to 1 if 'n' is not specified
        }
        catch {
            // If parsing fails, default to 1
            return 1;
        }
    }
    async getOutputCount(_content) {
        // For text-to-image, output should always be empty (0)
        return 0;
    }
}
exports.TextToImage = TextToImage;
//# sourceMappingURL=textToImage.js.map
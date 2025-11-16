"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ChatBot = void 0;
const extractor_1 = require("./extractor");
class ChatBot extends extractor_1.Extractor {
    svcInfo;
    constructor(svcInfo) {
        super();
        this.svcInfo = svcInfo;
    }
    getSvcInfo() {
        return Promise.resolve(this.svcInfo);
    }
    async getInputCount(content) {
        // For chatbot, parse the usage field to get token counts
        // content should be a JSON string with usage field containing prompt_tokens and output_tokens
        if (!content) {
            return 0;
        }
        try {
            const usage = JSON.parse(content);
            // We only care about prompt_tokens from the usage object
            if (usage && usage.prompt_tokens !== undefined) {
                const tokens = typeof usage.prompt_tokens === 'string' ? parseInt(usage.prompt_tokens, 10) : usage.prompt_tokens;
                return typeof tokens === 'number' && !isNaN(tokens) ? tokens : 0;
            }
            return 0;
        }
        catch {
            // If parsing fails, return 0
            return 0;
        }
    }
    async getOutputCount(content) {
        // For chatbot, parse the usage field to get token counts
        // content should be a JSON string with usage field containing prompt_tokens and completion_tokens
        if (!content) {
            return 0;
        }
        try {
            const usage = JSON.parse(content);
            // We only care about completion_tokens from the usage object
            if (usage && usage.completion_tokens !== undefined) {
                const tokens = typeof usage.completion_tokens === 'string' ? parseInt(usage.completion_tokens, 10) : usage.completion_tokens;
                return typeof tokens === 'number' && !isNaN(tokens) ? tokens : 0;
            }
            return 0;
        }
        catch {
            // If parsing fails, return 0
            return 0;
        }
    }
}
exports.ChatBot = ChatBot;
//# sourceMappingURL=chatbot.js.map
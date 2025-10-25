"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ResponseProcessor = void 0;
const base_1 = require("./base");
const model_1 = require("./model");
const verifier_1 = require("./verifier");
const utils_1 = require("../../common/utils");
/**
 * ResponseProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
class ResponseProcessor extends base_1.ZGServingUserBrokerBase {
    verifier;
    constructor(contract, ledger, metadata, cache) {
        super(contract, ledger, metadata, cache);
        this.verifier = new verifier_1.Verifier(contract, ledger, metadata, cache);
    }
    async processResponse(providerAddress, content, chatID, vllmProxy) {
        try {
            const extractor = await this.getExtractor(providerAddress);
            const outputFee = await this.calculateOutputFees(extractor, content);
            await this.updateCachedFee(providerAddress, outputFee);
            const svc = await extractor.getSvcInfo();
            if (!(0, model_1.isVerifiability)(svc.verifiability)) {
                return false;
            }
            if (!chatID) {
                throw new Error('Chat ID does not exist');
            }
            if (vllmProxy === undefined) {
                vllmProxy = true;
            }
            let singerRAVerificationResult = await this.verifier.getSigningAddress(providerAddress);
            if (!singerRAVerificationResult.valid) {
                singerRAVerificationResult =
                    await this.verifier.getSigningAddress(providerAddress, true, vllmProxy);
            }
            if (!singerRAVerificationResult.valid) {
                throw new Error('Signing address is invalid');
            }
            const ResponseSignature = await verifier_1.Verifier.fetSignatureByChatID(svc.url, chatID, svc.model, vllmProxy);
            return verifier_1.Verifier.verifySignature(ResponseSignature.text, ResponseSignature.signature, singerRAVerificationResult.signingAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async calculateOutputFees(extractor, content) {
        const svc = await extractor.getSvcInfo();
        const outputCount = await extractor.getOutputCount(content);
        return BigInt(outputCount) * BigInt(svc.outputPrice);
    }
}
exports.ResponseProcessor = ResponseProcessor;
//# sourceMappingURL=response.js.map
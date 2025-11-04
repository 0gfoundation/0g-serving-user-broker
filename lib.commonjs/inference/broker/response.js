"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ResponseProcessor = void 0;
const base_1 = require("./base");
const model_1 = require("./model");
const verifier_1 = require("./verifier");
const utils_1 = require("../../common/utils");
const logger_1 = require("../../common/logger");
/**
 * ResponseProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
class ResponseProcessor extends base_1.ZGServingUserBrokerBase {
    constructor(contract, ledger, metadata, cache) {
        super(contract, ledger, metadata, cache);
    }
    async processResponse(providerAddress, content, chatID) {
        try {
            const extractor = await this.getExtractor(providerAddress);
            const outputFee = await this.calculateOutputFees(extractor, content);
            await this.updateCachedFee(providerAddress, outputFee);
            const svc = await extractor.getSvcInfo();
            if (!(0, model_1.isVerifiability)(svc.verifiability)) {
                console.warn('this service is not verifiable');
                return false;
            }
            if (!svc.teeSignerAcknowledged) {
                console.warn('TEE Signer is not acknowledged');
                return false;
            }
            if (!chatID) {
                throw new Error('Chat ID does not exist');
            }
            if (!svc.additionalInfo) {
                console.warn('Service additionalInfo does not exist');
                return false;
            }
            logger_1.logger.debug('Chat ID:', chatID);
            // Parse additionalInfo JSON to determine signing address
            // based on https://github.com/0gfoundation/0g-serving-broker/api/inference/internal/contract/service.go
            let signingAddress = svc.teeSignerAddress;
            try {
                const additionalInfo = JSON.parse(svc.additionalInfo);
                if (additionalInfo.TargetSeparated === true &&
                    additionalInfo.TargetTeeAddress) {
                    signingAddress = additionalInfo.TargetTeeAddress;
                }
            }
            catch (error) {
                // If JSON parsing fails, fall back to using additionalInfo as the address directly (backward compatibility)
                logger_1.logger.warn('Failed to parse additionalInfo as JSON', error);
                return false;
            }
            logger_1.logger.debug('signing address:', signingAddress);
            const ResponseSignature = await verifier_1.Verifier.fetchSignatureByChatID(svc.url, chatID, svc.model);
            return verifier_1.Verifier.verifySignature(ResponseSignature.text, ResponseSignature.signature, signingAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async calculateOutputFees(extractor, content) {
        const svc = await extractor.getSvcInfo();
        logger_1.logger.debug('Service Info:', svc);
        const outputCount = await extractor.getOutputCount(content);
        return BigInt(outputCount) * BigInt(svc.outputPrice);
    }
}
exports.ResponseProcessor = ResponseProcessor;
//# sourceMappingURL=response.js.map
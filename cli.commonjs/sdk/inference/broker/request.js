"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RequestProcessor = void 0;
const base_1 = require("./base");
const automata_1 = require("../../common/automata");
const storage_1 = require("../../common/storage");
const utils_1 = require("../../common/utils");
/**
 * RequestProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
class RequestProcessor extends base_1.ZGServingUserBrokerBase {
    automata;
    constructor(contract, metadata, cache, ledger) {
        super(contract, ledger, metadata, cache);
        this.automata = new automata_1.Automata();
    }
    async getServiceMetadata(providerAddress) {
        const service = await this.getService(providerAddress);
        return {
            endpoint: `${service.url}/v1/proxy`,
            model: service.model,
        };
    }
    /*
     * 1. To Ensure No Insufficient Balance Occurs.
     *
     * The provider settles accounts regularly. In addition, we will add a rule to the provider's settlement logic:
     * if the actual balance of the customer's account is less than 500, settlement will be triggered immediately.
     * The actual balance is defined as the customer's inference account balance minus any unsettled amounts.
     *
     * This way, if the customer checks their account and sees a balance greater than 500, even if the provider settles
     * immediately, the deduction will leave about 500, ensuring that no insufficient balance situation occurs.
     *
     * 2. To Avoid Frequent Transfers
     *
     * On the customer's side, if the balance falls below 500, it should be topped up to 1000. This is to avoid frequent
     * transfers.
     *
     * 3. To Avoid Having to Check the Balance on Every Customer Request
     *
     * Record expenditures in processResponse and maintain a total consumption amount. Every time the total expenditure
     * reaches 1000, recheck the balance and perform a transfer if necessary.
     *
     * ps: The units for 500 and 1000 can be (service.inputPricePerToken + service.outputPricePerToken).
     */
    async getRequestHeaders(providerAddress, content) {
        try {
            await this.topUpAccountIfNeeded(providerAddress, content);
            // Simplified call - only pass required parameters
            return await this.getHeader(providerAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    /**
     * Check if provider's TEE signer is acknowledged by the contract owner.
     * This method no longer performs acknowledgement (which is owner-only),
     * but verifies if the provider is ready for use.
     */
    async checkProviderSignerStatus(providerAddress, gasPrice) {
        try {
            // Ensure user has an account with the provider
            try {
                await this.contract.getAccount(providerAddress);
            }
            catch {
                await this.ledger.transferFund(providerAddress, 'inference', BigInt(0), gasPrice);
            }
            // Get service information (now contains TEE signer info)
            const service = await this.getService(providerAddress);
            const userAddress = this.contract.getUserAddress();
            const cacheKey = storage_1.CacheKeyHelpers.getUserAckKey(userAddress, providerAddress);
            if (service.teeSignerAcknowledged &&
                service.teeSignerAddress !==
                    '0x0000000000000000000000000000000000000000') {
                // Cache the acknowledgement status
                this.cache.setItem(cacheKey, service.teeSignerAddress, 10 * 60 * 1000, // 10 minutes cache
                storage_1.CacheValueTypeEnum.Other);
                return {
                    isAcknowledged: true,
                    teeSignerAddress: service.teeSignerAddress,
                };
            }
            else {
                return {
                    isAcknowledged: false,
                    teeSignerAddress: service.teeSignerAddress || '',
                };
            }
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    /**
     * acknowledgeProviderSigner tells the contract that user trust the acknowledgment of contract owner towards certain provider.
     *
     * @param providerAddress - The address of the provider
     */
    async acknowledgeProviderSigner(providerAddress, gasPrice) {
        try {
            // Ensure user has an account with the provider
            try {
                await this.contract.getAccount(providerAddress);
            }
            catch {
                await this.ledger.transferFund(providerAddress, 'inference', BigInt(0), gasPrice);
            }
            await this.contract.acknowledgeTEESigner(providerAddress, true, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    /**
     * revokeAcknowledgeProviderSigner tells the contract that user not trust the acknowledgment of contract owner towards certain provider.
     * The function only take effect when the balance of the account is empty.
     *
     * @param providerAddress - The address of the provider
     */
    async revokeAcknowledgeProviderSigner(providerAddress, gasPrice) {
        try {
            const account = await this.contract.getAccount(providerAddress);
            if (account.balance > BigInt(0)) {
                throw new Error('Cannot revoke acknowledgement when account balance is not zero.');
            }
            await this.contract.acknowledgeTEESigner(providerAddress, false, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    /**
     * Acknowledge TEE Signer (Contract Owner Only)
     *
     * @param providerAddress - The address of the provider
     */
    async ownerAcknowledgeTEESigner(providerAddress, gasPrice) {
        try {
            await this.contract.acknowledgeTEESignerByOwner(providerAddress, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    /**
     * Revoke TEE Signer Acknowledgement (Contract Owner Only)
     *
     * @param providerAddress - The address of the provider
     */
    async ownerRevokeTEESignerAcknowledgement(providerAddress, gasPrice) {
        try {
            await this.contract.revokeTEESignerAcknowledgement(providerAddress, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
}
exports.RequestProcessor = RequestProcessor;
//# sourceMappingURL=request.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RequestProcessor = void 0;
const base_1 = require("./base");
const automata_1 = require("../../common/automata ");
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
    async getRequestHeaders(providerAddress, content, vllmProxy) {
        try {
            await this.topUpAccountIfNeeded(providerAddress, content);
            if (vllmProxy === undefined) {
                vllmProxy = true;
            }
            // Simplified call - only pass required parameters
            return await this.getHeader(providerAddress, vllmProxy);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async acknowledgeProviderSigner(providerAddress, gasPrice) {
        try {
            try {
                await this.contract.getAccount(providerAddress);
            }
            catch {
                await this.ledger.transferFund(providerAddress, 'inference', BigInt(0), gasPrice);
            }
            let { quote, provider_signer } = await this.getQuote(providerAddress);
            if (!quote || !provider_signer) {
                throw new Error('Invalid quote');
            }
            if (!quote.startsWith('0x')) {
                quote = '0x' + quote;
            }
            // const rpc = process.env.RPC_ENDPOINT
            // // bypass quote verification if testing on localhost
            // if (!rpc || !/localhost|127\.0\.0\.1/.test(rpc)) {
            //     const isVerified = await this.automata.verifyQuote(quote)
            //     console.log('Quote verification:', isVerified)
            //     if (!isVerified) {
            //         throw new Error('Quote verification failed')
            //     }
            //     // if (nvidia_payload) {
            //     //     const svc = await this.getService(providerAddress)
            //     //     const valid = await Verifier.verifyRA(
            //     //         svc.url,
            //     //         nvidia_payload
            //     //     )
            //     //     console.log('nvidia payload verification:', valid)
            //     //     if (!valid) {
            //     //         throw new Error('nvidia payload verify failed')
            //     //     }
            //     // }
            // }
            const account = await this.contract.getAccount(providerAddress);
            if (account.teeSignerAddress === provider_signer) {
                console.log('Provider signer already acknowledged');
                return;
            }
            await this.contract.acknowledgeTEESigner(providerAddress, provider_signer);
            const userAddress = this.contract.getUserAddress();
            const cacheKey = storage_1.CacheKeyHelpers.getUserAckKey(userAddress, providerAddress);
            this.cache.setItem(cacheKey, provider_signer, 1 * 60 * 1000, storage_1.CacheValueTypeEnum.Other);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
}
exports.RequestProcessor = RequestProcessor;
//# sourceMappingURL=request.js.map
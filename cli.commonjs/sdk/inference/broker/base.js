"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZGServingUserBrokerBase = void 0;
const tslib_1 = require("tslib");
const extractor_1 = require("../extractor");
const utils_1 = require("../../common/utils");
const fs = tslib_1.__importStar(require("fs/promises"));
const storage_1 = require("../../common/storage");
const ethers_1 = require("ethers");
const logger_1 = require("../../common/logger");
const textToImage_1 = require("../extractor/textToImage");
class ZGServingUserBrokerBase {
    contract;
    metadata;
    cache;
    checkAccountThreshold = BigInt(100);
    topUpTriggerThreshold = BigInt(1000000);
    topUpTargetThreshold = BigInt(2000000);
    ledger;
    sessionDuration = 24 * 60 * 60 * 1000; // 24 hours validity
    constructor(contract, ledger, metadata, cache) {
        this.contract = contract;
        this.ledger = ledger;
        this.metadata = metadata;
        this.cache = cache;
    }
    async getService(providerAddress, useCache = true) {
        const key = storage_1.CacheKeyHelpers.getServiceKey(providerAddress);
        const cachedSvc = await this.cache.getItem(key);
        if (cachedSvc && useCache) {
            return cachedSvc;
        }
        try {
            const svc = await this.contract.getService(providerAddress);
            logger_1.logger.debug('Fetched service info from contract:', svc);
            await this.cache.setItem(key, svc, 10 * 60 * 1000, storage_1.CacheValueTypeEnum.Service);
            return svc;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getQuote(providerAddress) {
        try {
            const service = await this.getService(providerAddress);
            const url = service.url;
            const endpoint = `${url}/v1/quote`;
            const rawReport = await this.fetchText(endpoint, {
                method: 'GET',
            });
            const ret = JSON.parse(rawReport);
            const decodedData = Buffer.from(ret['report_data'], 'base64').toString('utf-8');
            // Remove NULL characters that pad the address
            const signingAddress = decodedData.replace(/\0/g, '');
            return {
                rawReport,
                signingAddress: signingAddress,
            };
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async downloadQuoteReport(providerAddress, outputPath) {
        try {
            const service = await this.getService(providerAddress);
            const url = service.url;
            const endpoint = `${url}/v1/quote`;
            const quoteString = await this.fetchText(endpoint, {
                method: 'GET',
            });
            await fs.writeFile(outputPath, quoteString);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async userAcknowledged(providerAddress) {
        const userAddress = this.contract.getUserAddress();
        const key = storage_1.CacheKeyHelpers.getUserAckKey(userAddress, providerAddress);
        const cachedSvc = await this.cache.getItem(key);
        if (cachedSvc) {
            return true;
        }
        try {
            const account = await this.contract.getAccount(providerAddress);
            if (account.acknowledged) {
                await this.cache.setItem(key, '', 10 * 60 * 1000, storage_1.CacheValueTypeEnum.Other);
                return true;
            }
            else {
                return false;
            }
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async fetchText(endpoint, options) {
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            const buffer = await response.arrayBuffer();
            return Buffer.from(buffer).toString('utf-8');
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getExtractor(providerAddress, useCache = true) {
        try {
            const svc = await this.getService(providerAddress, useCache);
            const extractor = this.createExtractor(svc);
            return extractor;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    createExtractor(svc) {
        switch (svc.serviceType) {
            case 'chatbot':
                return new extractor_1.ChatBot(svc);
            case 'text-to-image':
                return new textToImage_1.TextToImage(svc);
            default:
                throw new Error('Unknown service type');
        }
    }
    a0giToNeuron(value) {
        const valueStr = value.toFixed(18);
        const parts = valueStr.split('.');
        // Handle integer part
        const integerPart = parts[0];
        let integerPartAsBigInt = BigInt(integerPart) * BigInt(10 ** 18);
        // Handle fractional part if it exists
        if (parts.length > 1) {
            let fractionalPart = parts[1];
            while (fractionalPart.length < 18) {
                fractionalPart += '0';
            }
            if (fractionalPart.length > 18) {
                fractionalPart = fractionalPart.slice(0, 18); // Truncate to avoid overflow
            }
            const fractionalPartAsBigInt = BigInt(fractionalPart);
            integerPartAsBigInt += fractionalPartAsBigInt;
        }
        return integerPartAsBigInt;
    }
    neuronToA0gi(value) {
        const divisor = BigInt(10 ** 18);
        const integerPart = value / divisor;
        const remainder = value % divisor;
        const decimalPart = Number(remainder) / Number(divisor);
        return Number(integerPart) + decimalPart;
    }
    generateNonce() {
        if (typeof window !== 'undefined' && window.crypto) {
            // Browser environment - use Web Crypto API
            const array = new Uint8Array(16);
            window.crypto.getRandomValues(array);
            return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
        }
        else {
            // Node.js or other environment - use timestamp-based nonce
            const timestamp = Date.now();
            const random = Math.random();
            const randomStr = random.toString(36).substring(2, 15);
            return `${timestamp}-${randomStr}`.padEnd(32, '0');
        }
    }
    async generateSessionToken(providerAddress) {
        const userAddress = this.contract.getUserAddress();
        const timestamp = Date.now();
        const expiresAt = timestamp + this.sessionDuration;
        const nonce = this.generateNonce();
        const token = {
            address: userAddress,
            provider: providerAddress,
            timestamp,
            expiresAt,
            nonce,
        };
        // Create message to be signed
        const message = JSON.stringify(token);
        // Create hash using the same method as signRequest in encrypt.ts
        const messageHash = (0, ethers_1.keccak256)((0, ethers_1.toUtf8Bytes)(message));
        // Sign using the same pattern as signRequest: signMessage with toBeArray
        const signature = await this.contract.signer.signMessage(Buffer.from(messageHash.slice(2), 'hex'));
        const session = {
            token,
            signature,
            rawMessage: message,
        };
        // Cache the session using the existing cache with proper TTL
        const cacheKey = storage_1.CacheKeyHelpers.getSessionTokenKey(userAddress, providerAddress);
        await this.cache.setItem(cacheKey, session, this.sessionDuration, storage_1.CacheValueTypeEnum.Session);
        return session;
    }
    async getOrCreateSession(providerAddress) {
        const userAddress = this.contract.getUserAddress();
        const cacheKey = storage_1.CacheKeyHelpers.getSessionTokenKey(userAddress, providerAddress);
        const cached = (await this.cache.getItem(cacheKey));
        // Check if cached session exists and is not expired (with 1 hour buffer)
        if (cached && cached.token.expiresAt > Date.now() + 60 * 60 * 1000) {
            return cached;
        }
        // Generate new session
        return await this.generateSessionToken(providerAddress);
    }
    async getHeader(providerAddress) {
        // Check if provider is acknowledged - this is still necessary
        if (!(await this.userAcknowledged(providerAddress))) {
            throw new Error('Provider signer is not acknowledged');
        }
        // Get or create session token
        const session = await this.getOrCreateSession(providerAddress);
        return {
            Authorization: `Bearer app-sk-${Buffer.from(session.rawMessage + '|' + session.signature).toString('base64')}`,
        };
    }
    async calculateInputFees(extractor, content) {
        const svc = await extractor.getSvcInfo();
        const inputCount = await extractor.getInputCount(content);
        const inputFee = BigInt(inputCount) * BigInt(svc.inputPrice);
        return inputFee;
    }
    async updateCachedFee(provider, fee) {
        try {
            const key = storage_1.CacheKeyHelpers.getCachedFeeKey(provider);
            const curFee = (await this.cache.getItem(key)) || BigInt(0);
            await this.cache.setItem(key, BigInt(curFee) + fee, 1 * 60 * 1000, storage_1.CacheValueTypeEnum.BigInt);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async clearCacheFee(provider, fee) {
        try {
            const key = storage_1.CacheKeyHelpers.getCachedFeeKey(provider);
            const curFee = (await this.cache.getItem(key)) || BigInt(0);
            await this.cache.setItem(key, BigInt(curFee) + fee, 1 * 60 * 1000, storage_1.CacheValueTypeEnum.BigInt);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    /**
     * Transfer fund from ledger if fund in the inference account is less than a topUpTriggerThreshold * (inputPrice + outputPrice)
     */
    async topUpAccountIfNeeded(provider, content, gasPrice) {
        try {
            // Exit early if running in browser environment
            if (typeof window !== 'undefined' &&
                typeof window.document !== 'undefined') {
                return;
            }
            const extractor = await this.getExtractor(provider);
            const svc = await extractor.getSvcInfo();
            // Calculate target and trigger thresholds
            const targetThreshold = this.topUpTargetThreshold *
                (BigInt(svc.inputPrice) + BigInt(svc.outputPrice));
            const triggerThreshold = this.topUpTriggerThreshold *
                (BigInt(svc.inputPrice) + BigInt(svc.outputPrice));
            // Check if it's the first round
            const isFirstRound = (await this.cache.getItem(storage_1.CACHE_KEYS.FIRST_ROUND)) !== 'false';
            if (isFirstRound) {
                await this.handleFirstRound(provider, triggerThreshold, targetThreshold, gasPrice);
                return;
            }
            // Calculate new fee and update cached fee
            const newFee = await this.calculateInputFees(extractor, content);
            await this.updateCachedFee(provider, newFee);
            // Check if we need to check the account
            if (!(await this.shouldCheckAccount(svc)))
                return;
            // Re-check the account balance
            let needTransfer = false;
            try {
                const acc = await this.contract.getAccount(provider);
                const lockedFund = acc.balance - acc.pendingRefund;
                needTransfer = lockedFund < triggerThreshold;
            }
            catch {
                // Account doesn't exist, need to create it by transferring funds
                needTransfer = true;
            }
            if (needTransfer) {
                try {
                    await this.ledger.transferFund(provider, 'inference', targetThreshold, gasPrice);
                }
                catch (error) {
                    // Check if it's an insufficient balance error
                    const errorMessage = error?.message?.toLowerCase() || '';
                    if (errorMessage.includes('insufficient')) {
                        console.warn(`Warning: To ensure stable service from the provider, ${targetThreshold} neuron needs to be transferred from the balance, but the current balance is insufficient.`);
                        return;
                    }
                    console.warn(`Warning: Failed to transfer funds: ${error?.message || error}`);
                    return;
                }
            }
            await this.clearCacheFee(provider, newFee);
        }
        catch (error) {
            console.warn(`Warning: Top up account failed: ${error?.message || error}`);
        }
    }
    async handleFirstRound(provider, triggerThreshold, targetThreshold, gasPrice) {
        let needTransfer = false;
        try {
            const acc = await this.contract.getAccount(provider);
            const lockedFund = acc.balance - acc.pendingRefund;
            needTransfer = lockedFund < triggerThreshold;
        }
        catch {
            needTransfer = true;
        }
        if (needTransfer) {
            try {
                await this.ledger.transferFund(provider, 'inference', targetThreshold, gasPrice);
            }
            catch (error) {
                // Check if it's an insufficient balance error
                const errorMessage = error?.message?.toLowerCase() || '';
                if (errorMessage.includes('insufficient')) {
                    console.warn(`Warning: To ensure stable service from the provider, ${targetThreshold} neuron needs to be transferred from the balance, but the current balance is insufficient.`);
                    return;
                }
                console.warn(`Warning: Failed to transfer funds: ${error?.message || error}`);
                return;
            }
        }
        // Mark the first round as complete
        await this.cache.setItem(storage_1.CACHE_KEYS.FIRST_ROUND, 'false', 10000000 * 60 * 1000, storage_1.CacheValueTypeEnum.Other);
    }
    /**
     * Check the cache fund for this provider, return true if the fund is above checkAccountThreshold * (inputPrice + outputPrice)
     * @param svc
     */
    async shouldCheckAccount(svc) {
        try {
            const key = storage_1.CacheKeyHelpers.getCachedFeeKey(svc.provider);
            const usedFund = (await this.cache.getItem(key)) || BigInt(0);
            return (usedFund >
                this.checkAccountThreshold * (svc.inputPrice + svc.outputPrice));
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
}
exports.ZGServingUserBrokerBase = ZGServingUserBrokerBase;
//# sourceMappingURL=base.js.map
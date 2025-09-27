"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InferenceServingContract = void 0;
const typechain_1 = require("./typechain");
const utils_1 = require("../../common/utils");
class InferenceServingContract {
    serving;
    signer;
    _userAddress;
    constructor(signer, contractAddress, userAddress) {
        this.serving = typechain_1.InferenceServing__factory.connect(contractAddress, signer);
        this.signer = signer;
        this._userAddress = userAddress;
    }
    lockTime() {
        return this.serving.lockTime();
    }
    async listService() {
        try {
            const services = await this.serving.getAllServices();
            return services;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async listAccount(offset = 0, limit = 50) {
        try {
            const result = await this.serving.getAllAccounts(offset, limit);
            return result.accounts;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getAccount(provider) {
        try {
            const user = this.getUserAddress();
            const account = await this.serving.getAccount(user, provider);
            return account;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async acknowledgeTEESigner(providerAddress, providerSigner) {
        try {
            const tx = await this.serving.acknowledgeTEESigner(providerAddress, providerSigner);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getService(providerAddress) {
        try {
            return this.serving.getService(providerAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    getUserAddress() {
        return this._userAddress;
    }
}
exports.InferenceServingContract = InferenceServingContract;
//# sourceMappingURL=inference.js.map
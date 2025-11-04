"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LedgerManagerContract = void 0;
const typechain_1 = require("./typechain");
const const_1 = require("../../common/utils/const");
const utils_1 = require("../../common/utils");
const TIMEOUT_MS = 300_000;
class LedgerManagerContract {
    ledger;
    signer;
    _userAddress;
    _gasPrice;
    _maxGasPrice;
    _step;
    constructor(signer, contractAddress, userAddress, gasPrice, maxGasPrice, step) {
        this.ledger = typechain_1.LedgerManager__factory.connect(contractAddress, signer);
        this.signer = signer;
        this._userAddress = userAddress;
        this._gasPrice = gasPrice;
        this._maxGasPrice = maxGasPrice;
        this._step = step || 1.1;
    }
    async sendTx(name, txArgs, txOptions) {
        if (txOptions.gasPrice === undefined) {
            txOptions.gasPrice = (await this.signer.provider?.getFeeData())?.gasPrice;
            // Add a delay to avoid too frequent RPC calls
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        else {
            txOptions.gasPrice = BigInt(txOptions.gasPrice);
        }
        while (true) {
            try {
                console.log('sending tx with gas price', txOptions.gasPrice);
                const tx = await this.ledger.getFunction(name)(...txArgs, txOptions);
                console.log('tx hash:', tx.hash);
                const receipt = (await Promise.race([
                    tx.wait(),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('Get Receipt timeout')), TIMEOUT_MS)),
                ]));
                this.checkReceipt(receipt);
                break;
            }
            catch (error) {
                if (error.message ===
                    'Get Receipt timeout, try set higher gas price') {
                    const nonce = await this.signer.getNonce();
                    const pendingNonce = await this.signer.provider?.getTransactionCount(this._userAddress, 'pending');
                    if (pendingNonce !== undefined &&
                        pendingNonce - nonce > 5 &&
                        txOptions.nonce === undefined) {
                        console.warn(`Significant gap detected between pending nonce (${pendingNonce}) and current nonce (${nonce}). This may indicate skipped or missing transactions. Using the current confirmed nonce for the transaction.`);
                        txOptions.nonce = nonce;
                    }
                }
                if (this._maxGasPrice === undefined) {
                    (0, utils_1.throwFormattedError)(error);
                }
                let errorMessage = '';
                if (error.message) {
                    errorMessage = error.message;
                }
                else if (error.info?.error?.message) {
                    errorMessage = error.info.error.message;
                }
                const shouldRetry = const_1.RETRY_ERROR_SUBSTRINGS.some((substr) => errorMessage.includes(substr));
                if (!shouldRetry) {
                    (0, utils_1.throwFormattedError)(error);
                }
                console.log('Retrying transaction with higher gas price due to:', errorMessage);
                let currentGasPrice = txOptions.gasPrice;
                if (currentGasPrice >= this._maxGasPrice) {
                    (0, utils_1.throwFormattedError)(error);
                }
                currentGasPrice =
                    (currentGasPrice * BigInt(this._step)) / BigInt(10);
                if (currentGasPrice > this._maxGasPrice) {
                    currentGasPrice = this._maxGasPrice;
                }
                txOptions.gasPrice = currentGasPrice;
            }
        }
    }
    async addLedger(balance, additionalInfo, gasPrice) {
        try {
            const txOptions = { value: balance };
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('addLedger', [additionalInfo || ''], txOptions);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async listLedger(offset = 0, limit = 50) {
        try {
            const result = await this.ledger.getAllLedgers(offset, limit);
            return result.ledgers;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getLedger() {
        try {
            const user = this.getUserAddress();
            const ledger = await this.ledger.getLedger(user);
            return ledger;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getLedgerProviders(user, serviceName) {
        try {
            const providers = await this.ledger.getLedgerProviders(user, serviceName);
            return providers;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getServiceInfo(serviceAddress) {
        try {
            const serviceInfo = await this.ledger.getServiceInfo(serviceAddress);
            return serviceInfo;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async depositFund(balance, gasPrice) {
        try {
            const txOptions = { value: balance };
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('depositFund', [], txOptions);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async refund(amount, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('refund', [amount], txOptions);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async transferFund(provider, serviceName, amount, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('transferFund', [provider, serviceName, amount], txOptions);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async retrieveFund(providers, serviceName, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('retrieveFund', [providers, serviceName], txOptions);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async deleteLedger(gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('deleteLedger', [], txOptions);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    getUserAddress() {
        return this._userAddress;
    }
    checkReceipt(receipt) {
        if (!receipt) {
            throw new Error('Transaction failed with no receipt');
        }
        if (receipt.status !== 1) {
            throw new Error('Transaction reverted');
        }
    }
}
exports.LedgerManagerContract = LedgerManagerContract;
//# sourceMappingURL=ledger.js.map
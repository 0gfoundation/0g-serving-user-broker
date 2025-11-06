"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LedgerBroker = void 0;
exports.createLedgerBroker = createLedgerBroker;
const ethers_1 = require("ethers");
const ledger_1 = require("./ledger");
const contract_1 = require("./contract");
const contract_2 = require("../inference/contract");
const contract_3 = require("../fine-tuning/contract");
const storage_1 = require("../common/storage");
const utils_1 = require("../common/utils");
class LedgerBroker {
    ledger;
    signer;
    ledgerCA;
    inferenceCA;
    fineTuningCA;
    gasPrice;
    maxGasPrice;
    step;
    constructor(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice, maxGasPrice, step) {
        this.signer = signer;
        this.ledgerCA = ledgerCA;
        this.inferenceCA = inferenceCA;
        this.fineTuningCA = fineTuningCA;
        this.gasPrice = gasPrice;
        this.maxGasPrice = maxGasPrice;
        this.step = step;
    }
    async initialize() {
        let userAddress;
        try {
            userAddress = await this.signer.getAddress();
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
        const ledgerContract = new contract_1.LedgerManagerContract(this.signer, this.ledgerCA, userAddress, this.gasPrice, this.maxGasPrice, this.step);
        const inferenceContract = new contract_2.InferenceServingContract(this.signer, this.inferenceCA, userAddress);
        let fineTuningContract;
        if (this.signer instanceof ethers_1.Wallet) {
            fineTuningContract = new contract_3.FineTuningServingContract(this.signer, this.fineTuningCA, userAddress);
        }
        // Get service names from contract using getServiceInfo
        const serviceNames = await this.getServiceNames(ledgerContract, this.inferenceCA, this.fineTuningCA);
        const metadata = new storage_1.Metadata();
        const cache = new storage_1.Cache();
        this.ledger = new ledger_1.LedgerProcessor(metadata, cache, ledgerContract, inferenceContract, fineTuningContract, serviceNames);
    }
    async getServiceNames(ledgerContract, inferenceCA, fineTuningCA) {
        try {
            // Get service info for inference contract
            const inferenceServiceInfo = await ledgerContract.getServiceInfo(inferenceCA);
            const inferenceServiceName = inferenceServiceInfo.fullName;
            // Get service info for fine-tuning contract if using Wallet
            let fineTuningServiceName;
            if (this.signer instanceof ethers_1.Wallet) {
                try {
                    const fineTuningServiceInfo = await ledgerContract.getServiceInfo(fineTuningCA);
                    fineTuningServiceName = fineTuningServiceInfo.fullName;
                }
                catch (error) {
                    // Fine-tuning service might not be registered
                    console.warn('Fine-tuning service not registered in LedgerManager');
                }
            }
            return {
                inference: inferenceServiceName,
                fineTuning: fineTuningServiceName,
            };
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    /**
     * Adds a new ledger to the contract.
     *
     * @param {number} balance - The initial balance to be assigned to the new ledger. Units are in 0G.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the ledger creation fails.
     *
     * @remarks
     * When creating an ledger, a key pair is also created to sign the request.
     */
    addLedger = async (balance, gasPrice) => {
        try {
            return await this.ledger.addLedger(balance, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Retrieves the ledger information for current wallet address.
     *
     * @returns A promise that resolves to the ledger information.
     *
     * @throws Will throw an error if the ledger retrieval process fails.
     */
    getLedger = async () => {
        try {
            return await this.ledger.getLedger();
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Deposits a specified amount of funds into Ledger corresponding to the current wallet address.
     *
     * @param {string} amount - The amount of funds to be deposited. Units are in 0G.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deposit fails.
     */
    depositFund = async (amount, gasPrice) => {
        try {
            return await this.ledger.depositFund(amount, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Refunds a specified amount using the ledger.
     *
     * @param amount - The amount to be refunded.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves when the refund is processed.
     * @throws Will throw an error if the refund process fails.
     *
     * @remarks The amount should be a positive number.
     */
    refund = async (amount, gasPrice) => {
        try {
            return await this.ledger.refund(amount, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Transfers a specified amount of funds to a provider for a given service type.
     *
     * @param provider - The address of the provider to whom the funds are being transferred.
     * @param serviceTypeStr - The type of service for which the funds are being transferred.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param amount - The amount of funds to be transferred. Units are in neuron.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund transfer operation.
     * @throws Will throw an error if the fund transfer operation fails.
     */
    transferFund = async (provider, serviceTypeStr, amount, gasPrice) => {
        try {
            return await this.ledger.transferFund(provider, serviceTypeStr, amount, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Retrieves funds from the all sub-accounts (for inference and fine-tuning) of the current wallet address.
     *
     * @param serviceTypeStr - The type of service for which the funds are being retrieved.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund retrieval operation.
     * @throws Will throw an error if the fund retrieval operation fails.
     */
    retrieveFund = async (serviceTypeStr, gasPrice) => {
        try {
            return await this.ledger.retrieveFund(serviceTypeStr, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Deletes the ledger corresponding to the current wallet address.
     *
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                           the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deletion fails.
     */
    deleteLedger = async (gasPrice) => {
        try {
            return await this.ledger.deleteLedger(gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
}
exports.LedgerBroker = LedgerBroker;
/**
 * createLedgerBroker is used to initialize LedgerBroker
 *
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - Ledger contract address, use default address if not provided.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
async function createLedgerBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice, maxGasPrice, step) {
    const broker = new LedgerBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice, maxGasPrice, step);
    try {
        await broker.initialize();
        return broker;
    }
    catch (error) {
        throw error;
    }
}
//# sourceMappingURL=broker.js.map
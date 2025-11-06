"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZGComputeNetworkBroker = exports.CONTRACT_ADDRESSES = exports.MAINNET_CHAIN_ID = exports.TESTNET_CHAIN_ID = void 0;
exports.getNetworkType = getNetworkType;
exports.createZGComputeNetworkBroker = createZGComputeNetworkBroker;
const ethers_1 = require("ethers");
const ledger_1 = require("./ledger");
const broker_1 = require("./fine-tuning/broker");
const broker_2 = require("./inference/broker/broker");
// Network configurations
exports.TESTNET_CHAIN_ID = 16602n;
exports.MAINNET_CHAIN_ID = 16600n; // TODO: Update with actual mainnet chain ID when available
// Contract addresses for different networks
exports.CONTRACT_ADDRESSES = {
    testnet: {
        ledger: '0xc9BF91efc972e2B1225D4d9266B31aea458EE0B5',
        inference: '0xD18A6308793bDE62c3664729e3Fd0F7CFd2565Da',
        fineTuning: '0x434cAbDedef8eBB760e7e583E419BFD5537A8B8a'
    },
    mainnet: {
        // TODO: Update with actual mainnet addresses when available
        ledger: '0x0000000000000000000000000000000000000000',
        inference: '0x0000000000000000000000000000000000000000',
        fineTuning: '0x0000000000000000000000000000000000000000'
    }
};
/**
 * Helper function to determine network type from chain ID
 */
function getNetworkType(chainId) {
    if (chainId === exports.MAINNET_CHAIN_ID) {
        return 'mainnet';
    }
    else if (chainId === exports.TESTNET_CHAIN_ID) {
        return 'testnet';
    }
    return 'unknown';
}
class ZGComputeNetworkBroker {
    ledger;
    inference;
    fineTuning;
    constructor(ledger, inferenceBroker, fineTuningBroker) {
        this.ledger = ledger;
        this.inference = inferenceBroker;
        this.fineTuning = fineTuningBroker;
    }
}
exports.ZGComputeNetworkBroker = ZGComputeNetworkBroker;
/**
 * createZGComputeNetworkBroker is used to initialize ZGComputeNetworkBroker
 *
 * This function automatically detects the network from the signer's provider and uses
 * appropriate contract addresses. You can override any address by providing it explicitly.
 *
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - 0G Compute Network Ledger Contact address, auto-detected if not provided.
 * @param inferenceCA - 0G Compute Network Inference Serving contract address, auto-detected if not provided.
 * @param fineTuningCA - 0G Compute Network Fine Tuning Serving contract address, auto-detected if not provided.
 * @param gasPrice - Gas price for transactions. If not provided, the gas price will be calculated automatically.
 * @param maxGasPrice - Maximum gas price for transactions.
 * @param step - Step for gas price adjustment.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
async function createZGComputeNetworkBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice, maxGasPrice, step) {
    try {
        // Auto-detect network from signer's provider
        let defaultAddresses = exports.CONTRACT_ADDRESSES.testnet; // Default to testnet
        if (signer.provider) {
            const network = await signer.provider.getNetwork();
            const chainId = network.chainId;
            if (chainId === exports.MAINNET_CHAIN_ID) {
                defaultAddresses = exports.CONTRACT_ADDRESSES.mainnet;
                console.log('Detected mainnet (chain ID:', chainId.toString(), ')');
            }
            else if (chainId === exports.TESTNET_CHAIN_ID) {
                defaultAddresses = exports.CONTRACT_ADDRESSES.testnet;
                console.log('Detected testnet (chain ID:', chainId.toString(), ')');
            }
            else {
                console.warn(`Unknown chain ID: ${chainId}. Using testnet addresses as default.`);
            }
        }
        else {
            console.warn('No provider found on signer. Using testnet addresses as default.');
        }
        // Use provided addresses or fall back to auto-detected defaults
        const finalLedgerCA = ledgerCA || defaultAddresses.ledger;
        const finalInferenceCA = inferenceCA || defaultAddresses.inference;
        const finalFineTuningCA = fineTuningCA || defaultAddresses.fineTuning;
        const ledger = await (0, ledger_1.createLedgerBroker)(signer, finalLedgerCA, finalInferenceCA, finalFineTuningCA, gasPrice, maxGasPrice, step);
        const inferenceBroker = await (0, broker_2.createInferenceBroker)(signer, finalInferenceCA, ledger);
        let fineTuningBroker;
        if (signer instanceof ethers_1.Wallet) {
            fineTuningBroker = await (0, broker_1.createFineTuningBroker)(signer, finalFineTuningCA, ledger, gasPrice, maxGasPrice, step);
        }
        const broker = new ZGComputeNetworkBroker(ledger, inferenceBroker, fineTuningBroker);
        return broker;
    }
    catch (error) {
        throw error;
    }
}
//# sourceMappingURL=broker.js.map
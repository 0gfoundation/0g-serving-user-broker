"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.printTableWithTitle = exports.splitIntoChunks = exports.neuronToA0gi = void 0;
exports.initBroker = initBroker;
exports.withBroker = withBroker;
exports.withFineTuningBroker = withFineTuningBroker;
const tslib_1 = require("tslib");
const sdk_1 = require("../sdk");
const ethers_1 = require("ethers");
const chalk_1 = tslib_1.__importDefault(require("chalk"));
const network_setup_1 = require("./network-setup");
async function initBroker(options) {
    // Use the new interactive RPC endpoint selection
    const rpcEndpoint = await (0, network_setup_1.getRpcEndpoint)(options);
    const provider = new ethers_1.ethers.JsonRpcProvider(rpcEndpoint);
    const wallet = new ethers_1.ethers.Wallet(options.key, provider);
    return await (0, sdk_1.createZGComputeNetworkBroker)(wallet, options.ledgerCa || process.env.LEDGER_CA, options.inferenceCa || process.env.INFERENCE_CA, options.fineTuningCa || process.env.FINE_TUNING_CA, options.gasPrice, options.maxGasPrice, options.step);
}
async function withBroker(options, action) {
    try {
        const broker = await initBroker(options);
        await action(broker);
    }
    catch (error) {
        alertError(error);
    }
}
async function withFineTuningBroker(options, action) {
    try {
        const broker = await initBroker(options);
        if (broker.fineTuning) {
            await action(broker);
        }
        else {
            console.log('Fine tuning broker is not available.');
        }
    }
    catch (error) {
        alertError(error);
    }
}
const neuronToA0gi = (value) => {
    const divisor = BigInt(10 ** 18);
    const integerPart = value / divisor;
    const remainder = value % divisor;
    const decimalPart = Number(remainder) / Number(divisor);
    return Number(integerPart) + decimalPart;
};
exports.neuronToA0gi = neuronToA0gi;
const splitIntoChunks = (str, size) => {
    const chunks = [];
    for (let i = 0; i < str.length; i += size) {
        chunks.push(str.slice(i, i + size));
    }
    return chunks.join('\n');
};
exports.splitIntoChunks = splitIntoChunks;
const printTableWithTitle = (title, table) => {
    console.log(`\n${chalk_1.default.white(`  ${title}`)}\n` + table.toString());
};
exports.printTableWithTitle = printTableWithTitle;
const alertError = (error) => {
    // SDK now handles error formatting, so we just need to display the error message
    const errorMessage = error?.message || String(error);
    // Check for additional CLI-specific patterns
    const errorPatterns = [
        {
            pattern: /Deliverable not acknowledged yet/i,
            message: "Deliverable not acknowledged yet. Please use '0g-compute-cli acknowledge-model --provider <provider_address> --data-path <path_to_save_model>' to acknowledge the deliverable.",
        },
        {
            pattern: /EncryptedSecret not found/i,
            message: "Secret to decrypt model not found. Please ensure the task status is 'Finished' using '0g-compute-cli get-task --provider <provider_address>'.",
        },
    ];
    const matchedPattern = errorPatterns.find(({ pattern }) => pattern.test(errorMessage));
    if (matchedPattern) {
        console.error(chalk_1.default.red('✗ Operation failed:'), matchedPattern.message);
    }
    else {
        console.error(chalk_1.default.red('✗ Operation failed:'), errorMessage);
    }
    // Show raw error in verbose mode (can be controlled by an env variable)
    if (process.env.VERBOSE === 'true') {
        console.error(chalk_1.default.gray('\nRaw error:'), error);
    }
};
//# sourceMappingURL=util.js.map
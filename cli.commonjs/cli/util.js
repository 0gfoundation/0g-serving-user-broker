"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.printTableWithTitle = exports.splitIntoChunks = exports.a0giToNeuron = exports.neuronToA0gi = void 0;
exports.initBroker = initBroker;
exports.withBroker = withBroker;
exports.withFineTuningBroker = withFineTuningBroker;
const tslib_1 = require("tslib");
const sdk_1 = require("../sdk");
const ethers_1 = require("ethers");
const chalk_1 = tslib_1.__importDefault(require("chalk"));
const network_setup_1 = require("./network-setup");
const private_key_setup_1 = require("./private-key-setup");
async function initBroker(options) {
    // Use the new interactive RPC endpoint selection
    const rpcEndpoint = await (0, network_setup_1.getRpcEndpoint)(options);
    // Use the new interactive private key selection
    const privateKey = await (0, private_key_setup_1.getPrivateKey)(options);
    if (!privateKey) {
        throw new Error('Private key is required');
    }
    const provider = new ethers_1.ethers.JsonRpcProvider(rpcEndpoint);
    const wallet = new ethers_1.ethers.Wallet(privateKey, provider);
    return await (0, sdk_1.createZGComputeNetworkBroker)(wallet, options.ledgerCa || process.env.LEDGER_CA, options.inferenceCa || process.env.INFERENCE_CA, options.fineTuningCa || process.env.FINE_TUNING_CA, options.gasPrice, options.maxGasPrice, options.step);
}
async function withBroker(options, action) {
    try {
        const broker = await initBroker(options);
        await action(broker);
        process.exit(0);
    }
    catch (error) {
        alertError(error);
        process.exit(1);
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
        process.exit(0);
    }
    catch (error) {
        alertError(error);
        process.exit(1);
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
const a0giToNeuron = (value) => {
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
};
exports.a0giToNeuron = a0giToNeuron;
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
#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ensureNetworkConfiguration = ensureNetworkConfiguration;
exports.getRpcEndpoint = getRpcEndpoint;
const tslib_1 = require("tslib");
const chalk_1 = tslib_1.__importDefault(require("chalk"));
const config_1 = require("./config");
const interactive_selection_1 = require("./interactive-selection");
const MAINNET_RPC = 'https://evmrpc.0g.ai';
const TESTNET_RPC = 'https://evmrpc-testnet.0g.ai';
const NETWORKS = {
    mainnet: {
        name: 'Mainnet',
        rpc: MAINNET_RPC,
        description: '0G Chain Mainnet (Production)',
    },
    testnet: {
        name: 'Testnet',
        rpc: TESTNET_RPC,
        description: '0G Chain Testnet (Development)',
    },
};
/**
 * Sets the RPC endpoint in both session and persistent config
 */
function setRpcEndpoint(rpcEndpoint, network) {
    // Set for current session
    process.env['ZG_RPC_ENDPOINT'] = rpcEndpoint;
    // Save to persistent config
    (0, config_1.setConfiguredRpcEndpoint)(rpcEndpoint, network);
    console.log(chalk_1.default.green(`✓ RPC endpoint configured: ${rpcEndpoint}`));
    console.log(chalk_1.default.gray(`  Network: ${network}`));
    console.log(chalk_1.default.blue(`ℹ Settings saved to ~/.0g-compute-cli/config.json`));
}
/**
 * Prompts user to select a network or custom RPC
 */
async function promptNetworkSelection() {
    console.log(chalk_1.default.blue('\n🌐 0G Compute CLI Network Setup'));
    console.log();
    const networkChoice = await (0, interactive_selection_1.interactiveSelect)({
        message: 'Please select a network to use as default:',
        options: [
            {
                title: `${NETWORKS.mainnet.name}`,
                value: 'mainnet',
                description: `${NETWORKS.mainnet.description} (${NETWORKS.mainnet.rpc})`,
            },
            {
                title: `${NETWORKS.testnet.name}`,
                value: 'testnet',
                description: `${NETWORKS.testnet.description} (${NETWORKS.testnet.rpc})`,
            },
            {
                title: 'Custom RPC Endpoint',
                value: 'custom',
                description: 'Enter your own RPC endpoint URL',
            },
        ],
    });
    if (networkChoice === 'custom') {
        console.log();
        const customRpc = await (0, interactive_selection_1.textInput)('Enter custom RPC endpoint URL', 'https://your-rpc-endpoint.com');
        if (!customRpc) {
            console.log(chalk_1.default.red('Custom RPC endpoint cannot be empty'));
            return await promptNetworkSelection();
        }
        // Validate URL format
        try {
            new URL(customRpc);
        }
        catch {
            console.log(chalk_1.default.red('Invalid URL format. Please enter a valid URL.'));
            return await promptNetworkSelection();
        }
        return { type: 'custom', rpc: customRpc };
    }
    return { type: 'preset', network: networkChoice };
}
/**
 * Checks if RPC endpoint is configured, if not, prompts user to select and set it
 */
async function ensureNetworkConfiguration() {
    // Check environment variables first
    const envRpc = process.env['ZG_RPC_ENDPOINT'] || process.env.RPC_ENDPOINT;
    if (envRpc) {
        return envRpc;
    }
    // Check config file
    const configRpc = (0, config_1.getConfiguredRpcEndpoint)();
    if (configRpc) {
        // Set in current session as well
        process.env['ZG_RPC_ENDPOINT'] = configRpc;
        return configRpc;
    }
    console.log(chalk_1.default.yellow('⚠ No RPC endpoint configured.'));
    console.log(chalk_1.default.gray('Please select a network for CLI operations.\n'));
    const selection = await promptNetworkSelection();
    if (selection.type === 'custom') {
        // Custom RPC endpoint
        const customRpc = selection.rpc;
        console.log(chalk_1.default.green(`\n✓ Selected: Custom RPC`));
        console.log(chalk_1.default.gray(`  RPC: ${customRpc}\n`));
        // Save custom configuration
        setRpcEndpoint(customRpc, 'custom');
        return customRpc;
    }
    else {
        // Preset network
        const networkKey = selection.network;
        const networkConfig = NETWORKS[networkKey];
        console.log(chalk_1.default.green(`\n✓ Selected: ${networkConfig.name}`));
        console.log(chalk_1.default.gray(`  RPC: ${networkConfig.rpc}\n`));
        // Set and save the configuration
        setRpcEndpoint(networkConfig.rpc, networkKey);
        return networkConfig.rpc;
    }
}
/**
 * Gets the RPC endpoint, with interactive setup if needed
 */
async function getRpcEndpoint(options) {
    // Priority: CLI option > environment variable > interactive setup
    if (options.rpc) {
        return options.rpc;
    }
    if (process.env.ZG_RPC_ENDPOINT) {
        return process.env.ZG_RPC_ENDPOINT;
    }
    return await ensureNetworkConfiguration();
}
//# sourceMappingURL=network-setup.js.map
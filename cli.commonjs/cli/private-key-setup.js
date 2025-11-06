#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ensurePrivateKeyConfiguration = ensurePrivateKeyConfiguration;
exports.getPrivateKey = getPrivateKey;
const tslib_1 = require("tslib");
const chalk_1 = tslib_1.__importDefault(require("chalk"));
const config_1 = require("./config");
const interactive_selection_1 = require("./interactive-selection");
const ethers_1 = require("ethers");
/**
 * Validates if the provided string is a valid private key
 */
function isValidPrivateKey(key) {
    try {
        // Remove 0x prefix if present
        const cleanKey = key.startsWith('0x') ? key.slice(2) : key;
        // Check if it's 64 hex characters
        if (!/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
            return false;
        }
        // Try to create a wallet with it
        new ethers_1.ethers.Wallet('0x' + cleanKey);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Sets the private key in both session and persistent config
 */
function setPrivateKey(privateKey) {
    // Set for current session
    process.env['ZG_PRIVATE_KEY'] = privateKey;
    // Save to persistent config
    (0, config_1.setConfiguredPrivateKey)(privateKey);
    console.log(chalk_1.default.green(`✓ Private key configured`));
    console.log(chalk_1.default.blue(`ℹ Settings saved to ~/.0g-compute-cli/config.json`));
}
/**
 * Prompts user to enter their private key
 */
async function promptPrivateKeyInput() {
    console.log(chalk_1.default.blue('\n🔐 Private Key Configuration'));
    console.log(chalk_1.default.gray('Your private key is required to interact with the 0G network.'));
    console.log(chalk_1.default.yellow('⚠ Your private key will be saved locally and never transmitted.'));
    console.log();
    while (true) {
        const privateKey = await (0, interactive_selection_1.passwordInput)('Enter your wallet private key (0x...)', 'Private key (hidden)');
        if (!privateKey) {
            console.log(chalk_1.default.red('Private key cannot be empty'));
            continue;
        }
        // Add 0x prefix if not present
        const formattedKey = privateKey.startsWith('0x') ? privateKey : '0x' + privateKey;
        if (!isValidPrivateKey(formattedKey)) {
            console.log(chalk_1.default.red('Invalid private key format. Please enter a valid 64-character hex string.'));
            continue;
        }
        // Show the wallet address for confirmation
        try {
            const wallet = new ethers_1.ethers.Wallet(formattedKey);
            console.log(chalk_1.default.gray(`\nWallet address: ${wallet.address}`));
            // Ask for confirmation using prompts
            const prompts = await Promise.resolve().then(() => tslib_1.__importStar(require('prompts')));
            const confirmed = await prompts.default({
                type: 'confirm',
                name: 'value',
                message: 'Is this the correct wallet address?',
                initial: true
            });
            if (confirmed.value === false) {
                console.log(chalk_1.default.yellow('Please enter a different private key.'));
                continue;
            }
            if (confirmed.value === undefined) {
                // User pressed Ctrl+C
                console.log(chalk_1.default.yellow('\nOperation cancelled.'));
                process.exit(0);
            }
            return formattedKey;
        }
        catch (error) {
            console.log(chalk_1.default.red('Error creating wallet from private key'));
            continue;
        }
    }
}
/**
 * Checks if private key is configured, if not, prompts user to enter it
 */
async function ensurePrivateKeyConfiguration() {
    // Check environment variables first
    const envKey = process.env['ZG_PRIVATE_KEY'];
    if (envKey) {
        return envKey;
    }
    // Check config file
    const configKey = (0, config_1.getConfiguredPrivateKey)();
    if (configKey) {
        // Set in current session as well
        process.env['ZG_PRIVATE_KEY'] = configKey;
        return configKey;
    }
    console.log(chalk_1.default.yellow('⚠ No wallet private key configured.'));
    console.log(chalk_1.default.gray('Please enter your private key for CLI operations.\n'));
    const privateKey = await promptPrivateKeyInput();
    console.log(chalk_1.default.green(`\n✓ Private key configured successfully`));
    // Set and save the configuration
    setPrivateKey(privateKey);
    return privateKey;
}
/**
 * Gets the private key, with interactive setup if needed
 */
async function getPrivateKey(options) {
    // Priority: CLI option > environment variable > interactive setup
    if (options.key) {
        return options.key;
    }
    return await ensurePrivateKeyConfiguration();
}
//# sourceMappingURL=private-key-setup.js.map
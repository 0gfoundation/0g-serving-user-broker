#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = auth;
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
 * Login command - adds/sets private key
 */
async function loginCommand(options) {
    console.log(chalk_1.default.blue('\n🔐 Login - Private Key Configuration'));
    console.log(chalk_1.default.gray('Enter your private key to authenticate with the 0G network.'));
    console.log(chalk_1.default.yellow('⚠ Your private key will be saved locally and never transmitted.'));
    console.log();
    // Check if already logged in
    const existingKey = (0, config_1.getConfiguredPrivateKey)();
    if (existingKey && !options.force) {
        try {
            const wallet = new ethers_1.ethers.Wallet(existingKey);
            console.log(chalk_1.default.yellow('⚠ Already logged in'));
            console.log(chalk_1.default.gray(`Current wallet address: ${wallet.address}`));
            console.log(chalk_1.default.gray('Use --force to override the current login'));
            return;
        }
        catch {
            // Invalid existing key, continue with login
        }
    }
    while (true) {
        const privateKey = await (0, interactive_selection_1.passwordInput)('Enter your wallet private key (0x...)', 'Private key (hidden)');
        if (!privateKey) {
            console.log(chalk_1.default.red('Private key cannot be empty'));
            continue;
        }
        // Add 0x prefix if not present
        const formattedKey = privateKey.startsWith('0x')
            ? privateKey
            : '0x' + privateKey;
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
                message: 'Login with this wallet address?',
                initial: true,
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
            // Save to persistent config only
            (0, config_1.setConfiguredPrivateKey)(formattedKey);
            console.log(chalk_1.default.green('\n✓ Successfully logged in'));
            console.log(chalk_1.default.gray(`Wallet address: ${wallet.address}`));
            console.log(chalk_1.default.blue(`ℹ Settings saved to ~/.0g-compute-cli/config.json`));
            return;
        }
        catch {
            console.log(chalk_1.default.red('Error creating wallet from private key'));
            continue;
        }
    }
}
/**
 * Logout command - removes private key
 */
async function logoutCommand() {
    console.log(chalk_1.default.blue('\n🚪 Logout'));
    // Check if logged in
    const existingKey = (0, config_1.getConfiguredPrivateKey)();
    if (!existingKey) {
        console.log(chalk_1.default.yellow('⚠ Not currently logged in'));
        return;
    }
    // Show current wallet address
    try {
        const wallet = new ethers_1.ethers.Wallet(existingKey);
        console.log(chalk_1.default.gray(`Current wallet: ${wallet.address}`));
    }
    catch {
        // Invalid key format
    }
    // Ask for confirmation
    const prompts = await Promise.resolve().then(() => tslib_1.__importStar(require('prompts')));
    const confirmed = await prompts.default({
        type: 'confirm',
        name: 'value',
        message: 'Are you sure you want to logout?',
        initial: false,
    });
    if (confirmed.value !== true) {
        console.log(chalk_1.default.yellow('Logout cancelled.'));
        return;
    }
    // Clear from config file only
    const config = (0, config_1.loadConfig)();
    delete config.privateKey;
    (0, config_1.saveConfig)(config);
    console.log(chalk_1.default.green('✓ Successfully logged out'));
    console.log(chalk_1.default.blue('ℹ Private key removed from ~/.0g-compute-cli/config.json'));
}
/**
 * Status command - shows current login status
 */
async function statusCommand() {
    console.log(chalk_1.default.blue('\n👤 Login Status'));
    const privateKey = (0, config_1.getConfiguredPrivateKey)();
    if (!privateKey) {
        console.log(chalk_1.default.yellow('⚠ Not logged in'));
        console.log(chalk_1.default.gray('Use "0g-compute-cli login" to authenticate'));
        return;
    }
    try {
        const wallet = new ethers_1.ethers.Wallet(privateKey);
        console.log(chalk_1.default.green('✓ Logged in'));
        console.log(chalk_1.default.gray(`Wallet address: ${wallet.address}`));
    }
    catch {
        console.log(chalk_1.default.red('✗ Invalid private key stored'));
        console.log(chalk_1.default.gray('Use "0g-compute-cli login --force" to re-authenticate'));
    }
}
function auth(program) {
    program
        .command('login')
        .description('Login by setting your private key')
        .option('-f, --force', 'Force login even if already authenticated')
        .action(loginCommand);
    program
        .command('logout')
        .description('Logout by removing your private key')
        .action(logoutCommand);
    program
        .command('status')
        .description('Show current login status')
        .action(statusCommand);
}
//# sourceMappingURL=auth.js.map
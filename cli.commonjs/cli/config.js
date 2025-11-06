#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadConfig = loadConfig;
exports.saveConfig = saveConfig;
exports.getConfiguredRpcEndpoint = getConfiguredRpcEndpoint;
exports.setConfiguredRpcEndpoint = setConfiguredRpcEndpoint;
exports.getConfiguredPrivateKey = getConfiguredPrivateKey;
exports.setConfiguredPrivateKey = setConfiguredPrivateKey;
exports.clearConfig = clearConfig;
const tslib_1 = require("tslib");
const fs = tslib_1.__importStar(require("fs"));
const path = tslib_1.__importStar(require("path"));
const os = tslib_1.__importStar(require("os"));
/**
 * Gets the path to the CLI configuration file
 */
function getConfigPath() {
    const homeDir = os.homedir();
    const configDir = path.join(homeDir, '.0g-compute-cli');
    return path.join(configDir, 'config.json');
}
/**
 * Loads the CLI configuration from file
 */
function loadConfig() {
    try {
        const configPath = getConfigPath();
        const configData = fs.readFileSync(configPath, 'utf8');
        return JSON.parse(configData);
    }
    catch (error) {
        // Config file doesn't exist or is invalid, return empty config
        return {};
    }
}
/**
 * Saves the CLI configuration to file
 */
function saveConfig(config) {
    try {
        const configPath = getConfigPath();
        const configDir = path.dirname(configPath);
        // Ensure config directory exists
        fs.mkdirSync(configDir, { recursive: true });
        // Add timestamp
        config.lastUpdated = new Date().toISOString();
        // Write config file
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    }
    catch (error) {
        console.warn('Warning: Failed to save configuration:', error);
    }
}
/**
 * Gets the RPC endpoint from config file, environment variable, or user input
 */
function getConfiguredRpcEndpoint() {
    // Priority: Environment variable > Config file
    const envRpc = process.env['ZG_RPC_ENDPOINT'] || process.env.RPC_ENDPOINT;
    if (envRpc) {
        return envRpc;
    }
    // Check config file
    const config = loadConfig();
    return config.rpcEndpoint;
}
/**
 * Sets the RPC endpoint in config file
 */
function setConfiguredRpcEndpoint(rpcEndpoint, network) {
    const config = loadConfig();
    config.rpcEndpoint = rpcEndpoint;
    config.network = network;
    saveConfig(config);
}
/**
 * Gets the private key from config file or environment variable
 */
function getConfiguredPrivateKey() {
    // Priority: Environment variable > Config file
    const envKey = process.env['ZG_PRIVATE_KEY'];
    if (envKey) {
        return envKey;
    }
    // Check config file
    const config = loadConfig();
    return config.privateKey;
}
/**
 * Sets the private key in config file
 */
function setConfiguredPrivateKey(privateKey) {
    const config = loadConfig();
    config.privateKey = privateKey;
    saveConfig(config);
}
/**
 * Clears the configuration
 */
function clearConfig() {
    try {
        const configPath = getConfigPath();
        fs.unlinkSync(configPath);
    }
    catch (error) {
        // Config file doesn't exist, which is fine
    }
}
//# sourceMappingURL=config.js.map
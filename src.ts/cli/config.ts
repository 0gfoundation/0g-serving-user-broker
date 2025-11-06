#!/usr/bin/env ts-node

import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'

interface CLIConfig {
    rpcEndpoint?: string
    network?: 'mainnet' | 'testnet' | 'custom'
    lastUpdated?: string
}

/**
 * Gets the path to the CLI configuration file
 */
function getConfigPath(): string {
    const homeDir = os.homedir()
    const configDir = path.join(homeDir, '.0g-compute-cli')
    return path.join(configDir, 'config.json')
}

/**
 * Loads the CLI configuration from file
 */
export function loadConfig(): CLIConfig {
    try {
        const configPath = getConfigPath()
        const configData = fs.readFileSync(configPath, 'utf8')
        return JSON.parse(configData)
    } catch (error) {
        // Config file doesn't exist or is invalid, return empty config
        return {}
    }
}

/**
 * Saves the CLI configuration to file
 */
export function saveConfig(config: CLIConfig): void {
    try {
        const configPath = getConfigPath()
        const configDir = path.dirname(configPath)
        
        // Ensure config directory exists
        fs.mkdirSync(configDir, { recursive: true })
        
        // Add timestamp
        config.lastUpdated = new Date().toISOString()
        
        // Write config file
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2))
    } catch (error) {
        console.warn('Warning: Failed to save configuration:', error)
    }
}

/**
 * Gets the RPC endpoint from config file, environment variable, or user input
 */
export function getConfiguredRpcEndpoint(): string | undefined {
    // Priority: Environment variable > Config file
    const envRpc = process.env['0G_RPC_ENDPOINT'] || process.env.RPC_ENDPOINT
    if (envRpc) {
        return envRpc
    }
    
    // Check config file
    const config = loadConfig()
    return config.rpcEndpoint
}

/**
 * Sets the RPC endpoint in config file
 */
export function setConfiguredRpcEndpoint(rpcEndpoint: string, network: 'mainnet' | 'testnet' | 'custom'): void {
    const config = loadConfig()
    config.rpcEndpoint = rpcEndpoint
    config.network = network
    saveConfig(config)
}

/**
 * Clears the configuration
 */
export function clearConfig(): void {
    try {
        const configPath = getConfigPath()
        fs.unlinkSync(configPath)
    } catch (error) {
        // Config file doesn't exist, which is fine
    }
}
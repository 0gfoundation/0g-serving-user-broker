#!/usr/bin/env ts-node

import chalk from 'chalk'
import { getConfiguredPrivateKey, setConfiguredPrivateKey } from './config'
import { passwordInput } from './interactive-selection'
import { ethers } from 'ethers'

/**
 * Validates if the provided string is a valid private key
 */
function isValidPrivateKey(key: string): boolean {
    try {
        // Remove 0x prefix if present
        const cleanKey = key.startsWith('0x') ? key.slice(2) : key
        
        // Check if it's 64 hex characters
        if (!/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
            return false
        }
        
        // Try to create a wallet with it
        new ethers.Wallet('0x' + cleanKey)
        return true
    } catch {
        return false
    }
}

/**
 * Sets the private key in both session and persistent config
 */
function setPrivateKey(privateKey: string): void {
    // Set for current session
    process.env['ZG_PRIVATE_KEY'] = privateKey
    
    // Save to persistent config
    setConfiguredPrivateKey(privateKey)
    
    console.log(chalk.green(`✓ Private key configured`))
    console.log(chalk.blue(`ℹ Settings saved to ~/.0g-compute-cli/config.json`))
}

/**
 * Prompts user to enter their private key
 */
async function promptPrivateKeyInput(): Promise<string> {
    console.log(chalk.blue('\n🔐 Private Key Configuration'))
    console.log(chalk.gray('Your private key is required to interact with the 0G network.'))
    console.log(chalk.yellow('⚠ Your private key will be saved locally and never transmitted.'))
    console.log()
    
    while (true) {
        const privateKey = await passwordInput(
            'Enter your wallet private key (0x...)',
            'Private key (hidden)'
        )
        
        if (!privateKey) {
            console.log(chalk.red('Private key cannot be empty'))
            continue
        }
        
        // Add 0x prefix if not present
        const formattedKey = privateKey.startsWith('0x') ? privateKey : '0x' + privateKey
        
        if (!isValidPrivateKey(formattedKey)) {
            console.log(chalk.red('Invalid private key format. Please enter a valid 64-character hex string.'))
            continue
        }
        
        // Show the wallet address for confirmation
        try {
            const wallet = new ethers.Wallet(formattedKey)
            console.log(chalk.gray(`\nWallet address: ${wallet.address}`))
            
            // Ask for confirmation using prompts
            const prompts = await import('prompts')
            const confirmed = await prompts.default({
                type: 'confirm',
                name: 'value',
                message: 'Is this the correct wallet address?',
                initial: true
            })
            
            if (confirmed.value === false) {
                console.log(chalk.yellow('Please enter a different private key.'))
                continue
            }
            
            if (confirmed.value === undefined) {
                // User pressed Ctrl+C
                console.log(chalk.yellow('\nOperation cancelled.'))
                process.exit(0)
            }
            
            return formattedKey
        } catch (error) {
            console.log(chalk.red('Error creating wallet from private key'))
            continue
        }
    }
}

/**
 * Checks if private key is configured, if not, prompts user to enter it
 */
export async function ensurePrivateKeyConfiguration(): Promise<string> {
    // Check environment variables first
    const envKey = process.env['ZG_PRIVATE_KEY']
    if (envKey) {
        return envKey
    }
    
    // Check config file
    const configKey = getConfiguredPrivateKey()
    if (configKey) {
        // Set in current session as well
        process.env['ZG_PRIVATE_KEY'] = configKey
        return configKey
    }
    
    console.log(chalk.yellow('⚠ No wallet private key configured.'))
    console.log(chalk.gray('Please enter your private key for CLI operations.\n'))
    
    const privateKey = await promptPrivateKeyInput()
    
    console.log(chalk.green(`\n✓ Private key configured successfully`))
    
    // Set and save the configuration
    setPrivateKey(privateKey)
    return privateKey
}

/**
 * Gets the private key, with interactive setup if needed
 */
export async function getPrivateKey(options: any): Promise<string | undefined> {
    // Priority: CLI option > environment variable > interactive setup
    if (options.key) {
        return options.key
    }
    
    return await ensurePrivateKeyConfiguration()
}
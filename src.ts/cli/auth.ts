#!/usr/bin/env ts-node

import type { Command } from 'commander'
import chalk from 'chalk'
import {
    setConfiguredPrivateKey,
    getConfiguredPrivateKey,
    loadConfig,
    saveConfig,
} from './config'
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
 * Login command - adds/sets private key
 */
async function loginCommand(options: { force?: boolean }): Promise<void> {
    console.log(chalk.blue('\n🔐 Login - Private Key Configuration'))
    console.log(
        chalk.gray(
            'Enter your private key to authenticate with the 0G network.'
        )
    )
    console.log(
        chalk.yellow(
            '⚠ Your private key will be saved locally and never transmitted.'
        )
    )
    console.log()

    // Check if already logged in
    const existingKey = getConfiguredPrivateKey()
    if (existingKey && !options.force) {
        try {
            const wallet = new ethers.Wallet(existingKey)
            console.log(chalk.yellow('⚠ Already logged in'))
            console.log(chalk.gray(`Current wallet address: ${wallet.address}`))
            console.log(chalk.gray('Use --force to override the current login'))
            return
        } catch {
            // Invalid existing key, continue with login
        }
    }

    while (true) {
        const privateKey = await passwordInput(
            'Enter your wallet private key',
            'Private key (hidden)'
        )

        if (!privateKey) {
            console.log(chalk.red('Private key cannot be empty'))
            continue
        }

        // Add 0x prefix if not present
        const formattedKey = privateKey.startsWith('0x')
            ? privateKey
            : '0x' + privateKey

        if (!isValidPrivateKey(formattedKey)) {
            console.log(
                chalk.red(
                    'Invalid private key format. Please enter a valid 64-character hex string.'
                )
            )
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
                message: 'Login with this wallet address?',
                initial: true,
            })

            if (confirmed.value === false) {
                console.log(
                    chalk.yellow('Please enter a different private key.')
                )
                continue
            }

            if (confirmed.value === undefined) {
                // User pressed Ctrl+C
                console.log(chalk.yellow('\nOperation cancelled.'))
                process.exit(0)
            }

            // Save to persistent config only
            setConfiguredPrivateKey(formattedKey)

            console.log(chalk.green('\n✓ Successfully logged in'))
            console.log(chalk.gray(`Wallet address: ${wallet.address}`))
            console.log(
                chalk.blue(`ℹ Settings saved to ~/.0g-compute-cli/config.json`)
            )
            return
        } catch {
            console.log(chalk.red('Error creating wallet from private key'))
            continue
        }
    }
}

/**
 * Logout command - removes private key
 */
async function logoutCommand(): Promise<void> {
    console.log(chalk.blue('\n🚪 Logout'))

    // Check if logged in
    const existingKey = getConfiguredPrivateKey()
    if (!existingKey) {
        console.log(chalk.yellow('⚠ Not currently logged in'))
        return
    }

    // Show current wallet address
    try {
        const wallet = new ethers.Wallet(existingKey)
        console.log(chalk.gray(`Current wallet: ${wallet.address}`))
    } catch {
        // Invalid key format
    }

    // Ask for confirmation
    const prompts = await import('prompts')
    const confirmed = await prompts.default({
        type: 'confirm',
        name: 'value',
        message: 'Are you sure you want to logout?',
        initial: false,
    })

    if (confirmed.value !== true) {
        console.log(chalk.yellow('Logout cancelled.'))
        return
    }

    // Clear from config file only
    const config = loadConfig()
    delete config.privateKey
    saveConfig(config)

    console.log(chalk.green('✓ Successfully logged out'))
    console.log(
        chalk.blue('ℹ Private key removed from ~/.0g-compute-cli/config.json')
    )
}

/**
 * Status command - shows current login status
 */
async function statusCommand(): Promise<void> {
    console.log(chalk.blue('\n👤 Login Status'))

    const privateKey = getConfiguredPrivateKey()
    if (!privateKey) {
        console.log(chalk.yellow('⚠ Not logged in'))
        console.log(chalk.gray('Use "0g-compute-cli login" to authenticate'))
        return
    }

    try {
        const wallet = new ethers.Wallet(privateKey)
        console.log(chalk.green('✓ Logged in'))
        console.log(chalk.gray(`Wallet address: ${wallet.address}`))
    } catch {
        console.log(chalk.red('✗ Invalid private key stored'))
        console.log(
            chalk.gray('Use "0g-compute-cli login --force" to re-authenticate')
        )
    }
}

export default function auth(program: Command): void {
    program
        .command('login')
        .description('Login by setting your private key')
        .option('-f, --force', 'Force login even if already authenticated')
        .action(loginCommand)

    program
        .command('logout')
        .description('Logout by removing your private key')
        .action(logoutCommand)

    program
        .command('status')
        .description('Show current login status')
        .action(statusCommand)
}

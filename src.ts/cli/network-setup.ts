#!/usr/bin/env ts-node

import chalk from 'chalk'
import { getConfiguredRpcEndpoint, setConfiguredRpcEndpoint } from './config'
import { interactiveSelect, textInput } from './interactive-selection'

const MAINNET_RPC = 'https://evmrpc.0g.ai'
const TESTNET_RPC = 'https://evmrpc-testnet.0g.ai'

interface NetworkConfig {
    name: string
    rpc: string
    description: string
}

const NETWORKS: Record<string, NetworkConfig> = {
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
}

/**
 * Sets the RPC endpoint in both session and persistent config
 */
function setRpcEndpoint(
    rpcEndpoint: string,
    network: 'mainnet' | 'testnet' | 'custom'
): void {
    // Set for current session
    process.env['ZG_RPC_ENDPOINT'] = rpcEndpoint

    // Save to persistent config
    setConfiguredRpcEndpoint(rpcEndpoint, network)

    console.log(chalk.green(`✓ RPC endpoint configured: ${rpcEndpoint}`))
    console.log(chalk.gray(`  Network: ${network}`))
    console.log(chalk.blue(`ℹ Settings saved to ~/.0g-compute-cli/config.json`))
}

/**
 * Prompts user to select a network or custom RPC
 */
async function promptNetworkSelection(): Promise<{
    type: 'preset' | 'custom'
    network?: string
    rpc?: string
}> {
    console.log(chalk.blue('\n🌐 0G Compute CLI Network Setup'))
    console.log()

    const networkChoice = await interactiveSelect({
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
    })

    if (networkChoice === 'custom') {
        console.log()
        const customRpc = await textInput(
            'Enter custom RPC endpoint URL',
            'https://your-rpc-endpoint.com'
        )

        if (!customRpc) {
            console.log(chalk.red('Custom RPC endpoint cannot be empty'))
            return await promptNetworkSelection()
        }

        // Validate URL format
        try {
            new URL(customRpc)
        } catch {
            console.log(
                chalk.red('Invalid URL format. Please enter a valid URL.')
            )
            return await promptNetworkSelection()
        }

        return { type: 'custom', rpc: customRpc }
    }

    return { type: 'preset', network: networkChoice }
}

/**
 * Checks if RPC endpoint is configured, if not, prompts user to select and set it
 */
export async function ensureNetworkConfiguration(): Promise<string> {
    // Check environment variables first
    const envRpc = process.env['ZG_RPC_ENDPOINT'] || process.env.RPC_ENDPOINT
    if (envRpc) {
        return envRpc
    }

    // Check config file
    const configRpc = getConfiguredRpcEndpoint()
    if (configRpc) {
        // Set in current session as well
        process.env['ZG_RPC_ENDPOINT'] = configRpc
        return configRpc
    }

    console.log(chalk.yellow('⚠ No RPC endpoint configured.'))
    console.log(chalk.gray('Please select a network for CLI operations.\n'))

    const selection = await promptNetworkSelection()

    if (selection.type === 'custom') {
        // Custom RPC endpoint
        const customRpc = selection.rpc!
        console.log(chalk.green(`\n✓ Selected: Custom RPC`))
        console.log(chalk.gray(`  RPC: ${customRpc}\n`))

        // Save custom configuration
        setRpcEndpoint(customRpc, 'custom')
        return customRpc
    } else {
        // Preset network
        const networkKey = selection.network!
        const networkConfig = NETWORKS[networkKey as keyof typeof NETWORKS]

        console.log(chalk.green(`\n✓ Selected: ${networkConfig.name}`))
        console.log(chalk.gray(`  RPC: ${networkConfig.rpc}\n`))

        // Set and save the configuration
        setRpcEndpoint(networkConfig.rpc, networkKey as 'mainnet' | 'testnet')
        return networkConfig.rpc
    }
}

/**
 * Gets the RPC endpoint, with interactive setup if needed
 */
export async function getRpcEndpoint(options: any): Promise<string> {
    // Priority: CLI option > environment variable > interactive setup
    if (options.rpc) {
        return options.rpc
    }

    if (process.env.ZG_RPC_ENDPOINT) {
        return process.env.ZG_RPC_ENDPOINT
    }

    return await ensureNetworkConfiguration()
}

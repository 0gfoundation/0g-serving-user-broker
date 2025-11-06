#!/usr/bin/env ts-node

import type { Command } from 'commander'
import { ensureNetworkConfiguration } from './network-setup'
import { loadConfig, clearConfig } from './config'
import chalk from 'chalk'

export default function network(program: Command) {
    program
        .command('setup-network')
        .description('Configure network settings (mainnet/testnet)')
        .action(async () => {
            try {
                console.log(chalk.blue('🔧 Network Configuration Setup'))
                console.log(chalk.gray('This will configure your default RPC endpoint.\n'))
                
                // Force reconfiguration by clearing both env var and config
                delete process.env['0G_RPC_ENDPOINT']
                clearConfig()
                
                const selectedRpc = await ensureNetworkConfiguration()
                
                console.log(chalk.green('\n✓ Network configuration completed!'))
                console.log(chalk.gray(`Selected RPC: ${selectedRpc}`))
                console.log(chalk.yellow('\n💡 Configuration saved and will persist across CLI sessions'))
                process.exit(0)
                
            } catch (error) {
                console.error(chalk.red('✗ Network setup failed:'), error)
                process.exit(1)
            }
        })

    program
        .command('show-network')
        .description('Show current network configuration')
        .action(() => {
            const envRpc = process.env['0G_RPC_ENDPOINT'] || process.env.RPC_ENDPOINT
            const config = loadConfig()
            
            console.log(chalk.blue('🌐 Current Network Configuration'))
            
            // Show environment variable if set
            if (envRpc) {
                console.log(chalk.green('✓ RPC Endpoint (Environment):'), chalk.white(envRpc))
                
                // Determine network type
                if (envRpc.includes('evmrpc.0g.ai')) {
                    console.log(chalk.green('✓ Network:'), chalk.white('Mainnet'))
                } else if (envRpc.includes('evmrpc-testnet.0g.ai')) {
                    console.log(chalk.green('✓ Network:'), chalk.white('Testnet'))
                } else {
                    console.log(chalk.yellow('⚠ Network:'), chalk.white('Custom'))
                }
            }
            // Show config file settings
            else if (config.rpcEndpoint) {
                console.log(chalk.green('✓ RPC Endpoint (Config):'), chalk.white(config.rpcEndpoint))
                console.log(chalk.green('✓ Network:'), chalk.white(config.network || 'Unknown'))
                if (config.lastUpdated) {
                    console.log(chalk.gray('  Last updated:'), chalk.gray(new Date(config.lastUpdated).toLocaleString()))
                }
            } else {
                console.log(chalk.yellow('⚠ No RPC endpoint configured'))
                console.log(chalk.gray('Run: 0g-compute-cli setup-network'))
            }
            
            console.log()
            console.log(chalk.gray('Available networks:'))
            console.log(chalk.gray('  • Mainnet: https://evmrpc.0g.ai'))
            console.log(chalk.gray('  • Testnet: https://evmrpc-testnet.0g.ai'))
            console.log()
            console.log(chalk.gray('Configuration priority: Environment variables > Config file'))
            console.log(chalk.gray('Config file location: ~/.0g-compute-cli/config.json'))
        })
}
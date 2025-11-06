import type { ZGComputeNetworkBroker } from '../sdk'
import { createZGComputeNetworkBroker, getNetworkType } from '../sdk'
import { ethers } from 'ethers'
import chalk from 'chalk'
import type { Table } from 'cli-table3'
import { getRpcEndpoint } from './network-setup'
import { getPrivateKey } from './private-key-setup'

export async function initBroker(
    options: any
): Promise<ZGComputeNetworkBroker> {
    // Use the new interactive RPC endpoint selection
    const rpcEndpoint = await getRpcEndpoint(options)
    
    // Use the new interactive private key selection
    const privateKey = await getPrivateKey(options)
    if (!privateKey) {
        throw new Error('Private key is required')
    }
    
    const provider = new ethers.JsonRpcProvider(rpcEndpoint)
    const wallet = new ethers.Wallet(privateKey, provider)

    return await createZGComputeNetworkBroker(
        wallet,
        options.ledgerCa || process.env.LEDGER_CA,
        options.inferenceCa || process.env.INFERENCE_CA,
        options.fineTuningCa || process.env.FINE_TUNING_CA,
        options.gasPrice,
        options.maxGasPrice,
        options.step
    )
}

export async function withBroker(
    options: any,
    action: (broker: ZGComputeNetworkBroker) => Promise<void>
) {
    try {
        const broker = await initBroker(options)
        await action(broker)
        process.exit(0)
    } catch (error: any) {
        alertError(error)
        process.exit(1)
    }
}

export async function checkFineTuningAvailability(options: any): Promise<boolean> {
    try {
        const rpcEndpoint = await getRpcEndpoint(options)
        const provider = new ethers.JsonRpcProvider(rpcEndpoint)
        const network = await provider.getNetwork()
        const networkType = getNetworkType(network.chainId)
        
        if (networkType === 'mainnet') {
            console.log(chalk.yellow('⚠ Fine-tuning is not yet ready on mainnet.'))
            console.log(chalk.gray('Please switch to testnet to use fine-tuning features.\n'))
            
            const shouldSwitch = await promptNetworkSwitch()
            if (shouldSwitch) {
                await switchToTestnet()
                console.log(chalk.green('✓ Network switched to testnet. Please run the command again.'))
                process.exit(0)
            } else {
                process.exit(1)
            }
        }
        return true
    } catch (error: any) {
        alertError(error)
        process.exit(1)
    }
}

async function promptNetworkSwitch(): Promise<boolean> {
    const { interactiveSelect } = await import('./interactive-selection')
    
    const choice = await interactiveSelect({
        message: 'Would you like to switch to testnet?',
        options: [
            { title: 'Yes, switch to testnet', value: 'yes' },
            { title: 'No, exit', value: 'no' }
        ]
    })
    
    return choice === 'yes'
}

async function switchToTestnet(): Promise<void> {
    const { setConfiguredRpcEndpoint } = await import('./config')
    const testnetRpc = 'https://evmrpc-testnet.0g.ai'
    
    // Set for current session
    process.env['ZG_RPC_ENDPOINT'] = testnetRpc
    
    // Save to persistent config
    setConfiguredRpcEndpoint(testnetRpc, 'testnet')
}

export async function withFineTuningBroker(
    options: any,
    action: (broker: ZGComputeNetworkBroker) => Promise<void>
) {
    try {
        const isAvailable = await checkFineTuningAvailability(options)
        if (!isAvailable) {
            return
        }
        
        const broker = await initBroker(options)
        if (broker.fineTuning) {
            await action(broker)
        } else {
            console.log('Fine tuning broker is not available.')
        }
        process.exit(0)
    } catch (error: any) {
        alertError(error)
        process.exit(1)
    }
}

export const neuronToA0gi = (value: bigint): number => {
    const divisor = BigInt(10 ** 18)
    const integerPart = value / divisor
    const remainder = value % divisor
    const decimalPart = Number(remainder) / Number(divisor)

    return Number(integerPart) + decimalPart
}

export const a0giToNeuron = (value: number): bigint => {
    const valueStr = value.toFixed(18)
    const parts = valueStr.split('.')

    // Handle integer part
    const integerPart = parts[0]
    let integerPartAsBigInt = BigInt(integerPart) * BigInt(10 ** 18)

    // Handle fractional part if it exists
    if (parts.length > 1) {
        let fractionalPart = parts[1]
        while (fractionalPart.length < 18) {
            fractionalPart += '0'
        }
        if (fractionalPart.length > 18) {
            fractionalPart = fractionalPart.slice(0, 18) // Truncate to avoid overflow
        }

        const fractionalPartAsBigInt = BigInt(fractionalPart)
        integerPartAsBigInt += fractionalPartAsBigInt
    }

    return integerPartAsBigInt
}

export const splitIntoChunks = (str: string, size: number) => {
    const chunks: string[] = []
    for (let i = 0; i < str.length; i += size) {
        chunks.push(str.slice(i, i + size))
    }
    return chunks.join('\n')
}

export const printTableWithTitle = (title: string, table: Table) => {
    console.log(`\n${chalk.white(`  ${title}`)}\n` + table.toString())
}

const alertError = (error: any) => {
    // SDK now handles error formatting, so we just need to display the error message
    const errorMessage = error?.message || String(error)

    // Check for additional CLI-specific patterns
    const errorPatterns = [
        {
            pattern: /Deliverable not acknowledged yet/i,
            message:
                "Deliverable not acknowledged yet. Please use '0g-compute-cli acknowledge-model --provider <provider_address> --data-path <path_to_save_model>' to acknowledge the deliverable.",
        },
        {
            pattern: /EncryptedSecret not found/i,
            message:
                "Secret to decrypt model not found. Please ensure the task status is 'Finished' using '0g-compute-cli get-task --provider <provider_address>'.",
        },
    ]

    const matchedPattern = errorPatterns.find(({ pattern }) =>
        pattern.test(errorMessage)
    )

    if (matchedPattern) {
        console.error(chalk.red('✗ Operation failed:'), matchedPattern.message)
    } else {
        console.error(chalk.red('✗ Operation failed:'), errorMessage)
    }

    // Show raw error in verbose mode (can be controlled by an env variable)
    if (process.env.VERBOSE === 'true') {
        console.error(chalk.gray('\nRaw error:'), error)
    }
}

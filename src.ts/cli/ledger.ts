#!/usr/bin/env ts-node

import {
    neuronToA0gi,
    a0giToNeuron,
    printTableWithTitle,
    withBroker,
    splitIntoChunks,
    checkFineTuningAvailability,
} from './util'
import type { Command } from 'commander'
import Table from 'cli-table3'
import type { ZGComputeNetworkBroker } from '../sdk'
import chalk from 'chalk'
import { hexToRoots } from '../sdk/common/utils'
import type { DeliverableStructOutput } from '../sdk/fine-tuning/contract/typechain/FineTuningServing'

export default function ledger(program: Command) {
    program
        .command('get-account')
        .description('Retrieve account information')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withBroker(options, async (broker) => {
                await getLedgerTable(broker)

                // Add helpful information about sub-account details
                console.log(
                    chalk.yellow(
                        '\n💡 To get detailed sub-account information:'
                    )
                )
                console.log(chalk.gray('• For inference sub-account details:'))
                console.log(
                    chalk.cyan(
                        '  0g-compute-cli account get-sub-account --provider <provider_address> --service inference'
                    )
                )
                console.log(
                    chalk.gray('• For fine-tuning sub-account details:')
                )
                console.log(
                    chalk.cyan(
                        '  0g-compute-cli account get-sub-account --provider <provider_address> --service fine-tuning'
                    )
                )
            })
        })

    program
        .command('add-account')
        .description('Add account balance')
        .requiredOption('--amount <0G>', 'Amount to add')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options) => {
            withBroker(options, async (broker) => {
                console.log('Adding account...')
                await broker.ledger.addLedger(parseFloat(options.amount))
                console.log('Account Created!')
                getLedgerTable(broker)
            })
        })

    program
        .command('deposit')
        .description('Deposit funds into the account')
        .requiredOption('--amount <0G>', 'Amount of funds to deposit')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options) => {
            withBroker(options, async (broker) => {
                console.log('Depositing...')
                await broker.ledger.depositFund(parseFloat(options.amount))
                console.log('Deposited funds:', options.amount, '0G')
            })
        })

    program
        .command('refund')
        .description('Refund an amount from the account')
        .requiredOption('-a, --amount <0G>', 'Amount to refund')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options) => {
            withBroker(options, async (broker) => {
                console.log('Refunding...')
                await broker.ledger.refund(parseFloat(options.amount))
                console.log('Refunded amount:', options.amount, '0G')
            })
        })

    program
        .command('retrieve-fund')
        .description('Retrieve funds from sub account')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .requiredOption(
            '--service <type>',
            'Service type: inference or fine-tuning'
        )
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action(async (options: any) => {
            const serviceType = options.service as
                | 'inference'
                | 'fine-tuning'
            if (
                serviceType !== 'inference' &&
                serviceType !== 'fine-tuning'
            ) {
                console.error(
                    'Invalid service type. Must be "inference" or "fine-tuning"'
                )
                process.exit(1)
            }

            if (serviceType === 'fine-tuning') {
                const isAvailable = await checkFineTuningAvailability(options)
                if (!isAvailable) {
                    return
                }
            }

            withBroker(options, async (broker) => {
                console.log(
                    `Retrieving funds from ${serviceType} sub accounts...`
                )
                await broker.ledger.retrieveFund(serviceType)
                console.log(`Funds retrieved from ${serviceType} sub accounts`)

                // Add helpful information about checking lock time
                console.log(
                    chalk.yellow(
                        '\n💡 To check remaining lock time for funds to be retrieved to main account:'
                    )
                )
                console.log(
                    chalk.cyan(
                        `  0g-compute-cli account get-sub-account --provider <provider_address> --service ${serviceType}`
                    )
                )
            })
        })

    program
        .command('transfer-fund')
        .description('Transfer funds to a provider for a specific service provider')
        .requiredOption(
            '--provider <address>',
            'Provider address to transfer funds to'
        )
        .requiredOption('--amount <0G>', 'Amount to transfer in 0G')
        .requiredOption(
            '--service <type>',
            'Service type: inference or fine-tuning',
            'inference'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action(async (options: any) => {
            const serviceType = options.service as
                | 'inference'
                | 'fine-tuning'
            if (
                serviceType !== 'inference' &&
                serviceType !== 'fine-tuning'
            ) {
                console.error(
                    'Invalid service type. Must be "inference" or "fine-tuning"'
                )
                process.exit(1)
            }

            if (serviceType === 'fine-tuning') {
                const isAvailable = await checkFineTuningAvailability(options)
                if (!isAvailable) {
                    return
                }
            }

            withBroker(options, async (broker) => {
                const amountInNeuron = a0giToNeuron(parseFloat(options.amount))
                console.log(
                    `Transferring ${options.amount} 0G to ${options.provider} for ${serviceType}...`
                )
                await broker.ledger.transferFund(
                    options.provider,
                    serviceType,
                    amountInNeuron,
                    options.gasPrice ? parseFloat(options.gasPrice) : undefined
                )
                console.log(
                    `Successfully transferred ${options.amount} 0G to ${options.provider}`
                )
            })
        })

    program
        .command('get-sub-account')
        .description(
            'Retrieve detailed sub account information for a specific provider and service'
        )
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption(
            '--service <type>',
            'Service type: inference or fine-tuning'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action(async (options: any) => {
            if (
                options.service !== 'inference' &&
                options.service !== 'fine-tuning'
            ) {
                console.error(
                    chalk.red(
                        'Error: --service must be either "inference" or "fine-tuning"'
                    )
                )
                process.exit(1)
            }

            if (options.service === 'fine-tuning') {
                const isAvailable = await checkFineTuningAvailability(options)
                if (!isAvailable) {
                    return
                }
            }

            withBroker(options, async (broker) => {
                if (options.service === 'inference') {
                    const [account, refunds] =
                        await broker.inference.getAccountWithDetail(
                            options.provider
                        )

                    renderSubAccountOverview({
                        provider: account.provider,
                        balance: account.balance,
                        pendingRefund: account.pendingRefund,
                        service: 'Inference',
                    })
                    renderSubAccountRefunds(refunds)
                } else if (options.service === 'fine-tuning') {
                    if (!broker.fineTuning) {
                        console.log(
                            chalk.red('Fine tuning broker is not available.')
                        )
                        return
                    }

                    const { account, refunds } =
                        await broker.fineTuning.getAccountWithDetail(
                            options.provider
                        )

                    renderSubAccountOverview({
                        provider: account.provider,
                        balance: account.balance,
                        pendingRefund: account.pendingRefund,
                        service: 'Fine-tuning',
                    })
                    renderSubAccountRefunds(refunds)
                    renderDeliverables(account.deliverables)
                }

                // Add helpful information about fund operations
                console.log(chalk.yellow('\n💡 Fund Management Tips:'))
                console.log(chalk.gray('• To retrieve all funds from sub-accounts to main account:'))
                console.log(chalk.cyan(`  0g-compute-cli account retrieve-fund --service ${options.service}`))
                console.log(chalk.gray('  Note: Retrieved funds need to be locked for a period. After the lock period expires,'))
                console.log(chalk.gray('  use retrieve-fund again to transfer all unlocked amounts to the main account.'))
                console.log(chalk.gray('\n• To transfer funds from main account to this provider:'))
                console.log(chalk.cyan(`  0g-compute-cli account transfer-fund --provider ${options.provider} --amount <amount> --service ${options.service}`))
            })
        })
}

export const getLedgerTable = async (broker: ZGComputeNetworkBroker) => {
    // Ledger information
    const { ledgerInfo, infers, fines } =
        await broker.ledger.ledger.getLedgerWithDetail()

    const table = new Table({
        head: [chalk.blue('Balance'), chalk.blue('Value (0G)')],
        colWidths: [50, 81],
    })

    table.push(['Total', neuronToA0gi(ledgerInfo[0]).toFixed(18)])
    table.push([
        'Locked (transferred to sub-accounts)',
        neuronToA0gi(ledgerInfo[1]).toFixed(18),
    ])
    printTableWithTitle('Overview', table)
    // Inference information
    if (infers && infers.length !== 0) {
        const table = new Table({
            head: [
                chalk.blue('Provider'),
                chalk.blue('Balance (0G)'),
                chalk.blue('Requested Return to Main Account (0G)'),
            ],
            colWidths: [50, 30, 50],
        })
        for (const infer of infers) {
            table.push([
                infer[0],
                neuronToA0gi(infer[1]).toFixed(18),
                neuronToA0gi(infer[2]).toFixed(18),
            ])
        }

        printTableWithTitle(
            'Inference sub-accounts (Dynamically Created per Used Provider)',
            table
        )
    }

    // Fine tuning information
    if (fines && fines.length !== 0) {
        const table = new Table({
            head: [
                chalk.blue('Provider'),
                chalk.blue('Balance (0G)'),
                chalk.blue('Requested Return to Main Account (0G)'),
            ],
            colWidths: [50, 30, 50],
        })
        for (const fine of fines) {
            table.push([
                fine[0],
                neuronToA0gi(fine[1]).toFixed(18),
                neuronToA0gi(fine[2]).toFixed(18),
            ])
        }

        printTableWithTitle(
            'Fine-tuning sub-accounts (Dynamically Created per Used Provider)',
            table
        )
    }
}

// Helper functions for detailed sub-account information
function renderSubAccountOverview(account: {
    provider: string
    balance: bigint
    pendingRefund: bigint
    service: string
}) {
    const table = new Table({
        head: [chalk.blue('Field'), chalk.blue('Value')],
        colWidths: [50, 50],
    })

    table.push(['Service Type', account.service])
    table.push(['Provider', account.provider])
    table.push(['Balance (0G)', neuronToA0gi(account.balance).toFixed(18)])
    table.push([
        'Funds Applied for Return to Main Account (0G)',
        neuronToA0gi(account.pendingRefund).toFixed(18),
    ])

    printTableWithTitle(`${account.service} Sub-Account Overview`, table)
}

function renderSubAccountRefunds(
    refunds: { amount: bigint; remainTime: bigint }[]
) {
    if (!refunds || refunds.length === 0) {
        console.log(chalk.gray('\nNo pending refunds found.'))
        return
    }

    const table = new Table({
        head: [chalk.blue('Amount (0G)'), chalk.blue('Remaining Locked Time')],
        colWidths: [50, 50],
    })

    refunds.forEach((refund) => {
        const totalSeconds = Number(refund.remainTime)
        const hours = Math.floor(totalSeconds / 3600)
        const minutes = Math.floor((totalSeconds % 3600) / 60)
        const secs = totalSeconds % 60

        table.push([
            neuronToA0gi(refund.amount).toFixed(18),
            `${hours}h ${minutes}min ${secs}s`,
        ])
    })

    printTableWithTitle(
        'Details of Each Amount Applied for Return to Main Account',
        table
    )
}

function renderDeliverables(deliverables: DeliverableStructOutput[]) {
    if (!deliverables || deliverables.length === 0) {
        console.log(chalk.gray('\nNo deliverables found.'))
        return
    }

    const table = new Table({
        head: [chalk.blue('Root Hash'), chalk.blue('Access Confirmed')],
        colWidths: [75, 25],
    })

    deliverables.forEach((d) => {
        table.push([
            splitIntoChunks(hexToRoots(d.modelRootHash), 60),
            d.acknowledged ? chalk.greenBright.bold('\u2713') : '',
        ])
    })

    printTableWithTitle('Deliverables', table)
}

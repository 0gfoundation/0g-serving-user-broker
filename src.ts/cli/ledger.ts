#!/usr/bin/env ts-node

import { neuronToA0gi, printTableWithTitle, withBroker, splitIntoChunks } from './util'
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
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withBroker(options, async (broker) => {
                await getLedgerTable(broker)
                
                // Add helpful information about sub-account details
                console.log(chalk.yellow('\n💡 To get detailed sub-account information:'))
                console.log(chalk.gray('• For inference sub-account details:'))
                console.log(chalk.cyan('  0g-compute-cli ledger get-sub-account --provider <provider_address> --service inference'))
                console.log(chalk.gray('• For fine-tuning sub-account details:'))
                console.log(chalk.cyan('  0g-compute-cli ledger get-sub-account --provider <provider_address> --service fine-tuning'))
                console.log(chalk.gray('\nExample:'))
                console.log(chalk.green('  0g-compute-cli ledger get-sub-account --provider 0x4f371f6eff4cb5a9471c9cf9bE32c729024b063C --service inference'))
            })
        })

    program
        .command('add-account')
        .description('Add account balance')
        .requiredOption('--amount <A0GI>', 'Amount to add')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
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
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption('--amount <A0GI>', 'Amount of funds to deposit')
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
                console.log('Deposited funds:', options.amount, 'A0GI')
            })
        })

    program
        .command('refund')
        .description('Refund an amount from the account')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption('-a, --amount <A0GI>', 'Amount to refund')
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
                console.log('Refunded amount:', options.amount, 'A0GI')
            })
        })

    program
        .command('retrieve-fund')
        .description('Retrieve fund from sub account')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option(
            '--infer',
            'Retrieve fund from sub accounts for inference, default is fine-tuning'
        )
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options: any) => {
            withBroker(options, async (broker) => {
                console.log('Retrieving funds from sub accounts...')
                await broker.ledger.retrieveFund(
                    options.infer ? 'inference' : 'fine-tuning'
                )
                console.log('Funds retrieved from sub accounts')
            })
        })

    program
        .command('transfer-fund')
        .description('Transfer funds to a provider for a specific service')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption(
            '--provider <address>',
            'Provider address to transfer funds to'
        )
        .requiredOption('--amount <neuron>', 'Amount to transfer in neuron')
        .option(
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
        .action((options: any) => {
            withBroker(options, async (broker) => {
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

                console.log(
                    `Transferring ${options.amount} neuron to ${options.provider} for ${serviceType}...`
                )
                await broker.ledger.transferFund(
                    options.provider,
                    serviceType,
                    BigInt(options.amount),
                    options.gasPrice ? parseFloat(options.gasPrice) : undefined
                )
                console.log(
                    `Successfully transferred ${options.amount} neuron to ${options.provider}`
                )
            })
        })

    program
        .command('get-sub-account')
        .description('Retrieve detailed sub account information for a specific provider and service')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption('--service <type>', 'Service type: inference or fine-tuning')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options: any) => {
            if (options.service !== 'inference' && options.service !== 'fine-tuning') {
                console.error(chalk.red('Error: --service must be either "inference" or "fine-tuning"'))
                process.exit(1)
            }

            withBroker(options, async (broker) => {
                if (options.service === 'inference') {
                    const [account, refunds] = await broker.inference.getAccountWithDetail(options.provider)
                    
                    renderSubAccountOverview({
                        provider: account.provider,
                        balance: account.balance,
                        pendingRefund: account.pendingRefund,
                        service: 'Inference'
                    })
                    renderSubAccountRefunds(refunds)
                    
                } else if (options.service === 'fine-tuning') {
                    if (!broker.fineTuning) {
                        console.log(chalk.red('Fine tuning broker is not available.'))
                        return
                    }
                    
                    const { account, refunds } = await broker.fineTuning.getAccountWithDetail(options.provider)
                    
                    renderSubAccountOverview({
                        provider: account.provider,
                        balance: account.balance,
                        pendingRefund: account.pendingRefund,
                        service: 'Fine-tuning'
                    })
                    renderSubAccountRefunds(refunds)
                    renderDeliverables(account.deliverables)
                }
            })
        })
}

export const getLedgerTable = async (broker: ZGComputeNetworkBroker) => {
    // Ledger information
    const { ledgerInfo, infers, fines } =
        await broker.ledger.ledger.getLedgerWithDetail()

    let table = new Table({
        head: [chalk.blue('Balance'), chalk.blue('Value (A0GI)')],
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
        let table = new Table({
            head: [
                chalk.blue('Provider'),
                chalk.blue('Balance (A0GI)'),
                chalk.blue('Requested Return to Main Account (A0GI)'),
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
        let table = new Table({
            head: [
                chalk.blue('Provider'),
                chalk.blue('Balance (A0GI)'),
                chalk.blue('Requested Return to Main Account (A0GI)'),
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
    table.push(['Balance (A0GI)', neuronToA0gi(account.balance).toFixed(18)])
    table.push([
        'Funds Applied for Return to Main Account (A0GI)',
        neuronToA0gi(account.pendingRefund).toFixed(18),
    ])

    printTableWithTitle(`${account.service} Sub-Account Overview`, table)
}

function renderSubAccountRefunds(refunds: { amount: bigint; remainTime: bigint }[]) {
    if (!refunds || refunds.length === 0) {
        console.log(chalk.gray('\nNo pending refunds found.'))
        return
    }

    const table = new Table({
        head: [
            chalk.blue('Amount (A0GI)'),
            chalk.blue('Remaining Locked Time'),
        ],
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

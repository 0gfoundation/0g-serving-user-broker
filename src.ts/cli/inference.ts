#!/usr/bin/env ts-node

import type { Command } from 'commander'
import { withBroker, neuronToA0gi, printTableWithTitle } from './util'
import Table from 'cli-table3'
import chalk from 'chalk'

export default function inference(program: Command) {
    program
        .command('ack-provider')
        .description('verify TEE remote attestation of service')
        .requiredOption('--provider <address>', 'Provider address')
        .option(
            '--key <key>',
            'Wallet private key, if not provided, ensure the default key is set in the environment',
            process.env.ZG_PRIVATE_KEY
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.acknowledgeProviderTEESigner(
                    options.provider,
                    options.gasPrice
                )
                console.log('Provider acknowledged successfully!')
            })
        })

    program
        .command('download-report')
        .description('Download quote data to a specified file')
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption(
            '--output <path>',
            'Output file path for the quote report'
        )
        .option(
            '--key <key>',
            'Wallet private key, if not provided, ensure the default key is set in the environment',
            process.env.ZG_PRIVATE_KEY
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.downloadQuoteReport(
                    options.provider,
                    options.output
                )
                console.log(`Quote report downloaded to: ${options.output}`)
            })
        })

    program
        .command('verify-tee')
        .description('Verify the reliability of a service')
        .requiredOption('--provider <address>', 'Provider address')
        .option(
            '--output-dir <path>',
            'Output directory for verification reports',
            '.'
        )
        .option(
            '--key <key>',
            'Wallet private key, if not provided, ensure the default key is set in the environment',
            process.env.ZG_PRIVATE_KEY
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action((options) => {
            withBroker(options, async (broker) => {
                const result = await broker.inference.verifyService(
                    options.provider,
                    options.outputDir
                )
                if (result) {
                    if (!result.success) {
                        console.log('❌ Service verification failed')
                    }
                } else {
                    console.log('Verification result is null')
                }
            })
        })

    program
        .command('serve')
        .description('Start local inference service')
        .requiredOption('--provider <address>', 'Provider address')
        .option(
            '--key <key>',
            'Wallet private key, if not provided, ensure the default key is set in the environment',
            process.env.ZG_PRIVATE_KEY
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option(
            '--port <port>',
            'Port to run the local inference service on',
            '3000'
        )
        .option(
            '--host <host>',
            'Host to bind the local inference service',
            '0.0.0.0'
        )
        .action(async (options) => {
            const { runInferenceServer } = await import(
                '../example/inference-server'
            )
            await runInferenceServer(options)
        })

    program
        .command('router-serve')
        .description(
            'Start high-availability router service with multiple providers'
        )
        .option(
            '--add-provider <address,priority>',
            'Add on-chain provider with priority (e.g., 0x1234567890abcdef,10). Use comma separator. Can be used multiple times',
            (value: string, previous: any[]) => {
                const providers = previous || []
                const [address, priority] = value.split(',')
                if (!address) {
                    throw new Error(
                        'Invalid provider format. Use: address,priority (comma-separated)'
                    )
                }
                providers.push({
                    address: address.trim(),
                    priority:
                        priority && priority.trim()
                            ? parseInt(priority.trim())
                            : 100,
                })
                return providers
            },
            [] as any[]
        )
        .option(
            '--add-endpoint <id,endpoint,apikey,model,priority>',
            'Add direct endpoint (e.g., openai,https://api.openai.com/v1,key,gpt-4o,10). Use commas as separators. Can be used multiple times',
            (value: string, previous: any[]) => {
                const endpoints = previous || []
                const [id, endpoint, apiKey, model, priority] = value.split(',')
                if (!id || !endpoint) {
                    throw new Error(
                        'Invalid endpoint format. Use: id,endpoint,apikey,model,priority (comma-separated)'
                    )
                }
                endpoints.push({
                    id: id.trim(),
                    endpoint: endpoint.trim(),
                    apiKey: apiKey && apiKey.trim() ? apiKey.trim() : undefined,
                    model:
                        model && model.trim() ? model.trim() : 'gpt-3.5-turbo',
                    priority:
                        priority && priority.trim()
                            ? parseInt(priority.trim())
                            : 50,
                })
                return endpoints
            },
            [] as any[]
        )
        .option(
            '--default-provider-priority <number>',
            'Default priority for on-chain providers not explicitly set',
            '100'
        )
        .option(
            '--default-endpoint-priority <number>',
            'Default priority for direct endpoints not explicitly set',
            '50'
        )
        .option(
            '--key <key>',
            'Wallet private key, if not provided, ensure the default key is set in the environment',
            process.env.ZG_PRIVATE_KEY
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--port <port>', 'Port to run the router service on', '3000')
        .option('--host <host>', 'Host to bind the router service', '0.0.0.0')
        .option('--cache-duration <seconds>', 'Cache duration in seconds', '60')
        .option(
            '--request-timeout <seconds>',
            'Request timeout in seconds for each provider',
            '60'
        )
        .action(async (options) => {
            // Build providers list with priorities
            const providers: string[] = []
            const providerPriorities: Record<string, number> = {}

            if (options.addProvider && options.addProvider.length > 0) {
                for (const prov of options.addProvider) {
                    providers.push(prov.address)
                    providerPriorities[prov.address] = prov.priority
                }
            }

            // Build direct endpoints
            const directEndpoints: Record<string, any> = {}

            if (options.addEndpoint && options.addEndpoint.length > 0) {
                for (const ep of options.addEndpoint) {
                    directEndpoints[ep.id] = {
                        endpoint: ep.endpoint,
                        apiKey: ep.apiKey,
                        model: ep.model,
                        priority: ep.priority,
                    }
                }
            }

            // Build priority config
            const priorityConfig: any = {
                providers: providerPriorities,
                defaultProviderPriority: parseInt(
                    options.defaultProviderPriority
                ),
                defaultEndpointPriority: parseInt(
                    options.defaultEndpointPriority
                ),
            }

            // Ensure at least one provider type is specified
            if (
                providers.length === 0 &&
                Object.keys(directEndpoints).length === 0
            ) {
                console.error(
                    'Error: Must specify either --add-provider or --add-endpoint'
                )
                process.exit(1)
            }

            const routerOptions = {
                ...options,
                providers,
                directEndpoints:
                    Object.keys(directEndpoints).length > 0
                        ? directEndpoints
                        : undefined,
                priorityConfig,
                requestTimeout: options.requestTimeout,
            }

            const { runRouterServer } = await import('../example/router-server')
            await runRouterServer(routerOptions)
        })

    program
        .command('get-sub-account')
        .description('Retrieve sub account information for inference')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action((options: any) => {
            withBroker(options, async (broker) => {
                const [account, refunds] =
                    await broker.inference.getAccountWithDetail(
                        options.provider
                    )

                renderOverview({
                    provider: account.provider,
                    balance: account.balance,
                    pendingRefund: account.pendingRefund,
                })
                renderRefunds(refunds)
            })
        })

    program
        .command('list-providers')
        .description('List inference providers')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action((options: any) => {
            const table = new Table({
                colWidths: [50, 50],
            })
            withBroker(options, async (broker) => {
                const services = await broker.inference.listService()
                services.forEach((service, index) => {
                    table.push([
                        chalk.blue(`Provider ${index + 1}`),
                        chalk.blue(service.provider),
                    ])
                    table.push(['Model', service.model || 'N/A'])
                    table.push([
                        'Input Price Per Byte (0G)',
                        service.inputPrice
                            ? neuronToA0gi(BigInt(service.inputPrice)).toFixed(
                                  18
                              )
                            : 'N/A',
                    ])
                    table.push([
                        'Output Price Per Byte (0G)',
                        service.outputPrice
                            ? neuronToA0gi(BigInt(service.outputPrice)).toFixed(
                                  18
                              )
                            : 'N/A',
                    ])
                    table.push([
                        'Verifiability',
                        service.verifiability || 'N/A',
                    ])
                })
                console.log(table.toString())
            })
        })
}

function renderOverview(account: {
    provider: string
    balance: bigint
    pendingRefund: bigint
}) {
    const table = new Table({
        head: [chalk.blue('Field'), chalk.blue('Value')],
        colWidths: [50, 50],
    })

    table.push(['Provider', account.provider])
    table.push(['Balance (A0GI)', neuronToA0gi(account.balance).toFixed(18)])
    table.push([
        'Funds Applied for Return to Main Account (A0GI)',
        neuronToA0gi(account.pendingRefund).toFixed(18),
    ])

    printTableWithTitle('Overview', table)
}

function renderRefunds(refunds: { amount: bigint; remainTime: bigint }[]) {
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

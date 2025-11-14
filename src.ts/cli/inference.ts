#!/usr/bin/env ts-node

import type { Command } from 'commander'
import { withBroker, neuronToA0gi, initBroker } from './util'
import { getRpcEndpoint } from './network-setup'
import { ensurePrivateKeyConfiguration } from './private-key-setup'
import Table from 'cli-table3'
import chalk from 'chalk'
import axios from 'axios'
import fs from 'fs'
import { ethers } from 'ethers'

export default function inference(program: Command) {
    program
        .command('list-providers')
        .description('List inference providers')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option(
            '--include-invalid',
            'Include all services, even those without valid teeSignerAddress'
        )
        .action((options: any) => {
            const table = new Table({
                colWidths: [50, 50],
            })
            withBroker(options, async (broker) => {
                let services = await broker.inference.listService()
                if (!options.includeInvalid) {
                    services = services.filter(
                        (service) => service.teeSignerAcknowledged
                    )
                }
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

    program
        .command('acknowledge-provider')
        .description('Acknowledge the provider signer')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.acknowledgeProviderSigner(
                    options.provider,
                    options.gasPrice
                )
                console.log('Provider signer acknowledged successfully!')
            })
        })

    program
        .command('serve')
        .description('Start local inference service')
        .requiredOption('--provider <address>', 'Provider address')
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
            // Ensure RPC endpoint is configured
            const rpc = await getRpcEndpoint(options)
            // Ensure private key is configured
            const key = await ensurePrivateKeyConfiguration()
            const { runInferenceServer } = await import(
                '../example/inference-server'
            )
            await runInferenceServer({ ...options, rpc, key })
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

            // Ensure RPC endpoint is configured if we have on-chain providers
            let rpc = options.rpc
            let key = options.key
            if (providers.length > 0) {
                if (!rpc) {
                    rpc = await getRpcEndpoint(options)
                }
                if (!key) {
                    key = await ensurePrivateKeyConfiguration()
                }
            }

            const routerOptions = {
                ...options,
                rpc,
                key,
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
        .command('download-report')
        .description('Download quote data to a specified file')
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption(
            '--output <path>',
            'Output file path for the quote report'
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
        .command('verify')
        .description('Verify the reliability of a service')
        .requiredOption('--provider <address>', 'Provider address')
        .option(
            '--output-dir <path>',
            'Output directory for verification reports',
            '.'
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
        .command('list-logs')
        .description(
            '[For provider] List available log files from your provider service'
        )
        .option(
            '--component <component>',
            'Component name (broker/event/both)',
            'both'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action(async (options) => {
            try {
                const rpcEndpoint = await getRpcEndpoint(options)
                const privateKey = await ensurePrivateKeyConfiguration()
                if (!privateKey) {
                    throw new Error('Private key is required')
                }

                const provider = new ethers.JsonRpcProvider(rpcEndpoint)
                const wallet = new ethers.Wallet(privateKey, provider)
                const userAddress = await wallet.getAddress()

                const broker = await initBroker(options)

                try {
                    // Get service metadata for current user's provider service
                    const serviceMetadata =
                        await broker.inference.getServiceMetadata(userAddress)

                    // Create session for provider authentication
                    const session =
                        await broker.inference.requestProcessor.getOrCreateSession(
                            userAddress
                        )

                    const endpoint = `${serviceMetadata.endpoint.replace(
                        '/proxy',
                        '/logs'
                    )}?component=${options.component}`

                    const response = await axios.get(endpoint, {
                        headers: {
                            Address: userAddress,
                            'Session-Token': session.rawMessage,
                            'Session-Signature': session.signature,
                        },
                    })

                    const logs = response.data.logs || []

                    if (logs.length === 0) {
                        console.log('No log files found.')
                        return
                    }

                    const table = new Table({
                        head: [
                            'Component',
                            'Filename',
                            'Size (bytes)',
                            'Modified Time',
                            'Current',
                        ],
                        colWidths: [12, 30, 15, 25, 10],
                    })

                    logs.forEach(
                        (log: {
                            component: string
                            name: string
                            size: number
                            modifiedTime: number
                            isCurrentLog: boolean
                        }) => {
                            const modifiedTime = new Date(
                                log.modifiedTime * 1000
                            ).toLocaleString()
                            const isCurrent = log.isCurrentLog ? '✓' : ''
                            const size = log.size.toLocaleString()

                            table.push([
                                chalk.blue(log.component),
                                log.name,
                                size,
                                modifiedTime,
                                isCurrent ? chalk.green(isCurrent) : '',
                            ])
                        }
                    )

                    console.log('\nAvailable Log Files:')
                    console.log(table.toString())
                    process.exit(0)
                } catch (error: unknown) {
                    if (
                        error &&
                        typeof error === 'object' &&
                        'response' in error
                    ) {
                        const axiosError = error as {
                            response: {
                                data?: { error?: string }
                                statusText: string
                            }
                        }
                        console.error(
                            'Error:',
                            axiosError.response.data?.error ||
                                axiosError.response.statusText
                        )
                    } else if (error instanceof Error) {
                        console.error('Error:', error.message)
                    } else {
                        console.error('Error:', String(error))
                    }
                    process.exit(1)
                }
            } catch (error: unknown) {
                if (error instanceof Error) {
                    console.error('Error:', error.message)
                } else {
                    console.error('Error:', String(error))
                }
                process.exit(1)
            }
        })

    program
        .command('download-log')
        .description(
            '[For provider] Download a specific log file from your provider service'
        )
        .requiredOption(
            '--component <component>',
            'Component name (broker/event)'
        )
        .requiredOption('--filename <filename>', 'Log file name')
        .option('--output <path>', 'Output file path (defaults to filename)')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action(async (options) => {
            try {
                const rpcEndpoint = await getRpcEndpoint(options)
                const privateKey = await ensurePrivateKeyConfiguration()
                if (!privateKey) {
                    throw new Error('Private key is required')
                }

                const provider = new ethers.JsonRpcProvider(rpcEndpoint)
                const wallet = new ethers.Wallet(privateKey, provider)
                const userAddress = await wallet.getAddress()

                const broker = await initBroker(options)

                try {
                    // Get service metadata for current user's provider service
                    const serviceMetadata =
                        await broker.inference.getServiceMetadata(userAddress)

                    // Create session for provider authentication
                    const session =
                        await broker.inference.requestProcessor.getOrCreateSession(
                            userAddress
                        )

                    const endpoint = `${serviceMetadata.endpoint.replace(
                        '/proxy',
                        '/logs'
                    )}/${options.component}/${options.filename}`

                    const response = await axios.get(endpoint, {
                        headers: {
                            Address: userAddress,
                            'Session-Token': session.rawMessage,
                            'Session-Signature': session.signature,
                        },
                        responseType: 'stream',
                    })

                    const outputPath = options.output || options.filename
                    const writer = fs.createWriteStream(outputPath)

                    response.data.pipe(writer)

                    writer.on('finish', () => {
                        console.log(`Log file downloaded to: ${outputPath}`)
                        process.exit(0)
                    })

                    writer.on('error', (error: Error) => {
                        console.error('Error writing file:', error.message)
                        process.exit(1)
                    })
                } catch (error: unknown) {
                    if (
                        error &&
                        typeof error === 'object' &&
                        'response' in error
                    ) {
                        const axiosError = error as {
                            response: {
                                data?: { error?: string }
                                statusText: string
                            }
                        }
                        console.error(
                            'Error:',
                            axiosError.response.data?.error ||
                                axiosError.response.statusText
                        )
                    } else if (error instanceof Error) {
                        console.error('Error:', error.message)
                    } else {
                        console.error('Error:', String(error))
                    }
                    process.exit(1)
                }
            } catch (error: unknown) {
                if (error instanceof Error) {
                    console.error('Error:', error.message)
                } else {
                    console.error('Error:', String(error))
                }
                process.exit(1)
            }
        })

    program
        .command('view-log')
        .description(
            '[For provider] View a specific log file content from your provider service'
        )
        .requiredOption(
            '--component <component>',
            'Component name (broker/event)'
        )
        .requiredOption('--filename <filename>', 'Log file name')
        .option(
            '--lines <number>',
            'Number of lines to show (default: all)',
            'all'
        )
        .option('--tail', 'Show last N lines instead of first N lines')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action(async (options) => {
            try {
                const rpcEndpoint = await getRpcEndpoint(options)
                const privateKey = await ensurePrivateKeyConfiguration()
                if (!privateKey) {
                    throw new Error('Private key is required')
                }

                const provider = new ethers.JsonRpcProvider(rpcEndpoint)
                const wallet = new ethers.Wallet(privateKey, provider)
                const userAddress = await wallet.getAddress()

                const broker = await initBroker(options)

                try {
                    // Get service metadata for current user's provider service
                    const serviceMetadata =
                        await broker.inference.getServiceMetadata(userAddress)

                    // Create session for provider authentication
                    const session =
                        await broker.inference.requestProcessor.getOrCreateSession(
                            userAddress
                        )

                    const endpoint = `${serviceMetadata.endpoint.replace(
                        '/proxy',
                        '/logs'
                    )}/${options.component}/${options.filename}`

                    const response = await axios.get(endpoint, {
                        headers: {
                            Address: userAddress,
                            'Session-Token': session.rawMessage,
                            'Session-Signature': session.signature,
                        },
                    })

                    let content = response.data

                    if (options.lines !== 'all') {
                        const numLines = parseInt(options.lines)
                        const lines = content.split('\n')

                        if (options.tail) {
                            content = lines.slice(-numLines).join('\n')
                        } else {
                            content = lines.slice(0, numLines).join('\n')
                        }
                    }

                    console.log(
                        `\n${chalk.blue('Log file:')} ${options.component}/${
                            options.filename
                        }`
                    )
                    console.log(`${chalk.blue('Provider:')} ${userAddress}`)
                    console.log('─'.repeat(80))
                    console.log(content)
                    if (content && !content.endsWith('\n')) {
                        console.log() // Add newline if content doesn't end with one
                    }
                    process.exit(0)
                } catch (error: unknown) {
                    if (
                        error &&
                        typeof error === 'object' &&
                        'response' in error
                    ) {
                        const axiosError = error as {
                            response: {
                                data?: { error?: string }
                                statusText: string
                            }
                        }
                        console.error(
                            'Error:',
                            axiosError.response.data?.error ||
                                axiosError.response.statusText
                        )
                    } else if (error instanceof Error) {
                        console.error('Error:', error.message)
                    } else {
                        console.error('Error:', String(error))
                    }
                    process.exit(1)
                }
            } catch (error: unknown) {
                if (error instanceof Error) {
                    console.error('Error:', error.message)
                } else {
                    console.error('Error:', String(error))
                }
                process.exit(1)
            }
        })

    program
        .command('ack-provider', { hidden: true })
        .description('verify TEE remote attestation of service')
        .requiredOption('--provider <address>', 'Provider address')
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
        .command('revoke', { hidden: true })
        .description('Revoke TEE signer acknowledgement for a provider')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.revokeProviderTEESignerAcknowledgement(
                    options.provider,
                    options.gasPrice
                )
                console.log(
                    'Provider TEE signer acknowledgement revoked successfully!'
                )
            })
        })
}

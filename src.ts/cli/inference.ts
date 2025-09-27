#!/usr/bin/env ts-node

import type { Command } from 'commander'
import { withBroker } from './util'

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
                await broker.inference.acknowledgeProviderSigner(
                    options.provider,
                    options.gasPrice
                )
                console.log('Provider acknowledged successfully!')
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
            '30'
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
}

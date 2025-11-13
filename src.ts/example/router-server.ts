import express from 'express'
import { ethers } from 'ethers'
import { createServer } from 'http'
import { createZGComputeNetworkBroker } from '../sdk'
import { ZG_RPC_ENDPOINT_TESTNET } from '../cli/const'
import { Cache, CacheValueTypeEnum } from '../sdk/common/storage/cache'
import { CacheKeyHelpers } from '../sdk/common/storage/cache-keys'

// Configuration for direct endpoint providers (not on-chain)
export interface DirectEndpointConfig {
    endpoint: string
    apiKey?: string
    model?: string
    priority?: number // Lower number = higher priority (default: 50)
}

// Priority configuration for providers
export interface PriorityConfig {
    // Map of provider address to priority (lower number = higher priority)
    providers?: Record<string, number>
    // Default priority for providers not specified (default: 100)
    defaultProviderPriority?: number
    // Default priority for direct endpoints not specified (default: 50)
    defaultEndpointPriority?: number
}

export interface RouterServerOptions {
    providers: string[]
    directEndpoints?: Record<string, DirectEndpointConfig> // Key is endpoint ID
    priorityConfig?: PriorityConfig
    key?: string
    rpc?: string
    ledgerCa?: string
    inferenceCa?: string
    gasPrice?: string | number
    port?: string | number
    host?: string
    cacheDuration?: string | number
    requestTimeout?: string | number // Timeout in seconds for each request (default: 30)
}

interface ProviderInfo {
    id: string // Provider address or endpoint ID
    type: 'onchain' | 'direct' // Type of provider
    address?: string // Only for onchain providers
    endpoint: string
    model: string
    apiKey?: string // Only for direct endpoints
    priority: number // Lower number = higher priority
    available: boolean
    lastError?: string
    lastErrorTime?: number
}

export async function runRouterServer(options: RouterServerOptions) {
    const app = express()
    app.use(express.json())
    const cache = new Cache()

    // Parse cache duration from options, default to 60 seconds (1 minute)
    const cacheDurationMs = (Number(options.cacheDuration) || 60) * 1000

    // Parse request timeout from options, default to 30 seconds
    const requestTimeoutMs = (Number(options.requestTimeout) || 60) * 1000

    let broker: any
    const providers: Map<string, ProviderInfo> = new Map()
    const ERROR_RECOVERY_TIME = 60000 // 1 minute

    async function initBroker() {
        // Check if we have any on-chain providers that require broker initialization
        const hasOnChainProviders =
            options.providers && options.providers.length > 0

        if (hasOnChainProviders) {
            const provider = new ethers.JsonRpcProvider(
                options.rpc ||
                    process.env.ZG_RPC_ENDPOINT ||
                    ZG_RPC_ENDPOINT_TESTNET
            )
            const privateKey = options.key || process.env.ZG_PRIVATE_KEY
            if (!privateKey) {
                throw new Error(
                    'Missing wallet private key, please provide --key or set ZG_PRIVATE_KEY in environment variables'
                )
            }
            console.log('Initializing broker for on-chain providers...')
            broker = await createZGComputeNetworkBroker(
                new ethers.Wallet(privateKey, provider),
                options.ledgerCa,
                options.inferenceCa,
                undefined,
                options.gasPrice ? Number(options.gasPrice) : undefined
            )
        } else {
            console.log(
                'No on-chain providers configured, skipping broker initialization'
            )
        }

        // Get default priorities
        const defaultProviderPriority =
            options.priorityConfig?.defaultProviderPriority ?? 100
        const defaultEndpointPriority =
            options.priorityConfig?.defaultEndpointPriority ?? 50

        // Initialize on-chain providers
        if (hasOnChainProviders && broker) {
            console.log(
                `Initializing ${options.providers.length} on-chain providers...`
            )
            for (const providerAddress of options.providers) {
                try {
                    console.log(`Acknowledging provider: ${providerAddress}`)
                    await broker.inference.acknowledgeProviderSigner(
                        providerAddress
                    )
                    const meta = await broker.inference.getServiceMetadata(
                        providerAddress
                    )
                    const priority =
                        options.priorityConfig?.providers?.[providerAddress] ??
                        defaultProviderPriority
                    providers.set(providerAddress, {
                        id: providerAddress,
                        type: 'onchain',
                        address: providerAddress,
                        endpoint: meta.endpoint,
                        model: meta.model,
                        priority,
                        available: true,
                    })
                    console.log(
                        `✓ Provider ${providerAddress} initialized successfully (priority: ${priority})`
                    )
                } catch (error: any) {
                    console.error(
                        `✗ Failed to initialize provider ${providerAddress}: ${error.message}`
                    )
                    const priority =
                        options.priorityConfig?.providers?.[providerAddress] ??
                        defaultProviderPriority
                    providers.set(providerAddress, {
                        id: providerAddress,
                        type: 'onchain',
                        address: providerAddress,
                        endpoint: '',
                        model: '',
                        priority,
                        available: false,
                        lastError: error.message,
                        lastErrorTime: Date.now(),
                    })
                }
            }
        }

        // Initialize direct endpoints
        if (options.directEndpoints) {
            const endpointCount = Object.keys(options.directEndpoints).length
            console.log(`Initializing ${endpointCount} direct endpoints...`)

            for (const [endpointId, config] of Object.entries(
                options.directEndpoints
            )) {
                try {
                    // Validate endpoint URL
                    const endpoint = config.endpoint
                    if (
                        !endpoint.startsWith('http://') &&
                        !endpoint.startsWith('https://')
                    ) {
                        throw new Error(
                            `Invalid endpoint URL: ${endpoint}. Must start with http:// or https://`
                        )
                    }

                    const priority = config.priority ?? defaultEndpointPriority
                    providers.set(endpointId, {
                        id: endpointId,
                        type: 'direct',
                        endpoint: endpoint,
                        model: config.model || 'gpt-3.5-turbo',
                        apiKey: config.apiKey,
                        priority,
                        available: true,
                    })
                    console.log(
                        `✓ Direct endpoint ${endpointId} initialized successfully (priority: ${priority}) - ${endpoint}`
                    )
                } catch (error: any) {
                    console.error(
                        `✗ Failed to initialize direct endpoint ${endpointId}: ${error.message}`
                    )
                    const priority = config.priority ?? defaultEndpointPriority
                    providers.set(endpointId, {
                        id: endpointId,
                        type: 'direct',
                        endpoint: config.endpoint,
                        model: config.model || 'gpt-3.5-turbo',
                        apiKey: config.apiKey,
                        priority,
                        available: false,
                        lastError: error.message,
                        lastErrorTime: Date.now(),
                    })
                }
            }
        }

        const availableProviders = Array.from(providers.values()).filter(
            (p) => p.available
        )
        const totalProviders =
            options.providers.length +
            (options.directEndpoints
                ? Object.keys(options.directEndpoints).length
                : 0)

        if (availableProviders.length === 0) {
            throw new Error('No available providers after initialization')
        }
        console.log(
            `Successfully initialized ${availableProviders.length}/${totalProviders} providers`
        )
    }

    function getAvailableProvider(): ProviderInfo | null {
        const now = Date.now()

        // First, try to recover any providers that have been down for a while
        for (const provider of providers.values()) {
            if (!provider.available && provider.lastErrorTime) {
                if (now - provider.lastErrorTime > ERROR_RECOVERY_TIME) {
                    provider.available = true
                    console.log(
                        `Provider ${provider.id} marked as available for retry`
                    )
                }
            }
        }

        // Get all available providers sorted by priority (lower number = higher priority)
        const availableProviders = Array.from(providers.values())
            .filter((p) => p.available)
            .sort((a, b) => a.priority - b.priority)

        if (availableProviders.length === 0) {
            // If no providers are available, reset all and try again
            console.log(
                'No available providers, resetting all providers for retry'
            )
            for (const provider of providers.values()) {
                provider.available = true
            }
            // Return the highest priority provider after reset
            const resetProviders = Array.from(providers.values()).sort(
                (a, b) => a.priority - b.priority
            )
            return resetProviders[0] || null
        }

        // Return the highest priority available provider
        return availableProviders[0]
    }

    function markProviderUnavailable(providerId: string, error: string) {
        const provider = providers.get(providerId)
        if (provider) {
            provider.available = false
            provider.lastError = error
            provider.lastErrorTime = Date.now()
            console.error(
                `Provider ${providerId} marked as unavailable: ${error}`
            )
        }
    }

    // Helper function to create a timeout promise
    function createTimeoutPromise(
        ms: number,
        message?: string
    ): Promise<never> {
        return new Promise((_, reject) => {
            setTimeout(() => {
                reject(new Error(message || `Operation timeout after ${ms}ms`))
            }, ms)
        })
    }

    // Helper function to run any async operation with timeout
    async function withTimeout<T>(
        operation: Promise<T>,
        timeoutMs: number,
        operationName: string = 'Operation'
    ): Promise<T> {
        return Promise.race([
            operation,
            createTimeoutPromise(
                timeoutMs,
                `${operationName} timeout after ${timeoutMs}ms`
            ),
        ])
    }

    async function chatProxyWithFallback(
        body: any,
        stream: boolean = false,
        attemptedProviders: Set<string> = new Set()
    ): Promise<any> {
        const provider = getAvailableProvider()

        if (!provider) {
            throw new Error('No available providers')
        }

        if (attemptedProviders.has(provider.id)) {
            // Avoid infinite loop by not retrying the same provider
            const remainingProviders = Array.from(providers.values()).filter(
                (p) => !attemptedProviders.has(p.id) && p.available
            )
            if (remainingProviders.length === 0) {
                throw new Error('All providers have been attempted and failed')
            }
            return chatProxyWithFallback(body, stream, attemptedProviders)
        }

        attemptedProviders.add(provider.id)

        try {
            console.log(`Using ${provider.type} provider: ${provider.id}`)

            const requestHeaders: Record<string, string> = {
                'Content-Type': 'application/json',
            }

            // Handle authentication based on provider type
            if (provider.type === 'onchain') {
                // For on-chain providers, get headers from broker
                if (!broker) {
                    throw new Error(
                        'Broker not initialized for on-chain provider'
                    )
                }
                // Wrap getRequestHeaders in timeout protection
                const brokerHeaders = await withTimeout(
                    broker.inference.getRequestHeaders(
                        provider.address!,
                        Array.isArray(body.messages) && body.messages.length > 0
                            ? body.messages
                                  .map((m: any) => m.content)
                                  .join('\n')
                            : ''
                    ),
                    requestTimeoutMs,
                    'Getting request headers'
                )
                Object.assign(requestHeaders, brokerHeaders)
            } else if (provider.type === 'direct' && provider.apiKey) {
                // For direct endpoints, use API key if provided
                requestHeaders['Authorization'] = `Bearer ${provider.apiKey}`
            }

            body.model = provider.model
            if (stream) {
                body.stream = true
            }

            // Ensure proper URL construction
            const baseUrl = provider.endpoint.endsWith('/')
                ? provider.endpoint.slice(0, -1)
                : provider.endpoint
            const fullUrl = `${baseUrl}/chat/completions`

            console.log(
                `Making request to: ${fullUrl} (timeout: ${requestTimeoutMs}ms)`
            )

            const response = await withTimeout(
                fetch(fullUrl, {
                    method: 'POST',
                    headers: requestHeaders,
                    body: JSON.stringify(body),
                }),
                requestTimeoutMs,
                'HTTP request'
            )

            if (!response.ok) {
                throw new Error(`Provider returned status ${response.status}`)
            }

            return { response, provider: provider.id }
        } catch (error: any) {
            console.error(`Provider ${provider.id} failed: ${error.message}`)
            markProviderUnavailable(provider.id, error.message)

            // Try with another provider
            const remainingAvailableProviders = Array.from(
                providers.values()
            ).filter((p) => p.available && !attemptedProviders.has(p.id))

            if (remainingAvailableProviders.length > 0) {
                console.log(
                    `Retrying with another provider (${remainingAvailableProviders.length} remaining)`
                )
                return chatProxyWithFallback(body, stream, attemptedProviders)
            }

            throw new Error(
                `All providers failed. Last error: ${error.message}`
            )
        }
    }

    app.post(
        '/v1/chat/completions',
        async (req: any, res: any): Promise<void> => {
            const body = req.body
            const stream = body.stream === true
            if (!Array.isArray(body.messages) || body.messages.length === 0) {
                res.status(400).json({
                    error: 'Missing or invalid messages in request body',
                })
                return
            }

            try {
                const { response: result, provider: usedProvider } =
                    await chatProxyWithFallback(body, stream)

                if (stream) {
                    res.setHeader('Content-Type', 'text/event-stream')
                    res.setHeader('Cache-Control', 'no-cache')
                    res.setHeader('Connection', 'keep-alive')
                    res.setHeader('X-Provider-Address', usedProvider)

                    if (result.body) {
                        let rawBody = ''
                        const decoder = new TextDecoder()
                        const reader = result.body.getReader()
                        while (true) {
                            const { done, value } = await reader.read()
                            if (done) break
                            res.write(value)
                            rawBody += decoder.decode(value, {
                                stream: true,
                            })
                        }
                        res.end()

                        // Parse rawBody and cache it after the stream ends
                        let completeContent = ''
                        let id: string | undefined
                        for (const line of rawBody.split('\n')) {
                            const trimmed = line.trim()
                            if (!trimmed) continue
                            const jsonStr = trimmed.startsWith('data:')
                                ? trimmed.slice(5).trim()
                                : trimmed
                            if (jsonStr === '[DONE]') continue
                            try {
                                const message = JSON.parse(jsonStr)
                                if (!id && message.id) id = message.id
                                const receivedContent =
                                    message.choices?.[0]?.delta?.content
                                if (receivedContent) {
                                    completeContent += receivedContent
                                }
                            } catch (e) {}
                        }

                        // Cache the complete content with provider info
                        if (id) {
                            cache.setItem(
                                CacheKeyHelpers.getContentKey(id),
                                {
                                    content: completeContent,
                                    provider: usedProvider,
                                },
                                cacheDurationMs,
                                CacheValueTypeEnum.Other
                            )
                        }
                    } else {
                        res.status(500).json({
                            error: 'No stream body from remote server',
                        })
                    }
                } else {
                    const data = await result.json()
                    data['x-provider-address'] = usedProvider
                    const key = data.id
                    const value = data.choices?.[0]?.message?.content
                    cache.setItem(
                        CacheKeyHelpers.getContentKey(key),
                        { content: value, provider: usedProvider },
                        cacheDurationMs,
                        CacheValueTypeEnum.Other
                    )
                    res.json(data)
                }
            } catch (err: any) {
                res.status(500).json({ error: err.message })
            }
        }
    )

    app.get(
        '/v1/providers/status',
        async (req: any, res: any): Promise<void> => {
            const status = Array.from(providers.values()).map((p) => ({
                id: p.id,
                type: p.type,
                address: p.address,
                endpoint: p.endpoint,
                model: p.model,
                priority: p.priority,
                available: p.available,
                lastError: p.lastError,
                lastErrorTime: p.lastErrorTime,
            }))
            // Sort by priority for better readability
            status.sort((a, b) => a.priority - b.priority)
            res.json({ providers: status })
        }
    )
    app.post('/v1/verify', async (req: any, res: any): Promise<void> => {
        const { id } = req.body
        if (!id) {
            res.status(400).json({ error: 'Missing id in request body' })
            return
        }

        const cachedData = cache.getItem(CacheKeyHelpers.getContentKey(id))
        if (!cachedData) {
            res.status(404).json({ error: 'No cached content for this id' })
            return
        }

        // Extract content and provider from cached data
        const { content: completeContent, provider: usedProvider } = cachedData
        if (!completeContent || !usedProvider) {
            res.status(404).json({ error: 'Invalid cached data for this id' })
            return
        }

        // Verify that the provider is still available
        const providerInfo = providers.get(usedProvider)
        if (!providerInfo) {
            res.status(500).json({ error: 'Provider no longer available' })
            return
        }

        try {
            console.log(`Verifying response with provider: ${usedProvider}`)

            // Only verify responses from on-chain providers
            if (
                providerInfo.type === 'onchain' &&
                providerInfo.address &&
                broker
            ) {
                const isValid = await broker.inference.processResponse(
                    providerInfo.address,
                    id,
                    completeContent,
                )
                res.json({
                    isValid,
                    provider: usedProvider,
                    type: providerInfo.type,
                })
            } else {
                // For direct endpoints, we cannot verify through the broker
                res.json({
                    isValid: true, // Assume valid since we can't verify
                    provider: usedProvider,
                    type: providerInfo.type,
                    note: 'Direct endpoint responses cannot be verified through the broker',
                })
            }
        } catch (err: any) {
            res.status(500).json({ error: err.message })
        }
    })

    const port = options.port ? Number(options.port) : 3000
    const host = options.host || '0.0.0.0'

    // Check if port is already in use BEFORE initializing broker to save time
    const checkPort = async (port: number, host: string): Promise<boolean> => {
        return new Promise((resolve) => {
            const testServer = createServer()
            testServer.listen(port, host, () => {
                testServer.close(() => resolve(true)) // Port is available
            })
            testServer.on('error', (err: any) => {
                if (err.code === 'EADDRINUSE') {
                    resolve(false) // Port is in use
                } else {
                    resolve(false) // Other error, treat as unavailable
                }
            })
        })
    }

    const isPortAvailable = await checkPort(port, host)
    if (!isPortAvailable) {
        console.error(`\nError: Port ${port} is already in use.`)
        console.error(`Please try one of the following:`)
        console.error(`  1. Use a different port: --port <PORT>`)
        console.error(`  2. Stop the process using port ${port}`)
        console.error(
            `  3. Find the process: lsof -i :${port} or ss -tlnp | grep :${port}\n`
        )
        process.exit(1)
    }

    await initBroker()

    const server = app.listen(port, host, async () => {
        console.log(`\nRouter service is running on ${host}:${port}`)
        console.log(`Available endpoints:`)
        console.log(
            `  - POST /v1/chat/completions - Chat completions with automatic failover`
        )
        console.log(
            `  - POST /v1/verify          - Verify response with the same provider`
        )
        console.log(
            `  - GET  /v1/providers/status - Check status of all providers`
        )
        const directEndpointCount = options.directEndpoints
            ? Object.keys(options.directEndpoints).length
            : 0
        console.log(`\nConfigured providers:`)
        console.log(`  - On-chain providers: ${options.providers.length}`)
        console.log(`  - Direct endpoints: ${directEndpointCount}`)
        console.log(
            `  - Total: ${options.providers.length + directEndpointCount}`
        )

        // Perform health check
        try {
            const fetch = (await import('node-fetch')).default
            const healthCheckHost = host === '0.0.0.0' ? 'localhost' : host
            const res = await fetch(
                `http://${healthCheckHost}:${port}/v1/chat/completions`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        messages: [{ role: 'system', content: 'health check' }],
                    }),
                }
            )
            if (res.ok) {
                console.log(`\n✓ Health check passed`)
            } else {
                const errText = await res.text()
                console.error('\n✗ Health check failed:', res.status, errText)
            }
        } catch (e) {
            console.error('\n✗ Health check error:', e)
        }
    })

    server.on('error', (err: any) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`\nError: Port ${port} is already in use.`)
            console.error(`Please try one of the following:`)
            console.error(`  1. Use a different port: --port <PORT>`)
            console.error(`  2. Stop the process using port ${port}`)
            console.error(
                `  3. Find the process: lsof -i :${port} or netstat -tulpn | grep :${port}\n`
            )
            process.exit(1)
        } else {
            console.error('Server error:', err)
            process.exit(1)
        }
    })
}

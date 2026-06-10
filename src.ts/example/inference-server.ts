import express from 'express'
import { ethers } from 'ethers'
import { createServer } from 'http'
import { createZGComputeNetworkBroker } from '../sdk'
import { ZG_RPC_ENDPOINT_TESTNET } from '../cli/const'
import { logger } from '../sdk/common/logger'

export interface InferenceServerOptions {
    provider: string
    key?: string
    rpc?: string
    ledgerCa?: string
    inferenceCa?: string
    gasPrice?: string | number
    port?: string | number
    host?: string
}

export async function runInferenceServer(options: InferenceServerOptions) {
    const app = express()
    app.use(express.json())

    let broker: any
    let providerAddress: string
    let endpoint: string
    let model: string

    async function initBroker() {
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
        console.log('Initializing broker...')
        broker = await createZGComputeNetworkBroker(
            new ethers.Wallet(privateKey, provider),
            options.ledgerCa,
            options.inferenceCa,
            undefined,
            options.gasPrice ? Number(options.gasPrice) : undefined
        )
        providerAddress = options.provider
        await broker.inference.acknowledgeProviderSigner(providerAddress)
        const meta = await broker.inference.getServiceMetadata(providerAddress)
        endpoint = meta.endpoint
        model = meta.model
    }

    async function chatProxy(body: any, stream: boolean = false) {
        logger.debug(`Chat proxy request: ${JSON.stringify(body)}`)
        const headers = await broker.inference.getRequestHeaders(
            providerAddress,
            Array.isArray(body.messages) && body.messages.length > 0
                ? body.messages.map((m: any) => m.content).join('\n')
                : ''
        )

        // Respect a caller-specified model (multi-model providers serve many);
        // only fall back to the provider's default when the request omits one.
        // The model is forwarded as-is; the provider validates it against the
        // models it serves and bills it, rejecting an unknown id server-side.
        if (!body.model) {
            body.model = model
        }
        if (stream) {
            body.stream = true
        }
        logger.debug(
            `Proxying to ${endpoint}/chat/completions with body: ${JSON.stringify(
                body
            )} and headers: ${JSON.stringify(headers)}`
        )

        // Use fetch to get raw response for transparent proxying
        const response = await fetch(`${endpoint}/chat/completions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...headers,
            },
            body: JSON.stringify(body),
        })
        return response
    }

    app.post(
        '/v1/chat/completions',
        async (req: any, res: any): Promise<void> => {
            const body = req.body
            const stream = body.stream === true || body.stream === 'true'
            logger.debug(
                `Received chat/completions request: ${JSON.stringify(
                    body
                )}, stream: ${stream}`
            )
            if (!Array.isArray(body.messages) || body.messages.length === 0) {
                res.status(400).json({
                    error: 'Missing or invalid messages in request body',
                })
                return
            }
            try {
                const result = await chatProxy(body, stream)
                if (stream) {
                    res.setHeader('Content-Type', 'text/event-stream')
                    res.setHeader('Cache-Control', 'no-cache')
                    res.setHeader('Connection', 'keep-alive')

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

                        // Parse rawBody to extract usage information for fee calculation
                        let usage: any = null
                        for (const line of rawBody.split('\n')) {
                            const trimmed = line.trim()
                            if (!trimmed) continue
                            const jsonStr = trimmed.startsWith('data:')
                                ? trimmed.slice(5).trim()
                                : trimmed
                            if (jsonStr === '[DONE]') continue
                            try {
                                const message = JSON.parse(jsonStr)
                                if (message.usage) {
                                    usage = message.usage
                                }
                            } catch {}
                        }

                        // Process the usage information for fee calculation
                        if (usage) {
                            try {
                                logger.debug(
                                    'Processing streaming response usage for fee calculation:',
                                    usage
                                )
                                await broker.inference.processResponse(
                                    providerAddress,
                                    undefined, // chatID is undefined for non-verifiable responses
                                    JSON.stringify(usage) // Pass usage as JSON string
                                )
                            } catch (processErr: any) {
                                logger.warn(
                                    'Failed to process streaming response for fee calculation:',
                                    processErr.message
                                )
                            }
                        }
                    } else {
                        res.status(500).json({
                            error: 'No stream body from remote server',
                        })
                    }
                } else {
                    const data = await result.json()

                    // Process the response for fee calculation
                    try {
                        if (data.usage) {
                            logger.debug(
                                'Processing response usage for fee calculation:',
                                data.usage
                            )
                            await broker.inference.processResponse(
                                providerAddress,
                                undefined, // chatID is undefined for non-verifiable responses
                                JSON.stringify(data.usage) // Pass usage as JSON string
                            )
                        }
                    } catch (processErr: any) {
                        logger.warn(
                            'Failed to process response for fee calculation:',
                            processErr.message
                        )
                    }

                    res.json(data)
                }
            } catch (err: any) {
                res.status(500).json({ error: err.message })
            }
        }
    )

    app.post(
        '/v1/audio/transcriptions',
        async (req: any, res: any): Promise<void> => {
            logger.debug(`Received audio/transcriptions request`)

            try {
                // Get headers for authentication
                const headers = await broker.inference.getRequestHeaders(
                    providerAddress,
                    'audio transcription request'
                )

                // Parse the multipart boundary from content-type
                const contentType = req.headers['content-type']
                const boundary = contentType?.split('boundary=')[1]

                // Collect the raw body from the request
                const chunks: any[] = []
                for await (const chunk of req) {
                    chunks.push(chunk)
                }
                let rawBody = Buffer.concat(chunks)

                // Check if model is in the request body (handle both binary and text parts)
                const bodyStr = rawBody.toString('latin1') // Use latin1 to preserve binary data
                if (!bodyStr.includes('name="model"')) {
                    // Add model field before the final boundary
                    const modelField = Buffer.from(
                        `\r\n--${boundary}\r\nContent-Disposition: form-data; name="model"\r\n\r\n${model}`,
                        'utf-8'
                    )
                    const finalBoundary = Buffer.from(
                        `\r\n--${boundary}--`,
                        'utf-8'
                    )

                    // Find the position of final boundary
                    const finalBoundaryIndex = rawBody.indexOf(finalBoundary)
                    if (finalBoundaryIndex !== -1) {
                        // Insert model field before final boundary
                        const beforeFinal = rawBody.slice(0, finalBoundaryIndex)
                        const newBody = Buffer.concat([
                            beforeFinal,
                            modelField,
                            finalBoundary,
                        ])
                        rawBody = newBody
                    }
                }

                // Forward the entire request to the provider
                const response = await fetch(
                    `${endpoint}/audio/transcriptions`,
                    {
                        method: 'POST',
                        headers: {
                            ...headers,
                            // Forward content-type from original request
                            'content-type': contentType,
                            'content-length': String(rawBody.length),
                        },
                        body: rawBody,
                    }
                )

                // Check if it's a streaming response
                const isStreaming = response.headers
                    .get('content-type')
                    ?.includes('text/event-stream')

                if (isStreaming) {
                    res.setHeader('Content-Type', 'text/event-stream')
                    res.setHeader('Cache-Control', 'no-cache')
                    res.setHeader('Connection', 'keep-alive')

                    if (response.body) {
                        let rawBody = ''
                        const decoder = new TextDecoder()
                        const reader = response.body.getReader()
                        while (true) {
                            const { done, value } = await reader.read()
                            if (done) break
                            res.write(value)
                            rawBody += decoder.decode(value, {
                                stream: true,
                            })
                        }
                        res.end()

                        // Parse rawBody to extract usage information for fee calculation
                        let usage: any = null
                        for (const line of rawBody.split('\n')) {
                            const trimmed = line.trim()
                            if (!trimmed) continue
                            const jsonStr = trimmed.startsWith('data:')
                                ? trimmed.slice(5).trim()
                                : trimmed
                            if (jsonStr === '[DONE]') continue
                            try {
                                const message = JSON.parse(jsonStr)
                                if (message.usage) {
                                    usage = message.usage
                                }
                            } catch {}
                        }

                        // Process the usage information for fee calculation
                        if (usage) {
                            try {
                                logger.debug(
                                    'Processing audio streaming response usage for fee calculation:',
                                    usage
                                )
                                await broker.inference.processResponse(
                                    providerAddress,
                                    undefined, // chatID is undefined for non-verifiable responses
                                    JSON.stringify(usage) // Pass usage as JSON string
                                )
                            } catch (processErr: any) {
                                logger.warn(
                                    'Failed to process audio streaming response for fee calculation:',
                                    processErr.message
                                )
                            }
                        }
                    } else {
                        res.status(500).json({
                            error: 'No stream body from remote server',
                        })
                    }
                } else {
                    const data = await response.json()

                    // Process the response for fee calculation
                    try {
                        if (data.usage) {
                            logger.debug(
                                'Processing audio response usage for fee calculation:',
                                data.usage
                            )
                            await broker.inference.processResponse(
                                providerAddress,
                                undefined, // chatID is undefined for non-verifiable responses
                                JSON.stringify(data.usage) // Pass usage as JSON string
                            )
                        }
                    } catch (processErr: any) {
                        logger.warn(
                            'Failed to process audio response for fee calculation:',
                            processErr.message
                        )
                    }

                    res.json(data)
                }
            } catch (err: any) {
                res.status(500).json({ error: err.message })
            }
        }
    )

    app.post(
        '/v1/images/generations',
        async (req: any, res: any): Promise<void> => {
            const body = req.body
            logger.debug(
                `Received images/generations request: ${JSON.stringify(body)}`
            )

            if (!body.prompt) {
                res.status(400).json({
                    error: 'Missing prompt in request body',
                })
                return
            }

            try {
                const headers = await broker.inference.getRequestHeaders(
                    providerAddress,
                    JSON.stringify(body)
                )

                // Add model to the request body if not present
                const requestBody = {
                    model: model,
                    prompt: body.prompt,
                    size: body.size || '512x512',
                    n: body.n || 1,
                    ...body,
                }

                logger.debug(
                    `Proxying to ${endpoint}/images/generations with body: ${JSON.stringify(
                        requestBody
                    )} and headers: ${JSON.stringify(headers)}`
                )

                const result = await fetch(`${endpoint}/images/generations`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...headers,
                    },
                    body: JSON.stringify(requestBody),
                })

                const data = await result.json()

                // Process the response for fee calculation
                // For text-to-image, we need to pass the original request as content for input fee calculation
                try {
                    // Calculate fees using the original request body for input calculation
                    await broker.inference.processResponse(
                        providerAddress,
                        undefined, // chatID is undefined for non-verifiable responses
                        JSON.stringify(requestBody) // Pass request body for input fee calculation
                    )
                } catch (processErr: any) {
                    logger.warn(
                        'Failed to process image generation response for fee calculation:',
                        processErr.message
                    )
                }

                res.json(data)
            } catch (err: any) {
                res.status(500).json({ error: err.message })
            }
        }
    )

    // ---------------------------------------------------------------------------
    // Async image endpoints
    //
    // Instead of blocking until the provider responds, these endpoints submit a
    // job to the provider's async queue and immediately return the jobId.
    // The client is responsible for polling GET /v1/async/jobs/:jobId until the
    // job reaches "completed" or "failed" status.
    //
    // Submit async image generation job
    // POST /v1/async/images/generations
    // Body: { prompt, n?, size?, response_format?, ... }  (same as sync endpoint)
    // Response 202: { jobId, status: "pending" }
    app.post(
        '/v1/async/images/generations',
        async (req: any, res: any): Promise<void> => {
            const body = req.body
            logger.debug(
                `Received async images/generations request: ${JSON.stringify(body)}`
            )

            if (!body.prompt) {
                res.status(400).json({
                    error: 'Missing prompt in request body',
                })
                return
            }

            try {
                const headers = await broker.inference.getRequestHeaders(
                    providerAddress,
                    JSON.stringify(body)
                )

                const requestBody = {
                    model,
                    prompt: body.prompt,
                    size: body.size || '512x512',
                    n: body.n || 1,
                    ...body,
                }

                const result = await fetch(
                    `${endpoint.replace('/v1/proxy', '')}/v1/async/images/generations`,
                    {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...headers,
                        },
                        body: JSON.stringify(requestBody),
                    }
                )

                const data = await result.json()
                res.status(result.status).json(data)
            } catch (err: any) {
                res.status(500).json({ error: err.message })
            }
        }
    )

    // Submit async image editing job
    // POST /v1/async/images/edits
    // Body: multipart/form-data with image file + prompt (same fields as sync endpoint)
    // Response 202: { jobId, status: "pending" }
    app.post(
        '/v1/async/images/edits',
        async (req: any, res: any): Promise<void> => {
            logger.debug(`Received async images/edits request`)

            try {
                const headers = await broker.inference.getRequestHeaders(
                    providerAddress,
                    'image editing request'
                )

                const contentType = req.headers['content-type']
                const chunks: any[] = []
                for await (const chunk of req) {
                    chunks.push(chunk)
                }
                const rawBody = Buffer.concat(chunks)

                const result = await fetch(
                    `${endpoint.replace('/v1/proxy', '')}/v1/async/images/edits`,
                    {
                        method: 'POST',
                        headers: {
                            ...headers,
                            'content-type': contentType,
                            'content-length': String(rawBody.length),
                        },
                        body: rawBody,
                    }
                )

                const data = await result.json()
                res.status(result.status).json(data)
            } catch (err: any) {
                res.status(500).json({ error: err.message })
            }
        }
    )

    // Poll async job status
    // GET /v1/async/jobs/:jobId
    // Response: { jobId, status, createdAt, updatedAt, errorMessage?, data? }
    // Headers: Retry-After is forwarded when status is pending/processing
    app.get(
        '/v1/async/jobs/:jobId',
        async (req: any, res: any): Promise<void> => {
            const { jobId } = req.params
            logger.debug(`Polling async job status: ${jobId}`)

            try {
                const headers = await broker.inference.getRequestHeaders(
                    providerAddress
                )

                const result = await fetch(
                    `${endpoint.replace('/v1/proxy', '')}/v1/async/jobs/${jobId}`,
                    {
                        method: 'GET',
                        headers,
                    }
                )

                // Forward Retry-After hint when job is still running
                const retryAfter = result.headers.get('Retry-After')
                if (retryAfter) {
                    res.setHeader('Retry-After', retryAfter)
                }

                const data = await result.json()

                // Once completed, cache the fee so balance management stays accurate
                if (data.status === 'completed') {
                    try {
                        await broker.inference.processResponse(
                            providerAddress,
                            undefined,
                            JSON.stringify({ n: data.data?.data?.length ?? 1 })
                        )
                    } catch (processErr: any) {
                        logger.warn(
                            'Failed to process async job response for fee calculation:',
                            processErr.message
                        )
                    }
                }

                res.status(result.status).json(data)
            } catch (err: any) {
                res.status(500).json({ error: err.message })
            }
        }
    )
    // ---------------------------------------------------------------------------

    app.post('/v1/verify', async (req: any, res: any): Promise<void> => {
        const { id } = req.body
        if (!id) {
            res.status(400).json({ error: 'Missing id in request body' })
            return
        }
        try {
            const isValid = await broker.inference.processResponse(
                providerAddress,
                id
            )
            res.json({ isValid })
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
        try {
            const healthCheckHost = host === '0.0.0.0' ? 'localhost' : host
            logger.debug(
                `Performing health check on ${healthCheckHost}:${port}...`
            )
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
                console.log(
                    `Health check passed\nInference service is running on ${host}:${port}`
                )
            } else {
                const errText = await res.text()
                console.error('Health check failed:', res.status, errText)
            }
        } catch (e) {
            console.error('Health check error:', e)
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

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runInferenceServer = runInferenceServer;
const tslib_1 = require("tslib");
const express_1 = tslib_1.__importDefault(require("express"));
const ethers_1 = require("ethers");
const http_1 = require("http");
const sdk_1 = require("../sdk");
const const_1 = require("../cli/const");
const logger_1 = require("../sdk/common/logger");
async function runInferenceServer(options) {
    const app = (0, express_1.default)();
    app.use(express_1.default.json());
    let broker;
    let providerAddress;
    let endpoint;
    let model;
    async function initBroker() {
        const provider = new ethers_1.ethers.JsonRpcProvider(options.rpc ||
            process.env.ZG_RPC_ENDPOINT ||
            const_1.ZG_RPC_ENDPOINT_TESTNET);
        const privateKey = options.key || process.env.ZG_PRIVATE_KEY;
        if (!privateKey) {
            throw new Error('Missing wallet private key, please provide --key or set ZG_PRIVATE_KEY in environment variables');
        }
        console.log('Initializing broker...');
        broker = await (0, sdk_1.createZGComputeNetworkBroker)(new ethers_1.ethers.Wallet(privateKey, provider), options.ledgerCa, options.inferenceCa, undefined, options.gasPrice ? Number(options.gasPrice) : undefined);
        providerAddress = options.provider;
        await broker.inference.acknowledgeProviderSigner(providerAddress);
        const meta = await broker.inference.getServiceMetadata(providerAddress);
        endpoint = meta.endpoint;
        model = meta.model;
    }
    async function chatProxy(body, stream = false) {
        logger_1.logger.debug(`Chat proxy request: ${JSON.stringify(body)}`);
        const headers = await broker.inference.getRequestHeaders(providerAddress, Array.isArray(body.messages) && body.messages.length > 0
            ? body.messages.map((m) => m.content).join('\n')
            : '');
        body.model = model;
        if (stream) {
            body.stream = true;
        }
        logger_1.logger.debug(`Proxying to ${endpoint}/chat/completions with body: ${JSON.stringify(body)} and headers: ${JSON.stringify(headers)}`);
        const response = await fetch(`${endpoint}/chat/completions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...headers,
            },
            body: JSON.stringify(body),
        });
        return response;
    }
    app.post('/v1/chat/completions', async (req, res) => {
        const body = req.body;
        const stream = body.stream === true;
        if (!Array.isArray(body.messages) || body.messages.length === 0) {
            res.status(400).json({
                error: 'Missing or invalid messages in request body',
            });
            return;
        }
        try {
            const result = await chatProxy(body, stream);
            if (stream) {
                res.setHeader('Content-Type', 'text/event-stream');
                res.setHeader('Cache-Control', 'no-cache');
                res.setHeader('Connection', 'keep-alive');
                if (result.body) {
                    const reader = result.body.getReader();
                    const decoder = new TextDecoder();
                    let accumulatedUsage = null;
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done)
                            break;
                        // Try to extract usage information from the stream
                        const chunk = decoder.decode(value, { stream: true });
                        try {
                            // Look for usage information in the stream chunks
                            const lines = chunk.split('\n').filter(line => line.trim());
                            for (const line of lines) {
                                if (line.startsWith('data: ') && !line.includes('[DONE]')) {
                                    const jsonStr = line.substring(6).trim();
                                    if (jsonStr) {
                                        const data = JSON.parse(jsonStr);
                                        if (data.usage) {
                                            accumulatedUsage = data.usage;
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            // Ignore parsing errors for stream chunks
                        }
                        res.write(value);
                    }
                    // Process the accumulated usage information
                    if (accumulatedUsage) {
                        try {
                            logger_1.logger.debug('Processing streaming response usage for fee calculation:', accumulatedUsage);
                            await broker.inference.processResponse(providerAddress, undefined, // chatID is undefined for non-verifiable responses
                            JSON.stringify(accumulatedUsage) // Pass usage as JSON string
                            );
                        }
                        catch (processErr) {
                            logger_1.logger.warn('Failed to process streaming response for fee calculation:', processErr.message);
                        }
                    }
                    res.end();
                }
                else {
                    res.status(500).json({
                        error: 'No stream body from remote server',
                    });
                }
            }
            else {
                const data = await result.json();
                // Process the response for fee calculation
                try {
                    if (data.usage) {
                        logger_1.logger.debug('Processing response usage for fee calculation:', data.usage);
                        await broker.inference.processResponse(providerAddress, undefined, // chatID is undefined for non-verifiable responses
                        JSON.stringify(data.usage) // Pass usage as JSON string
                        );
                    }
                }
                catch (processErr) {
                    logger_1.logger.warn('Failed to process response for fee calculation:', processErr.message);
                }
                res.json(data);
            }
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    app.post('/v1/verify', async (req, res) => {
        const { id } = req.body;
        if (!id) {
            res.status(400).json({ error: 'Missing id in request body' });
            return;
        }
        try {
            const isValid = await broker.inference.processResponse(providerAddress, id);
            res.json({ isValid });
        }
        catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
    const port = options.port ? Number(options.port) : 3000;
    const host = options.host || '0.0.0.0';
    // Check if port is already in use BEFORE initializing broker to save time
    const checkPort = async (port, host) => {
        return new Promise((resolve) => {
            const testServer = (0, http_1.createServer)();
            testServer.listen(port, host, () => {
                testServer.close(() => resolve(true)); // Port is available
            });
            testServer.on('error', (err) => {
                if (err.code === 'EADDRINUSE') {
                    resolve(false); // Port is in use
                }
                else {
                    resolve(false); // Other error, treat as unavailable
                }
            });
        });
    };
    const isPortAvailable = await checkPort(port, host);
    if (!isPortAvailable) {
        console.error(`\nError: Port ${port} is already in use.`);
        console.error(`Please try one of the following:`);
        console.error(`  1. Use a different port: --port <PORT>`);
        console.error(`  2. Stop the process using port ${port}`);
        console.error(`  3. Find the process: lsof -i :${port} or ss -tlnp | grep :${port}\n`);
        process.exit(1);
    }
    await initBroker();
    const server = app.listen(port, host, async () => {
        try {
            const fetch = (await Promise.resolve().then(() => tslib_1.__importStar(require('node-fetch')))).default;
            const healthCheckHost = host === '0.0.0.0' ? 'localhost' : host;
            logger_1.logger.debug(`Performing health check on ${healthCheckHost}:${port}...`);
            const res = await fetch(`http://${healthCheckHost}:${port}/v1/chat/completions`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    messages: [{ role: 'system', content: 'health check' }],
                }),
            });
            if (res.ok) {
                console.log(`Health check passed\nInference service is running on ${host}:${port}`);
            }
            else {
                const errText = await res.text();
                console.error('Health check failed:', res.status, errText);
            }
        }
        catch (e) {
            console.error('Health check error:', e);
        }
    });
    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`\nError: Port ${port} is already in use.`);
            console.error(`Please try one of the following:`);
            console.error(`  1. Use a different port: --port <PORT>`);
            console.error(`  2. Stop the process using port ${port}`);
            console.error(`  3. Find the process: lsof -i :${port} or netstat -tulpn | grep :${port}\n`);
            process.exit(1);
        }
        else {
            console.error('Server error:', err);
            process.exit(1);
        }
    });
}
//# sourceMappingURL=inference-server.js.map
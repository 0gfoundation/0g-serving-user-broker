#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = inference;
const tslib_1 = require("tslib");
const util_1 = require("./util");
const network_setup_1 = require("./network-setup");
const private_key_setup_1 = require("./private-key-setup");
const cli_table3_1 = tslib_1.__importDefault(require("cli-table3"));
const chalk_1 = tslib_1.__importDefault(require("chalk"));
function inference(program) {
    program
        .command('list-providers')
        .description('List inference providers')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action((options) => {
        const table = new cli_table3_1.default({
            colWidths: [50, 50],
        });
        (0, util_1.withBroker)(options, async (broker) => {
            const services = await broker.inference.listService();
            services.forEach((service, index) => {
                table.push([
                    chalk_1.default.blue(`Provider ${index + 1}`),
                    chalk_1.default.blue(service.provider),
                ]);
                table.push(['Model', service.model || 'N/A']);
                table.push([
                    'Input Price Per Byte (0G)',
                    service.inputPrice
                        ? (0, util_1.neuronToA0gi)(BigInt(service.inputPrice)).toFixed(18)
                        : 'N/A',
                ]);
                table.push([
                    'Output Price Per Byte (0G)',
                    service.outputPrice
                        ? (0, util_1.neuronToA0gi)(BigInt(service.outputPrice)).toFixed(18)
                        : 'N/A',
                ]);
                table.push([
                    'Verifiability',
                    service.verifiability || 'N/A',
                ]);
            });
            console.log(table.toString());
        });
    });
    program
        .command('acknowledge-provider')
        .description('Acknowledge the provider signer')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            await broker.inference.acknowledgeProviderSigner(options.provider, options.gasPrice);
            console.log('Provider signer acknowledged successfully!');
        });
    });
    program
        .command('serve')
        .description('Start local inference service')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--port <port>', 'Port to run the local inference service on', '3000')
        .option('--host <host>', 'Host to bind the local inference service', '0.0.0.0')
        .action(async (options) => {
        // Ensure RPC endpoint is configured
        const rpc = await (0, network_setup_1.getRpcEndpoint)(options);
        // Ensure private key is configured
        const key = await (0, private_key_setup_1.ensurePrivateKeyConfiguration)();
        const { runInferenceServer } = await Promise.resolve().then(() => tslib_1.__importStar(require('../example/inference-server')));
        await runInferenceServer({ ...options, rpc, key });
    });
    program
        .command('router-serve')
        .description('Start high-availability router service with multiple providers')
        .option('--add-provider <address,priority>', 'Add on-chain provider with priority (e.g., 0x1234567890abcdef,10). Use comma separator. Can be used multiple times', (value, previous) => {
        const providers = previous || [];
        const [address, priority] = value.split(',');
        if (!address) {
            throw new Error('Invalid provider format. Use: address,priority (comma-separated)');
        }
        providers.push({
            address: address.trim(),
            priority: priority && priority.trim()
                ? parseInt(priority.trim())
                : 100,
        });
        return providers;
    }, [])
        .option('--add-endpoint <id,endpoint,apikey,model,priority>', 'Add direct endpoint (e.g., openai,https://api.openai.com/v1,key,gpt-4o,10). Use commas as separators. Can be used multiple times', (value, previous) => {
        const endpoints = previous || [];
        const [id, endpoint, apiKey, model, priority] = value.split(',');
        if (!id || !endpoint) {
            throw new Error('Invalid endpoint format. Use: id,endpoint,apikey,model,priority (comma-separated)');
        }
        endpoints.push({
            id: id.trim(),
            endpoint: endpoint.trim(),
            apiKey: apiKey && apiKey.trim() ? apiKey.trim() : undefined,
            model: model && model.trim() ? model.trim() : 'gpt-3.5-turbo',
            priority: priority && priority.trim()
                ? parseInt(priority.trim())
                : 50,
        });
        return endpoints;
    }, [])
        .option('--default-provider-priority <number>', 'Default priority for on-chain providers not explicitly set', '100')
        .option('--default-endpoint-priority <number>', 'Default priority for direct endpoints not explicitly set', '50')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--port <port>', 'Port to run the router service on', '3000')
        .option('--host <host>', 'Host to bind the router service', '0.0.0.0')
        .option('--cache-duration <seconds>', 'Cache duration in seconds', '60')
        .option('--request-timeout <seconds>', 'Request timeout in seconds for each provider', '60')
        .action(async (options) => {
        // Build providers list with priorities
        const providers = [];
        const providerPriorities = {};
        if (options.addProvider && options.addProvider.length > 0) {
            for (const prov of options.addProvider) {
                providers.push(prov.address);
                providerPriorities[prov.address] = prov.priority;
            }
        }
        // Build direct endpoints
        const directEndpoints = {};
        if (options.addEndpoint && options.addEndpoint.length > 0) {
            for (const ep of options.addEndpoint) {
                directEndpoints[ep.id] = {
                    endpoint: ep.endpoint,
                    apiKey: ep.apiKey,
                    model: ep.model,
                    priority: ep.priority,
                };
            }
        }
        // Build priority config
        const priorityConfig = {
            providers: providerPriorities,
            defaultProviderPriority: parseInt(options.defaultProviderPriority),
            defaultEndpointPriority: parseInt(options.defaultEndpointPriority),
        };
        // Ensure at least one provider type is specified
        if (providers.length === 0 &&
            Object.keys(directEndpoints).length === 0) {
            console.error('Error: Must specify either --add-provider or --add-endpoint');
            process.exit(1);
        }
        // Ensure RPC endpoint is configured if we have on-chain providers
        let rpc = options.rpc;
        let key = options.key;
        if (providers.length > 0) {
            if (!rpc) {
                rpc = await (0, network_setup_1.getRpcEndpoint)(options);
            }
            if (!key) {
                key = await (0, private_key_setup_1.ensurePrivateKeyConfiguration)();
            }
        }
        const routerOptions = {
            ...options,
            rpc,
            key,
            providers,
            directEndpoints: Object.keys(directEndpoints).length > 0
                ? directEndpoints
                : undefined,
            priorityConfig,
            requestTimeout: options.requestTimeout,
        };
        const { runRouterServer } = await Promise.resolve().then(() => tslib_1.__importStar(require('../example/router-server')));
        await runRouterServer(routerOptions);
    });
    program
        .command('download-report')
        .description('Download quote data to a specified file')
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption('--output <path>', 'Output file path for the quote report')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            await broker.inference.downloadQuoteReport(options.provider, options.output);
            console.log(`Quote report downloaded to: ${options.output}`);
        });
    });
    program
        .command('verify')
        .description('Verify the reliability of a service')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--output-dir <path>', 'Output directory for verification reports', '.')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            const result = await broker.inference.verifyService(options.provider, options.outputDir);
            if (result) {
                if (!result.success) {
                    console.log('❌ Service verification failed');
                }
            }
            else {
                console.log('Verification result is null');
            }
        });
    });
    program
        .command('ack-provider', { hidden: true })
        .description('verify TEE remote attestation of service')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            await broker.inference.acknowledgeProviderTEESigner(options.provider, options.gasPrice);
            console.log('Provider acknowledged successfully!');
        });
    });
}
//# sourceMappingURL=inference.js.map
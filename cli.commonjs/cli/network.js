#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = network;
const tslib_1 = require("tslib");
const network_setup_1 = require("./network-setup");
const config_1 = require("./config");
const chalk_1 = tslib_1.__importDefault(require("chalk"));
function network(program) {
    program
        .command('setup-network')
        .description('Configure network settings (mainnet/testnet)')
        .action(async () => {
        try {
            console.log(chalk_1.default.blue('🔧 Network Configuration Setup'));
            console.log(chalk_1.default.gray('This will configure your default RPC endpoint.\n'));
            // Force reconfiguration by clearing both env var and config
            delete process.env['0G_RPC_ENDPOINT'];
            (0, config_1.clearConfig)();
            const selectedRpc = await (0, network_setup_1.ensureNetworkConfiguration)();
            console.log(chalk_1.default.green('\n✓ Network configuration completed!'));
            console.log(chalk_1.default.gray(`Selected RPC: ${selectedRpc}`));
            console.log(chalk_1.default.yellow('\n💡 Configuration saved and will persist across CLI sessions'));
        }
        catch (error) {
            console.error(chalk_1.default.red('✗ Network setup failed:'), error);
            process.exit(1);
        }
    });
    program
        .command('show-network')
        .description('Show current network configuration')
        .action(() => {
        const envRpc = process.env['0G_RPC_ENDPOINT'] || process.env.RPC_ENDPOINT;
        const config = (0, config_1.loadConfig)();
        console.log(chalk_1.default.blue('🌐 Current Network Configuration'));
        // Show environment variable if set
        if (envRpc) {
            console.log(chalk_1.default.green('✓ RPC Endpoint (Environment):'), chalk_1.default.white(envRpc));
            // Determine network type
            if (envRpc.includes('evmrpc.0g.ai')) {
                console.log(chalk_1.default.green('✓ Network:'), chalk_1.default.white('Mainnet'));
            }
            else if (envRpc.includes('evmrpc-testnet.0g.ai')) {
                console.log(chalk_1.default.green('✓ Network:'), chalk_1.default.white('Testnet'));
            }
            else {
                console.log(chalk_1.default.yellow('⚠ Network:'), chalk_1.default.white('Custom'));
            }
        }
        // Show config file settings
        else if (config.rpcEndpoint) {
            console.log(chalk_1.default.green('✓ RPC Endpoint (Config):'), chalk_1.default.white(config.rpcEndpoint));
            console.log(chalk_1.default.green('✓ Network:'), chalk_1.default.white(config.network || 'Unknown'));
            if (config.lastUpdated) {
                console.log(chalk_1.default.gray('  Last updated:'), chalk_1.default.gray(new Date(config.lastUpdated).toLocaleString()));
            }
        }
        else {
            console.log(chalk_1.default.yellow('⚠ No RPC endpoint configured'));
            console.log(chalk_1.default.gray('Run: 0g-compute-cli setup-network'));
        }
        console.log();
        console.log(chalk_1.default.gray('Available networks:'));
        console.log(chalk_1.default.gray('  • Mainnet: https://evmrpc.0g.ai'));
        console.log(chalk_1.default.gray('  • Testnet: https://evmrpc-testnet.0g.ai'));
        console.log();
        console.log(chalk_1.default.gray('Configuration priority: Environment variables > Config file'));
        console.log(chalk_1.default.gray('Config file location: ~/.0g-compute-cli/config.json'));
    });
}
//# sourceMappingURL=network.js.map
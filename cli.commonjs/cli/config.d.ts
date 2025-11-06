#!/usr/bin/env ts-node
interface CLIConfig {
    rpcEndpoint?: string;
    network?: 'mainnet' | 'testnet' | 'custom';
    lastUpdated?: string;
}
/**
 * Loads the CLI configuration from file
 */
export declare function loadConfig(): CLIConfig;
/**
 * Saves the CLI configuration to file
 */
export declare function saveConfig(config: CLIConfig): void;
/**
 * Gets the RPC endpoint from config file, environment variable, or user input
 */
export declare function getConfiguredRpcEndpoint(): string | undefined;
/**
 * Sets the RPC endpoint in config file
 */
export declare function setConfiguredRpcEndpoint(rpcEndpoint: string, network: 'mainnet' | 'testnet' | 'custom'): void;
/**
 * Clears the configuration
 */
export declare function clearConfig(): void;
export {};
//# sourceMappingURL=config.d.ts.map
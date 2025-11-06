#!/usr/bin/env ts-node
/**
 * Checks if RPC endpoint is configured, if not, prompts user to select and set it
 */
export declare function ensureNetworkConfiguration(): Promise<string>;
/**
 * Gets the RPC endpoint, with interactive setup if needed
 */
export declare function getRpcEndpoint(options: any): Promise<string>;
//# sourceMappingURL=network-setup.d.ts.map
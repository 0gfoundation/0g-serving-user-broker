#!/usr/bin/env ts-node
/**
 * Checks if private key is configured, if not, prompts user to enter it
 */
export declare function ensurePrivateKeyConfiguration(): Promise<string>;
/**
 * Gets the private key, with interactive setup if needed
 */
export declare function getPrivateKey(options: any): Promise<string | undefined>;
//# sourceMappingURL=private-key-setup.d.ts.map
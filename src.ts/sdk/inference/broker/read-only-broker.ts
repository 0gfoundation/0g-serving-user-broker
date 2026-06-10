import type { JsonRpcProvider } from 'ethers'
import type { JsonRpcSigner, Wallet } from 'ethers'
import { JsonRpcProvider as JsonRpcProviderClass } from 'ethers'
import type { ServiceStructOutput } from '../contract'
import { ReadOnlyInferenceServingContract } from '../contract'
import { ReadOnlyModelProcessor } from './read-only-model'
import type { ServiceWithDetail, ProviderModels } from './read-only-model'
import { CONTRACT_ADDRESSES, TESTNET_CHAIN_ID, MAINNET_CHAIN_ID, HARDHAT_CHAIN_ID, isDevMode } from '../../constants'

// Re-export types for convenience
export type { ServiceWithDetail, ProviderModels } from './read-only-model'

/**
 * Read-only inference broker with operations that don't require authentication
 * Can be used with a Provider (read-only) without wallet connection
 *
 * Use this broker to:
 * - List available AI providers before connecting wallet
 * - Get service information and health metrics
 * - Browse services without authentication
 */
export class ReadOnlyInferenceBroker {
    protected modelProcessor: ReadOnlyModelProcessor
    protected contractAddress: string

    constructor(
        provider: JsonRpcProvider | JsonRpcSigner | Wallet,
        contractAddress: string
    ) {
        this.contractAddress = contractAddress
        const contract = new ReadOnlyInferenceServingContract(provider, contractAddress)
        this.modelProcessor = new ReadOnlyModelProcessor(contract)
    }

    /**
     * Retrieves a list of services from the contract.
     * This is a read-only operation that doesn't require authentication.
     *
     * @param {number} offset - The offset for pagination (default: 0).
     * @param {number} limit - The limit for pagination (default: 50).
     * @param {boolean} includeUnacknowledged - Whether to include providers whose TEE signer is not acknowledged (default: false).
     * @returns {Promise<ServiceStructOutput[]>} A promise that resolves to an array of ServiceStructOutput objects.
     * @throws An error if the service list cannot be retrieved.
     */
    public async listService(
        offset: number = 0,
        limit: number = 50,
        includeUnacknowledged: boolean = false
    ): Promise<ServiceStructOutput[]> {
        return this.modelProcessor.listService(offset, limit, includeUnacknowledged)
    }

    /**
     * Retrieves a list of services with detailed health metrics from the monitoring API.
     * This is a read-only operation that doesn't require authentication.
     *
     * This method combines on-chain service data with real-time health metrics including
     * uptime percentage and average response time (latency) for each service provider.
     *
     * @param {number} offset - The offset for pagination (default: 0).
     * @param {number} limit - The limit for pagination (default: 50).
     * @param {boolean} includeUnacknowledged - Whether to include providers whose TEE signer is not acknowledged (default: false).
     * @returns {Promise<ServiceWithDetail[]>} A promise that resolves to an array of ServiceWithDetail objects containing both blockchain and health data.
     * @throws An error if the service list cannot be retrieved.
     *
     * @example
     * ```typescript
     * const servicesWithHealth = await broker.listServiceWithDetail();
     * servicesWithHealth.forEach(service => {
     *   console.log(`Provider: ${service.provider}`);
     *   if (service.healthMetrics) {
     *     console.log(`  Uptime: ${service.healthMetrics.uptime}%`);
     *     console.log(`  Latency: ${service.healthMetrics.avgResponseTime}ms`);
     *   }
     * });
     * ```
     */
    public async listServiceWithDetail(
        offset: number = 0,
        limit: number = 50,
        includeUnacknowledged: boolean = false
    ): Promise<ServiceWithDetail[]> {
        return this.modelProcessor.listServiceWithDetail(offset, limit, includeUnacknowledged)
    }

    /**
     * Fetch the models a specific provider serves, live from its public
     * /v1/models endpoint. Works for both single-model and multi-model
     * providers; no authentication required.
     *
     * @param {string} providerAddress - The provider's on-chain address.
     * @returns {Promise<ProviderModels>} The provider's model catalog plus its
     *   multi-model flag and on-chain default model.
     * @throws An error if the on-chain read or the /v1/models fetch fails.
     *
     * @example
     * ```typescript
     * const { multiModel, models } = await broker.getProviderModels(addr);
     * if (multiModel) {
     *   models.forEach(m => console.log(m.id, m.canonical_id));
     * }
     * ```
     */
    public async getProviderModels(
        providerAddress: string
    ): Promise<ProviderModels> {
        return this.modelProcessor.getProviderModels(providerAddress)
    }
}

/**
 * Factory function to create a read-only inference broker
 * No authentication required - perfect for listing providers without wallet connection
 *
 * @param rpcUrl - JSON-RPC endpoint URL (e.g., https://rpc-testnet.0g.ai)
 * @param chainId - Optional chain ID (auto-detected if not provided)
 * @returns Read-only broker instance
 *
 * @example
 * ```typescript
 * // Create read-only broker (no wallet needed)
 * const broker = await createReadOnlyInferenceBroker('https://rpc-testnet.0g.ai')
 *
 * // List all services
 * const services = await broker.listService()
 *
 * // List services with health details
 * const detailedServices = await broker.listServiceWithDetail()
 * ```
 */
export async function createReadOnlyInferenceBroker(
    rpcUrl: string,
    chainId?: number
): Promise<ReadOnlyInferenceBroker> {
    const provider = new JsonRpcProviderClass(rpcUrl)

    // Auto-detect chain ID if not provided
    const detectedChainId = chainId ?? Number((await provider.getNetwork()).chainId)

    // Get contract address based on chain ID
    let inferenceCA: string

    if (detectedChainId === Number(MAINNET_CHAIN_ID)) {
        inferenceCA = CONTRACT_ADDRESSES.mainnet.inference
        console.log(`Using mainnet inference contract (chain ID: ${detectedChainId})`)
    } else if (detectedChainId === Number(TESTNET_CHAIN_ID)) {
        inferenceCA = isDevMode()
            ? CONTRACT_ADDRESSES.testnetDev.inference
            : CONTRACT_ADDRESSES.testnet.inference
        console.log(`Using testnet inference contract${isDevMode() ? ' [DEV MODE]' : ''} (chain ID: ${detectedChainId})`)
    } else if (detectedChainId === Number(HARDHAT_CHAIN_ID)) {
        inferenceCA = CONTRACT_ADDRESSES.hardhat.inference
        console.log(`Using hardhat inference contract (chain ID: ${detectedChainId})`)
    } else {
        // Default to testnet
        inferenceCA = CONTRACT_ADDRESSES.testnet.inference
        console.warn(`Unknown chain ID ${detectedChainId}, defaulting to testnet contract`)
    }

    // Create read-only broker
    return new ReadOnlyInferenceBroker(provider, inferenceCA)
}

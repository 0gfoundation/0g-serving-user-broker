import type { JsonRpcSigner } from 'ethers'
import { Wallet } from 'ethers'
import { createLedgerBroker } from './ledger'
import { createFineTuningBroker } from './fine-tuning/broker'
import { createInferenceBroker } from './inference/broker/broker'
import type { InferenceBroker } from './inference/broker/broker'
import type { LedgerBroker } from './ledger'
import type { FineTuningBroker } from './fine-tuning/broker'

// Network configurations
export const TESTNET_CHAIN_ID = 16602n
export const MAINNET_CHAIN_ID = 16600n // TODO: Update with actual mainnet chain ID when available

// Contract addresses for different networks
export const CONTRACT_ADDRESSES = {
    testnet: {
        ledger: '0xc9BF91efc972e2B1225D4d9266B31aea458EE0B5',
        inference: '0xD18A6308793bDE62c3664729e3Fd0F7CFd2565Da',
        fineTuning: '0x434cAbDedef8eBB760e7e583E419BFD5537A8B8a'
    },
    mainnet: {
        // TODO: Update with actual mainnet addresses when available
        ledger: '0x0000000000000000000000000000000000000000',
        inference: '0x0000000000000000000000000000000000000000',
        fineTuning: '0x0000000000000000000000000000000000000000'
    }
} as const

/**
 * Helper function to determine network type from chain ID
 */
export function getNetworkType(chainId: bigint): 'mainnet' | 'testnet' | 'unknown' {
    if (chainId === MAINNET_CHAIN_ID) {
        return 'mainnet'
    } else if (chainId === TESTNET_CHAIN_ID) {
        return 'testnet'
    }
    return 'unknown'
}

export class ZGComputeNetworkBroker {
    public ledger!: LedgerBroker
    public inference!: InferenceBroker
    public fineTuning?: FineTuningBroker

    constructor(
        ledger: LedgerBroker,
        inferenceBroker: InferenceBroker,
        fineTuningBroker?: FineTuningBroker
    ) {
        this.ledger = ledger
        this.inference = inferenceBroker
        this.fineTuning = fineTuningBroker
    }
}

/**
 * createZGComputeNetworkBroker is used to initialize ZGComputeNetworkBroker
 * 
 * This function automatically detects the network from the signer's provider and uses
 * appropriate contract addresses. You can override any address by providing it explicitly.
 *
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - 0G Compute Network Ledger Contact address, auto-detected if not provided.
 * @param inferenceCA - 0G Compute Network Inference Serving contract address, auto-detected if not provided.
 * @param fineTuningCA - 0G Compute Network Fine Tuning Serving contract address, auto-detected if not provided.
 * @param gasPrice - Gas price for transactions. If not provided, the gas price will be calculated automatically.
 * @param maxGasPrice - Maximum gas price for transactions.
 * @param step - Step for gas price adjustment.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
export async function createZGComputeNetworkBroker(
    signer: JsonRpcSigner | Wallet,
    ledgerCA?: string,
    inferenceCA?: string,
    fineTuningCA?: string,
    gasPrice?: number,
    maxGasPrice?: number,
    step?: number
): Promise<ZGComputeNetworkBroker> {
    try {
        // Auto-detect network from signer's provider
        let defaultAddresses: {
            ledger: string
            inference: string
            fineTuning: string
        } = CONTRACT_ADDRESSES.testnet // Default to testnet
        
        if (signer.provider) {
            const network = await signer.provider.getNetwork()
            const chainId = network.chainId
            
            if (chainId === MAINNET_CHAIN_ID) {
                defaultAddresses = CONTRACT_ADDRESSES.mainnet
                console.log(`Detected mainnet (chain ID: ${chainId})`)
            } else if (chainId === TESTNET_CHAIN_ID) {
                defaultAddresses = CONTRACT_ADDRESSES.testnet
                console.log(`Detected testnet (chain ID: ${chainId})`)
            } else {
                console.warn(
                    `Unknown chain ID: ${chainId}. Using testnet addresses as default.`
                )
            }
        } else {
            console.warn('No provider found on signer. Using testnet addresses as default.')
        }
        
        // Use provided addresses or fall back to auto-detected defaults
        const finalLedgerCA = ledgerCA || defaultAddresses.ledger
        const finalInferenceCA = inferenceCA || defaultAddresses.inference
        const finalFineTuningCA = fineTuningCA || defaultAddresses.fineTuning
        
        const ledger = await createLedgerBroker(
            signer,
            finalLedgerCA,
            finalInferenceCA,
            finalFineTuningCA,
            gasPrice,
            maxGasPrice,
            step
        )
        const inferenceBroker = await createInferenceBroker(
            signer,
            finalInferenceCA,
            ledger
        )

        let fineTuningBroker: FineTuningBroker | undefined
        if (signer instanceof Wallet) {
            fineTuningBroker = await createFineTuningBroker(
                signer,
                finalFineTuningCA,
                ledger,
                gasPrice,
                maxGasPrice,
                step
            )
        }

        const broker = new ZGComputeNetworkBroker(
            ledger,
            inferenceBroker,
            fineTuningBroker
        )
        return broker
    } catch (error) {
        throw error
    }
}

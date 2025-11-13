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
export const MAINNET_CHAIN_ID = 16661n
export const HARDHAT_CHAIN_ID = 31337n

// Contract addresses for different networks
export const CONTRACT_ADDRESSES = {
    testnet: {
        ledger: '0x327025B6435424735a3d97c4b1671FeFF0E8879B',
        inference: '0xa58e5220A5cF61768c7A5dBFC34a2377829240be',
        fineTuning: '0x434cAbDedef8eBB760e7e583E419BFD5537A8B8a',
    },
    mainnet: {
        // TODO: Update with actual mainnet addresses when available
        ledger: '0x1C4450Dc74504e585571B4aF70451C0737F10b71',
        inference: '0x0754221A9f2C11D820F827170249c3cc5cC3DC74',
        fineTuning: '0x0000000000000000000000000000000000000000',
    },
    hardhat: {
        ledger: '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0',
        inference: '0x0165878A594ca255338adfa4d48449f69242Eb8F',
        fineTuning: '0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0',
    },
} as const

/**
 * Helper function to determine network type from chain ID
 */
export function getNetworkType(
    chainId: bigint
): 'mainnet' | 'testnet' | 'hardhat' | 'unknown' {
    if (chainId === MAINNET_CHAIN_ID) {
        return 'mainnet'
    } else if (chainId === TESTNET_CHAIN_ID) {
        return 'testnet'
    } else if (chainId === HARDHAT_CHAIN_ID) {
        return 'hardhat'
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
            } else if (chainId === HARDHAT_CHAIN_ID) {
                defaultAddresses = CONTRACT_ADDRESSES.hardhat
                console.log(`Detected hardhat (chain ID: ${chainId})`)
            } else {
                console.warn(
                    `Unknown chain ID: ${chainId}. Using testnet addresses as default.`
                )
            }
        } else {
            console.warn(
                'No provider found on signer. Using testnet addresses as default.'
            )
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

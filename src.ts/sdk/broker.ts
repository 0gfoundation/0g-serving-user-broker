import type { JsonRpcSigner } from 'ethers'
import { Wallet } from 'ethers'
import { createLedgerBroker } from './ledger'
import { createFineTuningBroker } from './fine-tuning/broker'
import { createInferenceBroker } from './inference/broker/broker'
import type { InferenceBroker } from './inference/broker/broker'
import type { LedgerBroker } from './ledger'
import type { FineTuningBroker } from './fine-tuning/broker'

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
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - 0G Compute Network Ledger Contact address, use default address if not provided.
 * @param inferenceCA - 0G Compute Network Inference Serving contract address, use default address if not provided.
 * @param fineTuningCA - 0G Compute Network Fine Tuning Serving contract address, use default address if not provided.
 * @param gasPrice - Gas price for transactions. If not provided, the gas price will be calculated automatically.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
export async function createZGComputeNetworkBroker(
    signer: JsonRpcSigner | Wallet,
    ledgerCA = '0x907a552804CECC0cBAeCf734E2B9E45b2FA6a960',
    inferenceCA = '0x192ff84e5E3Ef3A6D29F508a56bF9beb344471f3',
    fineTuningCA = '0x9472Cc442354a5a3bEeA5755Ec781937aB891c10',
    gasPrice?: number,
    maxGasPrice?: number,
    step?: number
): Promise<ZGComputeNetworkBroker> {
    try {
        const ledger = await createLedgerBroker(
            signer,
            ledgerCA,
            inferenceCA,
            fineTuningCA,
            gasPrice,
            maxGasPrice,
            step
        )
        const inferenceBroker = await createInferenceBroker(
            signer,
            inferenceCA,
            ledger
        )

        let fineTuningBroker: FineTuningBroker | undefined
        if (signer instanceof Wallet) {
            fineTuningBroker = await createFineTuningBroker(
                signer,
                fineTuningCA,
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

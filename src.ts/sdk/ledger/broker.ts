import type { AddressLike, JsonRpcSigner } from 'ethers'
import { Wallet } from 'ethers'
import type { LedgerStructOutput } from './contract/typechain/LedgerManager'
import { LedgerProcessor } from './ledger'
import type { ServiceNames } from './ledger'
import { LedgerManagerContract } from './contract'
import { InferenceServingContract } from '../inference/contract'
import { FineTuningServingContract } from '../fine-tuning/contract'
import { Cache, Metadata } from '../common/storage'
import { throwFormattedError } from '../common/utils'

export class LedgerBroker {
    public ledger!: LedgerProcessor

    private signer: JsonRpcSigner | Wallet
    private ledgerCA: string
    private inferenceCA: string
    private fineTuningCA: string
    private gasPrice: number | undefined
    private maxGasPrice: number | undefined
    private step: number | undefined

    constructor(
        signer: JsonRpcSigner | Wallet,
        ledgerCA: string,
        inferenceCA: string,
        fineTuningCA: string,
        gasPrice?: number,
        maxGasPrice?: number,
        step?: number
    ) {
        this.signer = signer
        this.ledgerCA = ledgerCA
        this.inferenceCA = inferenceCA
        this.fineTuningCA = fineTuningCA
        this.gasPrice = gasPrice
        this.maxGasPrice = maxGasPrice
        this.step = step
    }

    async initialize() {
        let userAddress: string
        try {
            userAddress = await this.signer.getAddress()
        } catch (error) {
            throwFormattedError(error)
        }
        const ledgerContract = new LedgerManagerContract(
            this.signer,
            this.ledgerCA,
            userAddress,
            this.gasPrice,
            this.maxGasPrice,
            this.step
        )
        const inferenceContract = new InferenceServingContract(
            this.signer,
            this.inferenceCA,
            userAddress
        )

        let fineTuningContract: FineTuningServingContract | undefined
        if (this.signer instanceof Wallet) {
            fineTuningContract = new FineTuningServingContract(
                this.signer,
                this.fineTuningCA,
                userAddress
            )
        }

        // Get service names from contract using getServiceInfo
        const serviceNames: ServiceNames = await this.getServiceNames(
            ledgerContract,
            this.inferenceCA,
            this.fineTuningCA
        )

        const metadata = new Metadata()
        const cache = new Cache()

        this.ledger = new LedgerProcessor(
            metadata,
            cache,
            ledgerContract,
            inferenceContract,
            fineTuningContract,
            serviceNames
        )
    }

    private async getServiceNames(
        ledgerContract: LedgerManagerContract,
        inferenceCA: string,
        fineTuningCA: string
    ): Promise<ServiceNames> {
        try {
            // Get service info for inference contract
            const inferenceServiceInfo = await ledgerContract.getServiceInfo(
                inferenceCA
            )
            const inferenceServiceName = inferenceServiceInfo.fullName

            // Get service info for fine-tuning contract if using Wallet
            let fineTuningServiceName: string | undefined
            if (this.signer instanceof Wallet) {
                try {
                    const fineTuningServiceInfo =
                        await ledgerContract.getServiceInfo(fineTuningCA)
                    fineTuningServiceName = fineTuningServiceInfo.fullName
                } catch (error) {
                    // Fine-tuning service might not be registered
                    console.warn(
                        'Fine-tuning service not registered in LedgerManager'
                    )
                }
            }

            return {
                inference: inferenceServiceName,
                fineTuning: fineTuningServiceName,
            }
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Adds a new ledger to the contract.
     *
     * @param {number} balance - The initial balance to be assigned to the new ledger. Units are in A0GI.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the ledger creation fails.
     *
     * @remarks
     * When creating an ledger, a key pair is also created to sign the request.
     */
    public addLedger = async (balance: number, gasPrice?: number) => {
        try {
            return await this.ledger.addLedger(balance, gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Retrieves the ledger information for current wallet address.
     *
     * @returns A promise that resolves to the ledger information.
     *
     * @throws Will throw an error if the ledger retrieval process fails.
     */
    public getLedger = async (): Promise<LedgerStructOutput> => {
        try {
            return await this.ledger.getLedger()
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Deposits a specified amount of funds into Ledger corresponding to the current wallet address.
     *
     * @param {string} amount - The amount of funds to be deposited. Units are in A0GI.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deposit fails.
     */
    public depositFund = async (amount: number, gasPrice?: number) => {
        try {
            return await this.ledger.depositFund(amount, gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Refunds a specified amount using the ledger.
     *
     * @param amount - The amount to be refunded.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves when the refund is processed.
     * @throws Will throw an error if the refund process fails.
     *
     * @remarks The amount should be a positive number.
     */
    public refund = async (amount: number, gasPrice?: number) => {
        try {
            return await this.ledger.refund(amount, gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Transfers a specified amount of funds to a provider for a given service type.
     *
     * @param provider - The address of the provider to whom the funds are being transferred.
     * @param serviceTypeStr - The type of service for which the funds are being transferred.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param amount - The amount of funds to be transferred. Units are in neuron.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund transfer operation.
     * @throws Will throw an error if the fund transfer operation fails.
     */
    public transferFund = async (
        provider: AddressLike,
        serviceTypeStr: 'inference' | 'fine-tuning',
        amount: bigint,
        gasPrice?: number
    ) => {
        try {
            return await this.ledger.transferFund(
                provider,
                serviceTypeStr,
                amount,
                gasPrice
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Retrieves funds from the all sub-accounts (for inference and fine-tuning) of the current wallet address.
     *
     * @param serviceTypeStr - The type of service for which the funds are being retrieved.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund retrieval operation.
     * @throws Will throw an error if the fund retrieval operation fails.
     */
    public retrieveFund = async (
        serviceTypeStr: 'inference' | 'fine-tuning',
        gasPrice?: number
    ) => {
        try {
            return await this.ledger.retrieveFund(serviceTypeStr, gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Deletes the ledger corresponding to the current wallet address.
     *
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                           the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deletion fails.
     */
    public deleteLedger = async (gasPrice?: number) => {
        try {
            return await this.ledger.deleteLedger(gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }
}

/**
 * createLedgerBroker is used to initialize LedgerBroker
 *
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - Ledger contract address, use default address if not provided.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
export async function createLedgerBroker(
    signer: JsonRpcSigner | Wallet,
    ledgerCA: string,
    inferenceCA: string,
    fineTuningCA: string,
    gasPrice?: number,
    maxGasPrice?: number,
    step?: number
): Promise<LedgerBroker> {
    const broker = new LedgerBroker(
        signer,
        ledgerCA,
        inferenceCA,
        fineTuningCA,
        gasPrice,
        maxGasPrice,
        step
    )
    try {
        await broker.initialize()
        return broker
    } catch (error) {
        throw error
    }
}

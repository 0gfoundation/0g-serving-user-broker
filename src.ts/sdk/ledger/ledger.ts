import type { AddressLike } from 'ethers'
import { throwFormattedError } from '../common/utils'
import type { LedgerManagerContract } from './contract'
import type { InferenceServingContract } from '../inference/contract'
import type { FineTuningServingContract } from '../fine-tuning/contract'
import type { Cache, Metadata } from '../common/storage'
import { CacheValueTypeEnum, CACHE_KEYS } from '../common/storage'

export interface LedgerDetailStructOutput {
    ledgerInfo: bigint[]
    infers: [string, bigint, bigint][]
    fines: [string, bigint, bigint][] | null
}
/**
 * LedgerProcessor contains methods for creating, depositing funds, and retrieving 0G Compute Network Ledgers.
 */
export class LedgerProcessor {
    protected metadata: Metadata
    protected cache: Cache

    protected ledgerContract: LedgerManagerContract
    protected inferenceContract: InferenceServingContract
    protected fineTuningContract: FineTuningServingContract | undefined

    constructor(
        metadata: Metadata,
        cache: Cache,
        ledgerContract: LedgerManagerContract,
        inferenceContract: InferenceServingContract,
        fineTuningContract?: FineTuningServingContract
    ) {
        this.metadata = metadata
        this.ledgerContract = ledgerContract
        this.inferenceContract = inferenceContract
        this.fineTuningContract = fineTuningContract
        this.cache = cache
    }

    async getLedger() {
        try {
            const ledger = await this.ledgerContract.getLedger()
            return ledger
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getLedgerWithDetail(): Promise<LedgerDetailStructOutput> {
        try {
            const ledger = await this.ledgerContract.getLedger()
            const ledgerInfo = [
                ledger.totalBalance,
                ledger.totalBalance - ledger.availableBalance,
            ]
            const infers: [string, bigint, bigint][] = await Promise.all(
                ledger.inferenceProviders.map(async (provider) => {
                    const account = await this.inferenceContract.getAccount(
                        provider
                    )
                    return [provider, account.balance, account.pendingRefund]
                })
            )

            if (typeof this.fineTuningContract == 'undefined') {
                return { ledgerInfo, infers, fines: [] }
            }
            const fines: [string, bigint, bigint][] = await Promise.all(
                ledger.fineTuningProviders.map(async (provider) => {
                    const account = await this.fineTuningContract?.getAccount(
                        provider
                    )
                    return [provider, account!.balance, account!.pendingRefund]
                })
            )

            return { ledgerInfo, infers, fines }
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async listLedger() {
        try {
            const ledgers = await this.ledgerContract.listLedger()
            return ledgers
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async addLedger(balance: number, gasPrice?: number) {
        try {
            try {
                const ledger = await this.getLedger()
                if (ledger) {
                    throw new Error(
                        'Ledger already exists, with balance: ' +
                            this.neuronToA0gi(ledger.totalBalance) +
                            ' A0GI'
                    )
                }
            } catch (error) {}

            // Use placeholders since Inference contract doesn't use these values
            const placeholderSigner: [bigint, bigint] = [BigInt(0), BigInt(0)]
            const placeholderInfo = ""

            await this.ledgerContract.addLedger(
                placeholderSigner,
                this.a0giToNeuron(balance),
                placeholderInfo,
                gasPrice
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async deleteLedger(gasPrice?: number) {
        try {
            await this.ledgerContract.deleteLedger(gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async depositFund(balance: number, gasPrice?: number) {
        try {
            const amount = this.a0giToNeuron(balance).toString()
            await this.ledgerContract.depositFund(amount, gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async refund(balance: number, gasPrice?: number) {
        try {
            const amount = this.a0giToNeuron(balance).toString()
            await this.ledgerContract.refund(amount, gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async transferFund(
        to: AddressLike,
        serviceTypeStr: 'inference' | 'fine-tuning',
        balance: bigint,
        gasPrice?: number
    ) {
        try {
            const amount = balance.toString()
            await this.ledgerContract.transferFund(
                to,
                serviceTypeStr,
                amount,
                gasPrice
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async retrieveFund(
        serviceTypeStr: 'inference' | 'fine-tuning',
        gasPrice?: number
    ) {
        try {
            const ledger = await this.getLedgerWithDetail()
            const providers =
                serviceTypeStr == 'inference' ? ledger.infers : ledger.fines
            if (!providers) {
                throw new Error(
                    'No providers found, please ensure you are using Wallet instance to create the broker'
                )
            }

            const providerAddresses = providers
                .filter((x) => x[1] - x[2] > 0n)
                .map((x) => x[0])

            await this.ledgerContract.retrieveFund(
                providerAddresses,
                serviceTypeStr,
                gasPrice
            )

            if (serviceTypeStr == 'inference') {
                await this.cache.setItem(
                    CACHE_KEYS.FIRST_ROUND,
                    'true',
                    10000000 * 60 * 1000,
                    CacheValueTypeEnum.Other
                )
            }
        } catch (error) {
            throwFormattedError(error)
        }
    }

    // Method removed: createSettleSignerKey is no longer needed
    // since we're using placeholders in addLedger

    protected a0giToNeuron(value: number): bigint {
        const valueStr = value.toFixed(18)
        const parts = valueStr.split('.')

        // Handle integer part
        const integerPart = parts[0]
        let integerPartAsBigInt = BigInt(integerPart) * BigInt(10 ** 18)

        // Handle fractional part if it exists
        if (parts.length > 1) {
            let fractionalPart = parts[1]
            while (fractionalPart.length < 18) {
                fractionalPart += '0'
            }
            if (fractionalPart.length > 18) {
                fractionalPart = fractionalPart.slice(0, 18) // Truncate to avoid overflow
            }

            const fractionalPartAsBigInt = BigInt(fractionalPart)
            integerPartAsBigInt += fractionalPartAsBigInt
        }

        return integerPartAsBigInt
    }

    protected neuronToA0gi(value: bigint): number {
        const divisor = BigInt(10 ** 18)
        const integerPart = value / divisor
        const remainder = value % divisor
        const decimalPart = Number(remainder) / Number(divisor)

        return Number(integerPart) + decimalPart
    }
}

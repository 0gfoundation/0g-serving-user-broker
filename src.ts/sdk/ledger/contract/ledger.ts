import type {
    JsonRpcSigner,
    BigNumberish,
    AddressLike,
    Wallet,
    ContractTransactionReceipt,
    ContractMethodArgs,
} from 'ethers'
import type { LedgerManager } from './typechain'
import { LedgerManager__factory } from './typechain'
import { RETRY_ERROR_SUBSTRINGS } from '../../common/utils/const'
import { throwFormattedError } from '../../common/utils'

const TIMEOUT_MS = 300_000

export class LedgerManagerContract {
    public ledger: LedgerManager
    public signer: JsonRpcSigner | Wallet

    private _userAddress: string
    private _gasPrice?: number
    private _maxGasPrice?: number
    private _step: number

    constructor(
        signer: JsonRpcSigner | Wallet,
        contractAddress: string,
        userAddress: string,
        gasPrice?: number,
        maxGasPrice?: number,
        step?: number
    ) {
        this.ledger = LedgerManager__factory.connect(contractAddress, signer)
        this.signer = signer
        this._userAddress = userAddress
        this._gasPrice = gasPrice
        this._maxGasPrice = maxGasPrice
        this._step = step || 1.1
    }

    async sendTx(
        name: string,
        txArgs: ContractMethodArgs<any[]>,
        txOptions: any
    ) {
        if (txOptions.gasPrice === undefined) {
            txOptions.gasPrice = (
                await this.signer.provider?.getFeeData()
            )?.gasPrice

            // Add a delay to avoid too frequent RPC calls
            await new Promise((resolve) => setTimeout(resolve, 1000))
        } else {
            txOptions.gasPrice = BigInt(txOptions.gasPrice)
        }

        while (true) {
            try {
                console.log('sending tx with gas price', txOptions.gasPrice)
                const tx = await this.ledger.getFunction(name)(
                    ...txArgs,
                    txOptions
                )
                console.log('tx hash:', tx.hash)
                const receipt = (await Promise.race([
                    tx.wait(),
                    new Promise((_, reject) =>
                        setTimeout(
                            () => reject(new Error('Get Receipt timeout')),
                            TIMEOUT_MS
                        )
                    ),
                ])) as ContractTransactionReceipt | null

                this.checkReceipt(receipt)
                break
            } catch (error: any) {
                if (
                    error.message ===
                    'Get Receipt timeout, try set higher gas price'
                ) {
                    const nonce = await this.signer.getNonce()
                    const pendingNonce =
                        await this.signer.provider?.getTransactionCount(
                            this._userAddress,
                            'pending'
                        )
                    if (
                        pendingNonce !== undefined &&
                        pendingNonce - nonce > 5 &&
                        txOptions.nonce === undefined
                    ) {
                        console.warn(
                            `Significant gap detected between pending nonce (${pendingNonce}) and current nonce (${nonce}). This may indicate skipped or missing transactions. Using the current confirmed nonce for the transaction.`
                        )
                        txOptions.nonce = nonce
                    }
                }

                if (this._maxGasPrice === undefined) {
                    throwFormattedError(error)
                }

                let errorMessage = ''
                if (error.message) {
                    errorMessage = error.message
                } else if (error.info?.error?.message) {
                    errorMessage = error.info.error.message
                }
                const shouldRetry = RETRY_ERROR_SUBSTRINGS.some((substr) =>
                    errorMessage.includes(substr)
                )

                if (!shouldRetry) {
                    throwFormattedError(error)
                }
                console.log(
                    'Retrying transaction with higher gas price due to:',
                    errorMessage
                )
                let currentGasPrice = txOptions.gasPrice
                if (currentGasPrice >= this._maxGasPrice) {
                    throwFormattedError(error)
                }
                currentGasPrice =
                    (currentGasPrice * BigInt(this._step)) / BigInt(10)
                if (currentGasPrice > this._maxGasPrice) {
                    currentGasPrice = this._maxGasPrice
                }
                txOptions.gasPrice = currentGasPrice
            }
        }
    }

    async addLedger(
        balance: bigint,
        additionalInfo?: string,
        gasPrice?: number
    ) {
        try {
            const txOptions: any = { value: balance }
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice
            }

            await this.sendTx('addLedger', [additionalInfo || ''], txOptions)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async listLedger(offset: number = 0, limit: number = 50) {
        try {
            const result = await this.ledger.getAllLedgers(offset, limit)
            return result.ledgers
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getLedger() {
        try {
            const user = this.getUserAddress()
            const ledger = await this.ledger.getLedger(user)
            return ledger
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getLedgerProviders(user: string, serviceName: string) {
        try {
            const providers = await this.ledger.getLedgerProviders(
                user,
                serviceName
            )
            return providers
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getServiceInfo(serviceAddress: string) {
        try {
            const serviceInfo = await this.ledger.getServiceInfo(serviceAddress)
            return serviceInfo
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async depositFund(balance: string, gasPrice?: number) {
        try {
            const txOptions: any = { value: balance }
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice
            }
            await this.sendTx('depositFund', [], txOptions)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async refund(amount: BigNumberish, gasPrice?: number) {
        try {
            const txOptions: any = {}
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice
            }
            await this.sendTx('refund', [amount], txOptions)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async transferFund(
        provider: AddressLike,
        serviceName: string,
        amount: BigNumberish,
        gasPrice?: number
    ) {
        try {
            const txOptions: any = {}
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice
            }
            await this.sendTx(
                'transferFund',
                [provider, serviceName, amount],
                txOptions
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async retrieveFund(
        providers: AddressLike[],
        serviceName: string,
        gasPrice?: number
    ) {
        try {
            const txOptions: any = {}
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice
            }
            await this.sendTx(
                'retrieveFund',
                [providers, serviceName],
                txOptions
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async deleteLedger(gasPrice?: number) {
        try {
            const txOptions: any = {}
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice
            }
            await this.sendTx('deleteLedger', [], txOptions)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    getUserAddress(): string {
        return this._userAddress
    }

    checkReceipt(receipt: ContractTransactionReceipt | null): void {
        if (!receipt) {
            throw new Error('Transaction failed with no receipt')
        }
        if (receipt.status !== 1) {
            throw new Error('Transaction reverted')
        }
    }
}

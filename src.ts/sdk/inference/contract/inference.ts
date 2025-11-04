import type {
    JsonRpcSigner,
    AddressLike,
    Wallet,
    ContractTransactionReceipt,
    ContractMethodArgs,
} from 'ethers'
import { InferenceServing__factory } from './typechain'
import type { InferenceServing } from './typechain/InferenceServing'
import type { ServiceStructOutput } from './typechain/InferenceServing'
import { throwFormattedError } from '../../common/utils'
import { RETRY_ERROR_SUBSTRINGS } from '../../common/utils/const'

const TIMEOUT_MS = 300_000

export class InferenceServingContract {
    public serving: InferenceServing
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
        this.serving = InferenceServing__factory.connect(
            contractAddress,
            signer
        )
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
                const tx = await this.serving.getFunction(name)(
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

    lockTime(): Promise<bigint> {
        return this.serving.lockTime()
    }

    async listService(): Promise<ServiceStructOutput[]> {
        try {
            const services = await this.serving.getAllServices()
            return services
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async listAccount(offset: number = 0, limit: number = 50) {
        try {
            const result = await this.serving.getAllAccounts(offset, limit)
            return result.accounts
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getAccount(provider: AddressLike) {
        try {
            const user = this.getUserAddress()
            const account = await this.serving.getAccount(user, provider)
            return account
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Acknowledge TEE signer for a provider (Contract owner only)
     * 
     * @param providerAddress - The address of the provider
     */
    async acknowledgeTEESigner(
        providerAddress: AddressLike,
        gasPrice?: number
    ) {
        try {
            const txOptions: any = {}
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice
            }

            await this.sendTx(
                'acknowledgeTEESigner',
                [providerAddress],
                txOptions
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Revoke TEE signer acknowledgement for a provider (Contract owner only)
     * 
     * @param providerAddress - The address of the provider
     */
    async revokeTEESignerAcknowledgement(
        providerAddress: AddressLike,
        gasPrice?: number
    ) {
        try {
            const txOptions: any = {}
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice
            }

            await this.sendTx(
                'revokeTEESignerAcknowledgement',
                [providerAddress],
                txOptions
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getService(providerAddress: string): Promise<ServiceStructOutput> {
        try {
            return this.serving.getService(providerAddress)
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

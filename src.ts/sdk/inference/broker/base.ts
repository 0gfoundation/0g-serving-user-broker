import type { InferenceServingContract } from '../contract'
import { ChatBot } from '../extractor'
import type { Extractor } from '../extractor'
import type { ServiceStructOutput } from '../contract'
import type { ServingRequestHeaders } from './request'
import {
    decryptData,
    getNonceWithCache,
    strToPrivateKey,
    throwFormattedError,
} from '../../common/utils'
import type { PackedPrivkey } from '../../common/settle-signer'
import {
    Request,
    signData,
    pedersenHash,
    bigintToBytes,
} from '../../common/settle-signer'
import type { Cache, Metadata } from '../../common/storage'
import {
    CacheValueTypeEnum,
    CACHE_KEYS,
    CacheKeyHelpers,
} from '../../common/storage'
import type { LedgerBroker } from '../../ledger'
import { hexlify, ZeroAddress } from 'ethers'

export interface QuoteResponse {
    quote: string
    provider_signer: string
    key: [bigint, bigint]
    nvidia_payload: string
}

export abstract class ZGServingUserBrokerBase {
    protected contract: InferenceServingContract
    protected metadata: Metadata
    protected cache: Cache

    private checkAccountThreshold = BigInt(100)
    private topUpTriggerThreshold = BigInt(1000000)
    private topUpTargetThreshold = BigInt(2000000)
    protected ledger: LedgerBroker

    constructor(
        contract: InferenceServingContract,
        ledger: LedgerBroker,
        metadata: Metadata,
        cache: Cache
    ) {
        this.contract = contract
        this.ledger = ledger
        this.metadata = metadata
        this.cache = cache
    }

    protected async getProviderData() {
        const key = `${this.contract.getUserAddress()}`
        const [settleSignerPrivateKey] = await Promise.all([
            this.metadata.getSettleSignerPrivateKey(key),
        ])
        return { settleSignerPrivateKey }
    }

    protected async getService(
        providerAddress: string,
        useCache = true
    ): Promise<ServiceStructOutput> {
        const key = CacheKeyHelpers.getServiceKey(providerAddress)
        const cachedSvc = await this.cache.getItem(key)
        if (cachedSvc && useCache) {
            return cachedSvc
        }

        try {
            const svc = await this.contract.getService(providerAddress)
            await this.cache.setItem(
                key,
                svc,
                10 * 60 * 1000,
                CacheValueTypeEnum.Service
            )
            return svc
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getQuote(providerAddress: string): Promise<QuoteResponse> {
        try {
            const service = await this.getService(providerAddress)

            const url = service.url
            const endpoint = `${url}/v1/quote`

            const quoteString = await this.fetchText(endpoint, {
                method: 'GET',
            })

            const ret = JSON.parse(quoteString, (_, value) => {
                if (typeof value === 'string' && /^\d+$/.test(value)) {
                    return BigInt(value)
                }

                return value
            })
            return ret
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async userAcknowledged(providerAddress: string): Promise<boolean> {
        const userAddress = this.contract.getUserAddress()
        const key = CacheKeyHelpers.getUserAckKey(userAddress, providerAddress)
        const cachedSvc = await this.cache.getItem(key)
        if (cachedSvc) {
            return true
        }

        try {
            const account = await this.contract.getAccount(providerAddress)
            if (account.teeSignerAddress !== ZeroAddress) {
                await this.cache.setItem(
                    key,
                    account.providerPubKey,
                    10 * 60 * 1000,
                    CacheValueTypeEnum.Other
                )

                return true
            } else {
                return false
            }
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async fetchText(endpoint: string, options: RequestInit): Promise<string> {
        try {
            const response = await fetch(endpoint, options)
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`)
            }
            const buffer = await response.arrayBuffer()
            return Buffer.from(buffer).toString('utf-8')
        } catch (error) {
            throwFormattedError(error)
        }
    }

    protected async getExtractor(
        providerAddress: string,
        useCache = true
    ): Promise<Extractor> {
        try {
            const svc = await this.getService(providerAddress, useCache)
            const extractor = this.createExtractor(svc)
            return extractor
        } catch (error) {
            throwFormattedError(error)
        }
    }

    protected createExtractor(svc: ServiceStructOutput): Extractor {
        switch (svc.serviceType) {
            case 'chatbot':
                return new ChatBot(svc)
            default:
                throw new Error('Unknown service type')
        }
    }

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

    async getHeader(
        providerAddress: string,
        content: string,
        outputFee: bigint,
        vllmProxy: boolean
    ): Promise<ServingRequestHeaders> {
        try {
            const userAddress = this.contract.getUserAddress()
            if (!(await this.userAcknowledged(providerAddress))) {
                throw new Error('Provider signer is not acknowledged')
            }

            const extractor = await this.getExtractor(providerAddress)
            const { settleSignerPrivateKey } = await this.getProviderData()
            const key = userAddress

            let privateKey = settleSignerPrivateKey
            if (!privateKey) {
                const account = await this.contract.getAccount(providerAddress)
                const privateKeyStr = await decryptData(
                    this.contract.signer,
                    account.additionalInfo
                )
                privateKey = strToPrivateKey(privateKeyStr)
                console.log('Private key new:', privateKey)

                this.metadata.storeSettleSignerPrivateKey(key, privateKey)
            }

            const nonce = await getNonceWithCache(this.cache)

            const inputFee = await this.calculateInputFees(extractor, content)
            const fee = inputFee + outputFee

            const request = new Request(
                nonce.toString(),
                fee.toString(),
                userAddress,
                providerAddress
            )
            const settleSignature = await signData(
                [request],
                privateKey as PackedPrivkey
            )
            const sig = JSON.stringify(Array.from(settleSignature[0]))

            const requestHash = await this.calculatePedersenHash(
                nonce,
                userAddress,
                providerAddress
            )
            return {
                'X-Phala-Signature-Type': 'StandaloneApi',
                Address: userAddress,
                Fee: fee.toString(),
                'Input-Fee': inputFee.toString(),
                Nonce: nonce.toString(),
                'Request-Hash': requestHash,
                Signature: sig,
                'VLLM-Proxy': `${vllmProxy}`,
            }
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async calculatePedersenHash(
        nonce: number,
        userAddress: string,
        providerAddress: string
    ): Promise<string> {
        const ADDR_LENGTH = 20
        const NONCE_LENGTH = 8

        const buffer = new ArrayBuffer(NONCE_LENGTH + ADDR_LENGTH * 2)
        let offset = 0

        const nonceBytes = bigintToBytes(BigInt(nonce), NONCE_LENGTH)
        new Uint8Array(buffer, offset, NONCE_LENGTH).set(nonceBytes)
        offset += NONCE_LENGTH

        new Uint8Array(buffer, offset, ADDR_LENGTH).set(
            bigintToBytes(BigInt(userAddress), ADDR_LENGTH)
        )
        offset += ADDR_LENGTH

        new Uint8Array(buffer, offset, ADDR_LENGTH).set(
            bigintToBytes(BigInt(providerAddress), ADDR_LENGTH)
        )

        return hexlify(await pedersenHash(Buffer.from(buffer)))
    }

    async calculateInputFees(extractor: Extractor, content: string) {
        const svc = await extractor.getSvcInfo()
        const inputCount = await extractor.getInputCount(content)
        const inputFee = BigInt(inputCount) * BigInt(svc.inputPrice)
        return inputFee
    }

    async updateCachedFee(provider: string, fee: bigint) {
        try {
            const key = CacheKeyHelpers.getCachedFeeKey(provider)
            const curFee = (await this.cache.getItem(key)) || BigInt(0)
            await this.cache.setItem(
                key,
                BigInt(curFee) + fee,
                1 * 60 * 1000,
                CacheValueTypeEnum.BigInt
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async clearCacheFee(provider: string, fee: bigint) {
        try {
            const key = CacheKeyHelpers.getCachedFeeKey(provider)
            const curFee = (await this.cache.getItem(key)) || BigInt(0)
            await this.cache.setItem(
                key,
                BigInt(curFee) + fee,
                1 * 60 * 1000,
                CacheValueTypeEnum.BigInt
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Transfer fund from ledger if fund in the inference account is less than a topUpTriggerThreshold * (inputPrice + outputPrice)
     */
    async topUpAccountIfNeeded(
        provider: string,
        content: string,
        gasPrice?: number
    ) {
        try {
            // Exit early if running in browser environment
            if (
                typeof window !== 'undefined' &&
                typeof window.document !== 'undefined'
            ) {
                return
            }

            const extractor = await this.getExtractor(provider)
            const svc = await extractor.getSvcInfo()

            // Calculate target and trigger thresholds
            const targetThreshold =
                this.topUpTargetThreshold * (BigInt(svc.inputPrice) + BigInt(svc.outputPrice))
            const triggerThreshold =
                this.topUpTriggerThreshold * (BigInt(svc.inputPrice) + BigInt(svc.outputPrice))

            // Check if it's the first round
            const isFirstRound =
                (await this.cache.getItem(CACHE_KEYS.FIRST_ROUND)) !== 'false'
            if (isFirstRound) {
                await this.handleFirstRound(
                    provider,
                    triggerThreshold,
                    targetThreshold,
                    gasPrice
                )
                return
            }

            // Calculate new fee and update cached fee
            const newFee = await this.calculateInputFees(extractor, content)
            await this.updateCachedFee(provider, newFee)

            // Check if we need to check the account
            if (!(await this.shouldCheckAccount(svc))) return

            // Re-check the account balance
            const acc = await this.contract.getAccount(provider)
            const lockedFund = acc.balance - acc.pendingRefund
            if (lockedFund < triggerThreshold) {
                try {
                    await this.ledger.transferFund(
                        provider,
                        'inference',
                        targetThreshold,
                        gasPrice
                    )
                } catch (error: any) {
                    // Check if it's an insufficient balance error
                    const errorMessage = error?.message?.toLowerCase() || ''
                    if (errorMessage.includes('insufficient')) {
                        throw new Error(
                            `To ensure stable service from the provider, ${targetThreshold} neuron needs to be transferred from the balance, but the current balance is insufficient.`
                        )
                    }
                    throw error
                }
            }

            await this.clearCacheFee(provider, newFee)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    private async handleFirstRound(
        provider: string,
        triggerThreshold: bigint,
        targetThreshold: bigint,
        gasPrice?: number
    ) {
        let needTransfer = false

        try {
            const acc = await this.contract.getAccount(provider)
            const lockedFund = acc.balance - acc.pendingRefund
            needTransfer = lockedFund < triggerThreshold
        } catch {
            needTransfer = true
        }

        if (needTransfer) {
            try {
                await this.ledger.transferFund(
                    provider,
                    'inference',
                    targetThreshold,
                    gasPrice
                )
            } catch (error: any) {
                // Check if it's an insufficient balance error
                const errorMessage = error?.message?.toLowerCase() || ''
                if (errorMessage.includes('insufficient')) {
                    throw new Error(
                        `To ensure stable service from the provider, ${targetThreshold} neuron needs to be transferred from the balance, but the current balance is insufficient.`
                    )
                }
                throw error
            }
        }

        // Mark the first round as complete
        await this.cache.setItem(
            CACHE_KEYS.FIRST_ROUND,
            'false',
            10000000 * 60 * 1000,
            CacheValueTypeEnum.Other
        )
    }

    /**
     * Check the cache fund for this provider, return true if the fund is above checkAccountThreshold * (inputPrice + outputPrice)
     * @param svc
     */
    async shouldCheckAccount(svc: ServiceStructOutput) {
        try {
            const key = CacheKeyHelpers.getCachedFeeKey(svc.provider)
            const usedFund = (await this.cache.getItem(key)) || BigInt(0)
            return (
                usedFund >
                this.checkAccountThreshold * (svc.inputPrice + svc.outputPrice)
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }
}

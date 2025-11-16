import type { InferenceServingContract } from '../contract'
import { ChatBot } from '../extractor'
import type { Extractor } from '../extractor'
import type { ServiceStructOutput } from '../contract'
import type { ServingRequestHeaders } from './request'
import { throwFormattedError } from '../../common/utils'
import * as fs from 'fs/promises'
import type { Cache, Metadata } from '../../common/storage'
import {
    CacheValueTypeEnum,
    CACHE_KEYS,
    CacheKeyHelpers,
} from '../../common/storage'
import type { LedgerBroker } from '../../ledger'
import { keccak256, toUtf8Bytes } from 'ethers'
import { logger } from '../../common/logger'
import { TextToImage } from '../extractor/textToImage'
import { SpeechToText } from '../extractor/speech-to-text'

export interface TdxQuoteResponse {
    rawReport: string
    signingAddress: string
}

export interface SessionToken {
    address: string
    provider: string
    timestamp: number
    expiresAt: number
    nonce: string
}

export interface CachedSession {
    token: SessionToken
    signature: string
    rawMessage: string
}

export abstract class ZGServingUserBrokerBase {
    protected contract: InferenceServingContract
    protected metadata: Metadata
    protected cache: Cache

    private checkAccountThreshold = BigInt(100)
    private topUpTriggerThreshold = BigInt(1000000)
    private topUpTargetThreshold = BigInt(2000000)
    protected ledger: LedgerBroker

    private sessionDuration = 24 * 60 * 60 * 1000 // 24 hours validity

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
            logger.debug('Fetched service info from contract:', svc)
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

    async getQuote(providerAddress: string): Promise<TdxQuoteResponse> {
        try {
            const service = await this.getService(providerAddress)
            const url = service.url

            const endpoint = `${url}/v1/quote`

            const rawReport = await this.fetchText(endpoint, {
                method: 'GET',
            })

            return {
                rawReport,
                signingAddress: '',
            } as TdxQuoteResponse
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async downloadQuoteReport(
        providerAddress: string,
        outputPath: string
    ): Promise<void> {
        try {
            const service = await this.getService(providerAddress)

            const url = service.url
            const endpoint = `${url}/v1/quote`

            const quoteString = await this.fetchText(endpoint, {
                method: 'GET',
            })

            await fs.writeFile(outputPath, quoteString)
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
            if (account.acknowledged) {
                await this.cache.setItem(
                    key,
                    '',
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
            case 'text-to-image':
                return new TextToImage(svc)
            case 'speech-to-text':
                return new SpeechToText(svc)
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

    private generateNonce(): string {
        if (typeof window !== 'undefined' && window.crypto) {
            // Browser environment - use Web Crypto API
            const array = new Uint8Array(16)
            window.crypto.getRandomValues(array)
            return Array.from(array, (byte) =>
                byte.toString(16).padStart(2, '0')
            ).join('')
        } else {
            // Node.js or other environment - use timestamp-based nonce
            const timestamp = Date.now()
            const random = Math.random()
            const randomStr = random.toString(36).substring(2, 15)
            return `${timestamp}-${randomStr}`.padEnd(32, '0')
        }
    }

    async generateSessionToken(
        providerAddress: string,
        sessionDuration?: number
    ): Promise<CachedSession> {
        const userAddress = this.contract.getUserAddress()
        const timestamp = Date.now()
        const duration = sessionDuration ?? this.sessionDuration
        const expiresAt = timestamp + duration
        const nonce = this.generateNonce()

        const token: SessionToken = {
            address: userAddress,
            provider: providerAddress,
            timestamp,
            expiresAt,
            nonce,
        }

        // Create message to be signed
        const message = JSON.stringify(token)

        // Create hash using the same method as signRequest in encrypt.ts
        const messageHash = keccak256(toUtf8Bytes(message))

        // Sign using the same pattern as signRequest: signMessage with toBeArray
        const signature = await this.contract.signer.signMessage(
            Buffer.from(messageHash.slice(2), 'hex')
        )

        const session: CachedSession = {
            token,
            signature,
            rawMessage: message,
        }

        // Cache the session using the existing cache with proper TTL
        const cacheKey = CacheKeyHelpers.getSessionTokenKey(
            userAddress,
            providerAddress
        )
        await this.cache.setItem(
            cacheKey,
            session,
            duration,
            CacheValueTypeEnum.Session
        )

        return session
    }

    async getOrCreateSession(providerAddress: string): Promise<CachedSession> {
        const userAddress = this.contract.getUserAddress()
        const cacheKey = CacheKeyHelpers.getSessionTokenKey(
            userAddress,
            providerAddress
        )
        const cached = (await this.cache.getItem(
            cacheKey
        )) as CachedSession | null

        // Check if cached session exists and is not expired (with 1 hour buffer)
        if (cached && cached.token.expiresAt > Date.now() + 60 * 60 * 1000) {
            return cached
        }

        // Generate new session
        return await this.generateSessionToken(providerAddress)
    }

    async getHeader(providerAddress: string): Promise<ServingRequestHeaders> {
        // Check if provider is acknowledged - this is still necessary
        if (!(await this.userAcknowledged(providerAddress))) {
            throw new Error('Provider signer is not acknowledged')
        }

        // Get or create session token
        const session = await this.getOrCreateSession(providerAddress)

        return {
            Authorization: `Bearer app-sk-${Buffer.from(
                session.rawMessage + '|' + session.signature
            ).toString('base64')}`,
        }
    }

    async calculateFee(extractor: Extractor, content: string): Promise<bigint> {
        const svc = await extractor.getSvcInfo()
        const outputCount = await extractor.getOutputCount(content)
        const inputCount = await extractor.getInputCount(content)
        return (
            BigInt(outputCount) * BigInt(svc.outputPrice) +
            BigInt(inputCount) * BigInt(svc.inputPrice)
        )
    }

    async updateCachedFee(provider: string, fee: bigint) {
        try {
            const cacheFundKey = CacheKeyHelpers.getCachedFeeKey(provider)
            const balanceCheckKey = CacheKeyHelpers.getCheckBalanceKey(provider)
            const accumulatedCheckFee =
                (await this.cache.getItem(balanceCheckKey)) || BigInt(0)
            await this.cache.setItem(
                balanceCheckKey,
                BigInt(accumulatedCheckFee) + fee,
                1 * 60 * 1000,
                CacheValueTypeEnum.BigInt
            )
            const curFee = (await this.cache.getItem(cacheFundKey)) || BigInt(0)
            await this.cache.setItem(
                cacheFundKey,
                BigInt(curFee) + fee,
                1 * 60 * 1000,
                CacheValueTypeEnum.BigInt
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async clearBalanceCheckFee(provider: string) {
        try {
            const key = CacheKeyHelpers.getCheckBalanceKey(provider)
            await this.cache.setItem(
                key,
                BigInt(0),
                1 * 60 * 1000,
                CacheValueTypeEnum.BigInt
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async clearCacheFee(provider: string) {
        try {
            const key = CacheKeyHelpers.getCachedFeeKey(provider)
            await this.cache.setItem(
                key,
                BigInt(0),
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
        content?: string,
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
                this.topUpTargetThreshold *
                (BigInt(svc.inputPrice) + BigInt(svc.outputPrice))
            const triggerThreshold =
                this.topUpTriggerThreshold *
                (BigInt(svc.inputPrice) + BigInt(svc.outputPrice))

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

            let newFee = BigInt(0)
            if (content) {
                newFee = await this.calculateFee(extractor, content)
                await this.updateCachedFee(provider, newFee)
            }

            // Check if we need to check the account
            if (!(await this.shouldCheckAccount(svc))) return

            await this.clearBalanceCheckFee(provider)

            // Re-check the account balance
            let needTransfer = false
            try {
                const acc = await this.contract.getAccount(provider)
                const lockedFund = acc.balance - acc.pendingRefund

                logger.debug(
                    `Locked fund for provider ${provider}: ${lockedFund.toString()}, trigger threshold: ${triggerThreshold.toString()}`
                )
                needTransfer = lockedFund < triggerThreshold
            } catch {
                // Account doesn't exist, need to create it by transferring funds
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
                    await this.clearCacheFee(provider)
                } catch (error: any) {
                    // Check if it's an insufficient balance error
                    const errorMessage = error?.message?.toLowerCase() || ''
                    if (errorMessage.includes('insufficient')) {
                        console.warn(
                            `Warning: To ensure stable service from the provider, ${targetThreshold} neuron needs to be transferred from the balance, but the current balance is insufficient.`
                        )
                        return
                    }
                    console.warn(
                        `Warning: Failed to transfer funds: ${
                            error?.message || error
                        }`
                    )
                    return
                }
            }
        } catch (error: any) {
            console.warn(
                `Warning: Top up account failed: ${error?.message || error}`
            )
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
                    console.warn(
                        `Warning: To ensure stable service from the provider, ${targetThreshold} neuron needs to be transferred from the balance, but the current balance is insufficient.`
                    )
                    return
                }
                console.warn(
                    `Warning: Failed to transfer funds: ${
                        error?.message || error
                    }`
                )
                return
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
            const key = CacheKeyHelpers.getCheckBalanceKey(svc.provider)
            const accumulatedFund = (await this.cache.getItem(key)) || BigInt(0)
            logger.debug(
                `Accumulated fund for provider before checking balance ${
                    svc.provider
                }: ${accumulatedFund.toString()} and threshold to check account balance: ${
                    this.checkAccountThreshold *
                    (svc.inputPrice + svc.outputPrice)
                }`
            )
            return (
                accumulatedFund >
                this.checkAccountThreshold * (svc.inputPrice + svc.outputPrice)
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }
}

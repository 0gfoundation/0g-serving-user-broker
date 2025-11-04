import { ZGServingUserBrokerBase } from './base'
import type { Cache, Metadata } from '../../common/storage'
import type { InferenceServingContract } from '../contract'
import type { LedgerBroker } from '../../ledger'
import { Automata } from '../../common/automata '
import { CacheValueTypeEnum, CacheKeyHelpers } from '../../common/storage'
import { throwFormattedError } from '../../common/utils'
// import { Verifier } from './verifier'

/**
 * ServingRequestHeaders contains headers related to request.
 * Only Address and VLLM-Proxy are required now.
 */
export interface ServingRequestHeaders {
    /**
     * @deprecated This field is no longer used but kept for backwards compatibility
     */
    'X-Phala-Signature-Type'?: 'StandaloneApi'
    /**
     * User's address
     */
    Address: string
    /**
     * @deprecated Total fee for the request - no longer used
     */
    Fee?: string
    /**
     * @deprecated Fee required for the input - no longer used
     */
    'Input-Fee'?: string
    /**
     * @deprecated Pedersen hash - no longer used
     */
    'Request-Hash'?: string
    /**
     * @deprecated Nonce - no longer used
     */
    Nonce?: string
    /**
     * @deprecated User's signature - no longer used
     */
    Signature?: string
    /**
     * Session token containing user info and expiry
     */
    'Session-Token': string
    /**
     * Signature of the session token
     */
    'Session-Signature': string
}

/**
 * RequestProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
export class RequestProcessor extends ZGServingUserBrokerBase {
    protected automata: Automata

    constructor(
        contract: InferenceServingContract,
        metadata: Metadata,
        cache: Cache,
        ledger: LedgerBroker
    ) {
        super(contract, ledger, metadata, cache)
        this.automata = new Automata()
    }

    async getServiceMetadata(providerAddress: string): Promise<{
        endpoint: string
        model: string
    }> {
        const service = await this.getService(providerAddress)
        return {
            endpoint: `${service.url}/v1/proxy`,
            model: service.model,
        }
    }

    /*
     * 1. To Ensure No Insufficient Balance Occurs.
     *
     * The provider settles accounts regularly. In addition, we will add a rule to the provider's settlement logic:
     * if the actual balance of the customer's account is less than 500, settlement will be triggered immediately.
     * The actual balance is defined as the customer's inference account balance minus any unsettled amounts.
     *
     * This way, if the customer checks their account and sees a balance greater than 500, even if the provider settles
     * immediately, the deduction will leave about 500, ensuring that no insufficient balance situation occurs.
     *
     * 2. To Avoid Frequent Transfers
     *
     * On the customer's side, if the balance falls below 500, it should be topped up to 1000. This is to avoid frequent
     * transfers.
     *
     * 3. To Avoid Having to Check the Balance on Every Customer Request
     *
     * Record expenditures in processResponse and maintain a total consumption amount. Every time the total expenditure
     * reaches 1000, recheck the balance and perform a transfer if necessary.
     *
     * ps: The units for 500 and 1000 can be (service.inputPricePerToken + service.outputPricePerToken).
     */
    async getRequestHeaders(
        providerAddress: string,
        content: string
    ): Promise<ServingRequestHeaders> {
        try {
            await this.topUpAccountIfNeeded(providerAddress, content)
            // Simplified call - only pass required parameters
            return await this.getHeader(providerAddress)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Check if provider's TEE signer is acknowledged by the contract owner.
     * This method no longer performs acknowledgement (which is owner-only),
     * but verifies if the provider is ready for use.
     */
    async checkProviderSignerStatus(
        providerAddress: string,
        gasPrice?: number
    ): Promise<{
        isAcknowledged: boolean
        teeSignerAddress: string
    }> {
        try {
            // Ensure user has an account with the provider
            try {
                await this.contract.getAccount(providerAddress)
            } catch {
                await this.ledger.transferFund(
                    providerAddress,
                    'inference',
                    BigInt(0),
                    gasPrice
                )
            }

            // Get service information (now contains TEE signer info)
            const service = await this.getService(providerAddress)

            const userAddress = this.contract.getUserAddress()
            const cacheKey = CacheKeyHelpers.getUserAckKey(
                userAddress,
                providerAddress
            )
            
            if (
                service.teeSignerAcknowledged &&
                service.teeSignerAddress !==
                    '0x0000000000000000000000000000000000000000'
            ) {
                // Cache the acknowledgement status
                this.cache.setItem(
                    cacheKey,
                    service.teeSignerAddress,
                    10 * 60 * 1000, // 10 minutes cache
                    CacheValueTypeEnum.Other
                )

                return {
                    isAcknowledged: true,
                    teeSignerAddress: service.teeSignerAddress,
                }
            } else {
                return {
                    isAcknowledged: false,
                    teeSignerAddress: service.teeSignerAddress || '',
                }
            }
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * @deprecated Use checkProviderSignerStatus instead.
     * TEE signer acknowledgement is now handled by contract owner only.
     */
    async acknowledgeProviderSigner(
        providerAddress: string,
        gasPrice?: number
    ): Promise<void> {
        console.warn(
            'acknowledgeProviderSigner is deprecated. Use checkProviderSignerStatus instead.'
        )
        const status = await this.checkProviderSignerStatus(
            providerAddress,
            gasPrice
        )

        if (!status.isAcknowledged) {
            throw new Error(
                `Provider ${providerAddress} TEE signer is not acknowledged by contract owner. Contact the service administrator.`
            )
        }
    }

    /**
     * Acknowledge TEE Signer (Contract Owner Only)
     *
     * @param providerAddress - The address of the provider
     */
    async ownerAcknowledgeTEESigner(
        providerAddress: string,
        gasPrice?: number
    ): Promise<void> {
        try {
            await this.contract.acknowledgeTEESigner(providerAddress, gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Revoke TEE Signer Acknowledgement (Contract Owner Only)
     *
     * @param providerAddress - The address of the provider
     */
    async ownerRevokeTEESignerAcknowledgement(
        providerAddress: string,
        gasPrice?: number
    ): Promise<void> {
        try {
            await this.contract.revokeTEESignerAcknowledgement(providerAddress, gasPrice)
        } catch (error) {
            throwFormattedError(error)
        }
    }
}

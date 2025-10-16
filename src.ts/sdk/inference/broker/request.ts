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
     * Broker service use a proxy for chat signature
     */
    'VLLM-Proxy': string
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
        content: string,
        vllmProxy?: boolean
    ): Promise<ServingRequestHeaders> {
        try {
            await this.topUpAccountIfNeeded(providerAddress, content)
            if (vllmProxy === undefined) {
                vllmProxy = true
            }
            // Simplified call - only pass required parameters
            return await this.getHeader(providerAddress, vllmProxy)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async acknowledgeProviderSigner(
        providerAddress: string,
        gasPrice?: number
    ): Promise<void> {
        try {
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

            let { quote, provider_signer } = await this.getQuote(
                providerAddress
            )

            if (!quote || !provider_signer) {
                throw new Error('Invalid quote')
            }
            if (!quote.startsWith('0x')) {
                quote = '0x' + quote
            }

            // const rpc = process.env.RPC_ENDPOINT
            // // bypass quote verification if testing on localhost
            // if (!rpc || !/localhost|127\.0\.0\.1/.test(rpc)) {
            //     const isVerified = await this.automata.verifyQuote(quote)
            //     console.log('Quote verification:', isVerified)
            //     if (!isVerified) {
            //         throw new Error('Quote verification failed')
            //     }

            //     // if (nvidia_payload) {
            //     //     const svc = await this.getService(providerAddress)
            //     //     const valid = await Verifier.verifyRA(
            //     //         svc.url,
            //     //         nvidia_payload
            //     //     )
            //     //     console.log('nvidia payload verification:', valid)

            //     //     if (!valid) {
            //     //         throw new Error('nvidia payload verify failed')
            //     //     }
            //     // }
            // }

            const account = await this.contract.getAccount(providerAddress)
            if (account.teeSignerAddress === provider_signer) {
                console.log('Provider signer already acknowledged')
                return
            }

            await this.contract.acknowledgeTEESigner(
                providerAddress,
                provider_signer
            )

            const userAddress = this.contract.getUserAddress()
            const cacheKey = CacheKeyHelpers.getUserAckKey(
                userAddress,
                providerAddress
            )
            this.cache.setItem(
                cacheKey,
                provider_signer,
                1 * 60 * 1000,
                CacheValueTypeEnum.Other
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }
}

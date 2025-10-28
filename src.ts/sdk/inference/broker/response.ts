import type { InferenceServingContract } from '../contract'
import type { Extractor } from '../extractor'
import type { Metadata, Cache } from '../../common/storage'
import { ZGServingUserBrokerBase } from './base'
import { isVerifiability } from './model'
import { Verifier } from './verifier'
import type { LedgerBroker } from '../../ledger'
import { throwFormattedError } from '../../common/utils'
import { logger } from '../../common/logger'

/**
 * ResponseProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
export class ResponseProcessor extends ZGServingUserBrokerBase {
    private verifier: Verifier

    constructor(
        contract: InferenceServingContract,
        ledger: LedgerBroker,
        metadata: Metadata,
        cache: Cache
    ) {
        super(contract, ledger, metadata, cache)
        this.verifier = new Verifier(contract, ledger, metadata, cache)
    }

    async processResponse(
        providerAddress: string,
        content: string,
        chatID?: string,
        vllmProxy?: boolean
    ): Promise<boolean | null> {
        try {
            const extractor = await this.getExtractor(providerAddress)
            const outputFee = await this.calculateOutputFees(extractor, content)
            await this.updateCachedFee(providerAddress, outputFee)

            const svc = await extractor.getSvcInfo()
            if (!isVerifiability(svc.verifiability)) {
                return false
            }

            if (!chatID) {
                throw new Error('Chat ID does not exist')
            }
            logger.debug('Chat ID:', chatID)

            if (vllmProxy === undefined) {
                vllmProxy = true
            }

            let singerRAVerificationResult =
                await this.verifier.getSigningAddress(
                    providerAddress,
                    false,
                    vllmProxy
                )

            logger.debug(
                'Singer RA Verification Result:',
                singerRAVerificationResult
            )
            if (!singerRAVerificationResult.valid) {
                singerRAVerificationResult =
                    await this.verifier.getSigningAddress(
                        providerAddress,
                        true,
                        vllmProxy
                    )
            }

            if (!singerRAVerificationResult.valid) {
                throw new Error('Signing address is invalid')
            }

            logger.debug(
                'Fetching signature from provider broker URL:',
                svc.url,
                vllmProxy
                    ? 'with proxied LLM server'
                    : 'with original LLM server'
            )
            const ResponseSignature = await Verifier.fetSignatureByChatID(
                svc.url,
                chatID,
                svc.model,
                vllmProxy
            )

            return Verifier.verifySignature(
                ResponseSignature.text,
                ResponseSignature.signature,
                singerRAVerificationResult.signingAddress
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    private async calculateOutputFees(
        extractor: Extractor,
        content: string
    ): Promise<bigint> {
        const svc = await extractor.getSvcInfo()
        logger.debug('Service Info:', svc)
        const outputCount = await extractor.getOutputCount(content)
        return BigInt(outputCount) * BigInt(svc.outputPrice)
    }
}

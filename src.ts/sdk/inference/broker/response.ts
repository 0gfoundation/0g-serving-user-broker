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

    constructor(
        contract: InferenceServingContract,
        ledger: LedgerBroker,
        metadata: Metadata,
        cache: Cache
    ) {
        super(contract, ledger, metadata, cache)
    }

    async processResponse(
        providerAddress: string,
        content: string,
        chatID?: string
    ): Promise<boolean | null> {
        try {
            const extractor = await this.getExtractor(providerAddress)
            const outputFee = await this.calculateOutputFees(extractor, content)
            await this.updateCachedFee(providerAddress, outputFee)

            const svc = await extractor.getSvcInfo()
            if (!isVerifiability(svc.verifiability)) {
                console.warn('this service is not verifiable')
                return false
            }

            if (!svc.teeSignerAcknowledged) {
                console.warn('TEE Signer is not acknowledged')
                return false
            }

            if (!chatID) {
                throw new Error('Chat ID does not exist')
            }

            if (!svc.additionalInfo) {
                console.warn('Service additionalInfo does not exist')
                return false
            }

            logger.debug('Chat ID:', chatID)

            // Parse additionalInfo JSON to determine signing address
            // based on https://github.com/0gfoundation/0g-serving-broker/api/inference/internal/contract/service.go
            let signingAddress = svc.teeSignerAddress

            try {
                const additionalInfo = JSON.parse(svc.additionalInfo)
                if (
                    additionalInfo.TargetSeparated === true &&
                    additionalInfo.TargetTeeAddress
                ) {
                    signingAddress = additionalInfo.TargetTeeAddress
                }
            } catch (error) {
                // If JSON parsing fails, fall back to using additionalInfo as the address directly (backward compatibility)
                logger.warn(
                    'Failed to parse additionalInfo as JSON',
                    error
                )
                return false
            }

            logger.debug('signing address:', signingAddress)

            const ResponseSignature = await Verifier.fetchSignatureByChatID(
                svc.url,
                chatID,
                svc.model
            )

            return Verifier.verifySignature(
                ResponseSignature.text,
                ResponseSignature.signature,
                signingAddress
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

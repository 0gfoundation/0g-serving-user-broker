import type { InferenceServingContract } from '../contract'
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
        chatID?: string,
        content?: string // For chatbot: usage JSON with input_tokens/output_tokens; For speech-to-text: usage JSON, duration-billed ({"type":"duration","seconds":N}) or token-billed ({"type":"tokens",...}); For text-to-image: empty/undefined
    ): Promise<boolean | null> {
        try {
            const extractor = await this.getExtractor(providerAddress)
            if (content) {
                const fee = await this.calculateFee(extractor, content)
                logger.debug(`Calculated fee: ${fee.toString()}`)
                await this.updateCachedFee(providerAddress, fee)
            }

            if (!chatID) {
                // If no chatID provided, skip verifiability check
                return null
            }

            const svc = await extractor.getSvcInfo()
            if (!isVerifiability(svc.verifiability)) {
                logger.warn('this service is not verifiable')
                return false
            }

            if (!svc.teeSignerAcknowledged) {
                logger.warn('TEE Signer is not acknowledged')
                return false
            }

            if (!svc.additionalInfo) {
                logger.warn('Service additionalInfo does not exist')
                return false
            }

            logger.debug('Chat ID:', chatID)

            // Parse additionalInfo JSON to determine signing address
            // based on https://github.com/0gfoundation/0g-serving-broker/api/inference/internal/contract/service.go
            let signingAddress = svc.teeSignerAddress

            try {
                const additionalInfo = JSON.parse(svc.additionalInfo)
                let providerType = additionalInfo.ProviderType || 'decentralized'
                if (providerType !== 'decentralized' && providerType !== 'centralized') {
                    logger.warn(`Invalid ProviderType: ${providerType}, defaulting to 'decentralized'`)
                    providerType = 'decentralized'
                }
                const isCentralized = providerType === 'centralized'

                if (
                    additionalInfo.TargetSeparated === true &&
                    !isCentralized &&
                    additionalInfo.TargetTeeAddress
                ) {
                    // Separated decentralized: LLM runs in its own TEE, verify against LLM's TEE signer
                    signingAddress = additionalInfo.TargetTeeAddress
                }
                // For centralized providers (TargetSeparated=true but ProviderType='centralized'),
                // the broker TEE signs the response, so we keep svc.teeSignerAddress
            } catch (error) {
                // If JSON parsing fails, fall back to using additionalInfo as the address directly (backward compatibility)
                logger.warn('Failed to parse additionalInfo as JSON', error)
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
}

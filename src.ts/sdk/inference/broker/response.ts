import type { InferenceServingContract } from '../contract'
import type { Extractor } from '../extractor'
import type { Metadata, Cache } from '../../common/storage'
import { ZGServingUserBrokerBase } from './base'
import { isVerifiability } from './model'
import { Verifier } from './verifier'
import type { LedgerBroker } from '../../ledger'
import { throwFormattedError } from '../../common/utils'

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

            if (vllmProxy === undefined) {
                vllmProxy = true
            }

            let singerRAVerificationResult =
                await this.verifier.getSigningAddress(providerAddress)

            console.log(
                'singerRAVerificationResult',
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
        const outputCount = await extractor.getOutputCount(content)
        return BigInt(outputCount) * BigInt(svc.outputPrice)
    }
}

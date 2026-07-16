import { describe, it } from 'mocha'
import { expect } from 'chai'
import {
    parseTieredPricing,
    parseTieredPricingFromModelInfo,
    ProviderModelInfo,
} from '../read-only-model'

describe('tiered pricing multiplier fold', () => {
    it('folds num/den into an effective decimal (HTTP /v1/models)', () => {
        const modelInfo = {
            pricing: {
                tiered_pricing: [
                    {
                        max_input_tokens: 32000,
                        input_multiplier: 1,
                        output_multiplier: 1,
                    },
                    {
                        max_input_tokens: 0,
                        input_multiplier: 3,
                        input_multiplier_denominator: 2, // 1.5x
                        output_multiplier: 5,
                        output_multiplier_denominator: 2, // 2.5x
                    },
                ],
            },
        } as unknown as ProviderModelInfo

        const parsed = parseTieredPricingFromModelInfo(modelInfo)
        expect(parsed?.tiers).to.have.length(2)
        expect(parsed!.tiers[0].inputMultiplier).to.equal(1)
        expect(parsed!.tiers[1].inputMultiplier).to.equal(1.5)
        expect(parsed!.tiers[1].outputMultiplier).to.equal(2.5)
    })

    it('treats a missing denominator as 1 (legacy integer config unchanged)', () => {
        const modelInfo = {
            pricing: {
                tiered_pricing: [
                    {
                        max_input_tokens: 0,
                        input_multiplier: 4,
                        output_multiplier: 3,
                    },
                ],
            },
        } as unknown as ProviderModelInfo

        const parsed = parseTieredPricingFromModelInfo(modelInfo)
        expect(parsed!.tiers[0].inputMultiplier).to.equal(4)
        expect(parsed!.tiers[0].outputMultiplier).to.equal(3)
    })

    it('folds num/den from on-chain additionalInfo', () => {
        const additionalInfo = JSON.stringify({
            tieredPricing: {
                tiers: [
                    {
                        maxInputTokens: 0,
                        inputMultiplier: 3,
                        inputMultiplierDenominator: 2,
                        outputMultiplier: 2,
                        // outputMultiplierDenominator omitted -> 1
                    },
                ],
            },
        })

        const parsed = parseTieredPricing(additionalInfo)
        expect(parsed!.tiers[0].inputMultiplier).to.equal(1.5)
        expect(parsed!.tiers[0].outputMultiplier).to.equal(2)
    })
})

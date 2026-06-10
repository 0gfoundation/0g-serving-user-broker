// Unit tests for the speech-to-text usage extractor's dual billing modes.
// The dispatch rules must stay in sync with the broker's settlement logic
// (isDurationUsage / billableSeconds in 0g-serving-broker): the cached fee
// estimate the SDK computes drives auto top-up, and a divergence between the
// two re-introduces the zero-fee bug class the broker fixed in PR #523.

import { expect } from 'chai'
import { describe, it } from 'mocha'
import { SpeechToText } from '../speech-to-text'
import type { ServiceStructOutput } from '../../contract'

const svcInfo = {} as ServiceStructOutput

const extractor = new SpeechToText(svcInfo)

describe('SpeechToText extractor', () => {
    describe('duration-billed usage (whisper family)', () => {
        it('uses seconds as input count', async () => {
            const usage = JSON.stringify({ type: 'duration', seconds: 207 })
            expect(await extractor.getInputCount(usage)).to.equal(207)
            expect(await extractor.getOutputCount(usage)).to.equal(0)
        })

        it('rounds fractional seconds to the nearest second', async () => {
            expect(
                await extractor.getInputCount(
                    JSON.stringify({ type: 'duration', seconds: 207.5 })
                )
            ).to.equal(208)
            expect(
                await extractor.getInputCount(
                    JSON.stringify({ type: 'duration', seconds: 207.4 })
                )
            ).to.equal(207)
        })

        it('floors sub-second positive durations to 1 second', async () => {
            expect(
                await extractor.getInputCount(
                    JSON.stringify({ type: 'duration', seconds: 0.4 })
                )
            ).to.equal(1)
        })

        it('returns 0 for zero or negative seconds', async () => {
            expect(
                await extractor.getInputCount(
                    JSON.stringify({ type: 'duration', seconds: 0 })
                )
            ).to.equal(0)
            expect(
                await extractor.getInputCount(
                    JSON.stringify({ type: 'duration', seconds: -5 })
                )
            ).to.equal(0)
        })

        it('routes to duration when seconds is populated without a type field', async () => {
            const usage = JSON.stringify({ seconds: 42 })
            expect(await extractor.getInputCount(usage)).to.equal(42)
            expect(await extractor.getOutputCount(usage)).to.equal(0)
        })
    })

    describe('token-billed usage (gpt-4o-transcribe family)', () => {
        it('uses input_tokens and output_tokens', async () => {
            const usage = JSON.stringify({
                type: 'tokens',
                input_tokens: 120,
                output_tokens: 30,
            })
            expect(await extractor.getInputCount(usage)).to.equal(120)
            expect(await extractor.getOutputCount(usage)).to.equal(30)
        })

        it('stays on the tokens path even with a stray seconds field', async () => {
            const usage = JSON.stringify({
                type: 'tokens',
                input_tokens: 120,
                output_tokens: 0,
                seconds: 99,
            })
            expect(await extractor.getInputCount(usage)).to.equal(120)
            expect(await extractor.getOutputCount(usage)).to.equal(0)
        })

        it('accepts string-encoded token counts', async () => {
            const usage = JSON.stringify({
                type: 'tokens',
                input_tokens: '120',
                output_tokens: '30',
            })
            expect(await extractor.getInputCount(usage)).to.equal(120)
            expect(await extractor.getOutputCount(usage)).to.equal(30)
        })
    })

    describe('malformed usage', () => {
        it('returns 0 for empty content', async () => {
            expect(await extractor.getInputCount('')).to.equal(0)
            expect(await extractor.getOutputCount('')).to.equal(0)
        })

        it('returns 0 for invalid JSON', async () => {
            expect(await extractor.getInputCount('not json')).to.equal(0)
            expect(await extractor.getOutputCount('not json')).to.equal(0)
        })

        it('returns 0 for an empty usage object', async () => {
            expect(await extractor.getInputCount('{}')).to.equal(0)
            expect(await extractor.getOutputCount('{}')).to.equal(0)
        })
    })
})

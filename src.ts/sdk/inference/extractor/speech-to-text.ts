import type { ServiceStructOutput } from '../contract'
import { Extractor } from './extractor'

/**
 * Speech-to-text usage shape returned by providers. Two billing modes exist,
 * mirroring the broker's settlement logic:
 *
 * - duration (whisper family): `{"type":"duration","seconds":N}`. The service
 *   inputPrice is interpreted as price-per-second; outputPrice is unused.
 * - tokens (gpt-4o-transcribe family): `{"type":"tokens","input_tokens":N,"output_tokens":N}`.
 *   Standard per-token pricing applies.
 *
 * Dispatch rule (must stay in sync with the broker's isDurationUsage): trust
 * an explicit `type` discriminator when present; otherwise treat usage with a
 * positive `seconds` as duration-billed.
 */
interface SpeechToTextUsage {
    type?: string
    seconds?: number
    input_tokens?: number | string
    output_tokens?: number | string
}

function parseUsage(content: string): SpeechToTextUsage | null {
    if (!content) {
        return null
    }
    try {
        const usage = JSON.parse(content)
        return usage && typeof usage === 'object' ? usage : null
    } catch {
        return null
    }
}

function toCount(value: number | string | undefined): number {
    const num = typeof value === 'string' ? parseInt(value, 10) : value
    return typeof num === 'number' && !isNaN(num) && num > 0 ? num : 0
}

function isDurationUsage(usage: SpeechToTextUsage): boolean {
    const seconds = typeof usage.seconds === 'number' ? usage.seconds : 0
    return usage.type === 'duration' || (usage.type !== 'tokens' && seconds > 0)
}

/**
 * Billable seconds for duration-mode usage: round to the nearest second with
 * a 1-second floor for any positive duration, matching the broker's
 * billableSeconds() so the cached fee estimate agrees with settlement.
 */
function billableSeconds(usage: SpeechToTextUsage): number {
    const seconds = typeof usage.seconds === 'number' ? usage.seconds : 0
    if (seconds <= 0) {
        return 0
    }
    return Math.max(Math.round(seconds), 1)
}

export class SpeechToText extends Extractor {
    svcInfo: ServiceStructOutput

    constructor(svcInfo: ServiceStructOutput) {
        super()
        this.svcInfo = svcInfo
    }

    getSvcInfo(): Promise<ServiceStructOutput> {
        return Promise.resolve(this.svcInfo)
    }

    async getInputCount(content: string): Promise<number> {
        const usage = parseUsage(content)
        if (!usage) {
            return 0
        }
        if (isDurationUsage(usage)) {
            // Duration billing: inputPrice is price-per-second
            return billableSeconds(usage)
        }
        return toCount(usage.input_tokens)
    }

    async getOutputCount(content: string): Promise<number> {
        const usage = parseUsage(content)
        if (!usage) {
            return 0
        }
        if (isDurationUsage(usage)) {
            // Duration billing has no generation-side cost
            return 0
        }
        return toCount(usage.output_tokens)
    }
}

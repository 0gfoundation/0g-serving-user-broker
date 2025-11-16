import type { ServiceStructOutput } from '../contract'
import { Extractor } from './extractor'

export class SpeechToText extends Extractor {
    svcInfo: ServiceStructOutput

    constructor(svcInfo: ServiceStructOutput) {
        super()
        this.svcInfo = svcInfo
    }

    getSvcInfo(): Promise<ServiceStructOutput> {
        return Promise.resolve(this.svcInfo)
    }

    async getInputCount(_content: string): Promise<number> {
        // For speech-to-text, inputCount should always be 0
        // as the actual token counts come from the usage field
        return 0
    }

    async getOutputCount(content: string): Promise<number> {
        // For speech-to-text, parse the usage field to get token counts
        // content should be a JSON string with usage field containing input_tokens and output_tokens
        if (!content) {
            return 0
        }
        
        try {
            const usage = JSON.parse(content)
            // We only care about output_tokens from the usage object
            if (usage && usage.output_tokens !== undefined) {
                const tokens = typeof usage.output_tokens === 'string' ? parseInt(usage.output_tokens, 10) : usage.output_tokens
                return typeof tokens === 'number' && !isNaN(tokens) ? tokens : 0
            }
            return 0
        } catch {
            // If parsing fails, return 0
            return 0
        }
    }
}

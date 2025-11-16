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

    async getInputCount(content: string): Promise<number> {
        if (!content) {
            return 0
        }
        const utf8Encoder = new TextEncoder()
        const encoded = utf8Encoder.encode(content)
        return encoded.length
    }

    async getOutputCount(content: string): Promise<number> {
        if (!content) {
            return 0
        }
        const utf8Encoder = new TextEncoder()
        const encoded = utf8Encoder.encode(content)
        return encoded.length
    }
}

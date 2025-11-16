import type { ServiceStructOutput } from '../contract';
import { Extractor } from './extractor';
export declare class SpeechToText extends Extractor {
    svcInfo: ServiceStructOutput;
    constructor(svcInfo: ServiceStructOutput);
    getSvcInfo(): Promise<ServiceStructOutput>;
    getInputCount(content: string): Promise<number>;
    getOutputCount(content: string): Promise<number>;
}
//# sourceMappingURL=speech-to-text.d.ts.map
import type { ServiceStructOutput } from '../contract';
import { Extractor } from './extractor';
export declare class ChatBot extends Extractor {
    svcInfo: ServiceStructOutput;
    constructor(svcInfo: ServiceStructOutput);
    getSvcInfo(): Promise<ServiceStructOutput>;
    getInputCount(content?: string): Promise<number>;
    getOutputCount(content?: string): Promise<number>;
}
//# sourceMappingURL=chatbot.d.ts.map
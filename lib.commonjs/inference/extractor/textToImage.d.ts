import type { ServiceStructOutput } from '../contract';
import { Extractor } from './extractor';
export declare class TextToImage extends Extractor {
    svcInfo: ServiceStructOutput;
    constructor(svcInfo: ServiceStructOutput);
    getSvcInfo(): Promise<ServiceStructOutput>;
    getInputCount(content: string): Promise<number>;
    getOutputCount(_content: string): Promise<number>;
}
//# sourceMappingURL=textToImage.d.ts.map
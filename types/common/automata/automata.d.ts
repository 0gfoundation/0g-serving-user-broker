import { ethers } from 'ethers';
export declare class Automata {
    protected provider: any;
    protected contract: ethers.Contract;
    constructor();
    verifyQuote(rawQuote: string): Promise<boolean | undefined>;
}
//# sourceMappingURL=automata.d.ts.map
import type { InferenceServingContract } from '../contract';
import type { Metadata, Cache } from '../../common/storage';
import { ZGServingUserBrokerBase } from './base';
import type { LedgerBroker } from '../../ledger';
/**
 * ResponseProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
export declare class ResponseProcessor extends ZGServingUserBrokerBase {
    constructor(contract: InferenceServingContract, ledger: LedgerBroker, metadata: Metadata, cache: Cache);
    processResponse(providerAddress: string, chatID: string, content?: string): Promise<boolean | null>;
    private calculateOutputFees;
}
//# sourceMappingURL=response.d.ts.map
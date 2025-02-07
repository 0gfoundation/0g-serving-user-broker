import { InferenceServingContract } from '../contract';
import { Extractor } from '../extractor';
import { ServiceStructOutput } from '../contract';
import { ServingRequestHeaders } from './request';
import { Cache, Metadata } from '../../common/storage';
import { LedgerBroker } from '../../ledger';
export declare abstract class ZGServingUserBrokerBase {
    protected contract: InferenceServingContract;
    protected metadata: Metadata;
    protected cache: Cache;
    private checkAccountThreshold;
    private topUpTriggerThreshold;
    private topUpTargetThreshold;
    private ledger;
    constructor(contract: InferenceServingContract, ledger: LedgerBroker, metadata: Metadata, cache: Cache);
    protected getProviderData(providerAddress: string): Promise<{
        settleSignerPrivateKey: bigint[] | null;
    }>;
    protected getService(providerAddress: string, useCache?: boolean): Promise<ServiceStructOutput>;
    protected getExtractor(providerAddress: string, useCache?: boolean): Promise<Extractor>;
    protected createExtractor(svc: ServiceStructOutput): Extractor;
    protected a0giToNeuron(value: number): bigint;
    protected neuronToA0gi(value: bigint): number;
    getHeader(providerAddress: string, content: string, outputFee: bigint): Promise<ServingRequestHeaders>;
    calculateInputFees(extractor: Extractor, content: string): Promise<bigint>;
    updateCachedFee(provider: string, fee: bigint): Promise<void>;
    clearCacheFee(provider: string, fee: bigint): Promise<void>;
    /**
     * Transfer fund from ledger if fund in the inference account is less than a 5000 * (inputPrice + outputPrice)
     */
    topUpAccountIfNeeded(provider: string, content: string, gasPrice?: number): Promise<void>;
    private handleFirstRound;
    /**
     * Check the cache fund for this provider, return true if the fund is above 1000 * (inputPrice + outputPrice)
     * @param provider
     * @param svc
     */
    shouldCheckAccount(svc: ServiceStructOutput): Promise<boolean>;
}
//# sourceMappingURL=base.d.ts.map
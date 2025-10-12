import type { InferenceServingContract } from '../contract';
import type { Extractor } from '../extractor';
import type { ServiceStructOutput } from '../contract';
import type { ServingRequestHeaders } from './request';
import type { Cache, Metadata } from '../../common/storage';
import type { LedgerBroker } from '../../ledger';
export interface QuoteResponse {
    quote: string;
    provider_signer: string;
    key: [bigint, bigint];
    nvidia_payload: string;
}
export declare abstract class ZGServingUserBrokerBase {
    protected contract: InferenceServingContract;
    protected metadata: Metadata;
    protected cache: Cache;
    private checkAccountThreshold;
    private topUpTriggerThreshold;
    private topUpTargetThreshold;
    protected ledger: LedgerBroker;
    constructor(contract: InferenceServingContract, ledger: LedgerBroker, metadata: Metadata, cache: Cache);
    protected getService(providerAddress: string, useCache?: boolean): Promise<ServiceStructOutput>;
    getQuote(providerAddress: string): Promise<QuoteResponse>;
    userAcknowledged(providerAddress: string): Promise<boolean>;
    fetchText(endpoint: string, options: RequestInit): Promise<string>;
    protected getExtractor(providerAddress: string, useCache?: boolean): Promise<Extractor>;
    protected createExtractor(svc: ServiceStructOutput): Extractor;
    protected a0giToNeuron(value: number): bigint;
    protected neuronToA0gi(value: bigint): number;
    getHeader(providerAddress: string, vllmProxy: boolean): Promise<ServingRequestHeaders>;
    calculateInputFees(extractor: Extractor, content: string): Promise<bigint>;
    updateCachedFee(provider: string, fee: bigint): Promise<void>;
    clearCacheFee(provider: string, fee: bigint): Promise<void>;
    /**
     * Transfer fund from ledger if fund in the inference account is less than a topUpTriggerThreshold * (inputPrice + outputPrice)
     */
    topUpAccountIfNeeded(provider: string, content: string, gasPrice?: number): Promise<void>;
    private handleFirstRound;
    /**
     * Check the cache fund for this provider, return true if the fund is above checkAccountThreshold * (inputPrice + outputPrice)
     * @param svc
     */
    shouldCheckAccount(svc: ServiceStructOutput): Promise<boolean>;
}
//# sourceMappingURL=base.d.ts.map
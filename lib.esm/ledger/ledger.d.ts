import type { AddressLike } from 'ethers';
import type { LedgerManagerContract } from './contract';
import type { InferenceServingContract } from '../inference/contract';
import type { FineTuningServingContract } from '../fine-tuning/contract';
import type { Cache, Metadata } from '../common/storage';
export interface LedgerDetailStructOutput {
    ledgerInfo: bigint[];
    infers: [string, bigint, bigint][];
    fines: [string, bigint, bigint][] | null;
}
export interface ServiceNames {
    inference: string;
    fineTuning?: string;
}
/**
 * LedgerProcessor contains methods for creating, depositing funds, and retrieving 0G Compute Network Ledgers.
 */
export declare class LedgerProcessor {
    protected metadata: Metadata;
    protected cache: Cache;
    protected ledgerContract: LedgerManagerContract;
    protected inferenceContract: InferenceServingContract;
    protected fineTuningContract: FineTuningServingContract | undefined;
    protected serviceNames: ServiceNames;
    constructor(metadata: Metadata, cache: Cache, ledgerContract: LedgerManagerContract, inferenceContract: InferenceServingContract, fineTuningContract: FineTuningServingContract | undefined, serviceNames: ServiceNames);
    getLedger(): Promise<import("./contract").LedgerStructOutput>;
    getLedgerWithDetail(): Promise<LedgerDetailStructOutput>;
    listLedger(): Promise<import("./contract").LedgerStructOutput[]>;
    addLedger(balance: number, gasPrice?: number): Promise<void>;
    deleteLedger(gasPrice?: number): Promise<void>;
    depositFund(balance: number, gasPrice?: number): Promise<void>;
    refund(balance: number, gasPrice?: number): Promise<void>;
    transferFund(to: AddressLike, serviceTypeStr: 'inference' | 'fine-tuning', balance: bigint, gasPrice?: number): Promise<void>;
    retrieveFund(serviceTypeStr: 'inference' | 'fine-tuning', gasPrice?: number): Promise<void>;
    protected a0giToNeuron(value: number): bigint;
    protected neuronToA0gi(value: bigint): number;
}
//# sourceMappingURL=ledger.d.ts.map
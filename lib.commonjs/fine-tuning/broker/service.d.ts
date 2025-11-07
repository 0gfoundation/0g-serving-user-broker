import type { AddressLike } from 'ethers';
import type { AccountDetailsStructOutput, FineTuningServingContract } from '../contract';
import type { ServiceStructOutput } from '../contract';
import type { Provider, Task } from '../provider/provider';
import { BrokerBase } from './base';
import type { LedgerBroker } from '../../ledger';
import { Automata } from '../../common/automata';
export interface FineTuningAccountDetail {
    account: AccountDetailsStructOutput;
    refunds: {
        amount: bigint;
        remainTime: bigint;
    }[];
}
export declare class ServiceProcessor extends BrokerBase {
    protected automata: Automata;
    constructor(contract: FineTuningServingContract, ledger: LedgerBroker, servingProvider: Provider);
    getLockTime(): Promise<bigint>;
    getAccount(provider: AddressLike): Promise<AccountDetailsStructOutput>;
    getAccountWithDetail(provider: AddressLike): Promise<FineTuningAccountDetail>;
    listService(): Promise<ServiceStructOutput[]>;
    acknowledgeProviderSigner(providerAddress: string, gasPrice?: number): Promise<void>;
    createTask(providerAddress: string, preTrainedModelName: string, dataSize: number, datasetHash: string, trainingPath: string, gasPrice?: number): Promise<string>;
    cancelTask(providerAddress: string, taskID: string): Promise<string>;
    listTask(providerAddress: string): Promise<Task[]>;
    getTask(providerAddress: string, taskID?: string): Promise<Task>;
    getLog(providerAddress: string, taskID?: string): Promise<string>;
    modelUsage(providerAddress: string, preTrainedModelName: string, output: string): Promise<void>;
    private verifyTrainingParams;
}
//# sourceMappingURL=service.d.ts.map
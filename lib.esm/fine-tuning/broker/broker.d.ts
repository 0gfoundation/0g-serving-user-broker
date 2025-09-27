import type { Wallet } from 'ethers';
import type { FineTuningAccountDetail } from './service';
import type { LedgerBroker } from '../../ledger';
import type { Task } from '../provider/provider';
export declare class FineTuningBroker {
    private signer;
    private fineTuningCA;
    private ledger;
    private modelProcessor;
    private serviceProcessor;
    private serviceProvider;
    private _gasPrice?;
    private _maxGasPrice?;
    private _step?;
    constructor(signer: Wallet, fineTuningCA: string, ledger: LedgerBroker, gasPrice?: number, maxGasPrice?: number, step?: number);
    initialize(): Promise<void>;
    listService: () => Promise<import("..").FineTuningServiceStructOutput[]>;
    getLockedTime: () => Promise<bigint>;
    getAccount: (providerAddress: string) => Promise<import("../contract").AccountDetailsStructOutput>;
    getAccountWithDetail: (providerAddress: string) => Promise<FineTuningAccountDetail>;
    acknowledgeProviderSigner: (providerAddress: string, gasPrice?: number) => Promise<void>;
    listModel: () => Promise<[string, {
        [key: string]: string;
    }][][]>;
    modelUsage: (providerAddress: string, preTrainedModelName: string, output: string) => Promise<void>;
    uploadDataset: (dataPath: string, gasPrice?: number, maxGasPrice?: number) => Promise<void>;
    downloadDataset: (dataPath: string, dataRoot: string) => Promise<void>;
    calculateToken: (datasetPath: string, preTrainedModelName: string, usePython: boolean, providerAddress?: string) => Promise<void>;
    createTask: (providerAddress: string, preTrainedModelName: string, dataSize: number, datasetHash: string, trainingPath: string, gasPrice?: number) => Promise<string>;
    cancelTask: (providerAddress: string, taskID: string) => Promise<string>;
    listTask: (providerAddress: string) => Promise<Task[]>;
    getTask: (providerAddress: string, taskID?: string) => Promise<Task>;
    getLog: (providerAddress: string, taskID?: string) => Promise<string>;
    acknowledgeModel: (providerAddress: string, taskId: string, dataPath: string, gasPrice?: number) => Promise<void>;
    decryptModel: (providerAddress: string, taskId: string, encryptedModelPath: string, decryptedModelPath: string) => Promise<void>;
}
/**
 * createFineTuningBroker is used to initialize ZGServingUserBroker
 *
 * @param signer - Signer from ethers.js.
 * @param contractAddress - 0G Serving contract address, use default address if not provided.
 * @param ledger - Ledger broker instance.
 * @param gasPrice - Gas price for transactions. If not provided, the gas price will be calculated automatically.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
export declare function createFineTuningBroker(signer: Wallet, contractAddress: string, ledger: LedgerBroker, gasPrice?: number, maxGasPrice?: number, step?: number): Promise<FineTuningBroker>;
//# sourceMappingURL=broker.d.ts.map
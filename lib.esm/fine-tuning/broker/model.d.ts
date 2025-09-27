import { BrokerBase } from './base';
export declare class ModelProcessor extends BrokerBase {
    listModel(): Promise<[string, {
        [key: string]: string;
    }][][]>;
    uploadDataset(privateKey: string, dataPath: string, gasPrice?: number, maxGasPrice?: number): Promise<void>;
    calculateToken(datasetPath: string, usePython: boolean, preTrainedModelName: string, providerAddress?: string): Promise<void>;
    downloadDataset(dataPath: string, dataRoot: string): Promise<void>;
    acknowledgeModel(providerAddress: string, taskId: string, dataPath: string, gasPrice?: number): Promise<void>;
    decryptModel(providerAddress: string, taskId: string, encryptedModelPath: string, decryptedModelPath: string): Promise<void>;
}
//# sourceMappingURL=model.d.ts.map
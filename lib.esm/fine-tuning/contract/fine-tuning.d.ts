import type { AddressLike, Wallet, ContractMethodArgs, ContractTransactionReceipt } from 'ethers';
import type { DeliverableStructOutput, ServiceStructOutput, FineTuningServing } from './typechain/FineTuningServing';
export declare class FineTuningServingContract {
    serving: FineTuningServing;
    signer: Wallet;
    private _userAddress;
    private _gasPrice?;
    private _maxGasPrice?;
    private _step;
    constructor(signer: Wallet, contractAddress: string, userAddress: string, gasPrice?: number, maxGasPrice?: number, step?: number);
    lockTime(): Promise<bigint>;
    sendTx(name: string, txArgs: ContractMethodArgs<any[]>, txOptions: any): Promise<void>;
    listService(): Promise<ServiceStructOutput[]>;
    listAccount(offset?: number, limit?: number): Promise<import(".").AccountSummaryStructOutput[]>;
    getAccount(provider: AddressLike): Promise<import(".").AccountDetailsStructOutput>;
    acknowledgeProviderSigner(providerAddress: AddressLike, providerSigner: AddressLike, gasPrice?: number): Promise<void>;
    acknowledgeDeliverable(providerAddress: AddressLike, id: string, gasPrice?: number): Promise<void>;
    getService(providerAddress: string): Promise<ServiceStructOutput>;
    getDeliverable(providerAddress: AddressLike, id: string): Promise<DeliverableStructOutput>;
    getUserAddress(): string;
    checkReceipt(receipt: ContractTransactionReceipt | null): void;
}
//# sourceMappingURL=fine-tuning.d.ts.map
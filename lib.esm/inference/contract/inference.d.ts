import type { JsonRpcSigner, AddressLike, Wallet, ContractTransactionReceipt, ContractMethodArgs } from 'ethers';
import type { InferenceServing } from './typechain/InferenceServing';
import type { ServiceStructOutput } from './typechain/InferenceServing';
export declare class InferenceServingContract {
    serving: InferenceServing;
    signer: JsonRpcSigner | Wallet;
    private _userAddress;
    private _gasPrice?;
    private _maxGasPrice?;
    private _step;
    constructor(signer: JsonRpcSigner | Wallet, contractAddress: string, userAddress: string, gasPrice?: number, maxGasPrice?: number, step?: number);
    sendTx(name: string, txArgs: ContractMethodArgs<any[]>, txOptions: any): Promise<void>;
    lockTime(): Promise<bigint>;
    listService(): Promise<ServiceStructOutput[]>;
    listAccount(offset?: number, limit?: number): Promise<import(".").AccountStructOutput[]>;
    getAccount(provider: AddressLike): Promise<import(".").AccountStructOutput>;
    /**
     * Acknowledge TEE signer for a provider (Contract owner only)
     *
     * @param providerAddress - The address of the provider
     */
    acknowledgeTEESigner(providerAddress: AddressLike, gasPrice?: number): Promise<void>;
    /**
     * Revoke TEE signer acknowledgement for a provider (Contract owner only)
     *
     * @param providerAddress - The address of the provider
     */
    revokeTEESignerAcknowledgement(providerAddress: AddressLike, gasPrice?: number): Promise<void>;
    getService(providerAddress: string): Promise<ServiceStructOutput>;
    getUserAddress(): string;
    checkReceipt(receipt: ContractTransactionReceipt | null): void;
}
//# sourceMappingURL=inference.d.ts.map
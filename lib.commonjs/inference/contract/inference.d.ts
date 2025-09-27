import type { JsonRpcSigner, AddressLike, Wallet } from 'ethers';
import type { InferenceServing } from './typechain/InferenceServing';
import type { ServiceStructOutput } from './typechain/InferenceServing';
export declare class InferenceServingContract {
    serving: InferenceServing;
    signer: JsonRpcSigner | Wallet;
    private _userAddress;
    constructor(signer: JsonRpcSigner | Wallet, contractAddress: string, userAddress: string);
    lockTime(): Promise<bigint>;
    listService(): Promise<ServiceStructOutput[]>;
    listAccount(offset?: number, limit?: number): Promise<import("./typechain/InferenceServing").AccountStructOutput[]>;
    getAccount(provider: AddressLike): Promise<import("./typechain/InferenceServing").AccountStructOutput>;
    acknowledgeTEESigner(providerAddress: AddressLike, providerSigner: AddressLike): Promise<void>;
    getService(providerAddress: string): Promise<ServiceStructOutput>;
    getUserAddress(): string;
}
//# sourceMappingURL=inference.d.ts.map
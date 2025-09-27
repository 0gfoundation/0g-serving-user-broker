import type { JsonRpcSigner, BigNumberish, AddressLike, Wallet, ContractTransactionReceipt, ContractMethodArgs } from 'ethers';
import type { LedgerManager } from './typechain';
export declare class LedgerManagerContract {
    ledger: LedgerManager;
    signer: JsonRpcSigner | Wallet;
    private _userAddress;
    private _gasPrice?;
    private _maxGasPrice?;
    private _step;
    constructor(signer: JsonRpcSigner | Wallet, contractAddress: string, userAddress: string, gasPrice?: number, maxGasPrice?: number, step?: number);
    sendTx(name: string, txArgs: ContractMethodArgs<any[]>, txOptions: any): Promise<void>;
    addLedger(signer: [BigNumberish, BigNumberish], balance: bigint, settleSignerEncryptedPrivateKey: string, gasPrice?: number): Promise<void>;
    listLedger(offset?: number, limit?: number): Promise<import(".").LedgerStructOutput[]>;
    getLedger(): Promise<import(".").LedgerStructOutput>;
    depositFund(balance: string, gasPrice?: number): Promise<void>;
    refund(amount: BigNumberish, gasPrice?: number): Promise<void>;
    transferFund(provider: AddressLike, serviceTypeStr: 'inference' | 'fine-tuning', amount: BigNumberish, gasPrice?: number): Promise<void>;
    retrieveFund(providers: AddressLike[], serviceTypeStr: 'inference' | 'fine-tuning', gasPrice?: number): Promise<void>;
    deleteLedger(gasPrice?: number): Promise<void>;
    getUserAddress(): string;
    checkReceipt(receipt: ContractTransactionReceipt | null): void;
}
//# sourceMappingURL=ledger.d.ts.map
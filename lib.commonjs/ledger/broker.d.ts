import type { AddressLike, JsonRpcSigner } from 'ethers';
import { Wallet } from 'ethers';
import type { LedgerStructOutput } from './contract/typechain/LedgerManager';
import { LedgerProcessor } from './ledger';
export declare class LedgerBroker {
    ledger: LedgerProcessor;
    private signer;
    private ledgerCA;
    private inferenceCA;
    private fineTuningCA;
    private gasPrice;
    private maxGasPrice;
    private step;
    constructor(signer: JsonRpcSigner | Wallet, ledgerCA: string, inferenceCA: string, fineTuningCA: string, gasPrice?: number, maxGasPrice?: number, step?: number);
    initialize(): Promise<void>;
    private getServiceNames;
    /**
     * Adds a new ledger to the contract.
     *
     * @param {number} balance - The initial balance to be assigned to the new ledger. Units are in 0G.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the ledger creation fails.
     *
     * @remarks
     * When creating an ledger, a key pair is also created to sign the request.
     */
    addLedger: (balance: number, gasPrice?: number) => Promise<void>;
    /**
     * Retrieves the ledger information for current wallet address.
     *
     * @returns A promise that resolves to the ledger information.
     *
     * @throws Will throw an error if the ledger retrieval process fails.
     */
    getLedger: () => Promise<LedgerStructOutput>;
    /**
     * Deposits a specified amount of funds into Ledger corresponding to the current wallet address.
     *
     * @param {string} amount - The amount of funds to be deposited. Units are in 0G.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deposit fails.
     */
    depositFund: (amount: number, gasPrice?: number) => Promise<void>;
    /**
     * Refunds a specified amount using the ledger.
     *
     * @param amount - The amount to be refunded.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves when the refund is processed.
     * @throws Will throw an error if the refund process fails.
     *
     * @remarks The amount should be a positive number.
     */
    refund: (amount: number, gasPrice?: number) => Promise<void>;
    /**
     * Transfers a specified amount of funds to a provider for a given service type.
     *
     * @param provider - The address of the provider to whom the funds are being transferred.
     * @param serviceTypeStr - The type of service for which the funds are being transferred.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param amount - The amount of funds to be transferred. Units are in neuron.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund transfer operation.
     * @throws Will throw an error if the fund transfer operation fails.
     */
    transferFund: (provider: AddressLike, serviceTypeStr: "inference" | "fine-tuning", amount: bigint, gasPrice?: number) => Promise<void>;
    /**
     * Retrieves funds from the all sub-accounts (for inference and fine-tuning) of the current wallet address.
     *
     * @param serviceTypeStr - The type of service for which the funds are being retrieved.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund retrieval operation.
     * @throws Will throw an error if the fund retrieval operation fails.
     */
    retrieveFund: (serviceTypeStr: "inference" | "fine-tuning", gasPrice?: number) => Promise<void>;
    /**
     * Deletes the ledger corresponding to the current wallet address.
     *
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                           the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deletion fails.
     */
    deleteLedger: (gasPrice?: number) => Promise<void>;
}
/**
 * createLedgerBroker is used to initialize LedgerBroker
 *
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - Ledger contract address, use default address if not provided.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
export declare function createLedgerBroker(signer: JsonRpcSigner | Wallet, ledgerCA: string, inferenceCA: string, fineTuningCA: string, gasPrice?: number, maxGasPrice?: number, step?: number): Promise<LedgerBroker>;
//# sourceMappingURL=broker.d.ts.map
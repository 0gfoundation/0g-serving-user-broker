import type { JsonRpcSigner } from 'ethers';
import { Wallet } from 'ethers';
import type { InferenceBroker } from './inference/broker/broker';
import type { LedgerBroker } from './ledger';
import type { FineTuningBroker } from './fine-tuning/broker';
export declare const TESTNET_CHAIN_ID = 16602n;
export declare const MAINNET_CHAIN_ID = 16661n;
export declare const CONTRACT_ADDRESSES: {
    readonly testnet: {
        readonly ledger: "0x327025B6435424735a3d97c4b1671FeFF0E8879B";
        readonly inference: "0xa58e5220A5cF61768c7A5dBFC34a2377829240be";
        readonly fineTuning: "0x434cAbDedef8eBB760e7e583E419BFD5537A8B8a";
    };
    readonly mainnet: {
        readonly ledger: "0x1C4450Dc74504e585571B4aF70451C0737F10b71";
        readonly inference: "0x0754221A9f2C11D820F827170249c3cc5cC3DC74";
        readonly fineTuning: "0x0000000000000000000000000000000000000000";
    };
};
/**
 * Helper function to determine network type from chain ID
 */
export declare function getNetworkType(chainId: bigint): 'mainnet' | 'testnet' | 'unknown';
export declare class ZGComputeNetworkBroker {
    ledger: LedgerBroker;
    inference: InferenceBroker;
    fineTuning?: FineTuningBroker;
    constructor(ledger: LedgerBroker, inferenceBroker: InferenceBroker, fineTuningBroker?: FineTuningBroker);
}
/**
 * createZGComputeNetworkBroker is used to initialize ZGComputeNetworkBroker
 *
 * This function automatically detects the network from the signer's provider and uses
 * appropriate contract addresses. You can override any address by providing it explicitly.
 *
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - 0G Compute Network Ledger Contact address, auto-detected if not provided.
 * @param inferenceCA - 0G Compute Network Inference Serving contract address, auto-detected if not provided.
 * @param fineTuningCA - 0G Compute Network Fine Tuning Serving contract address, auto-detected if not provided.
 * @param gasPrice - Gas price for transactions. If not provided, the gas price will be calculated automatically.
 * @param maxGasPrice - Maximum gas price for transactions.
 * @param step - Step for gas price adjustment.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
export declare function createZGComputeNetworkBroker(signer: JsonRpcSigner | Wallet, ledgerCA?: string, inferenceCA?: string, fineTuningCA?: string, gasPrice?: number, maxGasPrice?: number, step?: number): Promise<ZGComputeNetworkBroker>;
//# sourceMappingURL=broker.d.ts.map
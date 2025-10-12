import type { AddressLike, BigNumberish, Wallet } from 'ethers';
export declare function hexToRoots(hexString: string): string;
export declare function signRequest(signer: Wallet, userAddress: AddressLike, nonce: BigNumberish, datasetRootHash: string, fee: BigNumberish): Promise<string>;
export declare function signTaskID(signer: Wallet, taskID: string): Promise<string>;
export declare function eciesDecrypt(signer: Wallet, encryptedData: string): Promise<string>;
export declare function aesGCMDecrypt(key: string, data: Buffer, providerSigner: string): Promise<Buffer>;
export declare function aesGCMDecryptToFile(key: string, encryptedModelPath: string, decryptedModelPath: string, providerSigner: string): Promise<void>;
//# sourceMappingURL=encrypt.d.ts.map
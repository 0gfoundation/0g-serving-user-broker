"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.hexToRoots = hexToRoots;
exports.signRequest = signRequest;
exports.signTaskID = signTaskID;
exports.eciesDecrypt = eciesDecrypt;
exports.aesGCMDecrypt = aesGCMDecrypt;
exports.aesGCMDecryptToFile = aesGCMDecryptToFile;
const ethers_1 = require("ethers");
const eciesjs_1 = require("eciesjs");
const crypto_adapter_1 = require("./crypto-adapter");
const env_1 = require("./env");
const ivLength = 12;
const tagLength = 16;
const sigLength = 65;
const chunkLength = 64 * 1024 * 1024 + tagLength;
// Fine-tuning
function hexToRoots(hexString) {
    if (hexString.startsWith('0x')) {
        hexString = hexString.slice(2);
    }
    return Buffer.from(hexString, 'hex').toString('utf8');
}
async function signRequest(signer, userAddress, nonce, datasetRootHash, fee) {
    const hash = ethers_1.ethers.solidityPackedKeccak256(['address', 'uint256', 'string', 'uint256'], [userAddress, nonce, datasetRootHash, fee]);
    return await signer.signMessage(ethers_1.ethers.toBeArray(hash));
}
async function signTaskID(signer, taskID) {
    const hash = ethers_1.ethers.solidityPackedKeccak256(['bytes'], ['0x' + taskID.replace(/-/g, '')]);
    return await signer.signMessage(ethers_1.ethers.toBeArray(hash));
}
async function eciesDecrypt(signer, encryptedData) {
    encryptedData = encryptedData.startsWith('0x')
        ? encryptedData.slice(2)
        : encryptedData;
    const privateKey = eciesjs_1.PrivateKey.fromHex(signer.privateKey);
    const data = Buffer.from(encryptedData, 'hex');
    const decrypted = (0, eciesjs_1.decrypt)(privateKey.secret, data);
    return decrypted.toString('hex');
}
async function aesGCMDecrypt(key, data, providerSigner) {
    const iv = data.subarray(0, ivLength);
    const encryptedText = data.subarray(ivLength, data.length - tagLength - sigLength);
    const authTag = data.subarray(data.length - tagLength - sigLength, data.length - sigLength);
    const tagSig = data.subarray(data.length - sigLength, data.length);
    const recoveredAddress = ethers_1.ethers.recoverAddress(ethers_1.ethers.keccak256(authTag), '0x' + tagSig.toString('hex'));
    if (recoveredAddress.toLowerCase() !== providerSigner.toLowerCase()) {
        throw new Error('Invalid tag signature');
    }
    const privateKey = Buffer.from(key, 'hex');
    const cryptoAdapter = (0, crypto_adapter_1.getCryptoAdapter)();
    const decrypted = await cryptoAdapter.aesGCMDecrypt(privateKey, Buffer.from(encryptedText), Buffer.from(iv), Buffer.from(authTag));
    return decrypted;
}
async function aesGCMDecryptToFile(key, encryptedModelPath, decryptedModelPath, providerSigner) {
    if ((0, env_1.isBrowser)()) {
        throw new Error('File operations are not supported in browser environment. Use aesGCMDecrypt with ArrayBuffer instead.');
    }
    // Only import fs when in Node.js environment
    const { promises: fs } = await Promise.resolve().then(() => __importStar(require('fs')));
    const fd = await fs.open(encryptedModelPath, 'r');
    // read signature and nonce
    const tagSig = Buffer.alloc(sigLength);
    const iv = Buffer.alloc(ivLength);
    let offset = 0;
    let readResult = await fd.read(tagSig, 0, sigLength, offset);
    offset += readResult.bytesRead;
    readResult = await fd.read(iv, 0, ivLength, offset);
    offset += readResult.bytesRead;
    const privateKey = Buffer.from(key, 'hex');
    const buffer = Buffer.alloc(chunkLength);
    let tagsBuffer = Buffer.from([]);
    const writeFd = await fs.open(decryptedModelPath, 'w');
    const cryptoAdapter = (0, crypto_adapter_1.getCryptoAdapter)();
    // read chunks
    while (true) {
        readResult = await fd.read(buffer, 0, chunkLength, offset);
        const chunkSize = readResult.bytesRead;
        if (chunkSize === 0) {
            break;
        }
        const tag = buffer.subarray(chunkSize - tagLength, chunkSize);
        const encryptedChunk = buffer.subarray(0, chunkSize - tagLength);
        const decrypted = await cryptoAdapter.aesGCMDecrypt(privateKey, Buffer.from(encryptedChunk), Buffer.from(iv), Buffer.from(tag));
        await writeFd.appendFile(decrypted);
        tagsBuffer = Buffer.concat([tagsBuffer, tag]);
        offset += chunkSize;
        for (let i = iv.length - 1; i >= 0; i--) {
            iv[i]++;
            if (iv[i] !== 0)
                break;
        }
    }
    await writeFd.close();
    await fd.close();
    const recoveredAddress = ethers_1.ethers.recoverAddress(ethers_1.ethers.keccak256(tagsBuffer), '0x' + tagSig.toString('hex'));
    if (recoveredAddress.toLowerCase() !== providerSigner.toLowerCase()) {
        throw new Error('Invalid tag signature');
    }
}
//# sourceMappingURL=encrypt.js.map
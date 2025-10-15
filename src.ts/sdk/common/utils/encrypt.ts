import type { AddressLike, BigNumberish, Wallet } from 'ethers'
import { ethers } from 'ethers'
import { PrivateKey, decrypt } from 'eciesjs'
import { getCryptoAdapter } from './crypto-adapter'
import { isBrowser } from './env'

const ivLength: number = 12
const tagLength: number = 16
const sigLength: number = 65
const chunkLength: number = 64 * 1024 * 1024 + tagLength

// Fine-tuning

export function hexToRoots(hexString: string): string {
    if (hexString.startsWith('0x')) {
        hexString = hexString.slice(2)
    }
    return Buffer.from(hexString, 'hex').toString('utf8')
}

export async function signRequest(
    signer: Wallet,
    userAddress: AddressLike,
    nonce: BigNumberish,
    datasetRootHash: string,
    fee: BigNumberish
): Promise<string> {
    const hash = ethers.solidityPackedKeccak256(
        ['address', 'uint256', 'string', 'uint256'],
        [userAddress, nonce, datasetRootHash, fee]
    )

    return await signer.signMessage(ethers.toBeArray(hash))
}

export async function signTaskID(
    signer: Wallet,
    taskID: string
): Promise<string> {
    const hash = ethers.solidityPackedKeccak256(
        ['bytes'],
        ['0x' + taskID.replace(/-/g, '')]
    )
    return await signer.signMessage(ethers.toBeArray(hash))
}

export async function eciesDecrypt(
    signer: Wallet,
    encryptedData: string
): Promise<string> {
    encryptedData = encryptedData.startsWith('0x')
        ? encryptedData.slice(2)
        : encryptedData

    const privateKey = PrivateKey.fromHex(signer.privateKey)
    const data = Buffer.from(encryptedData, 'hex')
    const decrypted = decrypt(privateKey.secret, data)
    return decrypted.toString('hex')
}

export async function aesGCMDecrypt(
    key: string,
    data: Buffer,
    providerSigner: string
): Promise<Buffer> {
    const iv = data.subarray(0, ivLength)
    const encryptedText = data.subarray(
        ivLength,
        data.length - tagLength - sigLength
    )
    const authTag = data.subarray(
        data.length - tagLength - sigLength,
        data.length - sigLength
    )
    const tagSig = data.subarray(data.length - sigLength, data.length)
    const recoveredAddress = ethers.recoverAddress(
        ethers.keccak256(authTag),
        '0x' + tagSig.toString('hex')
    )
    if (recoveredAddress.toLowerCase() !== providerSigner.toLowerCase()) {
        throw new Error('Invalid tag signature')
    }

    const privateKey = Buffer.from(key, 'hex')
    const cryptoAdapter = getCryptoAdapter()
    const decrypted = await cryptoAdapter.aesGCMDecrypt(
        privateKey,
        Buffer.from(encryptedText),
        Buffer.from(iv),
        Buffer.from(authTag)
    )

    return decrypted
}

export async function aesGCMDecryptToFile(
    key: string,
    encryptedModelPath: string,
    decryptedModelPath: string,
    providerSigner: string
) {
    if (isBrowser()) {
        throw new Error(
            'File operations are not supported in browser environment. Use aesGCMDecrypt with ArrayBuffer instead.'
        )
    }

    // Only import fs when in Node.js environment
    const { promises: fs } = await import('fs')

    const fd = await fs.open(encryptedModelPath, 'r')

    // read signature and nonce
    const tagSig = Buffer.alloc(sigLength)
    const iv = Buffer.alloc(ivLength)

    let offset = 0
    let readResult = await fd.read(tagSig, 0, sigLength, offset)
    offset += readResult.bytesRead

    readResult = await fd.read(iv, 0, ivLength, offset)
    offset += readResult.bytesRead

    const privateKey = Buffer.from(key, 'hex')
    const buffer = Buffer.alloc(chunkLength)
    let tagsBuffer = Buffer.from([])

    const writeFd = await fs.open(decryptedModelPath, 'w')
    const cryptoAdapter = getCryptoAdapter()

    // read chunks
    while (true) {
        readResult = await fd.read(buffer, 0, chunkLength, offset)
        const chunkSize = readResult.bytesRead
        if (chunkSize === 0) {
            break
        }

        const tag = buffer.subarray(chunkSize - tagLength, chunkSize)
        const encryptedChunk = buffer.subarray(0, chunkSize - tagLength)

        const decrypted = await cryptoAdapter.aesGCMDecrypt(
            privateKey,
            Buffer.from(encryptedChunk),
            Buffer.from(iv),
            Buffer.from(tag)
        )

        await writeFd.appendFile(decrypted)

        tagsBuffer = Buffer.concat([tagsBuffer, tag])
        offset += chunkSize

        for (let i = iv.length - 1; i >= 0; i--) {
            iv[i]++
            if (iv[i] !== 0) break
        }
    }

    await writeFd.close()
    await fd.close()

    const recoveredAddress = ethers.recoverAddress(
        ethers.keccak256(tagsBuffer),
        '0x' + tagSig.toString('hex')
    )

    if (recoveredAddress.toLowerCase() !== providerSigner.toLowerCase()) {
        throw new Error('Invalid tag signature')
    }
}

import {
    aesGCMDecryptToFile,
    eciesDecrypt,
    hexToRoots,
    throwFormattedError,
} from '../../common/utils'
import {
    MODEL_HASH_MAP,
    TOKEN_COUNTER_FILE_HASH,
    TOKEN_COUNTER_MERKLE_ROOT,
} from '../const'
import { download, upload } from '../zg-storage'
import { BrokerBase } from './base'
import { calculateTokenSizeViaPython, calculateTokenSizeViaExe } from '../token'

export class ModelProcessor extends BrokerBase {
    async listModel(): Promise<[string, { [key: string]: string }][][]> {
        const services = await this.contract.listService()
        let customizedModels: [string, { [key: string]: string }][] = []
        for (const service of services) {
            if (service.models.length !== 0) {
                const url = service.url
                const models = await this.servingProvider.getCustomizedModels(
                    url
                )
                for (const item of models) {
                    customizedModels.push([
                        item.name,
                        {
                            description: item.description,
                            provider: service.provider,
                        },
                    ])
                }
            }
        }

        return [Object.entries(MODEL_HASH_MAP), customizedModels]
    }

    async uploadDataset(
        privateKey: string,
        dataPath: string,
        gasPrice?: number,
        maxGasPrice?: number
    ): Promise<void> {
        await upload(privateKey, dataPath, gasPrice)
    }

    async calculateToken(
        datasetPath: string,
        usePython: boolean,
        preTrainedModelName: string,
        providerAddress?: string
    ) {
        let tokenizer: string
        let dataType: string
        if (preTrainedModelName in MODEL_HASH_MAP) {
            tokenizer = MODEL_HASH_MAP[preTrainedModelName].tokenizer
            dataType = MODEL_HASH_MAP[preTrainedModelName].type
        } else {
            if (providerAddress === undefined) {
                throw new Error(
                    'Provider address is required for customized model'
                )
            }

            let model = await this.servingProvider.getCustomizedModel(
                providerAddress,
                preTrainedModelName
            )
            tokenizer = model.tokenizer
            dataType = model.dataType
        }

        let dataSize = 0
        if (usePython) {
            dataSize = await calculateTokenSizeViaPython(
                tokenizer,
                datasetPath,
                dataType
            )
        } else {
            dataSize = await calculateTokenSizeViaExe(
                tokenizer,
                datasetPath,
                dataType,
                TOKEN_COUNTER_MERKLE_ROOT,
                TOKEN_COUNTER_FILE_HASH
            )
        }

        console.log(
            `The token size for the dataset ${datasetPath} is ${dataSize}`
        )
    }

    async downloadDataset(dataPath: string, dataRoot: string): Promise<void> {
        download(dataPath, dataRoot)
    }

    async acknowledgeModel(
        providerAddress: string,
        taskId: string,
        dataPath: string,
        gasPrice?: number
    ): Promise<void> {
        try {
            const deliverable = await this.contract.getDeliverable(
                providerAddress,
                taskId
            )

            if (!deliverable) {
                throw new Error('No deliverable found')
            }

            await download(dataPath, hexToRoots(deliverable.modelRootHash))

            await this.contract.acknowledgeDeliverable(
                providerAddress,
                taskId,
                gasPrice
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async decryptModel(
        providerAddress: string,
        taskId: string,
        encryptedModelPath: string,
        decryptedModelPath: string
    ): Promise<void> {
        try {
            const [account, deliverable] = await Promise.all([
                this.contract.getAccount(providerAddress),
                this.contract.getDeliverable(providerAddress, taskId),
            ])

            if (!deliverable) {
                throw new Error('No deliverable found')
            }

            if (!deliverable.acknowledged) {
                throw new Error('Deliverable not acknowledged yet')
            }

            if (!deliverable.encryptedSecret) {
                throw new Error('EncryptedSecret not found')
            }

            const secret = await eciesDecrypt(
                this.contract.signer,
                deliverable.encryptedSecret
            )

            await aesGCMDecryptToFile(
                secret,
                encryptedModelPath,
                decryptedModelPath,
                account.providerSigner
            )
        } catch (error) {
            throwFormattedError(error)
        }
        return
    }
}

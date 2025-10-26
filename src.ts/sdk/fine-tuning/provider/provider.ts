import type { FineTuningServingContract } from '../contract'
import axios from 'axios'
import * as fs from 'fs/promises'
import * as path from 'path'
import { throwFormattedError } from '../../common/utils'

export interface Task {
    readonly id?: string
    readonly createdAt?: string
    readonly updatedAt?: string
    userAddress: string
    preTrainedModelHash: string
    datasetHash: string
    trainingParams: string
    fee: string
    nonce: string
    signature: string
    readonly progress?: string
    readonly deliverIndex?: string
    wait?: boolean
}

export interface TdxQuoteResponse {
    rawReport: string
    signingAddress: string
}

export interface CustomizedModel {
    name: string
    hash: string
    image: string
    dataType: string
    trainingScript: string
    description: string
    tokenizer: string
}

export class Provider {
    private contract: FineTuningServingContract

    constructor(contract: FineTuningServingContract) {
        this.contract = contract
    }

    private async fetchJSON(
        endpoint: string,
        options: RequestInit
    ): Promise<any> {
        try {
            const response = await fetch(endpoint, options)
            if (!response.ok) {
                const errorData = await response.json()
                throw new Error(errorData.error)
            }
            return response.json()
        } catch (error) {
            throwFormattedError(error)
        }
    }

    private async fetchText(
        endpoint: string,
        options: RequestInit
    ): Promise<string> {
        try {
            const response = await fetch(endpoint, options)
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`)
            }
            const buffer = await response.arrayBuffer()
            return Buffer.from(buffer).toString('utf-8')
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getProviderUrl(providerAddress: string): Promise<string> {
        try {
            const service = await this.contract.getService(providerAddress)
            return service.url
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getQuote(providerAddress: string): Promise<TdxQuoteResponse> {
        try {
            const url = await this.getProviderUrl(providerAddress)
            const endpoint = `${url}/v1/quote`

            const rawReport = await this.fetchText(endpoint, {
                method: 'GET',
            })
            const ret = JSON.parse(rawReport)
            return {
                rawReport,
                signingAddress: ret['report_data'],
            } as TdxQuoteResponse
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async createTask(providerAddress: string, task: Task): Promise<string> {
        try {
            const url = await this.getProviderUrl(providerAddress)
            const userAddress = this.contract.getUserAddress()
            const endpoint = `${url}/v1/user/${userAddress}/task`

            const response = await this.fetchJSON(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(task),
            })
            return response.id
        } catch (error) {
            if (error instanceof Error) {
                throw new Error(`Failed to create task: ${error.message}`)
            }
            throw new Error('Failed to create task')
        }
    }

    async cancelTask(
        providerAddress: string,
        signature: string,
        taskID: string
    ): Promise<string> {
        try {
            const url = await this.getProviderUrl(providerAddress)
            const userAddress = this.contract.getUserAddress()
            const endpoint = `${url}/v1/user/${userAddress}/task/${taskID}/cancel`

            const response = await this.fetchText(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    signature: signature,
                }),
            })
            return response
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getTask(
        providerAddress: string,
        userAddress: string,
        taskID: string
    ): Promise<Task> {
        try {
            const url = await this.getProviderUrl(providerAddress)
            const endpoint = `${url}/v1/user/${encodeURIComponent(
                userAddress
            )}/task/${taskID}`

            console.log('url', url)
            console.log('endpoint', endpoint)

            return this.fetchJSON(endpoint, { method: 'GET' }) as Promise<Task>
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async listTask(
        providerAddress: string,
        userAddress: string,
        latest = false
    ): Promise<Task[]> {
        try {
            const url = await this.getProviderUrl(providerAddress)
            let endpoint = `${url}/v1/user/${encodeURIComponent(
                userAddress
            )}/task`

            if (latest) {
                endpoint += '?latest=true'
            }

            return this.fetchJSON(endpoint, { method: 'GET' }) as Promise<
                Task[]
            >
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getPendingTaskCounter(providerAddress: string) {
        try {
            const url = await this.getProviderUrl(providerAddress)
            const endpoint = `${url}/v1/task/pending`

            return Number(
                await this.fetchText(endpoint, {
                    method: 'GET',
                })
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getLog(
        providerAddress: string,
        userAddress: string,
        taskID: string
    ): Promise<string> {
        try {
            const url = await this.getProviderUrl(providerAddress)
            const endpoint = `${url}/v1/user/${userAddress}/task/${taskID}/log`
            return this.fetchText(endpoint, { method: 'GET' })
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getCustomizedModels(url: string): Promise<CustomizedModel[]> {
        try {
            const endpoint = `${url}/v1/model`
            const response = await this.fetchJSON(endpoint, { method: 'GET' })
            return response as CustomizedModel[]
        } catch (error) {
            console.error(`Failed to get customized models: ${error}`)
            return []
        }
    }

    async getCustomizedModel(
        providerAddress: string,
        moduleName: string
    ): Promise<CustomizedModel> {
        try {
            const url = await this.getProviderUrl(providerAddress)
            const endpoint = `${url}/v1/model/${moduleName}`
            const response = await this.fetchJSON(endpoint, { method: 'GET' })
            return response as CustomizedModel
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getCustomizedModelDetailUsage(
        providerAddress: string,
        moduleName: string,
        outputPath: string
    ): Promise<void> {
        try {
            const url = await this.getProviderUrl(providerAddress)
            const endpoint = `${url}/v1/model/desc/${moduleName}`

            let destFile = outputPath
            try {
                const stats = await fs.stat(outputPath)
                if (stats.isDirectory()) {
                    destFile = path.join(outputPath, `${moduleName}.zip`)
                }

                await fs.unlink(destFile)
            } catch (err) {}

            const response = await axios({
                method: 'get',
                url: endpoint,
                responseType: 'arraybuffer',
            })

            await fs.writeFile(destFile, response.data)
            console.log(`Model downloaded and saved to ${destFile}`)
        } catch (error: any) {
            throwFormattedError(error)
        }
    }
}

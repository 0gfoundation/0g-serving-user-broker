import { FineTuningServingContract } from '../contract'
import type { Wallet } from 'ethers'
import { ModelProcessor } from './model'
import type { FineTuningAccountDetail } from './service'
import { ServiceProcessor } from './service'
import type { LedgerBroker } from '../../ledger'
import { Provider } from '../provider/provider'
import type { Task } from '../provider/provider'
import { throwFormattedError } from '../../common/utils'

export class FineTuningBroker {
    private signer: Wallet
    private fineTuningCA: string
    private ledger!: LedgerBroker
    private modelProcessor!: ModelProcessor
    private serviceProcessor!: ServiceProcessor
    private serviceProvider!: Provider
    private _gasPrice?: number
    private _maxGasPrice?: number
    private _step?: number

    constructor(
        signer: Wallet,
        fineTuningCA: string,
        ledger: LedgerBroker,
        gasPrice?: number,
        maxGasPrice?: number,
        step?: number
    ) {
        this.signer = signer
        this.fineTuningCA = fineTuningCA
        this.ledger = ledger
        this._gasPrice = gasPrice
        this._maxGasPrice = maxGasPrice
        this._step = step
    }

    async initialize() {
        let userAddress: string
        try {
            userAddress = await this.signer.getAddress()
        } catch (error) {
            throwFormattedError(error)
        }

        const contract = new FineTuningServingContract(
            this.signer,
            this.fineTuningCA,
            userAddress,
            this._gasPrice,
            this._maxGasPrice,
            this._step
        )

        this.serviceProvider = new Provider(contract)
        this.modelProcessor = new ModelProcessor(
            contract,
            this.ledger,
            this.serviceProvider
        )
        this.serviceProcessor = new ServiceProcessor(
            contract,
            this.ledger,
            this.serviceProvider
        )
    }

    public listService = async () => {
        try {
            return await this.serviceProcessor.listService()
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public getLockedTime = async () => {
        try {
            return await this.serviceProcessor.getLockTime()
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public getAccount = async (providerAddress: string) => {
        try {
            return await this.serviceProcessor.getAccount(providerAddress)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public getAccountWithDetail = async (
        providerAddress: string
    ): Promise<FineTuningAccountDetail> => {
        try {
            return await this.serviceProcessor.getAccountWithDetail(
                providerAddress
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public acknowledgeProviderSigner = async (
        providerAddress: string,
        gasPrice?: number
    ) => {
        try {
            return await this.serviceProcessor.acknowledgeProviderSigner(
                providerAddress,
                gasPrice
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public listModel = () => {
        try {
            return this.modelProcessor.listModel()
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public modelUsage = (
        providerAddress: string,
        preTrainedModelName: string,
        output: string
    ) => {
        try {
            return this.serviceProcessor.modelUsage(
                providerAddress,
                preTrainedModelName,
                output
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public uploadDataset = async (
        dataPath: string,
        gasPrice?: number,
        maxGasPrice?: number
    ): Promise<void> => {
        try {
            await this.modelProcessor.uploadDataset(
                this.signer.privateKey,
                dataPath,
                gasPrice || this._gasPrice,
                maxGasPrice || this._maxGasPrice
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public downloadDataset = async (
        dataPath: string,
        dataRoot: string
    ): Promise<void> => {
        try {
            await this.modelProcessor.downloadDataset(dataPath, dataRoot)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public calculateToken = async (
        datasetPath: string,
        preTrainedModelName: string,
        usePython: boolean,
        providerAddress?: string
    ): Promise<void> => {
        try {
            await this.modelProcessor.calculateToken(
                datasetPath,
                usePython,
                preTrainedModelName,
                providerAddress
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public createTask = async (
        providerAddress: string,
        preTrainedModelName: string,
        dataSize: number,
        datasetHash: string,
        trainingPath: string,
        gasPrice?: number
    ): Promise<string> => {
        try {
            return await this.serviceProcessor.createTask(
                providerAddress,
                preTrainedModelName,
                dataSize,
                datasetHash,
                trainingPath,
                gasPrice
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public cancelTask = async (
        providerAddress: string,
        taskID: string
    ): Promise<string> => {
        try {
            return await this.serviceProcessor.cancelTask(
                providerAddress,
                taskID
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public listTask = async (providerAddress: string): Promise<Task[]> => {
        try {
            return await this.serviceProcessor.listTask(providerAddress)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public getTask = async (
        providerAddress: string,
        taskID?: string
    ): Promise<Task> => {
        try {
            const task = await this.serviceProcessor.getTask(
                providerAddress,
                taskID
            )
            return task
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public getLog = async (
        providerAddress: string,
        taskID?: string
    ): Promise<string> => {
        try {
            return await this.serviceProcessor.getLog(providerAddress, taskID)
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public acknowledgeModel = async (
        providerAddress: string,
        taskId: string,
        dataPath: string,
        gasPrice?: number
    ): Promise<void> => {
        try {
            return await this.modelProcessor.acknowledgeModel(
                providerAddress,
                taskId,
                dataPath,
                gasPrice
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }

    public decryptModel = async (
        providerAddress: string,
        taskId: string,
        encryptedModelPath: string,
        decryptedModelPath: string
    ): Promise<void> => {
        try {
            return await this.modelProcessor.decryptModel(
                providerAddress,
                taskId,
                encryptedModelPath,
                decryptedModelPath
            )
        } catch (error) {
            throwFormattedError(error)
        }
    }
}

/**
 * createFineTuningBroker is used to initialize ZGServingUserBroker
 *
 * @param signer - Signer from ethers.js.
 * @param contractAddress - 0G Serving contract address, use default address if not provided.
 * @param ledger - Ledger broker instance.
 * @param gasPrice - Gas price for transactions. If not provided, the gas price will be calculated automatically.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
export async function createFineTuningBroker(
    signer: Wallet,
    contractAddress: string,
    ledger: LedgerBroker,
    gasPrice?: number,
    maxGasPrice?: number,
    step?: number
): Promise<FineTuningBroker> {
    const broker = new FineTuningBroker(
        signer,
        contractAddress,
        ledger,
        gasPrice,
        maxGasPrice,
        step
    )
    try {
        await broker.initialize()
        return broker
    } catch (error) {
        throw error
    }
}

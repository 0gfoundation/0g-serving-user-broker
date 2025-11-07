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
exports.ServiceProcessor = void 0;
const utils_1 = require("../../common/utils");
const const_1 = require("../const");
const base_1 = require("./base");
const env_1 = require("../../common/utils/env");
const automata_1 = require("../../common/automata");
// Browser-safe function to avoid readline dependency
async function askUser(question) {
    if ((0, env_1.isBrowser)()) {
        throw new Error('Interactive input operations are not available in browser environment. Please use these functions in a Node.js environment.');
    }
    // Only import readline in Node.js environment
    try {
        const readline = await Promise.resolve().then(() => __importStar(require('readline')));
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
        });
        return new Promise((resolve) => {
            rl.question(question, (answer) => {
                rl.close();
                resolve(answer.trim());
            });
        });
    }
    catch (error) {
        throw new Error('readline module is not available. This function can only be used in Node.js environment.');
    }
}
// Browser-safe function to avoid fs dependency
async function readFileContent(filePath) {
    if ((0, env_1.isBrowser)()) {
        throw new Error('File system operations are not available in browser environment. Please use these functions in a Node.js environment.');
    }
    try {
        const fs = await Promise.resolve().then(() => __importStar(require('fs/promises')));
        return await fs.readFile(filePath, 'utf-8');
    }
    catch (error) {
        throw new Error('fs module is not available. This function can only be used in Node.js environment.');
    }
}
class ServiceProcessor extends base_1.BrokerBase {
    automata;
    constructor(contract, ledger, servingProvider) {
        super(contract, ledger, servingProvider);
        this.automata = new automata_1.Automata();
    }
    async getLockTime() {
        try {
            const lockTime = await this.contract.lockTime();
            return lockTime;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getAccount(provider) {
        try {
            const account = await this.contract.getAccount(provider);
            return account;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getAccountWithDetail(provider) {
        try {
            const account = await this.contract.getAccount(provider);
            const lockTime = await this.getLockTime();
            const now = BigInt(Math.floor(Date.now() / 1000)); // Converts milliseconds to seconds
            const refunds = account.refunds
                .filter((refund) => !refund.processed)
                .filter((refund) => refund.amount !== BigInt(0))
                .map((refund) => ({
                amount: refund.amount,
                remainTime: lockTime - (now - refund.createdAt),
            }));
            return { account, refunds };
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async listService() {
        try {
            const services = await this.contract.listService();
            return services;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async acknowledgeProviderSigner(providerAddress, gasPrice) {
        try {
            try {
                await this.contract.getAccount(providerAddress);
            }
            catch {
                await this.ledger.transferFund(providerAddress, 'fine-tuning', BigInt(0), gasPrice);
            }
            const { rawReport, signingAddress } = await this.servingProvider.getQuote(providerAddress);
            if (!rawReport || !signingAddress) {
                throw new Error('Invalid quote');
            }
            // TODO: separate automata verification logic
            // const rpc = process.env.RPC_ENDPOINT
            // // bypass quote verification if testing on localhost
            // if (!rpc || !/localhost|127\.0\.0\.1/.test(rpc)) {
            //     const isVerified = await this.automata.verifyQuote(intel_quote)
            //     console.log('Quote verification:', isVerified)
            //     if (!isVerified) {
            //         throw new Error('Quote verification failed')
            //     }
            // }
            const account = await this.contract.getAccount(providerAddress);
            if (account.providerSigner === signingAddress) {
                console.log('Provider signer already acknowledged');
                return;
            }
            await this.contract.acknowledgeProviderSigner(providerAddress, signingAddress, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async createTask(providerAddress, preTrainedModelName, dataSize, datasetHash, trainingPath, gasPrice) {
        try {
            let preTrainedModelHash;
            if (preTrainedModelName in const_1.MODEL_HASH_MAP) {
                preTrainedModelHash = const_1.MODEL_HASH_MAP[preTrainedModelName].turbo;
            }
            else {
                const model = await this.servingProvider.getCustomizedModel(providerAddress, preTrainedModelName);
                preTrainedModelHash = model.hash;
                console.log(`customized model hash: ${preTrainedModelHash}`);
            }
            const service = await this.contract.getService(providerAddress);
            const trainingParams = await readFileContent(trainingPath);
            const parsedParams = this.verifyTrainingParams(trainingParams);
            const trainEpochs = (parsedParams.num_train_epochs || parsedParams.total_steps) ?? 3;
            const fee = service.pricePerToken * BigInt(dataSize) * BigInt(trainEpochs);
            console.log(`Estimated fee: ${fee} (neuron), data size: ${dataSize}, train epochs: ${trainEpochs}, price per token: ${service.pricePerToken} (neuron)`);
            const account = await this.contract.getAccount(providerAddress);
            if (account.balance - account.pendingRefund < fee) {
                await this.ledger.transferFund(providerAddress, 'fine-tuning', fee, gasPrice);
            }
            const nonce = (0, utils_1.getNonce)();
            const signature = await (0, utils_1.signRequest)(this.contract.signer, this.contract.getUserAddress(), BigInt(nonce), datasetHash, fee);
            let wait = false;
            const counter = await this.servingProvider.getPendingTaskCounter(providerAddress);
            if (counter > 0) {
                while (true) {
                    const answer = await askUser(`There are ${counter} tasks in the queue. Do you want to continue? (yes/no): `);
                    if (answer.toLowerCase() === 'yes' ||
                        answer.toLowerCase() === 'y') {
                        wait = true;
                        break;
                    }
                    else if (['no', 'n'].includes(answer.toLowerCase())) {
                        throw new Error('User opted not to continue due to pending tasks in the queue.');
                    }
                    else {
                        console.log('Invalid input. Please respond with yes/y or no/n.');
                    }
                }
            }
            const task = {
                userAddress: this.contract.getUserAddress(),
                datasetHash,
                trainingParams,
                preTrainedModelHash,
                fee: fee.toString(),
                nonce: nonce.toString(),
                signature,
                wait,
            };
            return await this.servingProvider.createTask(providerAddress, task);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async cancelTask(providerAddress, taskID) {
        try {
            const signature = await (0, utils_1.signTaskID)(this.contract.signer, taskID);
            return await this.servingProvider.cancelTask(providerAddress, signature, taskID);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async listTask(providerAddress) {
        try {
            return await this.servingProvider.listTask(providerAddress, this.contract.getUserAddress());
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getTask(providerAddress, taskID) {
        try {
            if (!taskID) {
                const tasks = await this.servingProvider.listTask(providerAddress, this.contract.getUserAddress(), true);
                if (tasks.length === 0) {
                    throw new Error('No task found');
                }
                return tasks[0];
            }
            return await this.servingProvider.getTask(providerAddress, this.contract.getUserAddress(), taskID);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    // 8. [`call provider`] call provider task progress api to get task progress
    async getLog(providerAddress, taskID) {
        if (!taskID) {
            const tasks = await this.servingProvider.listTask(providerAddress, this.contract.getUserAddress(), true);
            taskID = tasks[0].id;
            if (tasks.length === 0 || !taskID) {
                throw new Error('No task found');
            }
        }
        return this.servingProvider.getLog(providerAddress, this.contract.getUserAddress(), taskID);
    }
    async modelUsage(providerAddress, preTrainedModelName, output) {
        try {
            return await this.servingProvider.getCustomizedModelDetailUsage(providerAddress, preTrainedModelName, output);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    verifyTrainingParams(trainingParams) {
        try {
            return JSON.parse(trainingParams);
        }
        catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred';
            throw new Error(`Invalid JSON in trainingPath file: ${errorMessage}`);
        }
    }
}
exports.ServiceProcessor = ServiceProcessor;
//# sourceMappingURL=service.js.map
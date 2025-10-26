"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Provider = void 0;
const tslib_1 = require("tslib");
const axios_1 = tslib_1.__importDefault(require("axios"));
const fs = tslib_1.__importStar(require("fs/promises"));
const path = tslib_1.__importStar(require("path"));
const utils_1 = require("../../common/utils");
class Provider {
    contract;
    constructor(contract) {
        this.contract = contract;
    }
    async fetchJSON(endpoint, options) {
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error);
            }
            return response.json();
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async fetchText(endpoint, options) {
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            const buffer = await response.arrayBuffer();
            return Buffer.from(buffer).toString('utf-8');
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getProviderUrl(providerAddress) {
        try {
            const service = await this.contract.getService(providerAddress);
            return service.url;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getQuote(providerAddress) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/quote`;
            const rawReport = await this.fetchText(endpoint, {
                method: 'GET',
            });
            const ret = JSON.parse(rawReport);
            return {
                rawReport,
                signingAddress: ret['report_data'],
            };
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async createTask(providerAddress, task) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const userAddress = this.contract.getUserAddress();
            const endpoint = `${url}/v1/user/${userAddress}/task`;
            const response = await this.fetchJSON(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(task),
            });
            return response.id;
        }
        catch (error) {
            if (error instanceof Error) {
                throw new Error(`Failed to create task: ${error.message}`);
            }
            throw new Error('Failed to create task');
        }
    }
    async cancelTask(providerAddress, signature, taskID) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const userAddress = this.contract.getUserAddress();
            const endpoint = `${url}/v1/user/${userAddress}/task/${taskID}/cancel`;
            const response = await this.fetchText(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    signature: signature,
                }),
            });
            return response;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getTask(providerAddress, userAddress, taskID) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/user/${encodeURIComponent(userAddress)}/task/${taskID}`;
            console.log('url', url);
            console.log('endpoint', endpoint);
            return this.fetchJSON(endpoint, { method: 'GET' });
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async listTask(providerAddress, userAddress, latest = false) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            let endpoint = `${url}/v1/user/${encodeURIComponent(userAddress)}/task`;
            if (latest) {
                endpoint += '?latest=true';
            }
            return this.fetchJSON(endpoint, { method: 'GET' });
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getPendingTaskCounter(providerAddress) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/task/pending`;
            return Number(await this.fetchText(endpoint, {
                method: 'GET',
            }));
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getLog(providerAddress, userAddress, taskID) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/user/${userAddress}/task/${taskID}/log`;
            return this.fetchText(endpoint, { method: 'GET' });
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getCustomizedModels(url) {
        try {
            const endpoint = `${url}/v1/model`;
            const response = await this.fetchJSON(endpoint, { method: 'GET' });
            return response;
        }
        catch (error) {
            console.error(`Failed to get customized models: ${error}`);
            return [];
        }
    }
    async getCustomizedModel(providerAddress, moduleName) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/model/${moduleName}`;
            const response = await this.fetchJSON(endpoint, { method: 'GET' });
            return response;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getCustomizedModelDetailUsage(providerAddress, moduleName, outputPath) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/model/desc/${moduleName}`;
            let destFile = outputPath;
            try {
                const stats = await fs.stat(outputPath);
                if (stats.isDirectory()) {
                    destFile = path.join(outputPath, `${moduleName}.zip`);
                }
                await fs.unlink(destFile);
            }
            catch (err) { }
            const response = await (0, axios_1.default)({
                method: 'get',
                url: endpoint,
                responseType: 'arraybuffer',
            });
            await fs.writeFile(destFile, response.data);
            console.log(`Model downloaded and saved to ${destFile}`);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
}
exports.Provider = Provider;
//# sourceMappingURL=provider.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InferenceBroker = void 0;
exports.createInferenceBroker = createInferenceBroker;
const contract_1 = require("../contract");
const request_1 = require("./request");
const response_1 = require("./response");
const verifier_1 = require("./verifier");
const account_1 = require("./account");
const model_1 = require("./model");
const storage_1 = require("../../common/storage");
const utils_1 = require("../../common/utils");
class InferenceBroker {
    requestProcessor;
    responseProcessor;
    verifier;
    accountProcessor;
    modelProcessor;
    signer;
    contractAddress;
    ledger;
    constructor(signer, contractAddress, ledger) {
        this.signer = signer;
        this.contractAddress = contractAddress;
        this.ledger = ledger;
    }
    async initialize() {
        let userAddress;
        try {
            userAddress = await this.signer.getAddress();
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
        const contract = new contract_1.InferenceServingContract(this.signer, this.contractAddress, userAddress);
        const metadata = new storage_1.Metadata();
        const cache = new storage_1.Cache();
        this.requestProcessor = new request_1.RequestProcessor(contract, metadata, cache, this.ledger);
        this.responseProcessor = new response_1.ResponseProcessor(contract, this.ledger, metadata, cache);
        this.accountProcessor = new account_1.AccountProcessor(contract, this.ledger, metadata, cache);
        this.modelProcessor = new model_1.ModelProcessor(contract, this.ledger, metadata, cache);
        this.verifier = new verifier_1.Verifier(contract, this.ledger, metadata, cache);
    }
    /**
     * Retrieves a list of services from the contract.
     *
     * @returns {Promise<ServiceStructOutput[]>} A promise that resolves to an array of ServiceStructOutput objects.
     * @throws An error if the service list cannot be retrieved.
     */
    listService = async () => {
        try {
            return await this.modelProcessor.listService();
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Retrieves the account information for a given provider address.
     *
     * @param {string} providerAddress - The address of the provider identifying the account.
     *
     * @returns A promise that resolves to the account information.
     *
     * @throws Will throw an error if the account retrieval process fails.
     */
    getAccount = async (providerAddress) => {
        try {
            return await this.accountProcessor.getAccount(providerAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    getAccountWithDetail = async (providerAddress) => {
        try {
            return await this.accountProcessor.getAccountWithDetail(providerAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * checks if the user has acknowledged the provider signer.
     *
     * @param {string} providerAddress - The address of the provider.
     * @returns {Promise<boolean>} A promise that resolves to a boolean indicating whether the user
     * has acknowledged the provider signer.
     * @throws Will throw an error if the acknowledgment check fails.
     */
    acknowledged = async (providerAddress) => {
        try {
            return await this.requestProcessor.userAcknowledged(providerAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Check Provider Signer Status
     *
     * Checks if the provider's TEE signer has been acknowledged by the contract owner.
     * This replaces the old user-level acknowledgement system.
     *
     * @param {string} providerAddress - The address of the provider identifying the account.
     * @param {number} gasPrice - Optional gas price for the transaction.
     * @returns Promise<{isAcknowledged: boolean, teeSignerAddress: string, needsAccount: boolean}>
     *
     * @throws Will throw an error if failed to check status.
     */
    checkProviderSignerStatus = async (providerAddress, gasPrice) => {
        try {
            return await this.requestProcessor.checkProviderSignerStatus(providerAddress, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Acknowledge TEE Signer (Contract Owner Only)
     *
     * This function allows the contract owner to acknowledge a provider's TEE signer.
     * The TEE signer address should already be set in the service registration.
     *
     * @param {string} providerAddress - The address of the provider
     * @throws Will throw an error if caller is not the contract owner or if acknowledgement fails.
     */
    acknowledgeProviderTEESigner = async (providerAddress, gasPrice) => {
        try {
            return await this.requestProcessor.ownerAcknowledgeTEESigner(providerAddress, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Revoke TEE Signer Acknowledgement (Contract Owner Only)
     *
     * This function allows the contract owner to revoke a provider's TEE signer acknowledgement.
     *
     * @param {string} providerAddress - The address of the provider
     * @throws Will throw an error if caller is not the contract owner or if revocation fails.
     */
    revokeProviderTEESignerAcknowledgement = async (providerAddress, gasPrice) => {
        try {
            return await this.requestProcessor.ownerRevokeTEESignerAcknowledgement(providerAddress, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Acknowledge the given provider address.
     *
     * @param {string} providerAddress - The address of the provider identifying the account.
     *
     *
     * @throws Will throw an error if failed to acknowledge.
     */
    acknowledgeProviderSigner = async (providerAddress, gasPrice) => {
        try {
            return await this.requestProcessor.acknowledgeProviderSigner(providerAddress, gasPrice);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Downloads quote report data from the provider service to a specified file.
     *
     * @param {string} providerAddress - The address of the provider.
     * @param {string} outputPath - The file path where the quote report will be saved.
     *
     * @throws Will throw an error if failed to download the quote report.
     */
    downloadQuoteReport = async (providerAddress, outputPath) => {
        try {
            return await this.requestProcessor.downloadQuoteReport(providerAddress, outputPath);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * Generates request metadata for the provider service.
     * Includes:
     * 1. Request endpoint for the provider service
     * 2. Model information for the provider service
     *
     * @param {string} providerAddress - The address of the provider.
     *
     * @returns { endpoint, model } - Object containing endpoint and model.
     *
     * @throws An error if errors occur during the processing of the request.
     */
    getServiceMetadata = async (providerAddress) => {
        try {
            return await this.requestProcessor.getServiceMetadata(providerAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * getRequestHeaders generates billing-related headers for the request
     * when the user uses the provider service.
     *
     * In the 0G Serving system, a request with valid billing headers
     * is considered a settlement proof and will be used by the provider
     * for contract settlement.
     *
     * @param {string} providerAddress - The address of the provider.
     * @param {string} content - The content being billed. For example, in a chatbot service, it is the text input by the user.
     *
     * @returns headers. Records information such as the request fee and user signature.
     *
     * @example
     *
     * const { endpoint, model } = await broker.getServiceMetadata(
     *   providerAddress,
     *   serviceName,
     * );
     *
     * const headers = await broker.getServiceMetadata(
     *   providerAddress,
     *   serviceName,
     *   content,
     * );
     *
     * const openai = new OpenAI({
     *   baseURL: endpoint,
     *   apiKey: "",
     * });
     *
     * const completion = await openai.chat.completions.create(
     *   {
     *     messages: [{ role: "system", content }],
     *     model,
     *   },
     *   headers: {
     *     ...headers,
     *   },
     * );
     *
     * @throws An error if errors occur during the processing of the request.
     */
    getRequestHeaders = async (providerAddress, content) => {
        try {
            return await this.requestProcessor.getRequestHeaders(providerAddress, content);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * processResponse is used after the user successfully obtains a response from the provider service.
     *
     * It will settle the fee for the response content. Additionally, if the service is verifiable,
     * input the chat ID from the response and processResponse will determine the validity of the
     * returned content by checking the provider service's response and corresponding signature associated
     * with the chat ID.
     *
     * @param {string} providerAddress - The address of the provider.
     * @param {string} content - The main content returned by the service. For example, in the case of a chatbot service,
     * it would be the response text.
     * @param {string} chatID - Only for verifiable services. You can provide the chat ID obtained from the response to
     * automatically download the response signature. The function will verify the reliability of the response
     * using the service's signing address.
     *
     * @returns A boolean value. True indicates the returned content is valid, otherwise it is invalid.
     *
     * @throws An error if any issues occur during the processing of the response.
     */
    processResponse = async (providerAddress, chatID, content) => {
        try {
            return await this.responseProcessor.processResponse(providerAddress, chatID, content);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * verifyService is used to verify the reliability of the service.
     *
     * @param {string} providerAddress - The address of the provider.
     *
     * @returns A <boolean | null> value. True indicates the service is reliable, otherwise it is unreliable.
     *
     * @throws An error if errors occur during the verification process.
     */
    verifyService = async (providerAddress, outputDir = '.') => {
        try {
            return await this.verifier.verifyService(providerAddress, outputDir);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * getSignerRaDownloadLink returns the download link for the Signer RA.
     *
     * It can be provided to users who wish to manually verify the Signer RA.
     *
     * @param {string} providerAddress - provider address.
     *
     * @returns Download link.
     */
    getSignerRaDownloadLink = async (providerAddress) => {
        try {
            return await this.verifier.getSignerRaDownloadLink(providerAddress);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
    /**
     * getChatSignatureDownloadLink returns the download link for the signature of a single chat.
     *
     * It can be provided to users who wish to manually verify the content of a single chat.
     *
     * @param {string} providerAddress - provider address.
     * @param {string} chatID - ID of the chat.
     *
     * @remarks To verify the chat signature, use the following code:
     *
     * ```typescript
     * const messageHash = ethers.hashMessage(messageToBeVerified)
     * const recoveredAddress = ethers.recoverAddress(messageHash, signature)
     * const isValid = recoveredAddress.toLowerCase() === signingAddress.toLowerCase()
     * ```
     *
     * @returns Download link.
     */
    getChatSignatureDownloadLink = async (providerAddress, chatID) => {
        try {
            return await this.verifier.getChatSignatureDownloadLink(providerAddress, chatID);
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    };
}
exports.InferenceBroker = InferenceBroker;
/**
 * createInferenceBroker is used to initialize ZGServingUserBroker
 *
 * @param signer - Signer from ethers.js.
 * @param contractAddress - 0G Serving contract address, use default address if not provided.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
async function createInferenceBroker(signer, contractAddress, ledger) {
    const broker = new InferenceBroker(signer, contractAddress, ledger);
    try {
        await broker.initialize();
        return broker;
    }
    catch (error) {
        throw error;
    }
}
//# sourceMappingURL=broker.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeCustomError = decodeCustomError;
exports.formatError = formatError;
exports.getDetailedError = getDetailedError;
exports.throwFormattedError = throwFormattedError;
const ethers_1 = require("ethers");
const LedgerManager__factory_1 = require("../../ledger/contract/typechain/factories/LedgerManager__factory");
const InferenceServing__factory_1 = require("../../inference/contract/typechain/factories/InferenceServing__factory");
const FineTuningServing__factory_1 = require("../../fine-tuning/contract/typechain/factories/FineTuningServing__factory");
// Create interfaces from the contract factories
const ledgerInterface = new ethers_1.Interface(LedgerManager__factory_1.LedgerManager__factory.abi);
const inferenceInterface = new ethers_1.Interface(InferenceServing__factory_1.InferenceServing__factory.abi);
const fineTuningInterface = new ethers_1.Interface(FineTuningServing__factory_1.FineTuningServing__factory.abi);
const contractInterfaces = {
    ledger: ledgerInterface,
    inference: inferenceInterface,
    fineTuning: fineTuningInterface,
};
function decodeCustomError(error) {
    try {
        // Type guard for error with data property
        const errorWithData = error;
        // Check if it's an ethers error with custom error data
        if (errorWithData.data && typeof errorWithData.data === 'string') {
            const errorData = errorWithData.data;
            // Try to decode with each contract interface
            for (const [, contractInterface] of Object.entries(contractInterfaces)) {
                try {
                    // Parse the custom error
                    const decodedError = contractInterface.parseError(errorData);
                    if (decodedError) {
                        // Format the error message based on the error name
                        const errorMessages = {
                            LedgerNotExists: 'Account does not exist. Please create an account first using "add-account".',
                            LedgerExists: 'Account already exists. Use "deposit" to add funds or "get-account" to view details.',
                            InsufficientBalance: 'Insufficient balance in the account.',
                            ServiceNotExist: 'Service provider does not exist. Please check the provider address.',
                            AccountNotExist: 'Sub-account does not exist for this provider.',
                            AccountExist: 'Sub-account already exists for this provider.',
                            InvalidVerifierInput: 'Invalid verification input provided.',
                            Unauthorized: 'Unauthorized. You do not have permission to perform this action.',
                            InvalidInput: 'Invalid input parameters provided.',
                        };
                        let message = errorMessages[decodedError.name] ||
                            `Error: ${decodedError.name}`;
                        // Add parameter details if available
                        if (decodedError.args && decodedError.args.length > 0) {
                            const argDetails = decodedError.args
                                .map((arg, index) => {
                                // Check if it's an address
                                if (typeof arg === 'string' &&
                                    arg.startsWith('0x') &&
                                    arg.length === 42) {
                                    return `Address: ${arg}`;
                                }
                                return `Arg${index}: ${arg}`;
                            })
                                .filter(Boolean)
                                .join(', ');
                            if (argDetails) {
                                message += ` (${argDetails})`;
                            }
                        }
                        return message;
                    }
                }
                catch {
                    // Continue to next interface if this one doesn't match
                    continue;
                }
            }
        }
        // Check for error reason
        if (errorWithData.reason) {
            return errorWithData.reason;
        }
        // Check for shortMessage
        if (errorWithData.shortMessage) {
            return errorWithData.shortMessage;
        }
        return null;
    }
    catch {
        return null;
    }
}
function formatError(error) {
    // First try to decode custom error
    const decodedError = decodeCustomError(error);
    if (decodedError) {
        return decodedError;
    }
    const errorWithMessage = error;
    // Check for common error patterns
    if (errorWithMessage.message) {
        // Check for gas estimation errors
        if (errorWithMessage.message.includes('execution reverted')) {
            const decoded = decodeCustomError(error);
            if (decoded) {
                return `Transaction failed: ${decoded}`;
            }
            return 'Transaction execution reverted. This usually means a requirement was not met.';
        }
        // Check for insufficient funds
        if (errorWithMessage.message.includes('insufficient funds')) {
            return 'Insufficient funds for transaction. Please check your wallet balance.';
        }
        // Check for nonce errors
        if (errorWithMessage.message.includes('nonce')) {
            return 'Transaction nonce error. Please wait a moment and try again.';
        }
        // Check for user rejected
        if (errorWithMessage.message.includes('user rejected') ||
            errorWithMessage.message.includes('User denied')) {
            return 'Transaction was rejected by the user.';
        }
        // Check for additional specific patterns
        if (errorWithMessage.message.includes('Deliverable not acknowledged yet')) {
            return "Deliverable not acknowledged yet. Please use 'acknowledge-model' to acknowledge the deliverable.";
        }
        if (errorWithMessage.message.includes('EncryptedSecret not found')) {
            return "Secret to decrypt model not found. Please ensure the task status is 'Finished'.";
        }
    }
    // Return original error message
    return errorWithMessage.message || String(error);
}
// Helper function to extract and format error details
function getDetailedError(error) {
    const message = formatError(error);
    const errorWithDetails = error;
    const details = [];
    if (errorWithDetails.code) {
        details.push(`Error Code: ${errorWithDetails.code}`);
    }
    if (errorWithDetails.action) {
        details.push(`Action: ${errorWithDetails.action}`);
    }
    if (errorWithDetails.data && errorWithDetails.data !== '0x') {
        // Only show first 10 chars of data for brevity
        const dataPreview = errorWithDetails.data.length > 10
            ? errorWithDetails.data.substring(0, 10) + '...'
            : errorWithDetails.data;
        details.push(`Data: ${dataPreview}`);
    }
    return {
        message,
        details: details.length > 0 ? details.join(' | ') : undefined,
    };
}
// Helper function to throw formatted errors from within SDK functions
function throwFormattedError(error) {
    const formattedMessage = formatError(error);
    const formattedError = new Error(formattedMessage);
    // Preserve original error properties if possible
    if (error && typeof error === 'object') {
        Object.assign(formattedError, error);
        formattedError.message = formattedMessage;
    }
    throw formattedError;
}
//# sourceMappingURL=error-handler.js.map
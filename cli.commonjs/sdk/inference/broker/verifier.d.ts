import type { TdxQuoteResponse } from './base';
import { ZGServingUserBrokerBase } from './base';
import type { InferenceServingContract } from '../contract';
import type { LedgerBroker } from '../../ledger';
import type { Cache, Metadata } from '../../common/storage';
export interface ResponseSignature {
    text: string;
    signature: string;
}
export interface SingerRAVerificationResult {
    /**
     * Whether the signer RA is valid
     * null means the RA has not been verified
     */
    valid: boolean | null;
    /**
     * The signing address of the signer
     */
    signingAddress: string;
}
export interface VerificationResult {
    success: boolean;
    teeVerifier: string;
    targetSeparated: boolean;
    verifierURL?: string;
    reportsGenerated: string[];
    outputDirectory: string;
}
export interface AdditionalInfo {
    VerifierURL?: string;
    TargetSeparated?: boolean;
    TEEVerifier?: string;
    TargetTeeAddress?: string;
}
export interface AttestationReport {
    tcb_info?: Record<string, unknown>;
    info?: {
        tcb_info?: Record<string, unknown>;
    };
    event_log?: EventLogEntry[];
    [key: string]: unknown;
}
export interface EventLogEntry {
    event: string;
    event_payload?: string;
    [key: string]: unknown;
}
export interface ComposeVerificationResult {
    isValid: boolean;
    error?: string;
    calculatedHash?: string;
    eventLogHash?: string;
    composeHashEvent?: EventLogEntry;
}
export interface VerificationSummary {
    composeVerification: boolean;
    signerAddressVerification: boolean;
    signerAddressMatches: number;
    totalReports: number;
    allVerificationsPassed: boolean;
}
/**
 * The Verifier class contains methods for verifying service reliability.
 */
export declare class Verifier extends ZGServingUserBrokerBase {
    constructor(contract: InferenceServingContract, ledger: LedgerBroker, metadata: Metadata, cache: Cache);
    /**
     * Comprehensive TEE service verification guide
     * Guides users through verifying whether a provider is running in TEE
     *
     * @param providerAddress - The provider address to verify
     * @param outputDir - Directory to save attestation reports (default: current directory)
     * @returns Verification results and user guidance
     */
    verifyService(providerAddress: string, outputDir?: string): Promise<VerificationResult>;
    /**
     * Extract TEE signer address from attestation report
     */
    private extractTeeSignerAddress;
    /**
     * Process DStack-specific verification steps
     */
    private processDStackVerification;
    /**
     * Verify compose hash based on the dstack verification logic
     */
    private verifyComposeHash;
    /**
     * Extract all Docker images from tcb_info
     */
    private extractAllImagesFromTcbInfo;
    /**
     * Save report to file
     */
    private saveReportToFile;
    getSignerRaDownloadLink(providerAddress: string): Promise<string>;
    getChatSignatureDownloadLink(providerAddress: string, chatID: string): Promise<string>;
    static verifyRA(providerBrokerURL: string, nvidia_payload: Record<string, unknown>): Promise<boolean>;
    getQuoteInLLMServer(providerBrokerURL: string, model: string): Promise<TdxQuoteResponse>;
    static fetchSignatureByChatID(providerBrokerURL: string, chatID: string, model: string): Promise<ResponseSignature>;
    static verifySignature(message: string, signature: string, expectedAddress: string): boolean;
}
//# sourceMappingURL=verifier.d.ts.map
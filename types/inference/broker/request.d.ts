import { ZGServingUserBrokerBase } from './base';
import type { Cache, Metadata } from '../../common/storage';
import type { InferenceServingContract } from '../contract';
import type { LedgerBroker } from '../../ledger';
import { Automata } from '../../common/automata';
/**
 * ServingRequestHeaders contains headers related to request.
 * Only Address and VLLM-Proxy are required now.
 */
export interface ServingRequestHeaders {
    /**
     * @deprecated This field is no longer used but kept for backwards compatibility
     */
    'X-Phala-Signature-Type'?: 'StandaloneApi';
    /**
     * User's address
     */
    Address: string;
    /**
     * @deprecated Total fee for the request - no longer used
     */
    Fee?: string;
    /**
     * @deprecated Fee required for the input - no longer used
     */
    'Input-Fee'?: string;
    /**
     * @deprecated Pedersen hash - no longer used
     */
    'Request-Hash'?: string;
    /**
     * @deprecated Nonce - no longer used
     */
    Nonce?: string;
    /**
     * @deprecated User's signature - no longer used
     */
    Signature?: string;
    /**
     * Session token containing user info and expiry
     */
    'Session-Token': string;
    /**
     * Signature of the session token
     */
    'Session-Signature': string;
}
/**
 * RequestProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
export declare class RequestProcessor extends ZGServingUserBrokerBase {
    protected automata: Automata;
    constructor(contract: InferenceServingContract, metadata: Metadata, cache: Cache, ledger: LedgerBroker);
    getServiceMetadata(providerAddress: string): Promise<{
        endpoint: string;
        model: string;
    }>;
    getRequestHeaders(providerAddress: string, content: string): Promise<ServingRequestHeaders>;
    /**
     * Check if provider's TEE signer is acknowledged by the contract owner.
     * This method no longer performs acknowledgement (which is owner-only),
     * but verifies if the provider is ready for use.
     */
    checkProviderSignerStatus(providerAddress: string, gasPrice?: number): Promise<{
        isAcknowledged: boolean;
        teeSignerAddress: string;
    }>;
    /**
     * @deprecated Use checkProviderSignerStatus instead.
     * TEE signer acknowledgement is now handled by contract owner only.
     */
    acknowledgeProviderSigner(providerAddress: string, gasPrice?: number): Promise<void>;
    /**
     * Acknowledge TEE Signer (Contract Owner Only)
     *
     * @param providerAddress - The address of the provider
     */
    ownerAcknowledgeTEESigner(providerAddress: string, gasPrice?: number): Promise<void>;
    /**
     * Revoke TEE Signer Acknowledgement (Contract Owner Only)
     *
     * @param providerAddress - The address of the provider
     */
    ownerRevokeTEESignerAcknowledgement(providerAddress: string, gasPrice?: number): Promise<void>;
}
//# sourceMappingURL=request.d.ts.map
import type { TdxQuoteResponse } from './base'
import { ZGServingUserBrokerBase } from './base'
import { ethers } from 'ethers'
import { throwFormattedError } from '../../common/utils'
import { Automata } from '../../common/automata '
import type { InferenceServingContract } from '../contract'
import type { LedgerBroker } from '../../ledger'
import type { Cache, Metadata } from '../../common/storage'

export interface ResponseSignature {
    text: string
    signature: string
}

export interface SingerRAVerificationResult {
    /**
     * Whether the signer RA is valid
     * null means the RA has not been verified
     */
    valid: boolean | null
    /**
     * The signing address of the signer
     */
    signingAddress: string
}

/**
 * The Verifier class contains methods for verifying service reliability.
 */
export class Verifier extends ZGServingUserBrokerBase {
    protected automata: Automata

    constructor(
        contract: InferenceServingContract,
        ledger: LedgerBroker,
        metadata: Metadata,
        cache: Cache
    ) {
        super(contract, ledger, metadata, cache)
        this.automata = new Automata()
    }

    async verifyService(providerAddress: string): Promise<boolean | null> {
        try {
            const { valid } = await this.getSigningAddress(
                providerAddress,
                true
            )
            return valid
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * getSigningAddress verifies whether the signing address
     * of the signer corresponds to a valid RA.
     *
     * It also stores the signing address of the RA in
     * localStorage and returns it.
     *
     * @param providerAddress - provider address.
     * @param verifyRA - whether to verify the RA， default is false.
     * @returns The first return value indicates whether the RA is valid,
     * and the second return value indicates the signing address of the RA.
     */
    async getSigningAddress(
        providerAddress: string,
        verifyRA = false,
        vllmProxy = true
    ): Promise<SingerRAVerificationResult> {
        const key = `${this.contract.getUserAddress()}_${providerAddress}`
        let signingKey = await this.metadata.getSigningKey(key)
        if (!verifyRA && signingKey) {
            return {
                valid: null,
                signingAddress: signingKey,
            }
        }

        try {
            const extractor = await this.getExtractor(providerAddress, false)
            const svc = await extractor.getSvcInfo()

            const { signingAddress } = vllmProxy
                ? await this.getQuoteInLLMServer(svc.url, svc.model)
                : await this.getQuote(providerAddress)
            if (!signingAddress) {
                throw new Error('signing address does not exist')
            }

            signingKey = `${this.contract.getUserAddress()}_${providerAddress}`
            await this.metadata.storeSigningKey(signingKey, signingAddress)

            // Verification of RA should be separated from fetching signing address

            // const rpc = process.env.RPC_ENDPOINT
            // // bypass quote verification if testing on localhost
            // if (!rpc || !/localhost|127\.0\.0\.1/.test(rpc)) {
            //     valid =
            //         (await this.automata.verifyQuote(signerRA.intel_quote)) ||
            //         false
            //     console.log(
            //         'Quote verification when verify signing key quote:',
            //         valid
            //     )

            //     // if (nvidia_payload) {
            //     //     const svc = await this.getService(providerAddress)
            //     //     const valid = await Verifier.verifyRA(
            //     //         svc.url,
            //     //         nvidia_payload
            //     //     )
            //     //     console.log('nvidia payload verification:', valid)

            //     //     if (!valid) {
            //     //         throw new Error('nvidia payload verify failed')
            //     //     }
            //     // }
            // }

            // TODO: use intel_quote to verify signing address
            // valid = await Verifier.verifyRA(svc.url, signerRA.nvidia_payload)

            return {
                valid: true,
                signingAddress,
            }
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getSignerRaDownloadLink(providerAddress: string): Promise<string> {
        try {
            const svc = await this.getService(providerAddress)
            return `${svc.url}/v1/proxy/attestation/report`
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getChatSignatureDownloadLink(
        providerAddress: string,
        chatID: string
    ): Promise<string> {
        try {
            const svc = await this.getService(providerAddress)
            return `${svc.url}/v1/proxy/signature/${chatID}`
        } catch (error) {
            throwFormattedError(error)
        }
    }

    static async verifyRA(
        providerBrokerURL: string,
        nvidia_payload: any
    ): Promise<boolean> {
        return fetch(`${providerBrokerURL}/v1/quote/verify/gpu`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify(nvidia_payload),
        })
            .then((response) => {
                if (response.status === 200) {
                    return true
                }
                if (response.status === 404) {
                    throw new Error('verify RA error: 404')
                } else {
                    return false
                }
            })
            .catch((error) => {
                if (error instanceof Error) {
                    console.error(error.message)
                }
                return false
            })
    }

    // async fetSignerRA(
    //     providerBrokerURL: string,
    //     model: string
    // ): Promise<string> {
    //     const endpoint = `${providerBrokerURL}/v1/proxy/attestation/report?model=${model}`
    //     const quoteString = await this.fetchText(endpoint, {
    //         method: 'GET',
    //     })
    //     // Write quoteString to /tmp/del
    //     await fs.promises.writeFile('/tmp/del', quoteString)
    //     return quoteString
    // }

    async getQuoteInLLMServer(
        providerBrokerURL: string,
        model: string
    ): Promise<TdxQuoteResponse> {
        try {
            const rawReport = await this.fetchText(
                `${providerBrokerURL}/v1/proxy/attestation/report?model=${model}`,
                {
                    method: 'GET',
                }
            )
            const ret = JSON.parse(rawReport)
            return {
                rawReport,
                signingAddress: ret['signing_address'],
            } as TdxQuoteResponse
        } catch (error) {
            throwFormattedError(error)
        }
    }

    static async fetchSignatureByChatID(
        providerBrokerURL: string,
        chatID: string,
        model: string,
    ): Promise<ResponseSignature> {
        return fetch(
            `${providerBrokerURL}/v1/proxy/signature/${chatID}?model=${model}`,
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
            }
        )
            .then((response) => {
                if (!response.ok) {
                    throw new Error('getting signature error')
                }
                return response.json()
            })
            .then((data) => {
                return data as ResponseSignature
            })
            .catch((error) => {
                throwFormattedError(error)
            })
    }

    static verifySignature(
        message: string,
        signature: string,
        expectedAddress: string
    ): boolean {
        const messageHash = ethers.hashMessage(message)

        const recoveredAddress = ethers.recoverAddress(messageHash, signature)

        return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase()
    }
}

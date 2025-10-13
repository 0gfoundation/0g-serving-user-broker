"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Verifier = void 0;
const base_1 = require("./base");
const ethers_1 = require("ethers");
const utils_1 = require("../../common/utils");
const automata_1 = require("../../common/automata ");
/**
 * The Verifier class contains methods for verifying service reliability.
 */
class Verifier extends base_1.ZGServingUserBrokerBase {
    automata;
    constructor(contract, ledger, metadata, cache) {
        super(contract, ledger, metadata, cache);
        this.automata = new automata_1.Automata();
    }
    async verifyService(providerAddress) {
        try {
            const { valid } = await this.getSigningAddress(providerAddress, true);
            return valid;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
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
    async getSigningAddress(providerAddress, verifyRA = false, vllmProxy = true) {
        const key = `${this.contract.getUserAddress()}_${providerAddress}`;
        let signingKey = await this.metadata.getSigningKey(key);
        if (!verifyRA && signingKey) {
            return {
                valid: null,
                signingAddress: signingKey,
            };
        }
        try {
            const extractor = await this.getExtractor(providerAddress, false);
            const svc = await extractor.getSvcInfo();
            let signerRA = {
                signing_address: '',
                nvidia_payload: '',
                intel_quote: '',
            };
            // if (vllmProxy) {
            //     const quoteString = await this.fetSignerRA(svc.url, svc.model)
            //     signerRA = JSON.parse(quoteString)
            //     if (!signerRA?.signing_address) {
            //         throw new Error('signing address does not exist')
            //     }
            // } else {
            //     const { quote } = await this.getQuote(providerAddress)
            //     signerRA = JSON.parse(quote)
            // }
            if (vllmProxy) {
                signerRA = await Verifier.fetSignerRA(svc.url, svc.model);
                if (!signerRA?.signing_address) {
                    throw new Error('signing address does not exist');
                }
            }
            else {
                const { quote, provider_signer, nvidia_payload } = await this.getQuote(providerAddress);
                signerRA = {
                    signing_address: provider_signer,
                    nvidia_payload: nvidia_payload,
                    intel_quote: quote,
                };
            }
            signingKey = `${this.contract.getUserAddress()}_${providerAddress}`;
            await this.metadata.storeSigningKey(signingKey, signerRA.signing_address);
            let valid = false;
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
            valid = await Verifier.verifyRA(svc.url, signerRA.nvidia_payload);
            return {
                valid,
                signingAddress: signerRA.signing_address,
            };
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getSignerRaDownloadLink(providerAddress) {
        try {
            const svc = await this.getService(providerAddress);
            return `${svc.url}/v1/proxy/attestation/report`;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    async getChatSignatureDownloadLink(providerAddress, chatID) {
        try {
            const svc = await this.getService(providerAddress);
            return `${svc.url}/v1/proxy/signature/${chatID}`;
        }
        catch (error) {
            (0, utils_1.throwFormattedError)(error);
        }
    }
    static async verifyRA(providerBrokerURL, nvidia_payload) {
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
                return true;
            }
            if (response.status === 404) {
                throw new Error('verify RA error: 404');
            }
            else {
                return false;
            }
        })
            .catch((error) => {
            if (error instanceof Error) {
                console.error(error.message);
            }
            return false;
        });
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
    static async fetSignerRA(providerBrokerURL, model) {
        return fetch(`${providerBrokerURL}/v1/proxy/attestation/report?model=${model}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        })
            .then((response) => {
            return response.json();
        })
            .then((data) => {
            if (data.nvidia_payload) {
                try {
                    data.nvidia_payload = JSON.parse(data.nvidia_payload);
                }
                catch (error) {
                    throw Error('parsing nvidia_payload error');
                }
            }
            if (data.intel_quote) {
                try {
                    data.intel_quote =
                        '0x' +
                            Buffer.from(data.intel_quote, 'base64').toString('hex');
                }
                catch (error) {
                    throw Error('parsing intel_quote error');
                }
            }
            return data;
        })
            .catch((error) => {
            (0, utils_1.throwFormattedError)(error);
        });
    }
    static async fetSignatureByChatID(providerBrokerURL, chatID, model, vllmProxy) {
        return fetch(`${providerBrokerURL}/v1/proxy/signature/${chatID}?model=${model}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'VLLM-Proxy': `${vllmProxy}`,
            },
        })
            .then((response) => {
            if (!response.ok) {
                throw new Error('getting signature error');
            }
            return response.json();
        })
            .then((data) => {
            return data;
        })
            .catch((error) => {
            (0, utils_1.throwFormattedError)(error);
        });
    }
    static verifySignature(message, signature, expectedAddress) {
        const messageHash = ethers_1.ethers.hashMessage(message);
        const recoveredAddress = ethers_1.ethers.recoverAddress(messageHash, signature);
        return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
    }
}
exports.Verifier = Verifier;
//# sourceMappingURL=verifier.js.map
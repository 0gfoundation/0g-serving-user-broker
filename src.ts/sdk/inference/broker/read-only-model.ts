import type { ServiceStructOutput } from '../contract'
import type { ReadOnlyInferenceServingContract } from '../contract'
import { throwFormattedError } from '../../common/utils'
import axios from 'axios'

export enum VerifiabilityEnum {
    OpML = 'OpML',
    TeeML = 'TeeML',
    ZKML = 'ZKML',
}

export type Verifiability =
    | VerifiabilityEnum.OpML
    | VerifiabilityEnum.TeeML
    | VerifiabilityEnum.ZKML

export type HealthStatus = 'healthy' | 'warning' | 'critical' | 'unknown'

export interface ServiceHealthMetric {
    serviceType: string
    model: string
    provider: string
    status: HealthStatus
    checks: {
        total: number
        successful: number
        failed: number
        uptime: number
    }
    performance: {
        response_time?: {
            avg: number
            unit: string
            samples: number
        }
        ttft?: {
            avg: number
            unit: string
            samples: number
        }
        tokens_per_second?: {
            avg: number
            unit: string
            samples: number
        }
    }
    lastCheck: string
}

/**
 * Model information returned by the status API's /v1/models endpoint
 */
export interface ProviderModelInfo {
    id: string
    provider?: string
    /**
     * Router-owned canonical model id this model maps to (bare lowercase, e.g.
     * "glm-5.1"). Emitted per-model by multi-model providers so a catalog can
     * group endpoints under a canonical model. Optional.
     */
    canonical_id?: string
    object?: string
    created?: number
    owned_by?: string
    name?: string
    description?: string
    type?: string
    context_length?: number
    max_completion_tokens?: number
    architecture?: {
        modality?: string
        input_modalities?: string[]
        output_modalities?: string[]
        /** Instruction format the model expects, e.g. "none" | "alpaca" | "chatml" */
        instruct_type?: string
        tokenizer?: string
    }
    supported_parameters?: string[]
    /** Default parameter values to use when constructing requests */
    default_parameters?: {
        temperature?: number
        top_p?: number
        top_k?: number
        [key: string]: number | string | boolean | undefined
    }
    pricing?: {
        prompt?: string
        completion?: string
        /** Price per generated image (text-to-image services) */
        image?: string
        /** Price per effective output second (video-generation services) */
        video?: string
        /** Tiered pricing tiers based on input token count */
        tiered_pricing?: Array<{
            max_input_tokens: number
            input_multiplier: number
            output_multiplier: number
        }>
        /** Cache token billing configuration */
        cache_token_billing?: {
            divisor: number
        }
    }
    /**
     * Pricing expressed in USD. Values are decimal strings (e.g. "0.000000175").
     * Returned by the status API alongside `pricing` (which is in native token units).
     */
    pricing_usd?: {
        /** USD price per prompt token */
        prompt?: string
        /** USD price per completion token */
        completion?: string
        /** USD price per generated image (image services) */
        image?: string
        /** USD price per effective output second (video-generation services) */
        video?: string
        /** Tiered pricing tiers based on input token count */
        tiered_pricing?: Array<{
            max_input_tokens: number
            input_multiplier: number
            output_multiplier: number
        }>
        /** Cache token billing configuration */
        cache_token_billing?: {
            divisor: number
        }
    }
    /** ISO 8601 date string indicating when this model will no longer be served */
    expiration_date?: string
    verifiability?: string
    tee_attested?: boolean
    tee_type?: string
    tee_verifier?: string
}

/**
 * A single pricing tier for input-length-based tiered pricing.
 * Tiers are ordered by maxInputTokens ascending.
 * maxInputTokens: 0 means unlimited (the highest tier).
 */
export interface PricingTier {
    maxInputTokens: number
    inputMultiplier: number
    outputMultiplier: number
}

/**
 * Tiered pricing configuration parsed from service additionalInfo.
 */
export interface TieredPricingInfo {
    tiers: PricingTier[]
}

/**
 * Parse tiered pricing info from service additionalInfo JSON string.
 * Returns undefined if not present or invalid.
 */
export function parseTieredPricing(
    additionalInfo: string
): TieredPricingInfo | undefined {
    try {
        const parsed = JSON.parse(additionalInfo)
        if (
            parsed?.tieredPricing?.tiers &&
            Array.isArray(parsed.tieredPricing.tiers)
        ) {
            const tiers: PricingTier[] = parsed.tieredPricing.tiers
                .filter(
                    (t: any) =>
                        typeof t.maxInputTokens === 'number' &&
                        typeof t.inputMultiplier === 'number' &&
                        typeof t.outputMultiplier === 'number'
                )
                .map((t: any) => ({
                    maxInputTokens: t.maxInputTokens,
                    inputMultiplier: t.inputMultiplier,
                    outputMultiplier: t.outputMultiplier,
                }))
            if (tiers.length > 0) {
                return { tiers }
            }
        }
    } catch {
        // additionalInfo is not valid JSON or doesn't contain tieredPricing
    }
    return undefined
}

/**
 * Parse tiered pricing from ProviderModelInfo (returned by /v1/models endpoint).
 * Returns undefined if not present.
 */
export function parseTieredPricingFromModelInfo(
    modelInfo?: ProviderModelInfo
): TieredPricingInfo | undefined {
    const raw = modelInfo?.pricing?.tiered_pricing
    if (!raw || !Array.isArray(raw) || raw.length === 0) {
        return undefined
    }
    const tiers: PricingTier[] = raw
        .filter(
            (t) =>
                typeof t.max_input_tokens === 'number' &&
                typeof t.input_multiplier === 'number' &&
                typeof t.output_multiplier === 'number'
        )
        .map((t) => ({
            maxInputTokens: t.max_input_tokens,
            inputMultiplier: t.input_multiplier,
            outputMultiplier: t.output_multiplier,
        }))
    if (tiers.length > 0) {
        return { tiers }
    }
    return undefined
}

/**
 * Cache token billing configuration parsed from service additionalInfo or modelInfo.
 */
export interface CacheTokenBillingInfo {
    divisor: number
}

/**
 * Parse cache token billing info from service additionalInfo JSON string.
 * Returns undefined if not present or invalid.
 */
export function parseCacheTokenBilling(
    additionalInfo: string
): CacheTokenBillingInfo | undefined {
    try {
        const parsed = JSON.parse(additionalInfo)
        if (
            parsed?.cacheTokenBilling &&
            typeof parsed.cacheTokenBilling.divisor === 'number' &&
            parsed.cacheTokenBilling.divisor > 0
        ) {
            return { divisor: parsed.cacheTokenBilling.divisor }
        }
    } catch {
        // additionalInfo is not valid JSON or doesn't contain cacheTokenBilling
    }
    return undefined
}

/**
 * Parse cache token billing from ProviderModelInfo (returned by /v1/models endpoint).
 * Returns undefined if not present.
 */
export function parseCacheTokenBillingFromModelInfo(
    modelInfo?: ProviderModelInfo
): CacheTokenBillingInfo | undefined {
    const raw = modelInfo?.pricing?.cache_token_billing
    if (raw && typeof raw.divisor === 'number' && raw.divisor > 0) {
        return { divisor: raw.divisor }
    }
    return undefined
}

/**
 * Multi-model serving info parsed from service additionalInfo.
 *
 * A centralized provider that serves N models advertises `MultiModel: true`
 * (and its price denomination) on-chain. The full per-model catalog is NOT
 * on-chain — fetch it from the provider's /v1/models endpoint via
 * {@link ReadOnlyModelProcessor.getProviderModels}.
 */
export interface MultiModelInfo {
    /** True if this provider serves multiple models behind one address. */
    multiModel: boolean
    /** Price denomination advertised on-chain ("USD" | "NATIVE"); undefined when absent. */
    priceDenomination?: string
}

/**
 * Parse multi-model serving info from a service's additionalInfo JSON string.
 * Returns { multiModel: false } when absent or the JSON is invalid (so a
 * single-model / legacy provider degrades cleanly).
 */
export function parseMultiModelInfo(additionalInfo: string): MultiModelInfo {
    try {
        const parsed = JSON.parse(additionalInfo)
        if (parsed?.MultiModel === true) {
            return {
                multiModel: true,
                priceDenomination:
                    typeof parsed.priceDenomination === 'string'
                        ? parsed.priceDenomination
                        : undefined,
            }
        }
    } catch {
        // additionalInfo not valid JSON / no MultiModel flag
    }
    return { multiModel: false }
}

/**
 * A provider's served-model catalog, fetched live from its public /v1/models
 * endpoint. Authoritative per-provider view (per-model pricing, canonical id,
 * type) for both single-model and multi-model providers.
 */
export interface ProviderModels {
    provider: string
    /** Provider base URL (the on-chain service.url). */
    url: string
    /** True if the provider advertises multi-model serving on-chain. */
    multiModel: boolean
    /** Price denomination advertised on-chain ("USD" | "NATIVE"), if any. */
    priceDenomination?: string
    /**
     * The on-chain default model — billed/forwarded when a request omits `model`.
     * For multi-model providers, callers should pick one of `models[].id` instead.
     */
    defaultModel: string
    /** Models served by this provider (exactly one for single-model providers). */
    models: ProviderModelInfo[]
}

/**
 * Service information with optional health metrics and provider model info
 */
export interface ServiceWithDetail {
    provider: string
    serviceType: string
    url: string
    inputPrice: bigint
    outputPrice: bigint
    updatedAt: bigint
    model: string
    verifiability: string
    additionalInfo: string
    teeSignerAddress: string
    teeSignerAcknowledged: boolean
    healthMetrics?: {
        status: string
        uptime: number
        avgResponseTime: number
        lastCheck: string
    }
    modelInfo?: ProviderModelInfo
    tieredPricing?: TieredPricingInfo
    cacheTokenBilling?: CacheTokenBillingInfo
    /** True if this provider serves multiple models (from on-chain additionalInfo). */
    multiModel?: boolean
    /** Price denomination advertised on-chain ("USD" | "NATIVE"), if any. */
    priceDenomination?: string
    /**
     * All models this provider serves, when known from the status API. For a
     * multi-model provider this has the full catalog; for a single-model
     * provider it is the one model (or omitted if the status API had none).
     * Authoritative live data is available via getProviderModels().
     */
    models?: ProviderModelInfo[]
}

/**
 * Read-only model processor for listing services and fetching health metrics
 * Works without authentication - only requires a read-only contract
 */
export class ReadOnlyModelProcessor {
    protected contract: ReadOnlyInferenceServingContract

    constructor(contract: ReadOnlyInferenceServingContract) {
        this.contract = contract
    }

    /**
     * List services from the blockchain
     *
     * @param offset - Pagination offset (default: 0)
     * @param limit - Pagination limit (default: 50)
     * @param includeUnacknowledged - Include unacknowledged services (default: false)
     * @returns Array of service struct outputs
     */
    async listService(
        offset: number = 0,
        limit: number = 50,
        includeUnacknowledged: boolean = false
    ): Promise<ServiceStructOutput[]> {
        return this.contract.listService(offset, limit, includeUnacknowledged)
    }

    /**
     * Retrieves a list of services enriched with health metrics and model info from the status API.
     *
     * @param offset - The offset for pagination (default: 0)
     * @param limit - The limit for pagination (default: 50)
     * @param includeUnacknowledged - Whether to include providers whose TEE signer is not acknowledged (default: false)
     * @returns Promise that resolves to an array of ServiceWithDetail objects, each containing:
     *   - Blockchain service data (provider, model, pricing, verifiability, etc.)
     *   - `healthMetrics` — uptime, avg response time, and status (omitted if unavailable)
     *   - `modelInfo` — rich model metadata: context length, max completion tokens, tokenizer,
     *     TEE attestation details, supported parameters, pricing, and more (omitted if unavailable)
     * @throws An error if the service list cannot be retrieved
     *
     * @example
     * ```typescript
     * const services = await processor.listServiceWithDetail();
     * services.forEach(service => {
     *   console.log(`Provider: ${service.provider}`);
     *   if (service.healthMetrics) {
     *     console.log(`  Uptime: ${service.healthMetrics.uptime}%`);
     *     console.log(`  Latency: ${service.healthMetrics.avgResponseTime}ms`);
     *   }
     *   if (service.modelInfo) {
     *     console.log(`  Model: ${service.modelInfo.name}`);
     *     console.log(`  Context: ${service.modelInfo.context_length} tokens`);
     *     console.log(`  TEE Attested: ${service.modelInfo.tee_attested}`);
     *   }
     * });
     * ```
     */
    async listServiceWithDetail(
        offset: number = 0,
        limit: number = 50,
        includeUnacknowledged: boolean = false
    ): Promise<ServiceWithDetail[]> {
        try {
            // Get services from blockchain
            const services = await this.listService(
                offset,
                limit,
                includeUnacknowledged
            )

            // Determine status API endpoint based on chain ID
            const chainId = await this.contract.getChainId()
            const statusApiEndpoint = this.getStatusApiEndpoint(chainId)

            // Fetch health metrics and aggregated model info from status API in parallel
            let healthMetrics: ServiceHealthMetric[] = []
            let allModels: ProviderModelInfo[] = []
            await Promise.all([
                axios
                    .get(`${statusApiEndpoint}/health`, { timeout: 10000 })
                    .then((r) => {
                        healthMetrics = Array.isArray(r.data?.services)
                            ? r.data.services
                            : []
                    })
                    .catch(() => {}),
                axios
                    .get(`${statusApiEndpoint}/models`, { timeout: 10000 })
                    .then((r) => {
                        allModels = Array.isArray(r.data?.data)
                            ? r.data.data
                            : []
                    })
                    .catch(() => {}),
            ])

            // Create a map of health metrics by provider address
            const healthMap = new Map<string, ServiceHealthMetric>()
            for (const metric of healthMetrics) {
                healthMap.set(metric.provider.toLowerCase(), metric)
            }

            // Create a map of model info by provider address
            const providerModelsMap = new Map<string, ProviderModelInfo[]>()
            for (const model of allModels) {
                if (!model.provider) continue
                const key = model.provider.toLowerCase()
                const list = providerModelsMap.get(key) ?? []
                list.push(model)
                providerModelsMap.set(key, list)
            }

            // Merge health metrics and model info with services
            // Note: Explicitly construct clean objects to avoid numeric indices from ethers Result type
            const servicesWithDetail: ServiceWithDetail[] = services.map(
                (service) => {
                    const health = healthMap.get(service.provider.toLowerCase())
                    const providerModels =
                        providerModelsMap.get(service.provider.toLowerCase()) ??
                        []
                    const modelInfo = providerModels.find(
                        (m) => m.id === service.model
                    )
                    const multi = parseMultiModelInfo(service.additionalInfo)
                    return {
                        provider: service.provider,
                        serviceType: service.serviceType,
                        url: service.url,
                        inputPrice: service.inputPrice,
                        outputPrice: service.outputPrice,
                        updatedAt: service.updatedAt,
                        model: service.model,
                        verifiability: service.verifiability,
                        additionalInfo: service.additionalInfo,
                        teeSignerAddress: service.teeSignerAddress,
                        teeSignerAcknowledged: service.teeSignerAcknowledged,
                        healthMetrics: health
                            ? {
                                status: health.status,
                                uptime: health.checks.uptime,
                                avgResponseTime:
                                    health.performance.response_time?.avg ?? 0,
                                lastCheck: health.lastCheck,
                            }
                            : undefined,
                        modelInfo,
                        tieredPricing:
                            parseTieredPricing(service.additionalInfo) ??
                            parseTieredPricingFromModelInfo(modelInfo),
                        cacheTokenBilling:
                            parseCacheTokenBilling(service.additionalInfo) ??
                            parseCacheTokenBillingFromModelInfo(modelInfo),
                        multiModel: multi.multiModel,
                        priceDenomination: multi.priceDenomination,
                        models:
                            providerModels.length > 0
                                ? providerModels
                                : undefined,
                    }
                }
            )

            return servicesWithDetail
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Fetch the models a single provider serves, live from its public
     * /v1/models endpoint (no authentication required). Authoritative
     * per-provider view including per-model pricing, canonical id, and type —
     * works for both single-model and multi-model providers.
     *
     * Backward-compatible: a single-model provider returns exactly one model
     * with multiModel=false. The on-chain default model (used when a request
     * omits `model`) is returned as `defaultModel`.
     *
     * Unlike {@link listServiceWithDetail} (which degrades silently when a
     * provider is unreachable, since it lists many), this REJECTS if the
     * provider is unreachable or returns an unexpected response shape — you
     * asked about one specific provider, so an empty result must mean "serves
     * no models", never "the fetch quietly failed". Callers should try/catch.
     *
     * @param providerAddress - The provider's on-chain address.
     * @returns The provider's model catalog plus its multi-model flag.
     * @throws If the on-chain read, the /v1/models fetch, or the response shape fails.
     */
    async getProviderModels(providerAddress: string): Promise<ProviderModels> {
        try {
            const service = await this.contract.getService(providerAddress)
            const meta = parseMultiModelInfo(service.additionalInfo)
            const base = service.url.replace(/\/+$/, '')
            const resp = await axios.get(`${base}/v1/models`, {
                timeout: 10000,
                // Bound the response so a hostile/broken provider can't OOM the
                // client by streaming a huge body within the timeout window.
                maxContentLength: 5_000_000,
                maxBodyLength: 5_000_000,
            })
            // A valid /v1/models response is { object: "list", data: [...] }.
            // Treat a non-array `data` as a schema violation (throw) rather than
            // coercing to [], so "no models" stays distinguishable from a garbage
            // 200 (e.g. an HTML error page or { error: ... }).
            const data = resp.data?.data
            if (!Array.isArray(data)) {
                throw new Error(
                    'provider /v1/models returned an unexpected response shape (missing "data" array)'
                )
            }
            const models: ProviderModelInfo[] = data
            return {
                provider: service.provider,
                url: service.url,
                multiModel: meta.multiModel,
                priceDenomination: meta.priceDenomination,
                defaultModel: service.model,
                models,
            }
        } catch (error) {
            throwFormattedError(error)
        }
    }

    /**
     * Get status API endpoint based on chain ID
     * @param chainId - The chain ID
     * @returns The status API endpoint URL
     */
    protected getStatusApiEndpoint(chainId?: bigint): string {
        // Mainnet: 16661n, Testnet: 16602n
        if (chainId === 16661n) {
            return 'https://compute-status.0g.ai'
        } else {
            // Default to testnet
            return 'https://compute-status-testnet.0g.ai'
        }
    }
}

export function isVerifiability(value: string): value is Verifiability {
    return Object.values(VerifiabilityEnum).includes(value as VerifiabilityEnum)
}

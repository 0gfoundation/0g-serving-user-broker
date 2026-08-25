#!/usr/bin/env ts-node

import type { Command } from 'commander'
import {
    withBroker,
    withROBroker,
    neuronToA0gi,
    a0giToNeuron,
    initBroker,
} from './util'
import { getRpcEndpoint } from './network-setup'
import { ensurePrivateKeyConfiguration } from './private-key-setup'
import { interactiveSelect, textInput } from './interactive-selection'
import Table from 'cli-table3'
import chalk from 'chalk'
import axios from 'axios'
import fs from 'fs'
import { ethers } from 'ethers'
import { formatError } from '../sdk/common/utils/error-handler'
import {
    parseTieredPricing,
    parseCacheTokenBilling,
    parseMultiModelInfo,
    effectiveMultiplier,
} from '../sdk/inference'
import type {
    TieredPricingInfo,
    CacheTokenBillingInfo,
    ProviderModelInfo,
    ServiceHealthMetric,
} from '../sdk/inference'

/**
 * Format a token count for display (e.g., 256000 -> "256k", 1000000 -> "1M")
 */
function formatTokenCount(tokens: number): string {
    if (tokens >= 1000000) return `${tokens / 1000000}M`
    if (tokens >= 1000) return `${tokens / 1000}k`
    return `${tokens}`
}

// Multiply a bigint wei price by a fractional multiplier (e.g. 1.333) without
// losing precision. Scales the multiplier to a 6-decimal fixed-point integer
// before BigInt multiplication, then divides back out with round-half-up.
const MULTIPLIER_SCALE = 1_000_000n
function applyMultiplier(base: bigint, mul: number): bigint {
    const scaled = BigInt(Math.round(mul * Number(MULTIPLIER_SCALE)))
    const product = base * scaled
    return (product + MULTIPLIER_SCALE / 2n) / MULTIPLIER_SCALE
}

/**
 * Format a price value, trimming unnecessary trailing zeros while keeping
 * enough precision to distinguish non-zero values.
 */
function formatPrice(neurons: bigint): string {
    const s = neuronToA0gi(neurons).toFixed(18)
    // Keep at least one trailing zero after decimal point for readability
    return s.replace(/(\.\d*?[1-9])0+$/, '$1').replace(/\.0+$/, '.0')
}

/**
 * Push tiered pricing rows into a CLI table.
 * Each tier is displayed as a single compact row with all prices.
 */
function pushTieredPricingRows(
    table: Table.Table,
    baseInputPrice: bigint,
    baseOutputPrice: bigint,
    tieredPricing: TieredPricingInfo,
    cacheBilling?: CacheTokenBillingInfo
) {
    table.push([
        chalk.yellow('Tiered Pricing (0G/Token)'),
        chalk.yellow('Enabled'),
    ])
    let prevLabel = '0'
    for (const tier of tieredPricing.tiers) {
        const rangeLabel =
            tier.maxInputTokens === 0
                ? `>${prevLabel}`
                : `${prevLabel}-${formatTokenCount(tier.maxInputTokens)}`
        const effectiveInputPrice = applyMultiplier(
            baseInputPrice,
            tier.inputMultiplier
        )
        const inPrice = formatPrice(effectiveInputPrice)
        const outPrice = formatPrice(
            applyMultiplier(baseOutputPrice, tier.outputMultiplier)
        )
        let priceStr = `In: ${inPrice} / Out: ${outPrice}`
        if (cacheBilling) {
            const cachePrice = formatPrice(
                effectiveInputPrice / BigInt(cacheBilling.divisor)
            )
            priceStr += ` / Cache: ${cachePrice}`
        }
        table.push([`  Input ${rangeLabel} tokens`, priceStr])
        if (tier.maxInputTokens !== 0) {
            prevLabel = formatTokenCount(tier.maxInputTokens)
        }
    }
}

/**
 * Render a numeric price for display, dropping float artifacts. Returns '-' for
 * missing/non-finite values.
 */
function fmtPrice(value: number | undefined): string {
    if (value === undefined || !Number.isFinite(value)) return '-'
    return value.toLocaleString('en-US', {
        maximumFractionDigits: 20,
        useGrouping: false,
    })
}

/**
 * Build the multi-line pricing cell for a model in `get-models`. Shows the base
 * per-token (or per-image / per-second) price plus any tiered pricing and
 * cache-hit discount the provider advertises in /v1/models, mirroring the
 * tiered/cache rows `list-providers` shows so the two views stay consistent.
 *
 * @param m - The model entry from /v1/models.
 * @param useUsd - When true, base prices come from `pricing_usd` (decimal USD,
 *   used as-is). Otherwise from native `pricing`, whose values are in neuron and
 *   are converted to 0G for display (mirroring `list-providers`). Tiered
 *   multipliers and the cache divisor are unit-independent, so they're sourced
 *   from whichever object carries them (a provider commonly attaches them to
 *   native `pricing` only) and applied to the displayed base prices.
 */
function formatModelPricing(m: ProviderModelInfo, useUsd: boolean): string {
    const base = useUsd ? m.pricing_usd : m.pricing
    const alt = useUsd ? m.pricing : m.pricing_usd
    if (!base) return 'N/A'

    // USD prices are decimal strings; native prices are neuron integers that
    // must be converted to 0G for a human-readable per-token figure.
    const toDisplay = (v?: string): number | undefined => {
        if (v === undefined || v === null) return undefined
        if (useUsd) {
            const n = Number(v)
            return Number.isFinite(n) ? n : undefined
        }
        try {
            return neuronToA0gi(BigInt(v))
        } catch {
            const n = Number(v)
            return Number.isFinite(n) ? n : undefined
        }
    }

    if (base.video !== undefined)
        return `${fmtPrice(toDisplay(base.video))} / sec`
    if (base.image !== undefined)
        return `${fmtPrice(toDisplay(base.image))} / image`

    const inBase = toDisplay(base.prompt)
    const outBase = toDisplay(base.completion)
    if (inBase === undefined && outBase === undefined) return 'N/A'

    const lines = [
        `in ${fmtPrice(inBase)} / out ${fmtPrice(outBase)} per token`,
    ]

    const cache = base.cache_token_billing ?? alt?.cache_token_billing
    if (cache && cache.divisor > 0 && inBase !== undefined) {
        lines.push(`cache-hit in: ${fmtPrice(inBase / cache.divisor)}`)
    }

    const tiers = base.tiered_pricing ?? alt?.tiered_pricing
    if (Array.isArray(tiers) && tiers.length > 0) {
        lines.push('tiered by input tokens:')
        let prevLabel = '0'
        for (const tier of tiers) {
            const rangeLabel =
                tier.max_input_tokens === 0
                    ? `>${prevLabel}`
                    : `${prevLabel}-${formatTokenCount(tier.max_input_tokens)}`
            const tin =
                inBase !== undefined
                    ? fmtPrice(
                          inBase *
                              effectiveMultiplier(
                                  tier.input_multiplier,
                                  tier.input_multiplier_denominator
                              )
                      )
                    : '-'
            const tout =
                outBase !== undefined
                    ? fmtPrice(
                          outBase *
                              effectiveMultiplier(
                                  tier.output_multiplier,
                                  tier.output_multiplier_denominator
                              )
                      )
                    : '-'
            lines.push(`  ${rangeLabel}: in ${tin} / out ${tout}`)
            if (tier.max_input_tokens !== 0) {
                prevLabel = formatTokenCount(tier.max_input_tokens)
            }
        }
    }

    return lines.join('\n')
}

/**
 * Build the per-model Health cell for `get-models` from the status-API metric
 * merged onto the model. Shows status, uptime, and average response latency.
 * Returns '-' when the status API has no metric for this (provider, model).
 */
function formatModelHealth(health?: ServiceHealthMetric): string {
    if (!health) return '-'

    let statusLine: string
    if (health.status === 'healthy') {
        statusLine = chalk.green('✓ healthy')
    } else if (health.status === 'warning') {
        statusLine = chalk.yellow('⚠ warning')
    } else if (health.status === 'critical') {
        statusLine = chalk.red('✗ critical')
    } else {
        statusLine = chalk.gray('? unknown')
    }

    const lines = [statusLine]

    const uptime = health.checks?.uptime
    if (typeof uptime === 'number') {
        const pct = `${uptime}% up`
        lines.push(
            uptime >= 85
                ? chalk.green(pct)
                : uptime >= 70
                ? chalk.yellow(pct)
                : chalk.red(pct)
        )
    }

    const resp = health.performance?.response_time
    if (resp && typeof resp.avg === 'number') {
        lines.push(`${Math.round(resp.avg)}${resp.unit || 'ms'} resp`)
    }

    return lines.join('\n')
}

async function promptDurationSelection(): Promise<number> {
    console.log(chalk.blue('\n⏱️  API Key Duration Selection'))
    console.log()

    const durationChoice = await interactiveSelect({
        message: 'Please select the API Key expiration duration:',
        options: [
            {
                title: 'Never expires',
                value: '0',
                description: 'API Key will never expire (can still be revoked)',
            },
            {
                title: '1 hour',
                value: '3600000',
                description: '3600 seconds (1 hour)',
            },
            {
                title: '24 hours',
                value: '86400000',
                description: '86400 seconds (24 hours)',
            },
            {
                title: '7 days',
                value: '604800000',
                description: '604800 seconds (7 days)',
            },
            {
                title: '30 days',
                value: '2592000000',
                description: '2592000 seconds (30 days)',
            },
            {
                title: 'Custom duration',
                value: 'custom',
                description: 'Enter custom duration in seconds',
            },
        ],
    })

    if (durationChoice === 'custom') {
        console.log()
        const customSeconds = await textInput(
            'Enter duration in seconds (0 for never expires):'
        )
        const seconds = parseInt(customSeconds)
        if (isNaN(seconds) || seconds < 0) {
            throw new Error('Duration must be a non-negative number')
        }
        return seconds * 1000 // Convert to milliseconds
    }

    return parseInt(durationChoice)
}

export default function inference(program: Command) {
    program
        .command('list-providers')
        .description('List inference providers')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option(
            '--include-invalid',
            'Include all services, even those without valid teeSignerAddress'
        )
        .action(async (options: any) => {
            const table = new Table({
                colWidths: [40, 60],
                wordWrap: true,
            })
            await withROBroker(options, async (broker) => {
                const services = await broker.inference.listService(
                    0,
                    50,
                    options.includeInvalid
                )
                services.forEach((service, index) => {
                    table.push([
                        chalk.blue(`Provider ${index + 1}`),
                        chalk.blue(service.provider),
                    ])
                    // Multi-model providers serve N models behind one address;
                    // the on-chain `model` is only the default. Surface the flag
                    // and point to `get-models` for the full catalog.
                    const multi = parseMultiModelInfo(service.additionalInfo)
                    if (multi.multiModel) {
                        table.push([
                            'Models',
                            chalk.green(
                                `multi-model${
                                    multi.priceDenomination
                                        ? ` (${multi.priceDenomination})`
                                        : ''
                                }`
                            ) +
                                `\nRun: 0g-compute-cli inference get-models --provider ${service.provider}`,
                        ])
                    } else {
                        table.push(['Model', service.model || 'N/A'])
                    }

                    // Check for tiered pricing and cache billing in additionalInfo
                    const tiered = parseTieredPricing(service.additionalInfo)
                    const cacheBilling = parseCacheTokenBilling(
                        service.additionalInfo
                    )
                    const isImageService =
                        service.serviceType === 'text-to-image' ||
                        service.serviceType === 'image-editing'
                    const isSpeechService =
                        service.serviceType === 'speech-to-text'

                    if (tiered && !isImageService && !isSpeechService) {
                        // Display tiered pricing with optional cache hit prices
                        pushTieredPricingRows(
                            table,
                            BigInt(service.inputPrice),
                            BigInt(service.outputPrice),
                            tiered,
                            cacheBilling
                        )
                    } else if (isSpeechService) {
                        // Speech-to-text is billed per second of audio against inputPrice
                        table.push([
                            'Price Per Second (0G)',
                            service.inputPrice
                                ? neuronToA0gi(
                                      BigInt(service.inputPrice)
                                  ).toFixed(18)
                                : 'N/A',
                        ])
                    } else {
                        // Original flat pricing display
                        if (!isImageService) {
                            table.push([
                                'Input Price Per Token (0G)',
                                service.inputPrice
                                    ? neuronToA0gi(
                                          BigInt(service.inputPrice)
                                      ).toFixed(18)
                                    : 'N/A',
                            ])
                        }

                        const outputPriceLabel = isImageService
                            ? 'Price Per Image (OG)'
                            : 'Output Price Per Token (0G)'

                        table.push([
                            outputPriceLabel,
                            service.outputPrice
                                ? neuronToA0gi(
                                      BigInt(service.outputPrice)
                                  ).toFixed(18)
                                : 'N/A',
                        ])

                        // Show cache hit price for flat pricing (non-image services)
                        if (
                            cacheBilling &&
                            !isImageService &&
                            service.inputPrice
                        ) {
                            const cacheHitPrice = neuronToA0gi(
                                BigInt(service.inputPrice) /
                                    BigInt(cacheBilling.divisor)
                            ).toFixed(18)
                            table.push([
                                'Cache Hit Price Per Token (0G)',
                                cacheHitPrice,
                            ])
                        }
                    }
                    table.push([
                        'Verifiability',
                        service.verifiability || 'N/A',
                    ])
                })
                console.log(table.toString())
            })
        })

    program
        .command('get-models')
        .description(
            'Get the models a provider serves (live from its /v1/models endpoint)'
        )
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action(async (options: any) => {
            await withROBroker(options, async (broker) => {
                const result = await broker.inference.getProviderModels(
                    options.provider
                )
                console.log(chalk.blue(`Provider:      ${result.provider}`))
                console.log(
                    `Multi-model:   ${
                        result.multiModel ? chalk.green('yes') : 'no'
                    }` +
                        (result.priceDenomination
                            ? ` (${result.priceDenomination})`
                            : '')
                )
                console.log(`Default model: ${result.defaultModel || 'N/A'}`)

                if (result.models.length === 0) {
                    console.log(
                        chalk.yellow(
                            'No models returned by the provider /v1/models endpoint.'
                        )
                    )
                    return
                }

                // Mirror the denomination shown by `list-providers`: a provider
                // priced in USD advertises priceDenomination "USD" on-chain, so
                // surface its USD prices; otherwise fall back to native-token (0G)
                // prices. Keeping the unit consistent across both commands avoids
                // the "is this USD or 0G?" ambiguity the bare numbers caused.
                const useUsd = result.priceDenomination === 'USD'
                const priceUnit = useUsd ? 'USD' : '0G'
                const table = new Table({
                    head: [
                        'Model',
                        'Upstream',
                        'Type',
                        `Pricing (${priceUnit})`,
                        'Health',
                    ],
                    colWidths: [22, 12, 8, 40, 18],
                    wordWrap: true,
                })
                for (const m of result.models) {
                    table.push([
                        m.id,
                        m.provider_identity || '-',
                        m.type ?? '-',
                        formatModelPricing(m, useUsd),
                        formatModelHealth(m.healthMetrics),
                    ])
                }
                console.log(table.toString())
            })
        })

    program
        .command('list-providers-detail')
        .description('List inference providers with health metrics')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option(
            '--include-invalid',
            'Include all services, even those without valid teeSignerAddress'
        )
        .action(async (options: any) => {
            const table = new Table({
                colWidths: [40, 60],
                wordWrap: true,
            })
            await withROBroker(options, async (broker) => {
                const services = await broker.inference.listServiceWithDetail(
                    0,
                    50,
                    options.includeInvalid
                )
                services.forEach((service, index) => {
                    const health = service.healthMetrics
                    const modelInfo = service.modelInfo

                    table.push([
                        chalk.blue(`Provider ${index + 1}`),
                        chalk.blue(service.provider),
                    ])
                    // Multi-model providers serve N models behind one address;
                    // the on-chain `model` is only the default. Surface the flag
                    // and point to `get-models` for the full catalog (mirrors
                    // `list-providers`).
                    if (service.multiModel) {
                        table.push([
                            'Models',
                            chalk.green(
                                `multi-model${
                                    service.priceDenomination
                                        ? ` (${service.priceDenomination})`
                                        : ''
                                }`
                            ) +
                                `\nRun: 0g-compute-cli inference get-models --provider ${service.provider}`,
                        ])
                    } else {
                        table.push(['Model', service.model || 'N/A'])
                    }

                    // Human-readable model name and description from /v1/models
                    if (modelInfo?.name) {
                        table.push(['Model Name', modelInfo.name])
                    }
                    if (modelInfo?.description) {
                        const desc =
                            modelInfo.description.length > 80
                                ? modelInfo.description.slice(0, 77) + '...'
                                : modelInfo.description
                        table.push(['Description', desc])
                    }
                    if (modelInfo?.context_length) {
                        table.push([
                            'Context Length',
                            modelInfo.context_length.toLocaleString() +
                                ' tokens',
                        ])
                    }
                    if (modelInfo?.max_completion_tokens) {
                        table.push([
                            'Max Completion Tokens',
                            modelInfo.max_completion_tokens.toLocaleString() +
                                ' tokens',
                        ])
                    }
                    if (modelInfo?.architecture?.tokenizer) {
                        table.push([
                            'Tokenizer',
                            modelInfo.architecture.tokenizer,
                        ])
                    }
                    if (modelInfo?.owned_by) {
                        table.push(['Owned By', modelInfo.owned_by])
                    }
                    if (modelInfo?.tee_type) {
                        table.push(['TEE Type', modelInfo.tee_type])
                    }
                    if (modelInfo?.tee_verifier) {
                        table.push(['TEE Verifier', modelInfo.tee_verifier])
                    }
                    if (modelInfo?.supported_parameters?.length) {
                        table.push([
                            'Supported Parameters',
                            modelInfo.supported_parameters.join(', '),
                        ])
                    }

                    // Pricing display
                    const isImageService =
                        service.serviceType === 'text-to-image' ||
                        service.serviceType === 'image-editing'
                    const isSpeechService =
                        service.serviceType === 'speech-to-text'

                    if (isSpeechService) {
                        // Speech-to-text is billed per second of audio against inputPrice
                        table.push([
                            'Price Per Second (0G)',
                            service.inputPrice
                                ? neuronToA0gi(
                                      BigInt(service.inputPrice)
                                  ).toFixed(18)
                                : 'N/A',
                        ])
                    } else if (
                        service.priceDenomination === 'USD' &&
                        modelInfo?.pricing_usd
                    ) {
                        // USD-denominated provider: show USD prices (incl. tiered
                        // and cache) in one consolidated cell, consistent with
                        // `list-providers` (which flags "(USD)") and `get-models`.
                        // Tiered multipliers / cache divisor are unit-independent
                        // and fall back to the native `pricing` object inside
                        // formatModelPricing.
                        table.push([
                            'Pricing (USD)',
                            formatModelPricing(modelInfo, true),
                        ])
                    } else {
                        // Native (0G) display. Also the fallback for a USD provider
                        // whose per-model USD pricing the status API didn't carry —
                        // the multi-model header already flags USD and points to
                        // `get-models` for authoritative per-model USD prices.
                        if (service.tieredPricing && !isImageService) {
                            pushTieredPricingRows(
                                table,
                                BigInt(service.inputPrice),
                                BigInt(service.outputPrice),
                                service.tieredPricing,
                                service.cacheTokenBilling
                            )
                        } else {
                            if (!isImageService) {
                                table.push([
                                    'Input Price Per Token (0G)',
                                    service.inputPrice
                                        ? neuronToA0gi(
                                              BigInt(service.inputPrice)
                                          ).toFixed(18)
                                        : 'N/A',
                                ])
                            }

                            const outputPriceLabel = isImageService
                                ? 'Price Per Image (OG)'
                                : 'Output Price Per Token (0G)'

                            table.push([
                                outputPriceLabel,
                                service.outputPrice
                                    ? neuronToA0gi(
                                          BigInt(service.outputPrice)
                                      ).toFixed(18)
                                    : 'N/A',
                            ])

                            // Show cache hit price for flat pricing (non-image services)
                            if (
                                service.cacheTokenBilling &&
                                !isImageService &&
                                service.inputPrice
                            ) {
                                const cacheHitPrice = neuronToA0gi(
                                    BigInt(service.inputPrice) /
                                        BigInt(
                                            service.cacheTokenBilling.divisor
                                        )
                                ).toFixed(18)
                                table.push([
                                    'Cache Hit Price Per Token (0G)',
                                    cacheHitPrice,
                                ])
                            }
                        }

                        const pricingUSD = modelInfo?.pricing_usd
                        if (pricingUSD) {
                            if (!isImageService && pricingUSD.prompt) {
                                table.push([
                                    'Input Price Per Token (USD)',
                                    pricingUSD.prompt,
                                ])
                            }
                            if (pricingUSD.image) {
                                table.push([
                                    'Price Per Image (USD)',
                                    pricingUSD.image,
                                ])
                            } else if (pricingUSD.completion) {
                                const usdLabel = isImageService
                                    ? 'Price Per Image (USD)'
                                    : 'Output Price Per Token (USD)'
                                table.push([usdLabel, pricingUSD.completion])
                            }
                        }
                    }

                    table.push([
                        'Verifiability',
                        service.verifiability || 'N/A',
                    ])

                    // Add health metrics
                    if (health?.status) {
                        let statusDisplay = ''
                        if (health.status === 'healthy') {
                            statusDisplay = chalk.green('✓ Healthy')
                        } else if (health.status === 'warning') {
                            statusDisplay = chalk.yellow('⚠ Warning')
                        } else {
                            statusDisplay = chalk.red('✗ Critical')
                        }
                        table.push(['Health Status', statusDisplay])

                        if (health.uptime !== undefined) {
                            const uptimeDisplay =
                                health.uptime >= 85
                                    ? chalk.green(`${health.uptime}%`)
                                    : health.uptime >= 70
                                    ? chalk.yellow(`${health.uptime}%`)
                                    : chalk.red(`${health.uptime}%`)
                            table.push(['Uptime', uptimeDisplay])
                        }
                    } else {
                        table.push([
                            'Health Status',
                            chalk.gray('No metrics available'),
                        ])
                    }
                })
                console.log(table.toString())
                console.log(
                    chalk.gray(
                        '\nNote: Health metrics are fetched from the monitoring API. ' +
                            'Services without metrics may be newly registered or temporarily unavailable. ' +
                            'Model details are fetched from the status API.'
                    )
                )
            })
        })

    program
        .command('acknowledge-provider')
        .description('Acknowledge the provider signer')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.acknowledgeProviderSigner(
                    options.provider,
                    options.gasPrice
                )
                console.log('Provider signer acknowledged successfully!')
            })
        })

    program
        .command('remove-service')
        .description('[For provider] Remove your service from the contract')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.removeService(options.gasPrice)
                console.log('Service removed successfully!')
            })
        })

    program
        .command('update-service')
        .description(
            '[For provider] Update your service (url, model, input price, output price)'
        )
        .option('--url <url>', 'New service URL')
        .option('--model <model>', 'New model name')
        .option(
            '--input-price <price>',
            'New input price in 0G (e.g., 0.000000000000000001)'
        )
        .option(
            '--output-price <price>',
            'New output price in 0G (e.g., 0.000000000000000001)'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            // Check that at least one update option is provided
            if (
                !options.url &&
                !options.model &&
                !options.inputPrice &&
                !options.outputPrice
            ) {
                console.error(
                    'Error: At least one of --url, --model, --input-price, or --output-price must be provided'
                )
                process.exit(1)
            }

            withBroker(options, async (broker) => {
                const updateOptions: {
                    url?: string
                    model?: string
                    inputPrice?: bigint
                    outputPrice?: bigint
                    gasPrice?: number
                } = {}

                if (options.url) {
                    updateOptions.url = options.url
                }
                if (options.model) {
                    updateOptions.model = options.model
                }
                if (options.inputPrice) {
                    updateOptions.inputPrice = a0giToNeuron(
                        parseFloat(options.inputPrice)
                    )
                }
                if (options.outputPrice) {
                    updateOptions.outputPrice = a0giToNeuron(
                        parseFloat(options.outputPrice)
                    )
                }
                if (options.gasPrice) {
                    updateOptions.gasPrice = options.gasPrice
                }

                console.log('Updating service with options:', {
                    url: updateOptions.url,
                    model: updateOptions.model,
                    inputPrice: updateOptions.inputPrice
                        ? `${updateOptions.inputPrice} neuron`
                        : undefined,
                    outputPrice: updateOptions.outputPrice
                        ? `${updateOptions.outputPrice} neuron`
                        : undefined,
                })

                await broker.inference.updateService(updateOptions)
                console.log('Service updated successfully!')
            })
        })

    program
        .command('serve')
        .description('Start local inference service')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option(
            '--port <port>',
            'Port to run the local inference service on',
            '3000'
        )
        .option(
            '--host <host>',
            'Host to bind the local inference service',
            '0.0.0.0'
        )
        .action(async (options) => {
            // Ensure RPC endpoint is configured
            const rpc = await getRpcEndpoint(options)
            // Ensure private key is configured
            const key = await ensurePrivateKeyConfiguration()
            const { runInferenceServer } = await import(
                '../example/inference-server'
            )
            await runInferenceServer({ ...options, rpc, key })
        })

    program
        .command('router-serve')
        .description(
            'Start high-availability router service with multiple providers'
        )
        .option(
            '--add-provider <address,priority>',
            'Add on-chain provider with priority (e.g., 0x1234567890abcdef,10). Use comma separator. Can be used multiple times',
            (value: string, previous: any[]) => {
                const providers = previous || []
                const [address, priority] = value.split(',')
                if (!address) {
                    throw new Error(
                        'Invalid provider format. Use: address,priority (comma-separated)'
                    )
                }
                providers.push({
                    address: address.trim(),
                    priority:
                        priority && priority.trim()
                            ? parseInt(priority.trim())
                            : 100,
                })
                return providers
            },
            [] as any[]
        )
        .option(
            '--add-endpoint <id,endpoint,apikey,model,priority>',
            'Add direct endpoint (e.g., openai,https://api.openai.com/v1,key,gpt-4o,10). Use commas as separators. Can be used multiple times',
            (value: string, previous: any[]) => {
                const endpoints = previous || []
                const [id, endpoint, apiKey, model, priority] = value.split(',')
                if (!id || !endpoint) {
                    throw new Error(
                        'Invalid endpoint format. Use: id,endpoint,apikey,model,priority (comma-separated)'
                    )
                }
                endpoints.push({
                    id: id.trim(),
                    endpoint: endpoint.trim(),
                    apiKey: apiKey && apiKey.trim() ? apiKey.trim() : undefined,
                    model:
                        model && model.trim() ? model.trim() : 'gpt-3.5-turbo',
                    priority:
                        priority && priority.trim()
                            ? parseInt(priority.trim())
                            : 50,
                })
                return endpoints
            },
            [] as any[]
        )
        .option(
            '--default-provider-priority <number>',
            'Default priority for on-chain providers not explicitly set',
            '100'
        )
        .option(
            '--default-endpoint-priority <number>',
            'Default priority for direct endpoints not explicitly set',
            '50'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--port <port>', 'Port to run the router service on', '3000')
        .option('--host <host>', 'Host to bind the router service', '0.0.0.0')
        .option('--cache-duration <seconds>', 'Cache duration in seconds', '60')
        .option(
            '--request-timeout <seconds>',
            'Request timeout in seconds for each provider',
            '60'
        )
        .action(async (options) => {
            // Build providers list with priorities
            const providers: string[] = []
            const providerPriorities: Record<string, number> = {}

            if (options.addProvider && options.addProvider.length > 0) {
                for (const prov of options.addProvider) {
                    providers.push(prov.address)
                    providerPriorities[prov.address] = prov.priority
                }
            }

            // Build direct endpoints
            const directEndpoints: Record<string, any> = {}

            if (options.addEndpoint && options.addEndpoint.length > 0) {
                for (const ep of options.addEndpoint) {
                    directEndpoints[ep.id] = {
                        endpoint: ep.endpoint,
                        apiKey: ep.apiKey,
                        model: ep.model,
                        priority: ep.priority,
                    }
                }
            }

            // Build priority config
            const priorityConfig: any = {
                providers: providerPriorities,
                defaultProviderPriority: parseInt(
                    options.defaultProviderPriority
                ),
                defaultEndpointPriority: parseInt(
                    options.defaultEndpointPriority
                ),
            }

            // Ensure at least one provider type is specified
            if (
                providers.length === 0 &&
                Object.keys(directEndpoints).length === 0
            ) {
                console.error(
                    'Error: Must specify either --add-provider or --add-endpoint'
                )
                process.exit(1)
            }

            // Ensure RPC endpoint is configured if we have on-chain providers
            let rpc = options.rpc
            let key = options.key
            if (providers.length > 0) {
                if (!rpc) {
                    rpc = await getRpcEndpoint(options)
                }
                if (!key) {
                    key = await ensurePrivateKeyConfiguration()
                }
            }

            const routerOptions = {
                ...options,
                rpc,
                key,
                providers,
                directEndpoints:
                    Object.keys(directEndpoints).length > 0
                        ? directEndpoints
                        : undefined,
                priorityConfig,
                requestTimeout: options.requestTimeout,
            }

            const { runRouterServer } = await import('../example/router-server')
            await runRouterServer(routerOptions)
        })

    program
        .command('download-report')
        .description('Download quote data to a specified file')
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption(
            '--output <path>',
            'Output file path for the quote report'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.downloadQuoteReport(
                    options.provider,
                    options.output
                )
                console.log(`Quote report downloaded to: ${options.output}`)
            })
        })

    program
        .command('verify')
        .description('Verify the reliability of a service')
        .requiredOption('--provider <address>', 'Provider address')
        .option(
            '--output-dir <path>',
            'Output directory for verification reports',
            '.'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action((options) => {
            withBroker(options, async (broker) => {
                const result = await broker.inference.verifyService(
                    options.provider,
                    options.outputDir,
                    (step) => console.log(step.message)
                )
                if (result) {
                    if (!result.success) {
                        console.log('❌ Service verification failed')
                    }
                } else {
                    console.log('Verification result is null')
                }
            })
        })

    program
        .command('list-logs')
        .description(
            '[For provider] List available log files from your provider service'
        )
        .option(
            '--component <component>',
            'Component name (broker/event/both)',
            'both'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action(async (options) => {
            try {
                const rpcEndpoint = await getRpcEndpoint(options)
                const privateKey = await ensurePrivateKeyConfiguration()
                if (!privateKey) {
                    throw new Error('Private key is required')
                }

                const provider = new ethers.JsonRpcProvider(rpcEndpoint)
                const wallet = new ethers.Wallet(privateKey, provider)
                const userAddress = await wallet.getAddress()

                const broker = await initBroker(options)

                try {
                    // Get service metadata for current user's provider service
                    const serviceMetadata =
                        await broker.inference.getServiceMetadata(userAddress)

                    // Create session for provider authentication
                    const session =
                        await broker.inference.requestProcessor.getOrCreateSession(
                            userAddress
                        )

                    const endpoint = `${serviceMetadata.endpoint.replace(
                        '/proxy',
                        '/logs'
                    )}?component=${options.component}`

                    const response = await axios.get(endpoint, {
                        headers: {
                            Address: userAddress,
                            'Session-Token': session.rawMessage,
                            'Session-Signature': session.signature,
                        },
                    })

                    const logs = response.data.logs || []

                    if (logs.length === 0) {
                        console.log('No log files found.')
                        return
                    }

                    const table = new Table({
                        head: [
                            'Component',
                            'Filename',
                            'Size (bytes)',
                            'Modified Time',
                            'Current',
                        ],
                        colWidths: [12, 30, 15, 25, 10],
                    })

                    logs.forEach(
                        (log: {
                            component: string
                            name: string
                            size: number
                            modifiedTime: number
                            isCurrentLog: boolean
                        }) => {
                            const modifiedTime = new Date(
                                log.modifiedTime * 1000
                            ).toLocaleString()
                            const isCurrent = log.isCurrentLog ? '✓' : ''
                            const size = log.size.toLocaleString()

                            table.push([
                                chalk.blue(log.component),
                                log.name,
                                size,
                                modifiedTime,
                                isCurrent ? chalk.green(isCurrent) : '',
                            ])
                        }
                    )

                    console.log('\nAvailable Log Files:')
                    console.log(table.toString())
                    process.exit(0)
                } catch (error: unknown) {
                    if (
                        error &&
                        typeof error === 'object' &&
                        'response' in error
                    ) {
                        const axiosError = error as {
                            response: {
                                data?: { error?: string }
                                statusText: string
                            }
                        }
                        console.error(
                            'Error:',
                            axiosError.response.data?.error ||
                                axiosError.response.statusText
                        )
                    } else if (error instanceof Error) {
                        console.error('Error:', error.message)
                    } else {
                        console.error('Error:', String(error))
                    }
                    process.exit(1)
                }
            } catch (error: unknown) {
                if (error instanceof Error) {
                    console.error('Error:', error.message)
                } else {
                    console.error('Error:', String(error))
                }
                process.exit(1)
            }
        })

    program
        .command('download-log')
        .description(
            '[For provider] Download a specific log file from your provider service'
        )
        .requiredOption(
            '--component <component>',
            'Component name (broker/event)'
        )
        .requiredOption('--filename <filename>', 'Log file name')
        .option('--output <path>', 'Output file path (defaults to filename)')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action(async (options) => {
            try {
                const rpcEndpoint = await getRpcEndpoint(options)
                const privateKey = await ensurePrivateKeyConfiguration()
                if (!privateKey) {
                    throw new Error('Private key is required')
                }

                const provider = new ethers.JsonRpcProvider(rpcEndpoint)
                const wallet = new ethers.Wallet(privateKey, provider)
                const userAddress = await wallet.getAddress()

                const broker = await initBroker(options)

                try {
                    // Get service metadata for current user's provider service
                    const serviceMetadata =
                        await broker.inference.getServiceMetadata(userAddress)

                    // Create session for provider authentication
                    const session =
                        await broker.inference.requestProcessor.getOrCreateSession(
                            userAddress
                        )

                    const endpoint = `${serviceMetadata.endpoint.replace(
                        '/proxy',
                        '/logs'
                    )}/${options.component}/${options.filename}`

                    const response = await axios.get(endpoint, {
                        headers: {
                            Address: userAddress,
                            'Session-Token': session.rawMessage,
                            'Session-Signature': session.signature,
                        },
                        responseType: 'stream',
                    })

                    const outputPath = options.output || options.filename
                    const writer = fs.createWriteStream(outputPath)

                    response.data.pipe(writer)

                    writer.on('finish', () => {
                        console.log(`Log file downloaded to: ${outputPath}`)
                        process.exit(0)
                    })

                    writer.on('error', (error: Error) => {
                        console.error('Error writing file:', error.message)
                        process.exit(1)
                    })
                } catch (error: unknown) {
                    if (
                        error &&
                        typeof error === 'object' &&
                        'response' in error
                    ) {
                        const axiosError = error as {
                            response: {
                                data?: { error?: string }
                                statusText: string
                            }
                        }
                        console.error(
                            'Error:',
                            axiosError.response.data?.error ||
                                axiosError.response.statusText
                        )
                    } else if (error instanceof Error) {
                        console.error('Error:', error.message)
                    } else {
                        console.error('Error:', String(error))
                    }
                    process.exit(1)
                }
            } catch (error: unknown) {
                if (error instanceof Error) {
                    console.error('Error:', error.message)
                } else {
                    console.error('Error:', String(error))
                }
                process.exit(1)
            }
        })

    program
        .command('view-log')
        .description(
            '[For provider] View a specific log file content from your provider service'
        )
        .requiredOption(
            '--component <component>',
            'Component name (broker/event)'
        )
        .requiredOption('--filename <filename>', 'Log file name')
        .option(
            '--lines <number>',
            'Number of lines to show (default: all)',
            'all'
        )
        .option('--tail', 'Show last N lines instead of first N lines')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action(async (options) => {
            try {
                const rpcEndpoint = await getRpcEndpoint(options)
                const privateKey = await ensurePrivateKeyConfiguration()
                if (!privateKey) {
                    throw new Error('Private key is required')
                }

                const provider = new ethers.JsonRpcProvider(rpcEndpoint)
                const wallet = new ethers.Wallet(privateKey, provider)
                const userAddress = await wallet.getAddress()

                const broker = await initBroker(options)

                try {
                    // Get service metadata for current user's provider service
                    const serviceMetadata =
                        await broker.inference.getServiceMetadata(userAddress)

                    // Create session for provider authentication
                    const session =
                        await broker.inference.requestProcessor.getOrCreateSession(
                            userAddress
                        )

                    const endpoint = `${serviceMetadata.endpoint.replace(
                        '/proxy',
                        '/logs'
                    )}/${options.component}/${options.filename}`

                    const response = await axios.get(endpoint, {
                        headers: {
                            Address: userAddress,
                            'Session-Token': session.rawMessage,
                            'Session-Signature': session.signature,
                        },
                    })

                    let content = response.data

                    if (options.lines !== 'all') {
                        const numLines = parseInt(options.lines)
                        const lines = content.split('\n')

                        if (options.tail) {
                            content = lines.slice(-numLines).join('\n')
                        } else {
                            content = lines.slice(0, numLines).join('\n')
                        }
                    }

                    console.log(
                        `\n${chalk.blue('Log file:')} ${options.component}/${
                            options.filename
                        }`
                    )
                    console.log(`${chalk.blue('Provider:')} ${userAddress}`)
                    console.log('─'.repeat(80))
                    console.log(content)
                    if (content && !content.endsWith('\n')) {
                        console.log() // Add newline if content doesn't end with one
                    }
                    process.exit(0)
                } catch (error: unknown) {
                    if (
                        error &&
                        typeof error === 'object' &&
                        'response' in error
                    ) {
                        const axiosError = error as {
                            response: {
                                data?: { error?: string }
                                statusText: string
                            }
                        }
                        console.error(
                            'Error:',
                            axiosError.response.data?.error ||
                                axiosError.response.statusText
                        )
                    } else if (error instanceof Error) {
                        console.error('Error:', error.message)
                    } else {
                        console.error('Error:', String(error))
                    }
                    process.exit(1)
                }
            } catch (error: unknown) {
                if (error instanceof Error) {
                    console.error('Error:', error.message)
                } else {
                    console.error('Error:', String(error))
                }
                process.exit(1)
            }
        })

    program
        .command('ack-provider', { hidden: true })
        .description('verify TEE remote attestation of service')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.acknowledgeProviderTEESigner(
                    options.provider,
                    options.gasPrice
                )
                console.log('Provider acknowledged successfully!')
            })
        })

    program
        .command('revoke', { hidden: true })
        .description('Revoke TEE signer acknowledgement for a provider')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.revokeProviderTEESignerAcknowledgement(
                    options.provider,
                    options.gasPrice
                )
                console.log(
                    'Provider TEE signer acknowledgement revoked successfully!'
                )
            })
        })

    program
        .command('get-secret')
        .description(
            'Generate an authentication secret (API Key) for API access'
        )
        .requiredOption('--provider <address>', 'Provider address')
        .option(
            '--token-id <id>',
            'Specific token ID to use (0-254). If not provided, will find the first available slot'
        )
        .option(
            '--duration <ms>',
            'Token duration in milliseconds (0 = never expires). Skips interactive prompt when provided.'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .action(async (options) => {
            try {
                // Validate token-id if provided
                let tokenId: number | undefined
                if (options.tokenId !== undefined) {
                    tokenId = parseInt(options.tokenId)
                    if (isNaN(tokenId) || tokenId < 0 || tokenId > 254) {
                        console.error(
                            chalk.red(
                                'Error: Token ID must be a number between 0 and 254'
                            )
                        )
                        process.exit(1)
                    }
                }

                let duration: number
                if (options.duration !== undefined) {
                    duration = parseInt(options.duration)
                    if (isNaN(duration) || duration < 0) {
                        console.error(
                            chalk.red(
                                'Error: Duration must be a non-negative number (milliseconds)'
                            )
                        )
                        process.exit(1)
                    }
                } else {
                    duration = await promptDurationSelection()
                }

                withBroker(options, async (broker) => {
                    // First check if ledger (main account) exists
                    try {
                        await broker.ledger.getLedger()
                    } catch (error) {
                        const errorMessage = formatError(error)
                        throw new Error(errorMessage)
                    }

                    // Then check if subaccount exists for the provider
                    try {
                        await broker.inference.getAccount(options.provider)
                    } catch (error) {
                        // Parse the error to get a proper error message
                        const errorMessage = formatError(error)
                        throw new Error(errorMessage)
                    }

                    // Use createApiKey to generate a persistent token
                    const apiKey =
                        await broker.inference.requestProcessor.createApiKey(
                            options.provider,
                            {
                                expiresIn: duration,
                                tokenId: tokenId,
                            }
                        )

                    const bearerToken = apiKey.rawToken

                    // Get service metadata to determine service type
                    // TODO: Support pagination for listing services
                    const services = await broker.inference.listService(
                        0,
                        50,
                        true
                    )
                    const service = services.find(
                        (s) =>
                            s.provider.toLowerCase() ===
                            options.provider.toLowerCase()
                    )

                    if (!service) {
                        throw new Error(
                            `Service not found for provider: ${options.provider}`
                        )
                    }

                    const serviceType = service.serviceType
                    const serviceUrl = service.url
                    const serviceModel = service.model || 'default-model'

                    console.log()
                    console.log(
                        chalk.green('✓ API Key generated successfully!')
                    )
                    console.log(chalk.gray(`Provider: ${options.provider}`))
                    console.log(chalk.gray(`Service Type: ${serviceType}`))
                    console.log(chalk.gray(`Token ID: ${apiKey.tokenId}`))
                    if (apiKey.expiresAt > 0) {
                        console.log(
                            chalk.gray(
                                `Expires: ${new Date(
                                    apiKey.expiresAt
                                ).toLocaleString()}`
                            )
                        )
                    } else {
                        console.log(chalk.gray(`Expires: Never`))
                    }
                    console.log()
                    console.log(chalk.blue('Use this Authorization header:'))
                    console.log()
                    console.log(
                        chalk.white('Authorization: Bearer ' + bearerToken)
                    )
                    console.log()

                    // Show curl examples based on service type
                    console.log(chalk.blue('Example curl command:'))
                    console.log()

                    if (serviceType === 'speech-to-text') {
                        console.log(
                            chalk.white(`curl ${serviceUrl}/v1/proxy/audio/transcriptions \\
  -H "Authorization: Bearer ${bearerToken}" \\
  -H "Content-Type: multipart/form-data" \\
  -F "file=@audio.ogg" \\
  -F "model=${serviceModel}" \\
  -F "response_format=json"`)
                        )
                    } else if (serviceType === 'text-to-image') {
                        console.log(
                            chalk.white(`curl ${serviceUrl}/v1/proxy/images/generations \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer ${bearerToken}" \\
  -d '{
    "model": "${serviceModel}",
    "prompt": "A cute baby sea otter",
    "n": 1,
    "size": "512x512",
    "response_format": "b64_json"
  }' | jq -r ".data[0].b64_json" | base64 -d > output.png && open output.png`)
                        )
                    } else if (serviceType === 'image-editing') {
                        console.log(
                            chalk.white(`curl -s -X POST ${serviceUrl}/v1/proxy/images/edits \\
  -H "Authorization: Bearer ${bearerToken}" \\
  -F "prompt=Create a lovely gift basket with these items in it" \\
  -F "response_format=b64_json" \\
  -F "image=@image.png" \\
  | jq -r '.data[0].b64_json' | base64 -d > result.png`)
                        )
                    } else {
                        // Default to chatbot/text type
                        console.log(
                            chalk.white(`curl ${serviceUrl}/v1/proxy/chat/completions \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer ${bearerToken}" \\
  -d '{
    "model": "${serviceModel}",
    "messages": [
      {
        "role": "system",
        "content": "You are a helpful assistant."
      },
      {
        "role": "user",
        "content": "Hello!"
      }
    ]
  }'`)
                        )
                    }

                    console.log()
                    console.log(chalk.yellow('⚠️  IMPORTANT SECURITY NOTES:'))
                    console.log(
                        chalk.yellow(
                            `   • This API Key can be revoked using: 0g-compute-cli inference revoke-token --provider ${options.provider} --token-id ${apiKey.tokenId}`
                        )
                    )
                    console.log(
                        chalk.yellow(
                            `   • To generate another key, specify a different token-id: 0g-compute-cli inference get-secret --provider ${options.provider} --token-id <0-254>`
                        )
                    )
                    console.log(
                        chalk.yellow('   • Keep it secure and do not share it')
                    )
                    if (apiKey.expiresAt > 0) {
                        console.log(
                            chalk.yellow(
                                '   • It will expire automatically at the specified time'
                            )
                        )
                    }
                })
            } catch (error: unknown) {
                if (error instanceof Error) {
                    console.error(chalk.red('Error:'), error.message)
                } else {
                    console.error(chalk.red('Error:'), String(error))
                }
                process.exit(1)
            }
        })

    program
        .command('revoke-token')
        .description('Revoke a specific API Key by its token ID')
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption('--token-id <id>', 'Token ID to revoke (0-254)')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            const tokenId = parseInt(options.tokenId)
            if (isNaN(tokenId) || tokenId < 0 || tokenId > 254) {
                console.error(
                    chalk.red(
                        'Error: Token ID must be a number between 0 and 254'
                    )
                )
                process.exit(1)
            }

            withBroker(options, async (broker) => {
                await broker.inference.requestProcessor.revokeApiKey(
                    options.provider,
                    tokenId,
                    options.gasPrice
                )
                console.log(
                    chalk.green(
                        `✓ Token ID ${tokenId} revoked successfully for provider ${options.provider}`
                    )
                )
            })
        })

    program
        .command('revoke-all-tokens')
        .description(
            'Revoke all API Keys for a provider (increments generation)'
        )
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withBroker(options, async (broker) => {
                await broker.inference.requestProcessor.revokeAllTokens(
                    options.provider,
                    options.gasPrice
                )
                console.log(
                    chalk.green(
                        `✓ All tokens revoked successfully for provider ${options.provider}`
                    )
                )
                console.log(
                    chalk.yellow(
                        '   Note: All existing API Keys and ephemeral tokens are now invalid.'
                    )
                )
            })
        })
}

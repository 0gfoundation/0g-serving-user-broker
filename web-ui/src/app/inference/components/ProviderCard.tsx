'use client'

import * as React from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
    Tooltip,
    TooltipContent,
    TooltipTrigger,
} from '@/components/ui/tooltip'
import {
    MessageCircle,
    Code,
    Copy,
    AlertCircle,
    Loader2,
    Clock,
    TrendingDown,
    Image,
    Mic,
    Shield,
    Wand2,
} from 'lucide-react'
import { cn, copyToClipboard } from '@/lib/utils'
import type { Provider } from '@/shared/types/broker'
import { isOfficial0GProvider } from '@/shared/config/unstableProviders'
import {
    useProviderHealth,
    getModelHealthStatus,
    getHealthStatusColor,
    getHealthStatusText,
} from '@/shared/hooks/useProviderHealth'

interface ProviderCardProps {
    provider: Provider
    isOfficial: boolean
    isLoading?: boolean
    isRecentlyUsed?: boolean
    usageCount?: number
    isCheapest?: boolean
    onChat?: (provider: Provider) => void
    onBuild?: (provider: Provider) => void
    onImageGen?: (provider: Provider) => void
    onImageEdit?: (provider: Provider) => void
    onSpeechToText?: (provider: Provider) => void
}

function formatTokens(count: number): string {
    if (count >= 1000000) return `${count / 1000000}M`
    if (count >= 1000) return `${count / 1000}k`
    return `${count}`
}

export function ProviderCard({
    provider,
    isOfficial,
    isLoading = false,
    isRecentlyUsed = false,
    usageCount,
    isCheapest = false,
    onChat,
    onBuild,
    onImageGen,
    onImageEdit,
    onSpeechToText,
}: ProviderCardProps) {
    const isVerified = provider.teeSignerAcknowledged ?? false
    const isDisabled = !isVerified
    const is0GOfficial = isOfficial0GProvider(provider.address)

    // Get real-time health status for this specific model using SWR hook
    const { healthData, isLoading: isLoadingHealth } = useProviderHealth()
    const healthStatus = React.useMemo(
        () =>
            getModelHealthStatus(healthData, provider.address, provider.model),
        [healthData, provider.address, provider.model]
    )

    // Determine service type category for UI display
    // Separate text-to-image from image-editing (which requires file upload)
    const isImageEditing =
        provider.serviceType === 'image-editing' ||
        provider.name?.toLowerCase().includes('edit')
    const isTextToImage =
        !isImageEditing &&
        (provider.serviceType === 'text-to-image' ||
            provider.name?.toLowerCase().includes('image'))
    const isImageService = isTextToImage || isImageEditing
    const isChatService = provider.serviceType === 'chatbot'
    const isSpeechService = provider.serviceType === 'speech-to-text'

    const copyAddress = async () => {
        await copyToClipboard(provider.address)
    }

    const truncatedAddress = `${provider.address.slice(
        0,
        8
    )}...${provider.address.slice(-6)}`

    return (
        <Card
            className={cn(
                'relative group',
                isDisabled
                    ? 'opacity-60 cursor-not-allowed'
                    : 'hover:shadow-glow'
            )}
        >
            <CardContent className="p-5">
                {/* Loading indicator */}
                {isLoading && (
                    <div className="absolute top-3 right-3">
                        <Loader2 className="h-4 w-4 animate-spin text-primary" />
                    </div>
                )}

                {/* Header with name and badges */}
                <div className="flex items-start justify-between mb-4">
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                            <div className="flex items-center gap-1.5">
                                <h3 className="text-base font-semibold text-foreground truncate">
                                    {provider.name}
                                </h3>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <div className="flex items-center">
                                            {isLoadingHealth ? (
                                                <div className="w-2 h-2 rounded-full bg-gray-300 animate-pulse" />
                                            ) : (
                                                <div
                                                    className={cn(
                                                        'w-2 h-2 rounded-full',
                                                        getHealthStatusColor(
                                                            healthStatus.status
                                                        )
                                                    )}
                                                />
                                            )}
                                        </div>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <div className="text-sm">
                                            <p className="font-semibold mb-1">
                                                {getHealthStatusText(
                                                    healthStatus.status
                                                )}
                                            </p>
                                            {healthStatus.uptime !== null && (
                                                <p className="text-xs">
                                                    Uptime:{' '}
                                                    {healthStatus.uptime.toFixed(
                                                        2
                                                    )}
                                                    %
                                                </p>
                                            )}
                                            {healthStatus.serviceInfo && (
                                                <div className="mt-1 text-xs">
                                                    {healthStatus.serviceInfo
                                                        .performance
                                                        .response_time && (
                                                        <p>
                                                            Avg Response:{' '}
                                                            {
                                                                healthStatus
                                                                    .serviceInfo
                                                                    .performance
                                                                    .response_time
                                                                    .avg
                                                            }
                                                            ms
                                                        </p>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    </TooltipContent>
                                </Tooltip>
                            </div>
                            {isOfficial && (
                                <Badge className="bg-primary/10 text-primary hover:bg-primary/10 border-0 px-2 py-0.5 text-xs font-medium">
                                    0G Official
                                </Badge>
                            )}
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                            {isVerified ? (
                                <div className="flex items-center gap-1">
                                    <Badge className="bg-green-100 text-green-700 hover:bg-green-100 border-0 px-1.5 py-0.5 text-xs flex items-center gap-1">
                                        <Shield className="h-3 w-3" />
                                        {provider.verifiability}
                                    </Badge>
                                    {is0GOfficial && (
                                        <Badge className="bg-purple-100 text-purple-700 hover:bg-purple-100 border-0 px-1.5 py-0.5 text-xs font-semibold">
                                            0G
                                        </Badge>
                                    )}
                                </div>
                            ) : (
                                <Badge className="bg-red-100 text-red-700 hover:bg-red-100 border-0 px-1.5 py-0.5 text-xs">
                                    Unverified
                                </Badge>
                            )}
                            {isRecentlyUsed && (
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Badge className="bg-blue-100 text-blue-700 hover:bg-blue-100 border-0 px-1.5 py-0.5 text-xs flex items-center gap-1">
                                            <Clock className="h-3 w-3" />
                                            Recent
                                            {usageCount && usageCount > 1
                                                ? ` (${usageCount}x)`
                                                : ''}
                                        </Badge>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <p>
                                            You&apos;ve used this provider
                                            recently
                                        </p>
                                    </TooltipContent>
                                </Tooltip>
                            )}
                            {isCheapest && (
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Badge className="bg-emerald-100 text-emerald-700 hover:bg-emerald-100 border-0 px-1.5 py-0.5 text-xs flex items-center gap-1">
                                            <TrendingDown className="h-3 w-3" />
                                            Best Value
                                        </Badge>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <p>
                                            Lowest price among available
                                            providers
                                        </p>
                                    </TooltipContent>
                                </Tooltip>
                            )}
                        </div>

                        {/* Owner info */}
                        {provider.ownedBy && (
                            <p className="text-xs text-muted-foreground mt-1.5">
                                by {provider.ownedBy}
                            </p>
                        )}

                        {/* Pricing and address */}
                        <div className="flex items-center gap-2 flex-wrap mt-3">
                            {/* Pricing section */}
                            {(provider.inputPrice !== undefined ||
                                provider.outputPrice !== undefined) && (
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <div className="flex items-center gap-2 text-xs bg-secondary px-2.5 py-1.5 rounded-lg cursor-help font-mono">
                                            {isImageService ? (
                                                <div className="flex items-center gap-1">
                                                    <span className="text-muted-foreground">
                                                        Price:
                                                    </span>
                                                    <span className="font-semibold text-foreground">
                                                        {provider.outputPrice?.toFixed(
                                                            4
                                                        )}{' '}
                                                        0G/image
                                                    </span>
                                                </div>
                                            ) : isSpeechService ? (
                                                <div className="flex items-center gap-1">
                                                    <span className="text-muted-foreground">
                                                        Price:
                                                    </span>
                                                    <span className="font-semibold text-foreground">
                                                        {provider.inputPrice?.toFixed(
                                                            6
                                                        )}{' '}
                                                        0G/second
                                                    </span>
                                                </div>
                                            ) : provider.tieredPricing ? (
                                                <div className="flex items-center gap-1">
                                                    <span className="text-muted-foreground">
                                                        In:
                                                    </span>
                                                    <span className="font-semibold text-foreground">
                                                        {provider.inputPrice?.toFixed(
                                                            2
                                                        )}
                                                        ~
                                                        {(
                                                            (provider.inputPrice ?? 0) *
                                                            Math.max(
                                                                ...provider.tieredPricing.tiers.map(
                                                                    (t) =>
                                                                        t.inputMultiplier
                                                                )
                                                            )
                                                        ).toFixed(2)}
                                                    </span>
                                                    <span className="text-muted-foreground">
                                                        Out:
                                                    </span>
                                                    <span className="font-semibold text-foreground">
                                                        {provider.outputPrice?.toFixed(
                                                            2
                                                        )}
                                                        ~
                                                        {(
                                                            (provider.outputPrice ?? 0) *
                                                            Math.max(
                                                                ...provider.tieredPricing.tiers.map(
                                                                    (t) =>
                                                                        t.outputMultiplier
                                                                )
                                                            )
                                                        ).toFixed(2)}
                                                    </span>
                                                    <span className="text-muted-foreground">
                                                        0G/1M
                                                    </span>
                                                </div>
                                            ) : (
                                                <>
                                                    {provider.inputPrice !==
                                                        undefined && (
                                                        <div className="flex items-center gap-1">
                                                            <span className="text-muted-foreground">
                                                                In:
                                                            </span>
                                                            <span className="font-semibold text-foreground">
                                                                {provider.inputPrice.toFixed(
                                                                    2
                                                                )}
                                                            </span>
                                                        </div>
                                                    )}
                                                    {provider.outputPrice !==
                                                        undefined && (
                                                        <div className="flex items-center gap-1">
                                                            <span className="text-muted-foreground">
                                                                Out:
                                                            </span>
                                                            <span className="font-semibold text-foreground">
                                                                {provider.outputPrice.toFixed(
                                                                    2
                                                                )}
                                                            </span>
                                                        </div>
                                                    )}
                                                    <span className="text-muted-foreground">
                                                        0G/1M
                                                    </span>
                                                </>
                                            )}
                                        </div>
                                    </TooltipTrigger>
                                    <TooltipContent className="max-w-xs">
                                        <div className="text-sm">
                                            <p className="font-semibold mb-1">
                                                Pricing Details
                                            </p>
                                            {isImageService ? (
                                                <p>
                                                    Cost per generated image:{' '}
                                                    {provider.outputPrice?.toFixed(
                                                        4
                                                    )}{' '}
                                                    0G
                                                </p>
                                            ) : isSpeechService ? (
                                                <p>
                                                    Cost per second of audio:{' '}
                                                    {provider.inputPrice?.toFixed(
                                                        6
                                                    )}{' '}
                                                    0G
                                                </p>
                                            ) : provider.tieredPricing ? (
                                                <div className="space-y-1">
                                                    <p className="text-xs text-muted-foreground mb-1">
                                                        Tiered pricing based on input length
                                                    </p>
                                                    {provider.tieredPricing.tiers.map(
                                                        (tier, i) => {
                                                            const prevMax =
                                                                i > 0
                                                                    ? provider.tieredPricing!
                                                                          .tiers[
                                                                          i - 1
                                                                      ]
                                                                          .maxInputTokens
                                                                    : 0
                                                            const label =
                                                                tier.maxInputTokens ===
                                                                0
                                                                    ? `>${formatTokens(prevMax)}`
                                                                    : prevMax ===
                                                                        0
                                                                      ? `<=${formatTokens(tier.maxInputTokens)}`
                                                                      : `${formatTokens(prevMax)}-${formatTokens(tier.maxInputTokens)}`
                                                            return (
                                                                <div
                                                                    key={i}
                                                                    className="border-t border-border pt-1"
                                                                >
                                                                    <p className="font-medium text-xs">
                                                                        {label}{' '}
                                                                        tokens
                                                                    </p>
                                                                    <p>
                                                                        Input:{' '}
                                                                        {(
                                                                            (provider.inputPrice ??
                                                                                0) *
                                                                            tier.inputMultiplier
                                                                        ).toFixed(
                                                                            4
                                                                        )}{' '}
                                                                        0G/1M
                                                                    </p>
                                                                    <p>
                                                                        Output:{' '}
                                                                        {(
                                                                            (provider.outputPrice ??
                                                                                0) *
                                                                            tier.outputMultiplier
                                                                        ).toFixed(
                                                                            4
                                                                        )}{' '}
                                                                        0G/1M
                                                                    </p>
                                                                    {provider.cacheTokenBilling && (
                                                                        <p>
                                                                            Cache Hit:{' '}
                                                                            {(
                                                                                ((provider.inputPrice ?? 0) *
                                                                                    tier.inputMultiplier) /
                                                                                provider.cacheTokenBilling.divisor
                                                                            ).toFixed(
                                                                                4
                                                                            )}{' '}
                                                                            0G/1M
                                                                        </p>
                                                                    )}
                                                                </div>
                                                            )
                                                        }
                                                    )}
                                                </div>
                                            ) : (
                                                <>
                                                    {provider.inputPrice !==
                                                        undefined && (
                                                        <p>
                                                            Input (what you
                                                            send):{' '}
                                                            {provider.inputPrice.toFixed(
                                                                4
                                                            )}{' '}
                                                            0G per 1M tokens
                                                        </p>
                                                    )}
                                                    {provider.outputPrice !==
                                                        undefined && (
                                                        <p>
                                                            Output (AI
                                                            response):{' '}
                                                            {provider.outputPrice.toFixed(
                                                                4
                                                            )}{' '}
                                                            0G per 1M tokens
                                                        </p>
                                                    )}
                                                    {provider.cacheTokenBilling &&
                                                        provider.inputPrice !==
                                                            undefined && (
                                                        <p>
                                                            Cache Hit:{' '}
                                                            {(
                                                                provider.inputPrice /
                                                                provider.cacheTokenBilling.divisor
                                                            ).toFixed(4)}{' '}
                                                            0G per 1M tokens
                                                        </p>
                                                    )}
                                                    <p className="text-muted-foreground mt-1 text-xs">
                                                        ~
                                                        {(
                                                            (provider.inputPrice ||
                                                                0) +
                                                            (provider.outputPrice ||
                                                                0)
                                                        ).toFixed(4)}{' '}
                                                        0G per typical message
                                                    </p>
                                                </>
                                            )}
                                        </div>
                                    </TooltipContent>
                                </Tooltip>
                            )}

                            {/* Address with copy */}
                            <div className="flex items-center gap-1">
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <code className="text-xs text-muted-foreground font-mono bg-muted px-2 py-1 rounded-md cursor-default">
                                            {truncatedAddress}
                                        </code>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <p>{provider.address}</p>
                                    </TooltipContent>
                                </Tooltip>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Button
                                            variant="ghost"
                                            size="icon"
                                            className="h-6 w-6 text-muted-foreground hover:text-primary"
                                            onClick={copyAddress}
                                        >
                                            <Copy className="h-3 w-3" />
                                        </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        <p>Copy address</p>
                                    </TooltipContent>
                                </Tooltip>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Action buttons */}
                <div className="flex gap-2 mt-4">
                    {isDisabled ? (
                        <>
                            {isChatService && (
                                <Button
                                    variant="outline"
                                    size="sm"
                                    className="flex-1 text-xs cursor-not-allowed"
                                    disabled
                                >
                                    <MessageCircle className="h-3.5 w-3.5 mr-1.5" />
                                    Chat
                                </Button>
                            )}
                            {isImageService && (
                                <Button
                                    variant="outline"
                                    size="sm"
                                    className="flex-1 text-xs cursor-not-allowed"
                                    disabled
                                >
                                    <Image className="h-3.5 w-3.5 mr-1.5" />
                                    Generate
                                </Button>
                            )}
                            {isSpeechService && (
                                <Button
                                    variant="outline"
                                    size="sm"
                                    className="flex-1 text-xs cursor-not-allowed"
                                    disabled
                                >
                                    <Mic className="h-3.5 w-3.5 mr-1.5" />
                                    Transcribe
                                </Button>
                            )}
                            <Button
                                variant="outline"
                                size="sm"
                                className="flex-1 text-xs cursor-not-allowed"
                                disabled
                            >
                                <Code className="h-3.5 w-3.5 mr-1.5" />
                                Build
                            </Button>
                        </>
                    ) : (
                        <>
                            {isChatService && onChat && (
                                <Button
                                    variant="default"
                                    size="sm"
                                    className="flex-1 text-xs"
                                    onClick={() => onChat(provider)}
                                >
                                    <MessageCircle className="h-3.5 w-3.5 mr-1.5" />
                                    Chat
                                </Button>
                            )}
                            {isTextToImage && onImageGen && (
                                <Button
                                    variant="default"
                                    size="sm"
                                    className="flex-1 text-xs"
                                    onClick={() => onImageGen(provider)}
                                >
                                    <Image className="h-3.5 w-3.5 mr-1.5" />
                                    Generate
                                </Button>
                            )}
                            {isImageEditing && onImageEdit && (
                                <Button
                                    variant="default"
                                    size="sm"
                                    className="flex-1 text-xs"
                                    onClick={() => onImageEdit(provider)}
                                >
                                    <Wand2 className="h-3.5 w-3.5 mr-1.5" />
                                    Edit
                                </Button>
                            )}
                            {isSpeechService && onSpeechToText && (
                                <Button
                                    variant="default"
                                    size="sm"
                                    className="flex-1 text-xs"
                                    onClick={() => onSpeechToText(provider)}
                                >
                                    <Mic className="h-3.5 w-3.5 mr-1.5" />
                                    Transcribe
                                </Button>
                            )}
                            {onBuild && (
                                <Button
                                    variant="outline"
                                    size="sm"
                                    className="flex-1 text-xs"
                                    onClick={() => onBuild(provider)}
                                >
                                    <Code className="h-3.5 w-3.5 mr-1.5" />
                                    Build
                                </Button>
                            )}
                        </>
                    )}
                </div>

                {/* Unverified notice */}
                {!isVerified && (
                    <div className="mt-3 p-2.5 bg-red-50 border border-red-200 rounded-lg">
                        <div className="flex items-start">
                            <AlertCircle className="h-4 w-4 text-red-500 mr-2 flex-shrink-0" />
                            <p className="text-xs text-red-700">
                                This provider has not been verified and cannot
                                be used until verification is complete.
                            </p>
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    )
}

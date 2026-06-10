'use client'

import * as React from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
    MessageCircle,
    Image,
    Mic,
    Wand2,
    Users,
    Shield,
    ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ModelSummary } from '@/shared/types/broker'

interface ModelCardProps {
    model: ModelSummary
    onClick: (model: ModelSummary) => void
}

const SERVICE_TYPE_CONFIG: Record<string, { label: string; icon: React.ElementType; color: string; hoverColor: string }> = {
    chatbot: { label: 'Chatbot', icon: MessageCircle, color: 'bg-blue-100 text-blue-700', hoverColor: 'hover:bg-blue-100 hover:text-blue-700' },
    'text-to-image': { label: 'Text to Image', icon: Image, color: 'bg-purple-100 text-purple-700', hoverColor: 'hover:bg-purple-100 hover:text-purple-700' },
    'image-editing': { label: 'Image Editing', icon: Wand2, color: 'bg-pink-100 text-pink-700', hoverColor: 'hover:bg-pink-100 hover:text-pink-700' },
    'speech-to-text': { label: 'Speech to Text', icon: Mic, color: 'bg-amber-100 text-amber-700', hoverColor: 'hover:bg-amber-100 hover:text-amber-700' },
}

function formatPrice(value: number): string {
    // Per-second prices (speech-to-text) can be far below 0.01 0G;
    // fall back to more decimals so they don't render as "0.00"
    if (value > 0 && value < 0.01) {
        return parseFloat(value.toFixed(6)).toString()
    }
    return value.toFixed(2)
}

function formatPriceRange(range: { min: number; max: number } | null): string | null {
    if (!range) return null
    if (range.min === range.max) {
        return formatPrice(range.min)
    }
    return `${formatPrice(range.min)} - ${formatPrice(range.max)}`
}

export function ModelCard({ model, onClick }: ModelCardProps) {
    const typeConfig = SERVICE_TYPE_CONFIG[model.serviceType] || SERVICE_TYPE_CONFIG.chatbot
    const TypeIcon = typeConfig.icon
    const isImageService = model.serviceType === 'text-to-image' || model.serviceType === 'image-editing'
    const isSpeechService = model.serviceType === 'speech-to-text'

    const priceDisplay = isImageService
        ? formatPriceRange(model.outputPriceRange)
        : formatPriceRange(model.inputPriceRange)

    const priceUnit = isImageService
        ? '0G/image'
        : isSpeechService
          ? '0G/second'
          : '0G/1M tokens'

    return (
        <Card
            className="relative group cursor-pointer hover:shadow-glow"
            onClick={() => onClick(model)}
        >
            <CardContent className="p-5">
                {/* Header */}
                <div className="flex items-start justify-between mb-3">
                    <div className="flex-1 min-w-0">
                        <h3 className="text-base font-semibold text-foreground truncate mb-2">
                            {model.displayName}
                        </h3>
                        <Badge
                            className={cn(
                                'border-0 px-2 py-0.5 text-xs font-medium flex items-center gap-1 w-fit',
                                typeConfig.color,
                                typeConfig.hoverColor,
                            )}
                        >
                            <TypeIcon className="h-3 w-3" />
                            {typeConfig.label}
                        </Badge>
                    </div>
                    <ChevronRight className="h-5 w-5 text-muted-foreground group-hover:text-primary transition-colors flex-shrink-0 mt-1" />
                </div>

                {/* Stats */}
                <div className="flex items-center gap-3 mt-4 text-sm">
                    <div className="flex items-center gap-1.5 text-muted-foreground">
                        <Users className="h-3.5 w-3.5" />
                        <span>
                            {model.providerCount} provider{model.providerCount !== 1 ? 's' : ''}
                        </span>
                    </div>
                    {model.verifiedCount > 0 && (
                        <div className="flex items-center gap-1.5 text-green-600">
                            <Shield className="h-3.5 w-3.5" />
                            <span>{model.verifiedCount} verified</span>
                        </div>
                    )}
                </div>

                {/* Price range */}
                {priceDisplay && (
                    <div className="mt-3 flex items-center gap-2 text-xs bg-secondary px-2.5 py-1.5 rounded-lg font-mono">
                        <span className="text-muted-foreground">Price:</span>
                        <span className="font-semibold text-foreground">
                            {priceDisplay}
                        </span>
                        <span className="text-muted-foreground">{priceUnit}</span>
                    </div>
                )}
            </CardContent>
        </Card>
    )
}

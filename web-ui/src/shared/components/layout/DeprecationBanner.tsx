'use client'

import { useState } from 'react'
import { X, ExternalLink } from 'lucide-react'

const NEW_UI_URL = 'https://pc.0g.ai/sdk'

/**
 * Deprecation notice for the CLI-embedded web UI. New features are only
 * added to the hosted UI at pc.0g.ai/sdk.
 * See https://github.com/0gfoundation/0g-compute-ts-sdk/issues/207
 */
export function DeprecationBanner() {
    const [dismissed, setDismissed] = useState(false)

    if (dismissed) {
        return null
    }

    return (
        <div className="flex items-center justify-center gap-2 bg-amber-100 px-4 py-2 text-sm text-amber-900">
            <span>
                A new and improved web experience is now available — this
                local UI is in maintenance mode. Check it out at{' '}
                <a
                    href={NEW_UI_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-semibold underline hover:text-amber-700"
                >
                    pc.0g.ai/sdk
                    <ExternalLink className="h-3.5 w-3.5" />
                </a>
            </span>
            <button
                type="button"
                aria-label="Dismiss deprecation notice"
                onClick={() => setDismissed(true)}
                className="ml-2 rounded p-0.5 hover:bg-amber-200"
            >
                <X className="h-4 w-4" />
            </button>
        </div>
    )
}

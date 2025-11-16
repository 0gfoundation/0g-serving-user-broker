'use client'

import * as React from 'react'
import { useState } from 'react'
import { useAccount } from 'wagmi'
import { useRouter } from 'next/navigation'
import { use0GBroker } from '../../../shared/hooks/use0GBroker'
import { useOptimizedDataFetching } from '../../../shared/hooks/useOptimizedDataFetching'
import type { Provider } from '../../../shared/types/broker'
import { OFFICIAL_PROVIDERS } from '../constants/providers'
import { transformBrokerServicesToProviders } from '../utils/providerTransform'
import { useNavigation } from '../../../shared/components/navigation/OptimizedNavigation'
import ReactMarkdown from 'react-markdown'

export function OptimizedInferencePage() {
    const { isConnected } = useAccount()
    const { broker, isInitializing } = use0GBroker()
    const router = useRouter()
    const { setIsNavigating, setTargetRoute, setTargetPageType } =
        useNavigation()
    const [isDrawerOpen, setIsDrawerOpen] = useState(false)
    const [isDrawerVisible, setIsDrawerVisible] = useState(false)
    const [selectedProviderForBuild, setSelectedProviderForBuild] =
        useState<Provider | null>(null)
    const [selectedTab, setSelectedTab] = useState<
        'curl' | 'javascript' | 'python'
    >('curl')

    type TabType = 'curl' | 'javascript' | 'python'

    // Optimized providers data fetching
    const {
        data: providers,
        loading: providersLoading,
        error: providersError,
    } = useOptimizedDataFetching<Provider[]>({
        fetchFn: async () => {
            if (!broker) throw new Error('Broker not available')

            try {
                const services = await broker.inference.listService()

                // Transform services to Provider format
                return transformBrokerServicesToProviders(services)
            } catch (err) {
                return []
            }
        },
        cacheKey: 'inference-providers',
        cacheTTL: 2 * 60 * 1000, // 2 minutes cache
        dependencies: [broker],
        skip: !broker,
    })

    const handleChatWithProvider = (provider: Provider) => {
        setIsNavigating(true)
        setTargetRoute('Chat')
        setTargetPageType('chat')

        router.push(
            `/inference/chat?provider=${encodeURIComponent(provider.address)}`
        )
    }

    const handleBuildWithProvider = (provider: Provider) => {
        setSelectedProviderForBuild(provider)
        setIsDrawerVisible(true)
        setTimeout(() => setIsDrawerOpen(true), 10)
    }

    const handleCloseDrawer = () => {
        setIsDrawerOpen(false)
        setTimeout(() => {
            setIsDrawerVisible(false)
            setSelectedProviderForBuild(null)
        }, 300)
    }

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text)
    }

    const formatCodeAsMarkdown = (code: string, language: string) => {
        // Format code as markdown with language identifier for proper highlighting
        return `\`\`\`${language}\n${code}\n\`\`\``
    }

    const getCodeExample = (tab: string) => {
        const examples = {
            curl: `curl http://127.0.0.1:3000/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{
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
  }'`,
            javascript: `const OpenAI = require('openai');

const client = new OpenAI({
  baseURL: 'http://127.0.0.1:3000/v1',
  apiKey: ''
});

async function main() {
  const completion = await client.chat.completions.create({
    messages: [
      {
        role: 'system',
        content: 'You are a helpful assistant.'
      },
      {
        role: 'user',
        content: 'Hello!'
      }
    ],
  });
  
  console.log(completion.choices[0].message);
}

main();`,
            python: `from openai import OpenAI

client = OpenAI(
    base_url='http://127.0.0.1:3000/v1',
    api_key=''
)

completion = client.chat.completions.create(
    messages=[
        {
            'role': 'system',
            'content': 'You are a helpful assistant.'
        },
        {
            'role': 'user',
            'content': 'Hello!'
        }
    ]
)

print(completion.choices[0].message)`,
        }
        return examples[tab as keyof typeof examples] || examples.curl
    }

    const getSDKExample = (
        tab: string,
        serviceType?: string,
        provider?: Provider | null
    ) => {
        const serviceUrl = provider?.url || '<service.url>'
        const serviceModel = provider?.model || '<service.model>'

        if (serviceType === 'text-to-image') {
            const examples = {
                curl: `curl ${serviceUrl}/v1/proxy/images/generations \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer app-sk-<SECRET>" \\
  -d '{
    "model": "${serviceModel}",
    "prompt": "A cute baby sea otter",
    "n": 1,
    "size": "1024x1024"
  }'`,
                javascript: `const OpenAI = require('openai');

const client = new OpenAI({
  baseURL: '${serviceUrl}/v1/proxy',
  apiKey: 'app-sk-<SECRET>'
});

async function main() {
  const response = await client.images.generate({
    model: '${serviceModel}',
    prompt: 'A cute baby sea otter',
    n: 1,
    size: '1024x1024'
  });
  
  console.log(response.data);
}

main();`,
                python: `from openai import OpenAI

client = OpenAI(
    base_url='${serviceUrl}/v1/proxy',
    api_key='app-sk-<SECRET>'
)

response = client.images.generate(
    model='${serviceModel}',
    prompt='A cute baby sea otter',
    n=1,
    size='1024x1024'
)

print(response.data)`,
            }
            return examples[tab as keyof typeof examples] || examples.curl
        } else {
            // For chatbot/text type
            const examples = {
                curl: `curl ${serviceUrl}/v1/proxy/chat/completions \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer app-sk-<SECRET>" \\
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
  }'`,
                javascript: `const OpenAI = require('openai');

const client = new OpenAI({
  baseURL: '${serviceUrl}/v1/proxy',
  apiKey: 'app-sk-<SECRET>'
});

async function main() {
  const completion = await client.chat.completions.create({
    model: '${serviceModel}',
    messages: [
      {
        role: 'system',
        content: 'You are a helpful assistant.'
      },
      {
        role: 'user',
        content: 'Hello!'
      }
    ]
  });
  
  console.log(completion.choices[0].message);
}

main();`,
                python: `from openai import OpenAI

client = OpenAI(
    base_url='${serviceUrl}/v1/proxy',
    api_key='app-sk-<SECRET>'
)

completion = client.chat.completions.create(
    model='${serviceModel}',
    messages=[
        {
            'role': 'system',
            'content': 'You are a helpful assistant.'
        },
        {
            'role': 'user',
            'content': 'Hello!'
        }
    ]
)

print(completion.choices[0].message)`,
            }
            return examples[tab as keyof typeof examples] || examples.curl
        }
    }

    if (!isConnected) {
        return (
            <div className="w-full">
                <div className="bg-white rounded-xl border border-gray-200 p-8 text-center">
                    <div className="flex items-center justify-center mb-6">
                        <div className="w-16 h-16 bg-purple-50 rounded-full flex items-center justify-center border border-purple-200">
                            <svg
                                className="w-8 h-8 text-purple-600"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                            >
                                <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                                />
                            </svg>
                        </div>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-2">
                        Wallet Not Connected
                    </h3>
                    <p className="text-gray-600">
                        Please connect your wallet to access AI inference
                        features.
                    </p>
                </div>
            </div>
        )
    }

    // Show loading state only for critical loading (broker initialization)
    const isLoading = isInitializing
    const displayProviders = providers || []
    const hasError = providersError && !providers

    return (
        <div className="w-full">
            <div className="mb-3">
                <h1 className="text-lg font-semibold text-gray-900">
                    Inference
                </h1>
                <p className="text-xs text-gray-500">
                    Choose from decentralized AI providers to start chatting or
                    integrate the service into your own application
                </p>
            </div>

            {hasError && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 mb-6">
                    <div className="flex items-start">
                        <svg
                            className="w-5 h-5 text-yellow-500 mr-3 mt-0.5 flex-shrink-0"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                            />
                        </svg>
                        <div className="flex-1 min-w-0">
                            <h3 className="text-sm font-medium text-yellow-800">
                                Notice
                            </h3>
                            <p className="text-sm text-yellow-700 mt-1">
                                Failed to fetch live provider data. Showing
                                fallback providers.
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {isLoading ? (
                <div className="bg-white rounded-xl border border-gray-200 p-8 text-center">
                    <div className="flex items-center justify-center mb-4">
                        <div className="animate-spin rounded-full h-8 w-8 border-2 border-purple-600 border-t-transparent"></div>
                    </div>
                    <p className="text-gray-600">Initializing...</p>
                </div>
            ) : (
                <>
                    {/* Show providers immediately with inline loading indicators for data being fetched */}
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                        {displayProviders.map((provider) => {
                            const isOfficial = OFFICIAL_PROVIDERS.some(
                                (op) => op.address === provider.address
                            )
                            const isVerified =
                                provider.teeSignerAcknowledged ?? false
                            const isDisabled = !isVerified

                            return (
                                <div
                                    key={provider.address}
                                    className={`bg-white rounded-xl border border-gray-300 p-5 transition-shadow relative ${
                                        isDisabled
                                            ? 'opacity-60 cursor-not-allowed'
                                            : 'hover:shadow-lg cursor-pointer'
                                    }`}
                                >
                                    {/* Show loading indicator for individual provider data if still loading */}
                                    {providersLoading && (
                                        <div className="absolute top-2 right-2">
                                            <div className="animate-spin rounded-full h-3 w-3 border border-purple-600 border-t-transparent"></div>
                                        </div>
                                    )}

                                    {/* Header with name, badges and address */}
                                    <div className="flex items-start justify-between mb-4">
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center space-x-2 mb-1">
                                                <h3 className="text-base font-semibold text-gray-900 truncate">
                                                    {provider.name}
                                                </h3>
                                                {isOfficial && (
                                                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800 flex-shrink-0">
                                                        0G
                                                    </span>
                                                )}
                                                <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 flex-shrink-0">
                                                    {provider.verifiability}
                                                </span>
                                                {!isVerified && (
                                                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 flex-shrink-0">
                                                        Unverified
                                                    </span>
                                                )}
                                            </div>

                                            {/* Pricing and address with copy button */}
                                            <div className="flex items-center space-x-2 mb-2 min-h-[28px]">
                                                {/* Pricing section first */}
                                                {(provider.inputPrice !==
                                                    undefined ||
                                                    provider.outputPrice !==
                                                        undefined) && (
                                                    <div className="flex items-center space-x-2 text-xs h-full">
                                                        {provider.inputPrice !==
                                                            undefined && (
                                                            <div className="flex items-center space-x-1">
                                                                <span className="text-gray-600">
                                                                    In:
                                                                </span>
                                                                <span className="font-semibold text-gray-900">
                                                                    {provider.inputPrice.toFixed(
                                                                        4
                                                                    )}
                                                                </span>
                                                            </div>
                                                        )}
                                                        {provider.outputPrice !==
                                                            undefined && (
                                                            <div className="flex items-center space-x-1">
                                                                <span className="text-gray-600">
                                                                    Out:
                                                                </span>
                                                                <span className="font-semibold text-gray-900">
                                                                    {provider.outputPrice.toFixed(
                                                                        4
                                                                    )}
                                                                </span>
                                                            </div>
                                                        )}
                                                        <span className="text-gray-500">
                                                            0G
                                                        </span>
                                                    </div>
                                                )}

                                                <div className="flex items-center space-x-1 h-full">
                                                    <div className="relative group flex items-center">
                                                        <code className="text-xs text-gray-500 font-mono bg-gray-50 px-2 py-1 rounded cursor-default flex items-center">
                                                            {provider.address.slice(
                                                                0,
                                                                8
                                                            )}
                                                            ...
                                                            {provider.address.slice(
                                                                -6
                                                            )}
                                                        </code>
                                                        {/* Tooltip showing full address */}
                                                        <div className="absolute bottom-full left-0 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-10 whitespace-nowrap">
                                                            {provider.address}
                                                            <div className="absolute top-full left-4 -mt-1">
                                                                <div className="w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div className="relative group flex items-center">
                                                        <button
                                                            onClick={() =>
                                                                navigator.clipboard.writeText(
                                                                    provider.address
                                                                )
                                                            }
                                                            className="text-gray-400 hover:text-gray-600 p-1 cursor-pointer flex items-center justify-center"
                                                            title="Copy address"
                                                        >
                                                            <svg
                                                                className="w-3 h-3"
                                                                fill="none"
                                                                stroke="currentColor"
                                                                viewBox="0 0 24 24"
                                                            >
                                                                <path
                                                                    strokeLinecap="round"
                                                                    strokeLinejoin="round"
                                                                    strokeWidth={
                                                                        2
                                                                    }
                                                                    d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                                />
                                                            </svg>
                                                        </button>
                                                        {/* Copy tooltip */}
                                                        <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-10 whitespace-nowrap">
                                                            Copy address
                                                            <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
                                                                <div className="w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Action buttons */}
                                    <div className="flex space-x-1 mt-1">
                                        {isDisabled ? (
                                            <>
                                                {provider.serviceType ===
                                                    'chatbot' && (
                                                    <div className="flex-1 bg-gray-100 text-gray-400 rounded-md px-2 py-1.5 text-xs flex items-center justify-center space-x-1 border border-gray-200 cursor-not-allowed">
                                                        <svg
                                                            className="w-3 h-3"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03-8-9-8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                                                            />
                                                        </svg>
                                                        <span>Chat</span>
                                                    </div>
                                                )}
                                                <div className="flex-1 bg-gray-100 text-gray-400 rounded-md px-2 py-1.5 text-xs flex items-center justify-center space-x-1 border border-gray-200 cursor-not-allowed">
                                                    <svg
                                                        className="w-3 h-3"
                                                        fill="none"
                                                        stroke="currentColor"
                                                        viewBox="0 0 24 24"
                                                    >
                                                        <path
                                                            strokeLinecap="round"
                                                            strokeLinejoin="round"
                                                            strokeWidth={2}
                                                            d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"
                                                        />
                                                    </svg>
                                                    <span>Build</span>
                                                </div>
                                            </>
                                        ) : (
                                            <>
                                                {provider.serviceType ===
                                                    'chatbot' && (
                                                    <button
                                                        onClick={() =>
                                                            handleChatWithProvider(
                                                                provider
                                                            )
                                                        }
                                                        className="flex-1 text-gray-600 hover:text-purple-600 hover:bg-purple-50 transition-colors rounded-md px-2 py-1.5 cursor-pointer text-xs flex items-center justify-center space-x-1 border border-gray-200 hover:border-purple-200"
                                                    >
                                                        <svg
                                                            className="w-3 h-3"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03-8-9-8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                                                            />
                                                        </svg>
                                                        <span>Chat</span>
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() =>
                                                        handleBuildWithProvider(
                                                            provider
                                                        )
                                                    }
                                                    className="flex-1 text-gray-600 hover:text-purple-600 hover:bg-purple-50 transition-colors rounded-md px-2 py-1.5 cursor-pointer text-xs flex items-center justify-center space-x-1 border border-gray-200 hover:border-purple-200"
                                                >
                                                    <svg
                                                        className="w-3 h-3"
                                                        fill="none"
                                                        stroke="currentColor"
                                                        viewBox="0 0 24 24"
                                                    >
                                                        <path
                                                            strokeLinecap="round"
                                                            strokeLinejoin="round"
                                                            strokeWidth={2}
                                                            d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"
                                                        />
                                                    </svg>
                                                    <span>Build</span>
                                                </button>
                                            </>
                                        )}
                                    </div>

                                    {/* Unverified provider notice */}
                                    {!isVerified && (
                                        <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded-md">
                                            <div className="flex items-start">
                                                <svg
                                                    className="w-3 h-3 text-red-500 mr-1 mt-0.5 flex-shrink-0"
                                                    fill="none"
                                                    stroke="currentColor"
                                                    viewBox="0 0 24 24"
                                                >
                                                    <path
                                                        strokeLinecap="round"
                                                        strokeLinejoin="round"
                                                        strokeWidth={2}
                                                        d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                                                    />
                                                </svg>
                                                <p className="text-xs text-red-700">
                                                    This provider has not been
                                                    verified and cannot be used
                                                    until verification is
                                                    complete.
                                                </p>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )
                        })}
                    </div>
                </>
            )}

            {!isLoading && displayProviders.length === 0 && (
                <div className="bg-white rounded-xl border border-gray-200 p-8 text-center">
                    <div className="flex items-center justify-center mb-4">
                        <svg
                            className="w-12 h-12 text-gray-400"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M9.172 16.172a4 4 0 015.656 0M9 12h6m-6-4h6m2 5.291A7.962 7.962 0 0112 15c-2.034 0-3.9.785-5.291 2.067m-.709 3.316l3.578-3.578m0 0L10 18.184m0 0L8.184 16.5M18.816 16.5L17 18.184m0 0l1.416 1.416m0 0l-1.416-1.416"
                            />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-2">
                        No Providers Available
                    </h3>
                    <p className="text-gray-600">
                        There are currently no AI inference providers available.
                        Please try again later.
                    </p>
                </div>
            )}

            {/* Build Guide Drawer - keeping the same as original */}
            {isDrawerVisible && (
                <div className="fixed inset-0 z-50 overflow-hidden">
                    <div
                        className="absolute inset-0 transition-opacity duration-300"
                        onClick={handleCloseDrawer}
                    />

                    <div
                        className={`absolute right-0 top-0 h-full w-1/2 min-w-[600px] bg-white/95 backdrop-blur-sm shadow-2xl border-l border-gray-200 transform transition-all duration-300 ease-out ${
                            isDrawerOpen
                                ? 'translate-x-0 opacity-100'
                                : 'translate-x-full opacity-0'
                        }`}
                    >
                        <div className="flex flex-col h-full">
                            <div className="flex items-center justify-between py-4 px-6 border-b border-gray-200">
                                <div>
                                    <h2 className="text-xl font-semibold text-gray-900">
                                        Build with{' '}
                                        {selectedProviderForBuild
                                            ? selectedProviderForBuild.model.includes(
                                                  '/'
                                              )
                                                ? selectedProviderForBuild.model
                                                      .split('/')
                                                      .slice(1)
                                                      .join('/')
                                                : selectedProviderForBuild.model
                                            : 'Provider'}
                                    </h2>
                                </div>
                                <button
                                    onClick={handleCloseDrawer}
                                    className="p-2 rounded-md hover:bg-gray-100 transition-colors"
                                >
                                    <svg
                                        className="w-5 h-5 text-gray-500"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M6 18L18 6M6 6l12 12"
                                        />
                                    </svg>
                                </button>
                            </div>

                            <div className="flex-1 overflow-y-auto p-6">
                                <div className="space-y-6">
                                    {/* Setup Steps section for all types */}
                                    <div className="mb-8">
                                        <h2 className="text-lg font-semibold text-gray-800 mb-4">
                                            Setup Steps
                                        </h2>

                                        <div className="space-y-4">
                                            <div>
                                                <h3 className="text-base font-medium text-gray-700 mb-2">
                                                    1. Install the 0G Compute
                                                    CLI
                                                </h3>
                                                <div className="relative">
                                                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto">
                                                        <code className="text-gray-800 text-sm font-mono">
                                                            pnpm install
                                                            @0glabs/0g-serving-broker
                                                            -g
                                                        </code>
                                                    </div>
                                                    <button
                                                        onClick={() =>
                                                            copyToClipboard(
                                                                'pnpm install @0glabs/0g-serving-broker -g'
                                                            )
                                                        }
                                                        className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                        title="Copy to clipboard"
                                                    >
                                                        <svg
                                                            className="w-4 h-4 text-gray-500"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                            />
                                                        </svg>
                                                    </button>
                                                </div>
                                            </div>

                                            <div>
                                                <h3 className="text-base font-medium text-gray-700 mb-2">
                                                    2. Deposit funds to your
                                                    account
                                                </h3>
                                                <div className="relative">
                                                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto">
                                                        <code className="text-gray-800 text-sm font-mono">
                                                            0g-compute-cli
                                                            deposit --amount 5
                                                        </code>
                                                    </div>
                                                    <button
                                                        onClick={() =>
                                                            copyToClipboard(
                                                                '0g-compute-cli deposit --amount 5'
                                                            )
                                                        }
                                                        className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                        title="Copy to clipboard"
                                                    >
                                                        <svg
                                                            className="w-4 h-4 text-gray-500"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                            />
                                                        </svg>
                                                    </button>
                                                </div>
                                                <p className="text-xs text-gray-600 mt-1">
                                                    (If your account balance is
                                                    insufficient, please deposit
                                                    funds first.)
                                                </p>
                                            </div>

                                            <div>
                                                <h3 className="text-base font-medium text-gray-700 mb-2">
                                                    3. Verify provider
                                                    (Optional)
                                                </h3>
                                                <div className="relative">
                                                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto">
                                                        <code className="text-gray-800 text-sm font-mono">
                                                            {selectedProviderForBuild
                                                                ? `0g-compute-cli inference verify --provider ${selectedProviderForBuild.address}`
                                                                : '0g-compute-cli inference verify --provider <provider_address>'}
                                                        </code>
                                                    </div>
                                                    <button
                                                        onClick={() =>
                                                            copyToClipboard(
                                                                selectedProviderForBuild
                                                                    ? `0g-compute-cli inference verify --provider ${selectedProviderForBuild.address}`
                                                                    : '0g-compute-cli inference verify --provider <provider_address>'
                                                            )
                                                        }
                                                        className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                        title="Copy to clipboard"
                                                    >
                                                        <svg
                                                            className="w-4 h-4 text-gray-500"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                            />
                                                        </svg>
                                                    </button>
                                                </div>
                                                <p className="text-xs text-gray-600 mt-1">
                                                    (This will output the
                                                    provider's report and allow
                                                    you to further verify the
                                                    provider as instructed)
                                                </p>
                                            </div>

                                            <div>
                                                <h3 className="text-base font-medium text-gray-700 mb-2">
                                                    4. Transfer funds to
                                                    provider account
                                                </h3>
                                                <div className="relative">
                                                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto">
                                                        <code className="text-gray-800 text-sm font-mono">
                                                            {selectedProviderForBuild
                                                                ? `0g-compute-cli transfer-fund --provider ${selectedProviderForBuild.address} --amount 5`
                                                                : '0g-compute-cli transfer-fund --provider <provider_address> --amount 5'}
                                                        </code>
                                                    </div>
                                                    <button
                                                        onClick={() =>
                                                            copyToClipboard(
                                                                selectedProviderForBuild
                                                                    ? `0g-compute-cli transfer-fund --provider ${selectedProviderForBuild.address} --amount 5`
                                                                    : '0g-compute-cli transfer-fund --provider <provider_address> --amount 5'
                                                            )
                                                        }
                                                        className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                        title="Copy to clipboard"
                                                    >
                                                        <svg
                                                            className="w-4 h-4 text-gray-500"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                            />
                                                        </svg>
                                                    </button>
                                                </div>
                                                <p className="text-xs text-gray-600 mt-1">
                                                    (Transfer funds from main
                                                    account to sub-account for
                                                    the specified provider. We
                                                    recommend depositing more
                                                    than 5 0G, as the provider
                                                    requires a minimum balance
                                                    to respond.)
                                                </p>
                                            </div>

                                            <div>
                                                <h3 className="text-base font-medium text-gray-700 mb-2">
                                                    5. Accredit provider
                                                </h3>
                                                <div className="relative">
                                                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto">
                                                        <code className="text-gray-800 text-sm font-mono">
                                                            {selectedProviderForBuild
                                                                ? `0g-compute-cli inference acknowledge-provider --provider ${selectedProviderForBuild.address}`
                                                                : '0g-compute-cli inference acknowledge-provider --provider <provider_address>'}
                                                        </code>
                                                    </div>
                                                    <button
                                                        onClick={() =>
                                                            copyToClipboard(
                                                                selectedProviderForBuild
                                                                    ? `0g-compute-cli inference acknowledge-provider --provider ${selectedProviderForBuild.address}`
                                                                    : '0g-compute-cli inference acknowledge-provider --provider <provider_address>'
                                                            )
                                                        }
                                                        className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                        title="Copy to clipboard"
                                                    >
                                                        <svg
                                                            className="w-4 h-4 text-gray-500"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                            />
                                                        </svg>
                                                    </button>
                                                </div>
                                                <p className="text-xs text-gray-600 mt-1">
                                                    (This step indicates that
                                                    the user acknowledges the
                                                    provider)
                                                </p>
                                            </div>

                                            <div>
                                                <h3 className="text-base font-medium text-gray-700 mb-2">
                                                    6. Get secret for the
                                                    provider
                                                </h3>
                                                <div className="relative">
                                                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto">
                                                        <code className="text-gray-800 text-sm font-mono">
                                                            {selectedProviderForBuild
                                                                ? `0g-compute-cli inference get-secret --provider ${selectedProviderForBuild.address}`
                                                                : '0g-compute-cli inference get-secret --provider <provider_address>'}
                                                        </code>
                                                    </div>
                                                    <button
                                                        onClick={() =>
                                                            copyToClipboard(
                                                                selectedProviderForBuild
                                                                    ? `0g-compute-cli inference get-secret --provider ${selectedProviderForBuild.address}`
                                                                    : '0g-compute-cli inference get-secret --provider <provider_address>'
                                                            )
                                                        }
                                                        className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                        title="Copy to clipboard"
                                                    >
                                                        <svg
                                                            className="w-4 h-4 text-gray-500"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                            />
                                                        </svg>
                                                    </button>
                                                </div>
                                                <p className="text-xs text-gray-600 mt-1">
                                                    (Get the secret and use it
                                                    in various SDKs)
                                                </p>
                                            </div>

                                            {/* For text-to-image and chatbot, show SDK examples */}
                                            {(selectedProviderForBuild?.serviceType ===
                                                'text-to-image' ||
                                                selectedProviderForBuild?.serviceType ===
                                                    'chatbot') && (
                                                <div>
                                                    <h3 className="text-base font-medium text-gray-700 mb-2">
                                                        7. SDK Examples
                                                    </h3>
                                                    <p className="text-xs text-gray-600 mb-3">
                                                        Use your secret obtained
                                                        from step 6 in the
                                                        examples below:
                                                    </p>

                                                    {/* Tab Navigation */}
                                                    <div className="flex space-x-1 mb-3 bg-gray-100 rounded-lg p-1">
                                                        {[
                                                            {
                                                                key: 'curl',
                                                                label: 'cURL',
                                                            },
                                                            {
                                                                key: 'javascript',
                                                                label: 'JavaScript',
                                                            },
                                                            {
                                                                key: 'python',
                                                                label: 'Python',
                                                            },
                                                        ].map((tab) => (
                                                            <button
                                                                key={tab.key}
                                                                onClick={() =>
                                                                    setSelectedTab(
                                                                        tab.key as TabType
                                                                    )
                                                                }
                                                                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                                                                    selectedTab ===
                                                                    tab.key
                                                                        ? 'bg-white text-purple-700 shadow-sm border border-purple-200'
                                                                        : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50'
                                                                }`}
                                                            >
                                                                {tab.label}
                                                            </button>
                                                        ))}
                                                    </div>

                                                    {/* SDK Examples */}
                                                    <div className="relative">
                                                        <div className="bg-gray-50 border border-gray-200 rounded-lg overflow-x-auto">
                                                            <ReactMarkdown
                                                                components={{
                                                                    code: ({
                                                                        children,
                                                                        className,
                                                                    }) => {
                                                                        const isInline =
                                                                            !className
                                                                        if (
                                                                            isInline
                                                                        ) {
                                                                            return (
                                                                                <code className="bg-purple-50 text-purple-600 px-1 py-0.5 rounded text-xs font-mono">
                                                                                    {
                                                                                        children
                                                                                    }
                                                                                </code>
                                                                            )
                                                                        }
                                                                        return (
                                                                            <code className="text-gray-800 text-sm font-mono block whitespace-pre">
                                                                                {
                                                                                    children
                                                                                }
                                                                            </code>
                                                                        )
                                                                    },
                                                                    pre: ({
                                                                        children,
                                                                    }) => (
                                                                        <pre className="p-4 overflow-x-auto text-sm">
                                                                            {
                                                                                children
                                                                            }
                                                                        </pre>
                                                                    ),
                                                                }}
                                                            >
                                                                {formatCodeAsMarkdown(
                                                                    getSDKExample(
                                                                        selectedTab,
                                                                        selectedProviderForBuild?.serviceType,
                                                                        selectedProviderForBuild
                                                                    ),
                                                                    selectedTab
                                                                )}
                                                            </ReactMarkdown>
                                                        </div>
                                                        <button
                                                            onClick={() =>
                                                                copyToClipboard(
                                                                    getSDKExample(
                                                                        selectedTab,
                                                                        selectedProviderForBuild?.serviceType,
                                                                        selectedProviderForBuild
                                                                    )
                                                                )
                                                            }
                                                            className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                            title="Copy to clipboard"
                                                        >
                                                            <svg
                                                                className="w-4 h-4 text-gray-500"
                                                                fill="none"
                                                                stroke="currentColor"
                                                                viewBox="0 0 24 24"
                                                            >
                                                                <path
                                                                    strokeLinecap="round"
                                                                    strokeLinejoin="round"
                                                                    strokeWidth={
                                                                        2
                                                                    }
                                                                    d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                                />
                                                            </svg>
                                                        </button>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    {/* Quick Start section - only show for chatbot type */}
                                    {selectedProviderForBuild?.serviceType ===
                                        'chatbot' && (
                                        <div className="mb-8">
                                            <h2 className="text-lg font-semibold text-gray-800 mb-4">
                                                Quick Start a Service
                                            </h2>

                                            <div className="space-y-4">
                                                <div>
                                                    <h3 className="text-base font-medium text-gray-700 mb-2">
                                                        1. Start the server
                                                    </h3>
                                                    <div className="relative">
                                                        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto">
                                                            <code className="text-gray-800 text-sm font-mono">
                                                                {selectedProviderForBuild
                                                                    ? `0g-compute-cli inference serve --provider ${selectedProviderForBuild.address}`
                                                                    : '0g-compute-cli inference serve --provider <PROVIDER_ADDRESS>'}
                                                            </code>
                                                        </div>
                                                        <button
                                                            onClick={() =>
                                                                copyToClipboard(
                                                                    selectedProviderForBuild
                                                                        ? `0g-compute-cli inference serve --provider ${selectedProviderForBuild.address}`
                                                                        : '0g-compute-cli inference serve --provider <PROVIDER_ADDRESS>'
                                                                )
                                                            }
                                                            className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                            title="Copy to clipboard"
                                                        >
                                                            <svg
                                                                className="w-4 h-4 text-gray-500"
                                                                fill="none"
                                                                stroke="currentColor"
                                                                viewBox="0 0 24 24"
                                                            >
                                                                <path
                                                                    strokeLinecap="round"
                                                                    strokeLinejoin="round"
                                                                    strokeWidth={
                                                                        2
                                                                    }
                                                                    d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                                />
                                                            </svg>
                                                        </button>
                                                    </div>
                                                </div>

                                                <div>
                                                    <h3 className="text-base font-medium text-gray-700 mb-2">
                                                        2. Use OpenAI API format
                                                        to make a request
                                                    </h3>

                                                    {/* Tab Navigation */}
                                                    <div className="flex space-x-1 mb-3 bg-gray-100 rounded-lg p-1">
                                                        {[
                                                            {
                                                                key: 'curl',
                                                                label: 'cURL',
                                                            },
                                                            {
                                                                key: 'javascript',
                                                                label: 'JavaScript',
                                                            },
                                                            {
                                                                key: 'python',
                                                                label: 'Python',
                                                            },
                                                        ].map((tab) => (
                                                            <button
                                                                key={tab.key}
                                                                onClick={() =>
                                                                    setSelectedTab(
                                                                        tab.key as TabType
                                                                    )
                                                                }
                                                                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                                                                    selectedTab ===
                                                                    tab.key
                                                                        ? 'bg-white text-purple-700 shadow-sm border border-purple-200'
                                                                        : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50'
                                                                }`}
                                                                title={`View ${tab.label} example`}
                                                            >
                                                                {tab.label}
                                                            </button>
                                                        ))}
                                                    </div>

                                                    {/* Code Display */}
                                                    <div className="relative">
                                                        <div className="bg-gray-50 border border-gray-200 rounded-lg overflow-x-auto">
                                                            <ReactMarkdown
                                                                components={{
                                                                    code: ({
                                                                        children,
                                                                        className,
                                                                    }) => {
                                                                        const isInline =
                                                                            !className
                                                                        if (
                                                                            isInline
                                                                        ) {
                                                                            return (
                                                                                <code className="bg-purple-50 text-purple-600 px-1 py-0.5 rounded text-xs font-mono">
                                                                                    {
                                                                                        children
                                                                                    }
                                                                                </code>
                                                                            )
                                                                        }

                                                                        return (
                                                                            <code className="text-gray-800 text-sm font-mono block whitespace-pre">
                                                                                {
                                                                                    children
                                                                                }
                                                                            </code>
                                                                        )
                                                                    },
                                                                    pre: ({
                                                                        children,
                                                                    }) => (
                                                                        <pre className="p-4 overflow-x-auto text-sm">
                                                                            {
                                                                                children
                                                                            }
                                                                        </pre>
                                                                    ),
                                                                }}
                                                            >
                                                                {formatCodeAsMarkdown(
                                                                    getCodeExample(
                                                                        selectedTab
                                                                    ),
                                                                    selectedTab
                                                                )}
                                                            </ReactMarkdown>
                                                        </div>
                                                        <button
                                                            onClick={() =>
                                                                copyToClipboard(
                                                                    getCodeExample(
                                                                        selectedTab
                                                                    )
                                                                )
                                                            }
                                                            className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors cursor-pointer"
                                                            title="Copy to clipboard"
                                                        >
                                                            <svg
                                                                className="w-4 h-4 text-gray-500"
                                                                fill="none"
                                                                stroke="currentColor"
                                                                viewBox="0 0 24 24"
                                                            >
                                                                <path
                                                                    strokeLinecap="round"
                                                                    strokeLinejoin="round"
                                                                    strokeWidth={
                                                                        2
                                                                    }
                                                                    d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                                                                />
                                                            </svg>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    <div className="space-y-4">
                                        <h2 className="text-lg font-semibold text-gray-800">
                                            Integrate into your App
                                        </h2>

                                        <div className="bg-gradient-to-r from-purple-50 to-purple-100 rounded-lg p-6 border border-gray-200">
                                            <div className="flex items-start space-x-4">
                                                <div className="flex-shrink-0">
                                                    <svg
                                                        className="w-6 h-6 text-purple-600 mt-0.5"
                                                        fill="none"
                                                        stroke="currentColor"
                                                        viewBox="0 0 24 24"
                                                    >
                                                        <path
                                                            strokeLinecap="round"
                                                            strokeLinejoin="round"
                                                            strokeWidth={2}
                                                            d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
                                                        />
                                                    </svg>
                                                </div>
                                                <div className="flex-1">
                                                    <h3 className="text-base font-medium text-gray-900 mb-2">
                                                        SDK Documentation
                                                    </h3>
                                                    <p className="text-sm text-gray-600 mb-3">
                                                        Comprehensive guides for
                                                        integrating 0G Compute
                                                        Network into your
                                                        applications.
                                                    </p>
                                                    <a
                                                        href="https://docs.0g.ai/developer-hub/building-on-0g/compute-network/sdk"
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="inline-flex items-center px-4 py-2 bg-purple-600 text-white text-sm font-medium rounded-md hover:bg-purple-700 transition-colors cursor-pointer"
                                                        title="View SDK Documentation"
                                                    >
                                                        View Documentation
                                                        <svg
                                                            className="ml-2 -mr-1 w-4 h-4"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                                                            />
                                                        </svg>
                                                    </a>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="bg-gradient-to-r from-purple-50 to-purple-100 rounded-lg p-6 border border-gray-200">
                                            <div className="flex items-start space-x-4">
                                                <div className="flex-shrink-0">
                                                    <svg
                                                        className="w-6 h-6 text-purple-600 mt-0.5"
                                                        fill="none"
                                                        stroke="currentColor"
                                                        viewBox="0 0 24 24"
                                                    >
                                                        <path
                                                            strokeLinecap="round"
                                                            strokeLinejoin="round"
                                                            strokeWidth={2}
                                                            d="M13 10V3L4 14h7v7l9-11h-7z"
                                                        />
                                                    </svg>
                                                </div>
                                                <div className="flex-1">
                                                    <h3 className="text-base font-medium text-gray-900 mb-2">
                                                        Starter Kit
                                                    </h3>
                                                    <p className="text-sm text-gray-600 mb-3">
                                                        Ready-to-use TypeScript
                                                        starter kit with
                                                        examples and best
                                                        practices.
                                                    </p>
                                                    <a
                                                        href="https://github.com/0glabs/0g-compute-ts-starter-kit"
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="inline-flex items-center px-4 py-2 bg-purple-600 text-white text-sm font-medium rounded-md hover:bg-purple-700 transition-colors cursor-pointer"
                                                        title="View Starter Kit on GitHub"
                                                    >
                                                        View on GitHub
                                                        <svg
                                                            className="ml-2 -mr-1 w-4 h-4"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                                                            />
                                                        </svg>
                                                    </a>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="space-y-4">
                                        <h2 className="text-lg font-semibold text-gray-800">
                                            Not satisfied with existing
                                            providers?
                                        </h2>

                                        <div className="bg-gradient-to-r from-purple-50 to-purple-100 rounded-lg p-6 border border-gray-200">
                                            <div className="flex items-start space-x-4">
                                                <div className="flex-shrink-0">
                                                    <svg
                                                        className="w-6 h-6 text-purple-600 mt-0.5"
                                                        fill="none"
                                                        stroke="currentColor"
                                                        viewBox="0 0 24 24"
                                                    >
                                                        <path
                                                            strokeLinecap="round"
                                                            strokeLinejoin="round"
                                                            strokeWidth={2}
                                                            d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 100 4m0-4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 100 4m0-4v2m0-6V4"
                                                        />
                                                    </svg>
                                                </div>
                                                <div className="flex-1">
                                                    <h3 className="text-base font-medium text-gray-900 mb-2">
                                                        Become a Provider
                                                    </h3>
                                                    <p className="text-sm text-gray-600 mb-3">
                                                        Learn how to add your
                                                        own inference provider
                                                        to the 0G Compute
                                                        Network through our
                                                        comprehensive
                                                        documentation.
                                                    </p>
                                                    <a
                                                        href="https://docs.0g.ai/developer-hub/building-on-0g/compute-network/inference-provider"
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="inline-flex items-center px-4 py-2 bg-purple-600 text-white text-sm font-medium rounded-md hover:bg-purple-700 transition-colors cursor-pointer"
                                                        title="View Provider Documentation"
                                                    >
                                                        View Provider
                                                        Documentation
                                                        <svg
                                                            className="ml-2 -mr-1 w-4 h-4"
                                                            fill="none"
                                                            stroke="currentColor"
                                                            viewBox="0 0 24 24"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth={2}
                                                                d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                                                            />
                                                        </svg>
                                                    </a>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}

export default OptimizedInferencePage

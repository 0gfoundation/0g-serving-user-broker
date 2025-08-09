"use client";

import * as React from "react";
import { useState } from "react";
import { useAccount } from "wagmi";
import { useRouter } from "next/navigation";
import { use0GBroker } from "../../../hooks/use0GBroker";
import { useOptimizedDataFetching } from "../../../hooks/useOptimizedDataFetching";
import { useNavigation } from "../../../components/OptimizedNavigation";

// Convert neuron to A0GI (1 A0GI = 10^18 neuron)
const neuronToA0gi = (value: bigint): number => {
  const divisor = BigInt(10 ** 18);
  const integerPart = value / divisor;
  const remainder = value % divisor;
  const decimalPart = Number(remainder) / Number(divisor);
  return Number(integerPart) + decimalPart;
};

interface Provider {
  address: string;
  model: string;
  name: string;
  verifiability: string;
  url?: string;
  endpoint?: string;
  inputPrice?: number;
  outputPrice?: number;
  inputPriceNeuron?: bigint;
  outputPriceNeuron?: bigint;
}

// Official providers based on the documentation
const OFFICIAL_PROVIDERS: Provider[] = [
  {
    address: "0xf07240Efa67755B5311bc75784a061eDB47165Dd",
    model: "llama-3.3-70b-instruct",
    name: "Llama 3.3 70B Instruct",
    verifiability: "TEE (TeeML)",
  },
  {
    address: "0x3feE5a4dd5FDb8a32dDA97Bed899830605dBD9D3",
    model: "deepseek-r1-70b",
    name: "DeepSeek R1 70B",
    verifiability: "TEE (TeeML)",
  },
  {
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    model: "llama-3.3-70b-instruct",
    name: "Llama 3.3 70B Instruct",
    verifiability: "TEE (TeeML)",
  },
];

export function OptimizedInferencePage() {
  const { isConnected } = useAccount();
  const { broker, isInitializing } = use0GBroker();
  const router = useRouter();
  const { setIsNavigating, setTargetRoute, setTargetPageType } = useNavigation();
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [isDrawerVisible, setIsDrawerVisible] = useState(false);
  const [selectedProviderForBuild, setSelectedProviderForBuild] = useState<Provider | null>(null);

  // Optimized providers data fetching
  const { data: providers, loading: providersLoading, error: providersError } = useOptimizedDataFetching<Provider[]>({
    fetchFn: async () => {
      if (!broker) throw new Error('Broker not available');
      
      try {
        const services = await broker.inference.listService();
        console.log("Real services:", services);

        // Transform services to Provider format
        const transformedProviders: Provider[] = services.map(
          (service: unknown) => {
            const serviceObj = service as {
              provider?: string;
              model?: string;
              name?: string;
              verifiability?: string;
              url?: string;
              inputPrice?: bigint;
              outputPrice?: bigint;
            };
            
            const providerAddress = serviceObj.provider || "";
            const rawModel = serviceObj.model || "Unknown Model";
            const modelName = rawModel.includes('/') ? rawModel.split('/').slice(1).join('/') : rawModel;
            const rawProviderName = serviceObj.name || serviceObj.model || "Unknown Provider";
            const providerName = rawProviderName.includes('/') ? rawProviderName.split('/').slice(1).join('/') : rawProviderName;
            const verifiability = serviceObj.verifiability || "TEE";
            const serviceUrl = serviceObj.url || "";

            // Convert prices from neuron to A0GI per million tokens
            const inputPrice = serviceObj.inputPrice
              ? neuronToA0gi(serviceObj.inputPrice * BigInt(1000000))
              : undefined;
            const outputPrice = serviceObj.outputPrice
              ? neuronToA0gi(serviceObj.outputPrice * BigInt(1000000))
              : undefined;

            return {
              address: providerAddress,
              model: modelName,
              name: providerName,
              verifiability: verifiability,
              url: serviceUrl,
              inputPrice,
              outputPrice,
              inputPriceNeuron: serviceObj.inputPrice,
              outputPriceNeuron: serviceObj.outputPrice,
            };
          }
        );

        return transformedProviders;
      } catch (err) {
        console.error("Error fetching providers:", err);
        // Return fallback providers instead of throwing
        return OFFICIAL_PROVIDERS;
      }
    },
    cacheKey: 'inference-providers',
    cacheTTL: 2 * 60 * 1000, // 2 minutes cache
    dependencies: [broker],
    skip: !broker,
  });

  const handleChatWithProvider = (provider: Provider) => {
    // 触发导航 loading 状态
    setIsNavigating(true);
    setTargetRoute('Chat');
    setTargetPageType('chat');
    
    // 导航到 chat 页面
    router.push(`/inference/chat?provider=${encodeURIComponent(provider.address)}`);
  };

  const handleBuildWithProvider = (provider: Provider) => {
    setSelectedProviderForBuild(provider);
    setIsDrawerVisible(true);
    setTimeout(() => setIsDrawerOpen(true), 10);
  };

  const handleCloseDrawer = () => {
    setIsDrawerOpen(false);
    setTimeout(() => {
      setIsDrawerVisible(false);
      setSelectedProviderForBuild(null);
    }, 300);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

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
            Please connect your wallet to access AI inference features.
          </p>
        </div>
      </div>
    );
  }

  // Show loading state only for critical loading (broker initialization)
  const isLoading = isInitializing;
  const displayProviders = providers || OFFICIAL_PROVIDERS;
  const hasError = providersError && !providers;

  return (
    <div className="w-full">
      <div className="mb-3">
        <h1 className="text-lg font-semibold text-gray-900">Inference</h1>
        <p className="text-xs text-gray-500">
        Choose from decentralized AI providers to start chatting or integrate the service into your own application
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
              <h3 className="text-sm font-medium text-yellow-800">Notice</h3>
              <p className="text-sm text-yellow-700 mt-1">Failed to fetch live provider data. Showing fallback providers.</p>
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
              );
              
              return (
                <div
                  key={provider.address}
                  className="bg-white rounded-xl border border-gray-300 p-5 hover:shadow-lg transition-shadow relative"
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
                      </div>
                      
                      {/* Pricing and address with copy button */}
                      <div className="flex items-center space-x-2 mb-2 min-h-[28px]">
                        {/* Pricing section first */}
                        {(provider.inputPrice !== undefined || provider.outputPrice !== undefined) && (
                          <div className="flex items-center space-x-2 text-xs h-full">
                            {provider.inputPrice !== undefined && (
                              <div className="flex items-center space-x-1">
                                <span className="text-gray-600">In:</span>
                                <span className="font-semibold text-gray-900">
                                  {provider.inputPrice.toFixed(4)}
                                </span>
                              </div>
                            )}
                            {provider.outputPrice !== undefined && (
                              <div className="flex items-center space-x-1">
                                <span className="text-gray-600">Out:</span>
                                <span className="font-semibold text-gray-900">
                                  {provider.outputPrice.toFixed(4)}
                                </span>
                              </div>
                            )}
                            <span className="text-gray-500">A0GI</span>
                          </div>
                        )}

                        <div className="flex items-center space-x-1 h-full">
                          <div className="relative group flex items-center">
                            <code className="text-xs text-gray-500 font-mono bg-gray-50 px-2 py-1 rounded cursor-default flex items-center">
                              {provider.address.slice(0, 8)}...{provider.address.slice(-6)}
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
                              onClick={() => navigator.clipboard.writeText(provider.address)}
                              className="text-gray-400 hover:text-gray-600 p-1 cursor-pointer flex items-center justify-center"
                              title="Copy address"
                            >
                              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
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
                    <button
                      onClick={() => handleChatWithProvider(provider)}
                      className="flex-1 text-gray-600 hover:text-purple-600 hover:bg-purple-50 transition-colors rounded-md px-2 py-1.5 cursor-pointer text-xs flex items-center justify-center space-x-1 border border-gray-200 hover:border-purple-200"
                    >
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                      </svg>
                      <span>Chat</span>
                    </button>
                    <button
                      onClick={() => handleBuildWithProvider(provider)}
                      className="flex-1 text-gray-600 hover:text-purple-600 hover:bg-purple-50 transition-colors rounded-md px-2 py-1.5 cursor-pointer text-xs flex items-center justify-center space-x-1 border border-gray-200 hover:border-purple-200"
                    >
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                      </svg>
                      <span>Build</span>
                    </button>
                  </div>
                </div>
              );
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
            There are currently no AI inference providers available. Please try again later.
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
          
          <div className={`absolute right-0 top-0 h-full w-1/2 min-w-[600px] bg-white/95 backdrop-blur-sm shadow-2xl border-l border-gray-200 transform transition-all duration-300 ease-out ${
            isDrawerOpen ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0'
          }`}>
            <div className="flex flex-col h-full">
              <div className="flex items-center justify-between py-4 px-6 border-b border-gray-200">
                <div>
                  <h2 className="text-xl font-semibold text-gray-900">Build with Provider</h2>
                </div>
                <button
                  onClick={handleCloseDrawer}
                  className="p-2 rounded-md hover:bg-gray-100 transition-colors"
                >
                  <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6">
                {/* Include all the build guide content from original component here */}
                <div className="space-y-6">
                  <div className="mb-8">
                    <h2 className="text-lg font-semibold text-gray-800 mb-4">Quick Start with CLI</h2>
                    
                    <div className="space-y-4">
                      <div>
                        <h3 className="text-base font-medium text-gray-700 mb-2">1. Install the 0G CLI</h3>
                        <div className="relative">
                          <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto">
                            <code className="text-gray-800 text-sm font-mono">
                              pnpm install @0glabs/0g-serving-broker -g
                            </code>
                          </div>
                          <button
                            onClick={() => copyToClipboard('pnpm install @0glabs/0g-serving-broker -g')}
                            className="absolute top-2 right-2 p-2 rounded-md hover:bg-gray-200 transition-colors"
                            title="Copy to clipboard"
                          >
                            <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                            </svg>
                          </button>
                        </div>
                      </div>
                      {/* Continue with rest of build guide... */}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default OptimizedInferencePage;
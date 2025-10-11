"use client";

import React from 'react';
import type { Provider } from '../../../../shared/types/broker';
import { OFFICIAL_PROVIDERS } from '../../../../constants/providers';

interface ProviderSelectorProps {
  // Provider selection
  providers: Provider[];
  selectedProvider: Provider | null;
  onProviderSelect: (provider: Provider) => void;
  
  // UI state
  isDropdownOpen: boolean;
  setIsDropdownOpen: (open: boolean) => void;
  isInitializing: boolean;
  
  // Provider info
  providerBalance: number | null;
  providerBalanceNeuron: bigint | null;
  providerPendingRefund: number | null;
  
  // Actions
  onAddFunds: () => void;
}

export function ProviderSelector({
  providers,
  selectedProvider,
  onProviderSelect,
  isDropdownOpen,
  setIsDropdownOpen,
  isInitializing,
  providerBalance,
  providerBalanceNeuron,
  providerPendingRefund,
  onAddFunds,
}: ProviderSelectorProps) {
  return (
    <div className="flex items-center space-x-2 sm:space-x-4">
      {/* Provider Selection Dropdown */}
      <div className="relative min-w-[180px] sm:min-w-[300px] lg:min-w-[400px] provider-dropdown">
        <button
          onClick={() => setIsDropdownOpen(!isDropdownOpen)}
          className="w-full bg-white border border-gray-300 rounded-md pl-3 pr-10 py-3 text-left cursor-pointer focus:outline-none focus:ring-1 focus:ring-purple-500 focus:border-purple-500 text-sm"
          disabled={isInitializing || providers.length === 0}
        >
          {isInitializing ? (
            <span className="text-gray-500">Loading providers...</span>
          ) : providers.length === 0 ? (
            <span className="text-gray-500">
              No providers available
            </span>
          ) : selectedProvider ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="font-medium text-sm">
                  {selectedProvider.name}
                </span>
                <span className="text-gray-500">•</span>
                <span className="text-gray-600 text-xs">
                  {selectedProvider.address.slice(0, 8)}...
                  {selectedProvider.address.slice(-6)}
                </span>
                <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${
                  selectedProvider.verifiability?.toLowerCase().includes('teeml') || selectedProvider.verifiability?.toLowerCase().includes('tee')
                    ? 'bg-green-100 text-green-800'
                    : 'bg-purple-100 text-purple-800'
                }`}>
                  {selectedProvider.verifiability}
                </span>
                {OFFICIAL_PROVIDERS.some(
                  (op) => op.address === selectedProvider.address
                ) && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                    0G
                  </span>
                )}
              </div>
            </div>
          ) : (
            <span className="text-gray-500">Select a provider</span>
          )}
        </button>
        <div className="absolute inset-y-0 right-0 flex items-center px-2 pointer-events-none">
          <svg
            className={`h-4 w-4 text-gray-400 transition-transform ${
              isDropdownOpen ? "rotate-180" : ""
            }`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 9l-7 7-7-7"
            />
          </svg>
        </div>

        {/* Dropdown Menu */}
        {isDropdownOpen && providers.length > 0 && (
          <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
            {providers.map((provider) => (
              <div
                key={provider.address}
                onClick={() => {
                  onProviderSelect(provider);
                  setIsDropdownOpen(false);
                }}
                className="px-3 py-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100 last:border-b-0"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="font-medium text-sm">{provider.name}</span>
                    <span className="text-gray-500">•</span>
                    <span className="text-gray-600 text-xs">
                      {provider.address.slice(0, 8)}...
                      {provider.address.slice(-6)}
                    </span>
                    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${
                      provider.verifiability?.toLowerCase().includes('teeml') || provider.verifiability?.toLowerCase().includes('tee')
                        ? 'bg-green-100 text-green-800'
                        : 'bg-purple-100 text-purple-800'
                    }`}>
                      {provider.verifiability}
                    </span>
                    {OFFICIAL_PROVIDERS.some(
                      (op) => op.address === provider.address
                    ) && (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                        0G
                      </span>
                    )}
                  </div>
                </div>
                {provider.inputPrice !== undefined ||
                provider.outputPrice !== undefined ? (
                  <div className="mt-1 text-xs text-gray-500">
                    {provider.inputPrice !== undefined && (
                      <span>Input: {provider.inputPrice.toFixed(2)} A0GI/M</span>
                    )}
                    {provider.inputPrice !== undefined &&
                      provider.outputPrice !== undefined && (
                        <span className="mx-1">•</span>
                      )}
                    {provider.outputPrice !== undefined && (
                      <span>Output: {provider.outputPrice.toFixed(2)} A0GI/M</span>
                    )}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Provider Info Bar - Redesigned */}
      {selectedProvider && (
        <div className="flex items-center gap-2">
          {/* Left Section: Provider Status and Address */}
          <div className="flex items-center gap-2 flex-1">
            {/* Verification Status */}
            {selectedProvider.verifiability?.toLowerCase().includes('teeml') || selectedProvider.verifiability?.toLowerCase().includes('tee') ? (
              <div className="flex items-center gap-1">
                <svg className="w-3.5 h-3.5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span className="text-xs font-medium text-green-700">TEE Verified</span>
              </div>
            ) : (
              <div className="flex items-center gap-1">
                <svg className="w-3.5 h-3.5 text-purple-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
                <span className="text-xs font-medium text-purple-700">Standard</span>
              </div>
            )}
            
            {/* Provider Address with Copy */}
            <div className="flex items-center gap-1">
              <span className="text-xs text-gray-500 font-mono">
                {selectedProvider.address.slice(0, 6)}...{selectedProvider.address.slice(-4)}
              </span>
              <div className="relative group">
                <button
                  onClick={() => navigator.clipboard.writeText(selectedProvider.address)}
                  className="p-1 rounded hover:bg-gray-200 transition-colors cursor-pointer"
                >
                <svg
                  className="w-3 h-3 text-gray-400 hover:text-gray-600"
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
                {/* Copy Tooltip */}
                <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-20 whitespace-nowrap">
                  Copy address
                </div>
              </div>
            </div>
          </div>
          {/* Center Section: Price Info */}
          {(selectedProvider.inputPrice !== undefined ||
            selectedProvider.outputPrice !== undefined) && (
            <div className="relative group">
              <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-white border border-gray-200">
                <svg
                  className="w-3.5 h-3.5 text-gray-500"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1"
                  />
                </svg>
                <span className="text-xs font-medium text-gray-700">
                  {selectedProvider.inputPrice !== undefined && (
                    <span>{selectedProvider.inputPrice.toFixed(2)}</span>
                  )}
                  {selectedProvider.inputPrice !== undefined &&
                    selectedProvider.outputPrice !== undefined && (
                      <span className="mx-0.5">/</span>
                    )}
                  {selectedProvider.outputPrice !== undefined && (
                    <span>{selectedProvider.outputPrice.toFixed(2)}</span>
                  )}
                  <span className="ml-1 text-gray-500">A0GI/M</span>
                </span>
              </div>
              {/* Price Tooltip */}
              <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-20 whitespace-nowrap">
                <div className="font-semibold mb-1">Price per Million Tokens</div>
                {selectedProvider.inputPrice !== undefined && (
                  <div>Input: {selectedProvider.inputPrice.toFixed(2)} A0GI</div>
                )}
                {selectedProvider.outputPrice !== undefined && (
                  <div>Output: {selectedProvider.outputPrice.toFixed(2)} A0GI</div>
                )}
                <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
                  <div className="w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
                </div>
              </div>
            </div>
          )}
          {/* Right Section: Balance */}
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-md">
            <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md ${
              (providerBalanceNeuron !== null && providerBalanceNeuron === BigInt(0)) || (providerBalance ?? 0) === 0
                ? 'bg-red-50 border-red-200'
                : providerBalanceNeuron !== null &&
                  selectedProvider.inputPriceNeuron !== undefined && 
                  selectedProvider.outputPriceNeuron !== undefined && 
                  providerBalanceNeuron <= BigInt(50000) * (selectedProvider.inputPriceNeuron + selectedProvider.outputPriceNeuron)
                ? 'bg-yellow-50 border-yellow-200'
                : 'bg-white border-gray-200'
            }`}>
              {(providerBalanceNeuron !== null && providerBalanceNeuron === BigInt(0)) || (providerBalance ?? 0) === 0 ? (
                <svg 
                  className="w-3.5 h-3.5 text-red-500" 
                  fill="currentColor" 
                  viewBox="0 0 20 20"
                >
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              ) : providerBalanceNeuron !== null &&
                selectedProvider.inputPriceNeuron !== undefined && 
                selectedProvider.outputPriceNeuron !== undefined && 
                providerBalanceNeuron <= BigInt(50000) * (selectedProvider.inputPriceNeuron + selectedProvider.outputPriceNeuron) ? (
                <svg 
                  className="w-3.5 h-3.5 text-yellow-500" 
                  fill="currentColor" 
                  viewBox="0 0 20 20"
                >
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              ) : (
                <svg className="w-3.5 h-3.5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1" />
                </svg>
              )}
              <span className={`text-xs font-medium ${
                (providerBalanceNeuron !== null && providerBalanceNeuron === BigInt(0)) || (providerBalance ?? 0) === 0
                  ? 'text-red-700'
                  : providerBalanceNeuron !== null &&
                    selectedProvider.inputPriceNeuron !== undefined && 
                    selectedProvider.outputPriceNeuron !== undefined && 
                    providerBalanceNeuron <= BigInt(50000) * (selectedProvider.inputPriceNeuron + selectedProvider.outputPriceNeuron)
                  ? 'text-yellow-700'
                  : 'text-gray-700'
              }`}>
                {providerBalance !== null ? (
                  <>
                    {providerBalance.toFixed(4)} A0GI
                    {providerPendingRefund !== null && providerPendingRefund > 0 && (
                      <span className="text-orange-600"> (+{providerPendingRefund.toFixed(4)} pending)</span>
                    )}
                  </>
                ) : (
                  'Loading...'
                )}
              </span>
            </div>
            <button
              onClick={onAddFunds}
              className={`flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium transition-colors ${
                (providerBalanceNeuron !== null && providerBalanceNeuron === BigInt(0)) || (providerBalance ?? 0) === 0
                  ? 'bg-red-500 text-white hover:bg-red-600 shadow-md animate-pulse'
                  : providerBalanceNeuron !== null &&
                    selectedProvider.inputPriceNeuron !== undefined && 
                    selectedProvider.outputPriceNeuron !== undefined && 
                    providerBalanceNeuron <= BigInt(50000) * (selectedProvider.inputPriceNeuron + selectedProvider.outputPriceNeuron)
                  ? 'bg-yellow-500 text-white hover:bg-yellow-600'
                  : 'bg-purple-500 text-white hover:bg-purple-600'
              } ${
                (providerBalanceNeuron !== null && providerBalanceNeuron === BigInt(0)) || (providerBalance ?? 0) === 0
                  ? ''
                  : ''
              }`}
            >
            <svg
              className="w-3.5 h-3.5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2.5}
                d="M12 4v16m8-8H4"
              />
            </svg>
            <span>Add Funds</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
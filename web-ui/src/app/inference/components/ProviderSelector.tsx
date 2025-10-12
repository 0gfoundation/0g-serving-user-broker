import React, { useState, useRef, useEffect } from 'react';
import type { Provider } from '../../../shared/types/broker';
import { formatBalance } from '../../../shared/utils/currency';

interface ProviderSelectorProps {
  providers: Provider[];
  selectedProvider: Provider | null;
  onProviderSelect: (provider: Provider) => void;
  isLoading?: boolean;
  isStreaming?: boolean;
}

export const ProviderSelector: React.FC<ProviderSelectorProps> = ({
  providers,
  selectedProvider,
  onProviderSelect,
  isLoading = false,
  isStreaming = false,
}) => {
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false);
      }
    };

    if (isDropdownOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [isDropdownOpen]);

  const handleProviderSelect = (provider: Provider) => {
    onProviderSelect(provider);
    setIsDropdownOpen(false);
  };

  const disabled = isLoading || isStreaming;

  return (
    <div className="relative mb-4" ref={dropdownRef}>
      <button
        onClick={() => !disabled && setIsDropdownOpen(!isDropdownOpen)}
        disabled={disabled}
        className={`w-full p-3 border border-gray-300 rounded-lg text-left flex items-center justify-between ${
          disabled
            ? "bg-gray-100 text-gray-400 cursor-not-allowed"
            : "bg-white hover:border-gray-400 focus:outline-none focus:ring-1 focus:ring-purple-500"
        }`}
      >
        <div className="flex-1 min-w-0">
          {selectedProvider ? (
            <div>
              <div className="font-medium text-gray-900 truncate">
                {selectedProvider.name}
              </div>
              <div className="text-xs text-gray-500 mt-0.5 flex items-center space-x-4">
                <span>{selectedProvider.model.includes('/') ? selectedProvider.model.split('/').slice(1).join('/') : selectedProvider.model}</span>
                <span className="flex items-center space-x-1">
                  <span>🔒</span>
                  <span>{selectedProvider.verifiability}</span>
                </span>
                {selectedProvider.inputPrice && selectedProvider.outputPrice && (
                  <span className="text-green-600 font-medium">
                    {formatBalance(selectedProvider.inputPrice)}/
                    {formatBalance(selectedProvider.outputPrice)} A0GI per 1M tokens
                  </span>
                )}
              </div>
            </div>
          ) : (
            <div className="text-gray-500">Select a provider...</div>
          )}
        </div>
        
        <div className="flex items-center ml-2">
          {disabled && (
            <div className="animate-spin rounded-full h-4 w-4 border-2 border-gray-300 border-t-purple-600 mr-2"></div>
          )}
          <svg
            className={`w-4 h-4 text-gray-400 transition-transform ${
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
      </button>

      {isDropdownOpen && !disabled && (
        <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-gray-300 rounded-lg shadow-lg z-50 max-h-60 overflow-y-auto">
          {providers.length === 0 ? (
            <div className="p-4 text-center text-gray-500">
              No providers available
            </div>
          ) : (
            providers.map((provider) => (
              <button
                key={provider.address}
                onClick={() => handleProviderSelect(provider)}
                className={`w-full p-3 text-left hover:bg-gray-50 border-b border-gray-100 last:border-b-0 ${
                  selectedProvider?.address === provider.address
                    ? "bg-purple-50"
                    : ""
                }`}
              >
                <div className="font-medium text-gray-900">
                  {provider.name}
                </div>
                <div className="text-xs text-gray-500 mt-0.5 space-y-1">
                  <div className="flex items-center space-x-4">
                    <span>Model: {provider.model.includes('/') ? provider.model.split('/').slice(1).join('/') : provider.model}</span>
                    <span className="flex items-center space-x-1">
                      <span>🔒</span>
                      <span>{provider.verifiability}</span>
                    </span>
                  </div>
                  <div className="text-gray-600">
                    Address: {provider.address.slice(0, 8)}...{provider.address.slice(-6)}
                  </div>
                  {provider.inputPrice && provider.outputPrice && (
                    <div className="text-green-600 font-medium">
                      Cost: {formatBalance(provider.inputPrice)}/
                      {formatBalance(provider.outputPrice)} A0GI per 1M tokens
                    </div>
                  )}
                </div>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
};
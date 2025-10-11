import { useState, useCallback } from 'react';
import type { Provider } from "../../../shared/types/broker";

interface ServiceMetadata {
  endpoint: string;
  model: string;
}

interface UseProviderStateReturn {
  // Provider selection
  providers: Provider[];
  setProviders: (providers: Provider[]) => void;
  selectedProvider: Provider | null;
  setSelectedProvider: (provider: Provider | null) => void;
  
  // Service metadata
  serviceMetadata: ServiceMetadata | null;
  setServiceMetadata: (metadata: ServiceMetadata | null) => void;
  
  // Provider verification
  providerAcknowledged: boolean | null;
  setProviderAcknowledged: (acknowledged: boolean | null) => void;
  isVerifyingProvider: boolean;
  setIsVerifyingProvider: (verifying: boolean) => void;
  
  // Provider balance
  providerBalance: number | null;
  setProviderBalance: (balance: number | null) => void;
  providerBalanceNeuron: bigint | null;
  setProviderBalanceNeuron: (balance: bigint | null) => void;
  providerPendingRefund: number | null;
  setProviderPendingRefund: (refund: number | null) => void;
  
  // Dropdown state
  isDropdownOpen: boolean;
  setIsDropdownOpen: (open: boolean) => void;
  
  // Utility functions
  resetProviderState: () => void;
  updateProviderBalance: (balance: number | null, balanceNeuron: bigint | null) => void;
}

export function useProviderState(): UseProviderStateReturn {
  // Provider selection state
  const [providers, setProviders] = useState<Provider[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<Provider | null>(null);
  
  // Service metadata state
  const [serviceMetadata, setServiceMetadata] = useState<ServiceMetadata | null>(null);
  
  // Provider verification state
  const [providerAcknowledged, setProviderAcknowledged] = useState<boolean | null>(null);
  const [isVerifyingProvider, setIsVerifyingProvider] = useState(false);
  
  // Provider balance state
  const [providerBalance, setProviderBalance] = useState<number | null>(null);
  const [providerBalanceNeuron, setProviderBalanceNeuron] = useState<bigint | null>(null);
  const [providerPendingRefund, setProviderPendingRefund] = useState<number | null>(null);
  
  // UI state
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  
  // Utility functions
  const resetProviderState = useCallback(() => {
    setSelectedProvider(null);
    setServiceMetadata(null);
    setProviderAcknowledged(null);
    setIsVerifyingProvider(false);
    setProviderBalance(null);
    setProviderBalanceNeuron(null);
    setProviderPendingRefund(null);
    setIsDropdownOpen(false);
  }, []);

  const updateProviderBalance = useCallback((balance: number | null, balanceNeuron: bigint | null) => {
    setProviderBalance(balance);
    setProviderBalanceNeuron(balanceNeuron);
  }, []);

  return {
    // Provider selection
    providers,
    setProviders,
    selectedProvider,
    setSelectedProvider,
    
    // Service metadata
    serviceMetadata,
    setServiceMetadata,
    
    // Provider verification
    providerAcknowledged,
    setProviderAcknowledged,
    isVerifyingProvider,
    setIsVerifyingProvider,
    
    // Provider balance
    providerBalance,
    setProviderBalance,
    providerBalanceNeuron,
    setProviderBalanceNeuron,
    providerPendingRefund,
    setProviderPendingRefund,
    
    // Dropdown state
    isDropdownOpen,
    setIsDropdownOpen,
    
    // Utility functions
    resetProviderState,
    updateProviderBalance,
  };
}
import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { transformBrokerServicesToProviders } from '../utils/providerTransform';
import { neuronToA0gi } from '../../../shared/utils/currency';
import type { Provider } from '../../../shared/types/broker';

interface ServiceMetadata {
  endpoint: string;
  model: string;
}

interface ProviderManagementState {
  providers: Provider[];
  selectedProvider: Provider | null;
  serviceMetadata: ServiceMetadata | null;
  providerAcknowledged: boolean | null;
  isVerifyingProvider: boolean;
  providerBalance: number | null;
  providerBalanceNeuron: bigint | null;
  providerPendingRefund: number | null;
  isInitializing: boolean;
}

interface ProviderManagementActions {
  setSelectedProvider: (provider: Provider | null) => void;
  verifyProvider: () => Promise<void>;
  refreshProviderBalance: () => Promise<void>;
}

export function useProviderManagement(
  broker: any, // TODO: Replace with proper broker type when available
  refreshLedgerInfo: () => Promise<void>,
  showTutorial: boolean,
  tutorialStep: 'verify' | 'top-up' | null,
  setShowTutorial: (show: boolean) => void,
  setTutorialStep: (step: 'verify' | 'top-up' | null) => void,
  setErrorWithTimeout: (error: string | null) => void
): ProviderManagementState & ProviderManagementActions {
  const searchParams = useSearchParams();
  
  // Provider state
  const [providers, setProviders] = useState<Provider[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<Provider | null>(null);
  const [serviceMetadata, setServiceMetadata] = useState<ServiceMetadata | null>(null);
  const [providerAcknowledged, setProviderAcknowledged] = useState<boolean | null>(null);
  const [isVerifyingProvider, setIsVerifyingProvider] = useState(false);
  const [providerBalance, setProviderBalance] = useState<number | null>(null);
  const [providerBalanceNeuron, setProviderBalanceNeuron] = useState<bigint | null>(null);
  const [providerPendingRefund, setProviderPendingRefund] = useState<number | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  
  // Fetch providers list
  useEffect(() => {
    const fetchProviders = async () => {
      if (broker) {
        try {
          // Use the broker to get real service list
          const services = await broker.inference.listService();

          // Transform services to Provider format
          const transformedProviders = transformBrokerServicesToProviders(services);

          setProviders(transformedProviders);

          // Check for provider parameter from URL
          const providerParam = searchParams.get('provider');
          
          if (providerParam && !selectedProvider) {
            // Try to find the provider by address
            const targetProvider = transformedProviders.find(
              p => p.address.toLowerCase() === providerParam.toLowerCase()
            );
            if (targetProvider) {
              setSelectedProvider(targetProvider);
            } else if (transformedProviders.length > 0) {
              // Fallback to first provider if specified provider not found
              setSelectedProvider(transformedProviders[0]);
            }
          } else if (!selectedProvider && transformedProviders.length > 0) {
            // Set the first provider as selected if none is selected
            setSelectedProvider(transformedProviders[0]);
          }
        } catch (err: unknown) {
          console.log('Failed to fetch providers from broker:', err);
          // Fallback to empty array
          setProviders([]);
          setSelectedProvider(null);
        }
      }
    };

    fetchProviders();
    setIsInitializing(false);
  }, [broker, selectedProvider, searchParams]);
  
  // Fetch service metadata when provider changes
  useEffect(() => {
    const fetchServiceMetadata = async () => {
      if (broker && selectedProvider) {
        try {
          // Step 5.1: Get the request metadata
          const metadata = await broker.inference.getServiceMetadata(
            selectedProvider.address
          );
          if (metadata?.endpoint && metadata?.model) {
            setServiceMetadata({
              endpoint: metadata.endpoint,
              model: metadata.model
            });
          } else {
            setServiceMetadata(null);
          }
        } catch (err: unknown) {
          setServiceMetadata(null);
        }
      }
    };

    fetchServiceMetadata();
  }, [broker, selectedProvider]);

  // Fetch provider acknowledgment status when provider is selected
  useEffect(() => {
    const fetchProviderAcknowledgment = async () => {
      if (broker && selectedProvider) {
        try {
          const acknowledged = await broker.inference.userAcknowledged(
            selectedProvider.address
          );
          setProviderAcknowledged(acknowledged);
          
          // Check if we should show tutorial
          const tutorialKey = `tutorial_seen_${selectedProvider.address}`;
          if (!localStorage.getItem(tutorialKey) && showTutorial) {
            // If provider is already acknowledged, skip to top-up step
            if (acknowledged) {
              setTutorialStep('top-up');
            }
          }
        } catch (err: unknown) {
          setProviderAcknowledged(false);
        }
      }
    };

    fetchProviderAcknowledgment();
  }, [broker, selectedProvider, showTutorial, setTutorialStep]);

  // Fetch provider balance
  const refreshProviderBalance = async () => {
    if (broker && selectedProvider) {
      try {
        const account = await broker.inference.getAccount(selectedProvider.address);
        if (account && account.balance) {
          const balanceInA0gi = neuronToA0gi(BigInt(account.balance) - BigInt(account.pendingRefund));
          const pendingRefundInA0gi = neuronToA0gi(account.pendingRefund);
          setProviderBalance(balanceInA0gi);
          setProviderBalanceNeuron(account.balance);
          setProviderPendingRefund(pendingRefundInA0gi);
        } else {
          setProviderBalance(0);
          setProviderBalanceNeuron(BigInt(0));
          setProviderPendingRefund(0);
        }
      } catch (err: unknown) {
        setProviderBalance(null);
        setProviderBalanceNeuron(null);
        setProviderPendingRefund(null);
      }
    } else if (!selectedProvider) {
      // Reset balance states when no provider is selected
      setProviderBalance(null);
      setProviderBalanceNeuron(null);
      setProviderPendingRefund(null);
    }
  };
  
  // Only fetch balance when provider is acknowledged
  useEffect(() => {
    if (providerAcknowledged === true) {
      refreshProviderBalance();
    } else if (providerAcknowledged === false) {
      // Reset balance states when provider is not acknowledged
      setProviderBalance(null);
      setProviderBalanceNeuron(null);
      setProviderPendingRefund(null);
    }
  }, [broker, selectedProvider, providerAcknowledged]);

  // Initialize tutorial when provider changes
  useEffect(() => {
    if (selectedProvider) {
      const tutorialKey = `tutorial_seen_${selectedProvider.address}`;
      const hasSeenTutorial = localStorage.getItem(tutorialKey);
      
      
      if (!hasSeenTutorial) {
        // Small delay to ensure UI is ready
        const timer = setTimeout(() => {
          setShowTutorial(true);
          if (providerAcknowledged === true) {
            setTutorialStep('top-up');
          } else {
            setTutorialStep('verify');
          }
        }, 800);
        
        return () => clearTimeout(timer);
      }
    }
  }, [selectedProvider, providerAcknowledged, setTutorialStep]);
  
  // Verify provider
  const verifyProvider = async () => {
    if (!broker || !selectedProvider) {
      return;
    }

    setIsVerifyingProvider(true);
    setErrorWithTimeout(null);

    try {
      await broker.inference.acknowledgeProviderSigner(
        selectedProvider.address
      );

      // Refresh the acknowledgment status
      const acknowledged = await broker.inference.userAcknowledged(
        selectedProvider.address
      );
      setProviderAcknowledged(acknowledged);

      // Refresh ledger info and provider balance after successful verification
      if (acknowledged) {
        await Promise.all([
          refreshLedgerInfo(),
          refreshProviderBalance()  // Explicitly refresh balance after verification
        ]);
      }
      
      // Progress tutorial to top-up step if tutorial is active
      if (showTutorial && tutorialStep === 'verify' && acknowledged) {
        setTutorialStep('top-up');
      }
    } catch (err: unknown) {
      const errorMessage =
        err instanceof Error ? err.message : "Provider verification failed";
      setErrorWithTimeout(errorMessage);
      setProviderAcknowledged(false);
    } finally {
      setIsVerifyingProvider(false);
    }
  };

  return {
    // State
    providers,
    selectedProvider,
    serviceMetadata,
    providerAcknowledged,
    isVerifyingProvider,
    providerBalance,
    providerBalanceNeuron,
    providerPendingRefund,
    isInitializing,
    // Actions
    setSelectedProvider,
    verifyProvider,
    refreshProviderBalance,
  };
}
"use client";

import React, { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import { useAccount, useDisconnect, useChainId } from "wagmi";
import { Sidebar } from "./Sidebar";
import { use0GBroker } from "../../hooks/use0GBroker";
import { NavigationProvider, useNavigation } from "../navigation/OptimizedNavigation";
import SimpleLoader from "../ui/SimpleLoader";

interface LayoutContentProps {
  children: React.ReactNode;
}

const MainContentArea: React.FC<{ children: React.ReactNode; isHomePage: boolean }> = ({ 
  children, 
  isHomePage 
}) => {
  const { isNavigating, targetRoute } = useNavigation();

  if (isNavigating) {
    return (
      <main className="p-4">
        <SimpleLoader message={`Loading ${targetRoute || 'page'}...`} />
      </main>
    );
  }

  return (
    <main className="p-4">
      {isHomePage ? (
        <div className="container mx-auto px-4 py-8">{children}</div>
      ) : (
        children
      )}
    </main>
  );
};

export const LayoutContent: React.FC<LayoutContentProps> = ({ children }) => {
  const pathname = usePathname();
  const isHomePage = pathname === "/";
  const { isConnected, address } = useAccount();
  const { disconnect } = useDisconnect();
  const chainId = useChainId();
  const { broker, isInitializing, error: brokerError } = use0GBroker();
  
  const [showDepositModal, setShowDepositModal] = useState(false);
  const [showTopUpModal, setShowTopUpModal] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const checkLedger = async () => {
      if (broker && isConnected && !isHomePage) {
        try {
          const ledger = await broker.ledger.getLedger();
          // If we get here, it means ledger exists and has data
          // Check if the balance is valid (totalBalance > 0 indicates a real ledger)
          if (!ledger || ledger.totalBalance === BigInt(0)) {
            setShowDepositModal(true);
          } else {
            // Ledger exists and has balance, hide modal
            setShowDepositModal(false);
          }
        } catch (error) {
          // If error occurs (e.g., ledger does not exist), prompt for deposit
          setShowDepositModal(true);
        }
      }
    };
    
    checkLedger();
  }, [broker, isConnected, isHomePage, chainId]); // Added chainId to dependencies

  // Clear modals and errors when wallet is disconnected
  useEffect(() => {
    if (!isConnected) {
      setShowDepositModal(false);
      setShowTopUpModal(false);
      setError(null);
    }
  }, [isConnected]);

  // Reset state when network changes to ensure clean state for new network
  useEffect(() => {
    if (isConnected) {
      setError(null);
      setIsLoading(false);
      // Note: Don't close modals here immediately as checkLedger effect will handle it
      // This just ensures we have clean error/loading state for the new network
    }
  }, [chainId, isConnected]);

  const handleCreateAccount = async () => {
    if (!broker) return;
    
    setIsLoading(true);
    setError(null);
    try {
      await broker.ledger.addLedger(0);
      setShowDepositModal(false);
      setShowTopUpModal(true);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to create account. Please try again.';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeposit = async (amount: number) => {
    if (!broker) return;
    
    setIsLoading(true);
    setError(null);
    try {
      await broker.ledger.depositFund(amount);
      setShowTopUpModal(false);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to deposit funds. Please try again.';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSkipDeposit = () => {
    setShowTopUpModal(false);
  };

  const handleDisconnectWallet = () => {
    disconnect();
    setError(null);
    setShowDepositModal(false);
    setShowTopUpModal(false);
  };

  const handleCopyAddress = async () => {
    if (!address) return;
    
    try {
      await navigator.clipboard.writeText(address);
      // Optional: You could add a toast notification here
    } catch {
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = address;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    }
  };

  const formatAddress = (addr: string) => {
    return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
  };

  return (
    <NavigationProvider>
      <div className={`min-h-screen bg-gray-50 ${isHomePage ? "pt-20" : "pl-52 pt-20"}`}>
        {isHomePage ? null : <Sidebar />}
        <MainContentArea isHomePage={isHomePage}>
          {children}
        </MainContentArea>
      </div>

      {/* Global Account Creation Modal */}
      {showDepositModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-10 p-4">
          <div className="bg-white rounded-2xl shadow-xl p-6 w-80">
            <div className="text-center mb-4">
              <h3 className="text-lg font-medium text-gray-900 mb-2 whitespace-nowrap">
                Create Your Account
              </h3>
            </div>

            {/* Wallet Info */}
            {address && (
              <div className="mb-6">
                <div className="text-center">
                  <div className="text-sm font-mono text-gray-900 mb-4">{formatAddress(address)}</div>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={handleCopyAddress}
                    className="flex-1 px-2 py-2 text-xs font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors flex items-center justify-center whitespace-nowrap"
                  >
                    Copy Address
                  </button>
                  <button
                    onClick={handleDisconnectWallet}
                    className="flex-1 px-2 py-2 text-xs font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors flex items-center justify-center whitespace-nowrap"
                  >
                    Disconnect
                  </button>
                </div>
              </div>
            )}

            {/* Error Display */}
            {error && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-start">
                  <svg className="w-4 h-4 text-red-400 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <h4 className="text-xs font-medium text-red-800 mb-1">Account Creation Failed</h4>
                    <p className="text-xs text-red-700">{error}</p>
                  </div>
                </div>
              </div>
            )}

            <button
              onClick={handleCreateAccount}
              disabled={isLoading}
              className="w-full px-4 py-3 bg-purple-600 text-white text-sm font-medium rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center"
            >
              {isLoading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2"></div>
                  Creating Account...
                </>
              ) : error ? (
                "Retry Creating Account"
              ) : (
                "Create My Account"
              )}
            </button>
          </div>
        </div>
      )}

      {/* Top-up Modal - Step 2 */}
      {showTopUpModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-10 p-4">
          <div className="bg-white rounded-2xl shadow-xl p-6 w-80">
            <div className="text-center mb-6">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                Account Created Successfully!
              </h3>
              <p className="text-gray-600 text-sm">
                Would you like to add some funds to your account now?
              </p>
            </div>

            {/* Error Display for Top-up */}
            {error && (
              <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-start">
                  <svg className="w-5 h-5 text-red-400 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <h4 className="text-sm font-medium text-red-800 mb-1">Deposit Failed</h4>
                    <p className="text-sm text-red-700">{error}</p>
                  </div>
                </div>
              </div>
            )}

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={() => handleDeposit(0.1)}
                  disabled={isLoading}
                  className="px-4 py-3 bg-purple-600 text-white text-sm font-medium rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isLoading ? "Adding..." : "0.1 A0GI"}
                </button>
                <button
                  onClick={() => handleDeposit(1)}
                  disabled={isLoading}
                  className="px-4 py-3 bg-purple-600 text-white text-sm font-medium rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isLoading ? "Adding..." : "1 A0GI"}
                </button>
                <button
                  onClick={() => handleDeposit(5)}
                  disabled={isLoading}
                  className="px-4 py-3 bg-purple-600 text-white text-sm font-medium rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isLoading ? "Adding..." : "5 A0GI"}
                </button>
                <button
                  onClick={() => handleDeposit(10)}
                  disabled={isLoading}
                  className="px-4 py-3 bg-purple-600 text-white text-sm font-medium rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isLoading ? "Adding..." : "10 A0GI"}
                </button>
              </div>
              
              <button
                onClick={handleSkipDeposit}
                disabled={isLoading}
                className="w-full px-4 py-3 bg-gray-100 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Skip for Now
              </button>
            </div>
          </div>
        </div>
      )}
    </NavigationProvider>
  );
};

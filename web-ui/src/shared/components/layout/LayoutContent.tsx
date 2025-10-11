"use client";

import React, { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import { useAccount } from "wagmi";
import { Sidebar } from "./Sidebar";
import { use0GBroker } from "../../../hooks/use0GBroker";
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
  const { isConnected } = useAccount();
  const { broker } = use0GBroker();
  
  const [showDepositModal, setShowDepositModal] = useState(false);
  const [showTopUpModal, setShowTopUpModal] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const checkLedger = async () => {
      if (broker && isConnected && !isHomePage) {
        try {
          const ledger = await broker.ledger.getLedger();
          if (!ledger) {
            setShowDepositModal(true);
          }
        } catch (err: unknown) {
          setShowDepositModal(true);
        }
      }
    };
    checkLedger();
  }, [broker, isConnected, isHomePage]);

  const handleCreateAccount = async () => {
    if (!broker) return;
    
    setIsLoading(true);
    try {
      await broker.ledger.addLedger(0);
      setShowDepositModal(false);
      setShowTopUpModal(true);
    } catch (err: unknown) {
      // Keep modal open on error
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeposit = async (amount: number) => {
    if (!broker) return;
    
    setIsLoading(true);
    try {
      await broker.ledger.depositFund(amount);
      setShowTopUpModal(false);
    } catch (err: unknown) {
      // Keep modal open on error
    } finally {
      setIsLoading(false);
    }
  };

  const handleSkipDeposit = () => {
    setShowTopUpModal(false);
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
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-2xl p-8 max-w-md w-full mx-4">
            <div className="text-center mb-6">
              <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                Create Your Account
              </h3>
              <p className="text-gray-600 text-sm">
                Welcome to 0G Compute Network! Create your account to get started.
              </p>
            </div>

            <div className="space-y-4">
              <button
                onClick={handleCreateAccount}
                disabled={isLoading}
                className="w-full px-6 py-4 bg-purple-600 text-white text-lg font-medium rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center"
              >
                {isLoading ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent mr-2"></div>
                    Creating Account...
                  </>
                ) : (
                  "Create My Account"
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Top-up Modal - Step 2 */}
      {showTopUpModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-2xl p-8 max-w-md w-full mx-4">
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

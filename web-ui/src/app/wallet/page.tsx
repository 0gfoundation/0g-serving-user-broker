"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useAccount } from 'wagmi';
import { use0GBroker } from '../../shared/hooks/use0GBroker';
import { useSearchParams } from 'next/navigation';

function LedgerContent() {
  const { isConnected } = useAccount();
  const searchParams = useSearchParams();
  const {
    broker,
    isInitializing,
    error: brokerError,
    ledgerInfo,
    refreshLedgerInfo,
    addLedger: createLedger,
    depositFund,
  } = use0GBroker();
  
  const [addAmount, setAddAmount] = useState("");
  const [isAdding, setIsAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'detail'>('overview');
  const [isLockedExpanded, setIsLockedExpanded] = useState(false);
  const [expandedRefunds, setExpandedRefunds] = useState<{[key: string]: boolean}>({});
  const [refundDetails, setRefundDetails] = useState<{[key: string]: {amount: bigint, remainTime: bigint}[]}>({});
  const [loadingRefunds, setLoadingRefunds] = useState<{[key: string]: boolean}>({});
  const [isRetrieving, setIsRetrieving] = useState<{[key: string]: boolean}>({});
  const [isRetrievingAll, setIsRetrievingAll] = useState(false);
  const [showSuccessAlert, setShowSuccessAlert] = useState<{message: string, show: boolean}>({message: '', show: false});
  const [showWithdrawModal, setShowWithdrawModal] = useState(false);
  const [withdrawAmount, setWithdrawAmount] = useState("");

  // Handle tab parameter from URL
  useEffect(() => {
    const tab = searchParams.get('tab');
    if (tab === 'transactions') {
      setActiveTab('detail');
    } else {
      setActiveTab('overview');
    }
  }, [searchParams]);

  // Auto-refresh ledger info when component mounts and when wallet connection changes
  useEffect(() => {
    if (isConnected && refreshLedgerInfo) {
      refreshLedgerInfo();
    }
  }, [isConnected, refreshLedgerInfo]);

  // Helper function to format numbers and avoid scientific notation
  const formatNumber = (value: string | number) => {
    if (!value || value === "0" || value === 0) return "0";
    const num = parseFloat(value.toString());
    if (isNaN(num)) return "0";
    
    // Convert to string to avoid scientific notation
    // This preserves all significant digits
    return num.toLocaleString('en-US', {
      useGrouping: false,
      minimumFractionDigits: 0,
      maximumFractionDigits: 20
    });
  };

  // Helper function to format time from seconds
  const formatTime = (totalSeconds: number) => {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const secs = totalSeconds % 60;
    return `${hours}h ${minutes}min ${secs}s`;
  };

  // Function to fetch refund details
  const fetchRefundDetails = async (provider: string, type: 'inference' | 'fine-tuning') => {
    if (!broker) return;
    
    const key = `${type}-${provider}`;
    setLoadingRefunds(prev => ({ ...prev, [key]: true }));
    
    try {
      let refunds: {amount: bigint, remainTime: bigint}[] = [];
      
      if (type === 'inference') {
        const [, refundData] = await broker.inference.getAccountWithDetail(provider);
        refunds = refundData;
      } else {
        if (!broker.fineTuning) {
          throw new Error('Fine-tuning broker is not available');
        }
        const { refunds: refundData } = await broker.fineTuning.getAccountWithDetail(provider);
        refunds = refundData;
      }
      
      setRefundDetails(prev => ({ ...prev, [key]: refunds }));
    } catch {
      // Silently handle refund details fetching errors
    } finally {
      setLoadingRefunds(prev => ({ ...prev, [key]: false }));
    }
  };

  // Function to toggle refund details expansion
  const toggleRefundDetails = async (provider: string, type: 'inference' | 'fine-tuning') => {
    const key = `${type}-${provider}`;
    const isCurrentlyExpanded = expandedRefunds[key];
    
    if (!isCurrentlyExpanded && !refundDetails[key]) {
      await fetchRefundDetails(provider, type);
    }
    
    setExpandedRefunds(prev => ({ ...prev, [key]: !isCurrentlyExpanded }));
  };

  // Use real ledger info if available, otherwise show placeholder
  const displayLedgerInfo = ledgerInfo || {
    totalBalance: "0.000000",
    availableBalance: "0.000000",
    locked: "0.000000",
    inferences: [],
    fineTunings: [],
  };

  const handleAddFunds = async () => {
    if (!addAmount || !broker) return;
    
    setIsAdding(true);
    setError(null);
    
    try {
      const amount = parseFloat(addAmount);
      
      // Use depositFund which now handles both creation and deposit intelligently
      await depositFund(amount);
      alert(`Successfully added ${addAmount} A0GI tokens to your account!`);
      
      setAddAmount("");
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to add funds';
      setError(errorMessage);
    } finally {
      setIsAdding(false);
    }
  };

  const handleRefund = async () => {
    if (!broker) return;
    
    setIsAdding(true);
    setError(null);
    
    try {
      // Check if broker has a refund method, otherwise show a placeholder message
      if (typeof broker.ledger.refund === 'function') {
        const availableAmount = parseFloat(displayLedgerInfo.availableBalance);
        if (availableAmount > 0) {
          await broker.ledger.refund(availableAmount);
          alert('Successfully refunded available balance!');
          await refreshLedgerInfo();
        }
      } else {
        // Placeholder for refund functionality
        alert('Refund functionality will be implemented when the broker supports it.');
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to refund';
      setError(errorMessage);
    } finally {
      setIsAdding(false);
    }
  };

  if (!isConnected) {
    return (
      <div className="w-full">
        <div className="bg-[#F6F6F6] border border-[#E5E5E5] rounded-2xl p-8 text-center">
          <div className="flex items-center justify-center mb-6">
            <div className="w-16 h-16 bg-[#F3E6FE] rounded-full flex items-center justify-center border border-[#B75FFF]/20">
              <svg className="w-8 h-8 text-[#9200E1]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
          </div>
          <h3 className="text-lg font-semibold text-black mb-2">
            Wallet Not Connected
          </h3>
          <p className="text-sm text-[#666666]">
            Please connect your wallet to access account management features.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full">
      <div className="mb-3">
        <h1 className="text-lg font-semibold text-gray-900">
          Account
        </h1>
        <p className="text-xs text-gray-500">
          Manage your account balance and funding
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="bg-white rounded-t-xl border border-gray-200">
        <div className="flex border-b border-gray-200">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-6 py-4 font-medium text-sm transition-all relative cursor-pointer ${
              activeTab === 'overview'
                ? 'text-purple-600 bg-white'
                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
            }`}
          >
            Overview
            {activeTab === 'overview' && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-600"></div>
            )}
          </button>
          <button
            onClick={() => setActiveTab('detail')}
            className={`px-6 py-4 font-medium text-sm transition-all relative cursor-pointer ${
              activeTab === 'detail'
                ? 'text-purple-600 bg-white'
                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
            }`}
          >
            Fund Distribution
            {activeTab === 'detail' && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-purple-600"></div>
            )}
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="bg-white rounded-b-xl border border-gray-200 border-t-0 p-6">
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Total Balance Section */}
                <div className="bg-gray-50 rounded-lg border border-gray-200 p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h2 className="text-base font-semibold text-gray-900">
                      Total Balance
                    </h2>
                    {isInitializing && (
                      <div className="flex items-center text-gray-500">
                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-gray-300 border-t-purple-600 mr-2"></div>
                        <span className="text-sm">Loading...</span>
                      </div>
                    )}
                  </div>
                  <div className="text-xl font-semibold text-gray-900">
                    {formatNumber(displayLedgerInfo.totalBalance)} <span className="text-sm text-gray-500 font-normal">A0GI</span>
                  </div>
                </div>

                {/* Add Funds Section */}
                <div className="bg-gray-50 rounded-lg border border-gray-200 p-4">
                  <h2 className="text-base font-semibold text-gray-900 mb-4">
                    Add Funds
                  </h2>

                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div>
                        <label htmlFor="amount" className="block text-sm font-medium text-gray-700 mb-2">
                          Amount
                        </label>
                        <div className="relative">
                          <input
                            type="number"
                            id="amount"
                            value={addAmount}
                            onChange={(e) => setAddAmount(e.target.value)}
                            placeholder="0.1"
                            step="0.01"
                            min="0"
                            className="w-full px-4 py-3 pr-12 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500 transition-colors"
                          />
                          <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                            <span className="text-gray-500 text-sm">A0GI</span>
                          </div>
                        </div>
                      </div>

                      <button
                        onClick={handleAddFunds}
                        disabled={!addAmount || isAdding || parseFloat(addAmount) <= 0}
                        className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white px-6 py-3 rounded-lg font-medium transition-all flex items-center justify-center cursor-pointer"
                      >
                        {isAdding && (
                          <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2"></div>
                        )}
                        {isAdding ? "Adding Funds..." : "Add Funds"}
                      </button>
                    </div>

                    <div className="bg-purple-50 rounded-lg p-4">
                      <div className="flex items-start">
                        <div className="flex-shrink-0">
                          <svg className="h-5 w-5 text-purple-400 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                          </svg>
                        </div>
                        <div className="ml-3">
                          <h3 className="text-sm font-medium text-purple-800">
                            How it works
                          </h3>
                          <div className="mt-2 text-sm text-purple-700">
                            <ul className="space-y-1">
                              <li>• Funds are deposited to your account</li>
                              <li>• They are used automatically for AI service payments</li>
                              <li>• Unused funds can be withdrawn anytime</li>
                            </ul>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}


            {activeTab === 'detail' && (
              <div className="space-y-6">
                {/* Account Overview */}
                <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                  <div className="flex items-start">
                    <svg className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                    </svg>
                    <div className="ml-3 flex-1">
                      <p className="text-sm text-purple-800 font-medium mb-2">How fund management works</p>
                      <div className="text-xs text-purple-700 space-y-1">
                        <p>• <strong>Available Balance:</strong> Funds for provider services and withdrawals</p>
                        <p>• <strong>Provider Funds:</strong> Auto-allocated to AI service providers when used</p>
                        <p>• <strong>Retrieval:</strong> Transfer unused provider funds back to Available Balance</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Display success message for retrieve operations */}
                {showSuccessAlert.show && (
                  <div className="bg-green-50 border border-green-200 rounded-xl p-4">
                    <div className="flex items-start">
                      <svg className="w-5 h-5 text-green-500 mr-3 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <div>
                        <h5 className="text-sm font-medium text-green-800">Success</h5>
                        <div className="text-sm text-green-700 mt-1" dangerouslySetInnerHTML={{__html: showSuccessAlert.message}} />
                      </div>
                    </div>
                  </div>
                )}

                {/* Total Balance Container */}
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-6">
                  <div className="flex items-center mb-4">
                    <h2 className="text-sm font-medium text-gray-600 mr-2">
                      Total Balance:
                    </h2>
                    <div className="text-sm font-medium text-gray-600">
                      {formatNumber(displayLedgerInfo.totalBalance)} <span className="text-xs text-gray-500 font-normal">A0GI</span>
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    {/* Available Balance */}
                    <div className="bg-gray-50 rounded-lg border border-gray-200 p-4">
                      <div className="flex justify-between items-start mb-4">
                        <div>
                          <h3 className="text-base font-semibold text-gray-900">
                            Available Balance
                          </h3>
                          <p className="text-xs text-gray-500 mt-1">
                            Available for provider funding and withdrawal
                          </p>
                        </div>
                        <button
                          onClick={() => setShowWithdrawModal(true)}
                          disabled={parseFloat(displayLedgerInfo.availableBalance) === 0}
                          className="px-3 py-1.5 text-gray-600 hover:text-purple-600 hover:bg-purple-50 disabled:text-gray-400 disabled:cursor-not-allowed rounded-md text-sm font-medium transition-all flex items-center cursor-pointer"
                        >
                          Withdraw
                        </button>
                      </div>
                      <div className="text-xl font-semibold text-gray-900">
                        {formatNumber(displayLedgerInfo.availableBalance)} <span className="text-sm text-gray-500 font-normal">A0GI</span>
                      </div>
                    </div>

                    {/* Fund Flow Visualization */}
                    <div className="flex items-center justify-center gap-6 py-1">
                      {/* Auto-funding flow (downward) */}
                      <div className="flex items-center group relative">
                        <svg className="w-3 h-3 text-green-600 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
                        </svg>
                        <span className="text-xs text-green-600 cursor-help">Auto-funds on usage</span>
                        
                        {/* Tooltip */}
                        <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-64 bg-gray-900 text-white text-xs rounded-lg p-3 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-10">
                          <div className="text-center">
                            <p className="mb-2 font-medium">Auto-funding Process</p>
                            <p className="text-gray-300 leading-relaxed">
                              For each AI service provider you use, the system creates a separate sub-account under your control that holds funds specifically allocated for paying that provider's services.
                            </p>
                          </div>
                          {/* Arrow */}
                          <div className="absolute top-full left-1/2 transform -translate-x-1/2 w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
                        </div>
                      </div>
                      
                      {/* Manual retrieve flow (upward) */}
                      <div className="group relative">
                        <button
                          onClick={async () => {
                            if (!broker) return;
                            setIsRetrievingAll(true);
                            setError(null);
                            try {
                              await Promise.all([
                                broker.ledger.retrieveFund('inference'),
                                broker.ledger.retrieveFund('fine-tuning')
                              ]);
                              setShowSuccessAlert({
                                message: 'All provider fund retrieval has been requested successfully, please wait for <strong>lock period</strong>. Check the Distributed Provider Funds details section for wait times.<br/>Funds that have passed the lock period have been retrieved to your Available Balance.',
                                show: true
                              });
                              setTimeout(() => setShowSuccessAlert({message: '', show: false}), 8000);
                              await refreshLedgerInfo();
                            } catch (err: unknown) {
                              const errorMessage = err instanceof Error ? err.message : 'Failed to retrieve all funds';
                              setError(errorMessage);
                                    } finally {
                              setIsRetrievingAll(false);
                            }
                          }}
                          disabled={!broker || isRetrievingAll}
                          className="bg-purple-600 hover:bg-purple-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white rounded px-2 py-1 text-xs font-medium transition-all flex items-center cursor-pointer"
                        >
                          <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
                          </svg>
                          {isRetrievingAll && (
                            <div className="animate-spin rounded-full h-2 w-2 border border-white border-t-transparent mr-1"></div>
                          )}
                          Retrieve
                        </button>
                        
                        {/* Tooltip */}
                        <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-64 bg-gray-900 text-white text-xs rounded-lg p-3 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-10">
                          <div className="text-center">
                            <p className="mb-2 font-medium">Retrieve Unused Funds</p>
                            <p className="text-gray-300 leading-relaxed">
                              Transfer unused funds from provider sub-accounts back to your Available Balance for withdrawal or other uses.
                            </p>
                          </div>
                          {/* Arrow */}
                          <div className="absolute top-full left-1/2 transform -translate-x-1/2 w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
                        </div>
                      </div>
                    </div>

                    {/* Provider Funds with integrated details */}
                    <div className="bg-gray-50 rounded-lg border border-gray-200 p-4">
                      <div className="flex justify-between items-start mb-4">
                        <div>
                          <h3 className="text-base font-semibold text-gray-900">
                            Distributed Provider Funds
                          </h3>
                          <p className="text-xs text-gray-500 mt-1">
                            Funds currently distributed to service providers
                          </p>
                        </div>
                        <button
                          onClick={() => setIsLockedExpanded(!isLockedExpanded)}
                          className="flex items-center text-gray-600 hover:text-purple-600 hover:bg-purple-50 transition-colors rounded px-2 py-1 cursor-pointer"
                        >
                          <span className="mr-2 text-sm font-medium">
                            {isLockedExpanded ? 'Hide Details' : 'View Details'}
                          </span>
                          <svg 
                            className={`w-4 h-4 transition-transform ${isLockedExpanded ? 'rotate-180' : ''}`}
                            fill="none" 
                            stroke="currentColor" 
                            viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>
                      </div>
                      <div className="text-xl font-semibold text-gray-900">
                        {formatNumber(displayLedgerInfo.locked)} <span className="text-sm text-gray-500 font-normal">A0GI</span>
                      </div>
                      
                      {/* Integrated Sub-accounts Details - Full width when expanded */}
                      {isLockedExpanded && (
                        <div className="mt-4 pt-4 border-t border-gray-200">
                          
                          {/* Vertical layout for sub-accounts when expanded */}
                          <div className="space-y-6">
                            {/* Inference Sub-accounts */}
                            <div>
                              <div className="flex items-center justify-between mb-3">
                                <h5 className="text-sm font-medium text-gray-700">
                                  Inference Providers
                                </h5>
                                <button
                                  onClick={async () => {
                                    if (!broker) return;
                                    setIsRetrieving(prev => ({ ...prev, inference: true }));
                                    setError(null);
                                    try {
                                      await broker.ledger.retrieveFund('inference');
                                      setShowSuccessAlert({message: 'Inference funds retrieve request submitted', show: true});
                                      setTimeout(() => setShowSuccessAlert({message: '', show: false}), 3000);
                                      await refreshLedgerInfo();
                                    } catch (err: unknown) {
                                      const errorMessage = err instanceof Error ? err.message : 'Failed to retrieve inference funds';
                                      setError(errorMessage);
                                                    } finally {
                                      setIsRetrieving(prev => ({ ...prev, inference: false }));
                                    }
                                  }}
                                  disabled={!broker || isRetrieving.inference}
                                  className="px-3 py-1.5 text-gray-600 hover:text-purple-600 hover:bg-purple-50 disabled:text-gray-400 disabled:cursor-not-allowed rounded-md text-sm font-medium transition-all flex items-center cursor-pointer"
                                >
                                  {isRetrieving.inference && (
                                    <div className="animate-spin rounded-full h-3 w-3 border-2 border-gray-400 border-t-transparent mr-1.5"></div>
                                  )}
                                  Retrieve
                                </button>
                              </div>
                              {ledgerInfo?.inferences && ledgerInfo.inferences.length > 0 ? (
                                <div className="space-y-3 max-h-80 overflow-y-auto">
                                  {ledgerInfo.inferences.map((inference, index) => (
                                    <div key={index} className="bg-white rounded-lg p-4 border border-gray-200">
                                      <div className="grid grid-cols-3 gap-4">
                                        <div>
                                          <div className="text-xs font-medium text-gray-500 mb-1">Provider Address</div>
                                          <div className="text-sm font-medium text-gray-900">{inference.provider}</div>
                                        </div>
                                        <div>
                                          <div className="text-xs font-medium text-gray-500 mb-1">Current Fund</div>
                                          <div className="text-sm font-medium text-gray-900">{formatNumber(inference.balance)} A0GI</div>
                                        </div>
                                        <div>
                                          <div className="text-xs font-medium text-gray-500 mb-1">Pending Retrieval</div>
                                          <button
                                            onClick={() => toggleRefundDetails(inference.provider, 'inference')}
                                            className="text-sm font-medium text-gray-900 hover:text-purple-600 transition-colors cursor-pointer"
                                          >
                                            {formatNumber(inference.requestedReturn)} A0GI
                                            {parseFloat(inference.requestedReturn) > 0 && (
                                              <svg className={`inline w-3 h-3 ml-1 transition-transform ${expandedRefunds[`inference-${inference.provider}`] ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                                              </svg>
                                            )}
                                          </button>
                                        </div>
                                      </div>
                                      {/* Refund Details Expansion */}
                                      {expandedRefunds[`inference-${inference.provider}`] && (
                                        <div className="mt-3 pt-3 border-t border-gray-200">
                                          <div className="flex items-center justify-between mb-2">
                                            <div className="text-xs font-medium text-gray-700">Retrieval Details</div>
                                            <button
                                              onClick={() => fetchRefundDetails(inference.provider, 'inference')}
                                              disabled={loadingRefunds[`inference-${inference.provider}`]}
                                              className="text-purple-600 hover:text-purple-700 disabled:text-gray-400 transition-colors cursor-pointer"
                                              title="Refresh refund details"
                                            >
                                              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                              </svg>
                                            </button>
                                          </div>
                                          {loadingRefunds[`inference-${inference.provider}`] ? (
                                            <div className="flex items-center text-gray-500">
                                              <div className="animate-spin rounded-full h-3 w-3 border-2 border-gray-300 border-t-purple-600 mr-2"></div>
                                              <span className="text-xs">Loading...</span>
                                            </div>
                                          ) : refundDetails[`inference-${inference.provider}`]?.length > 0 ? (
                                            <div className="space-y-2">
                                              {refundDetails[`inference-${inference.provider}`].map((refund, refundIndex) => (
                                                <div key={refundIndex} className="bg-gray-50 rounded p-3">
                                                  <div className="grid grid-cols-3 gap-4">
                                                    <div>
                                                      <div className="text-xs font-medium text-gray-500 mb-1">Amount</div>
                                                      <div className="text-xs font-medium text-gray-900">{formatNumber((Number(refund.amount) / 1e18).toString())} A0GI</div>
                                                    </div>
                                                    <div>
                                                      <div className="text-xs font-medium text-gray-500 mb-1">Lock Time</div>
                                                      <div className="text-xs font-medium text-gray-900">{formatTime(Number(refund.remainTime))}</div>
                                                    </div>
                                                    <div></div>
                                                  </div>
                                                </div>
                                              ))}
                                            </div>
                                          ) : (
                                            <div className="text-xs text-gray-500 italic">No pending refunds</div>
                                          )}
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <div className="text-sm text-gray-500 italic bg-white rounded-lg p-4 border border-gray-200">No inference services have been used yet</div>
                              )}
                            </div>

                            {/* Fine-tuning Sub-accounts */}
                            <div>
                              <div className="flex items-center justify-between mb-3">
                                <h5 className="text-sm font-medium text-gray-700">
                                  Fine-tuning Providers
                                </h5>
                                <button
                                  onClick={async () => {
                                    if (!broker) return;
                                    setIsRetrieving(prev => ({ ...prev, 'fine-tuning': true }));
                                    setError(null);
                                    try {
                                      await broker.ledger.retrieveFund('fine-tuning');
                                      setShowSuccessAlert({message: 'Fine-tuning funds retrieve request submitted', show: true});
                                      setTimeout(() => setShowSuccessAlert({message: '', show: false}), 3000);
                                      await refreshLedgerInfo();
                                    } catch (err: unknown) {
                                      const errorMessage = err instanceof Error ? err.message : 'Failed to retrieve fine-tuning funds';
                                      setError(errorMessage);
                                                    } finally {
                                      setIsRetrieving(prev => ({ ...prev, 'fine-tuning': false }));
                                    }
                                  }}
                                  disabled={!broker || isRetrieving['fine-tuning']}
                                  className="px-3 py-1.5 text-gray-600 hover:text-purple-600 hover:bg-purple-50 disabled:text-gray-400 disabled:cursor-not-allowed rounded-md text-sm font-medium transition-all flex items-center cursor-pointer"
                                >
                                  {isRetrieving['fine-tuning'] && (
                                    <div className="animate-spin rounded-full h-3 w-3 border-2 border-gray-400 border-t-transparent mr-1.5"></div>
                                  )}
                                  Retrieve
                                </button>
                              </div>
                              {ledgerInfo?.fineTunings && ledgerInfo.fineTunings.length > 0 ? (
                                <div className="space-y-3 max-h-80 overflow-y-auto">
                                  {ledgerInfo.fineTunings.map((fineTuning, index) => (
                                    <div key={index} className="bg-white rounded-lg p-4 border border-gray-200">
                                      <div className="grid grid-cols-3 gap-4">
                                        <div>
                                          <div className="text-xs font-medium text-gray-500 mb-1">Provider Address</div>
                                          <div className="text-sm font-medium text-gray-900">{fineTuning.provider}</div>
                                        </div>
                                        <div>
                                          <div className="text-xs font-medium text-gray-500 mb-1">Current Fund</div>
                                          <div className="text-sm font-medium text-gray-900">{formatNumber(fineTuning.balance)} A0GI</div>
                                        </div>
                                        <div>
                                          <div className="text-xs font-medium text-gray-500 mb-1">Pending Retrieval</div>
                                          <button
                                            onClick={() => toggleRefundDetails(fineTuning.provider, 'fine-tuning')}
                                            className="text-sm font-medium text-gray-900 hover:text-purple-600 transition-colors cursor-pointer"
                                          >
                                            {formatNumber(fineTuning.requestedReturn)} A0GI
                                            {parseFloat(fineTuning.requestedReturn) > 0 && (
                                              <svg className={`inline w-3 h-3 ml-1 transition-transform ${expandedRefunds[`fine-tuning-${fineTuning.provider}`] ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                                              </svg>
                                            )}
                                          </button>
                                        </div>
                                      </div>
                                      {/* Refund Details Expansion */}
                                      {expandedRefunds[`fine-tuning-${fineTuning.provider}`] && (
                                        <div className="mt-3 pt-3 border-t border-gray-200">
                                          <div className="flex items-center justify-between mb-2">
                                            <div className="text-xs font-medium text-gray-700">Retrieval Details</div>
                                            <button
                                              onClick={() => fetchRefundDetails(fineTuning.provider, 'fine-tuning')}
                                              disabled={loadingRefunds[`fine-tuning-${fineTuning.provider}`]}
                                              className="text-purple-600 hover:text-purple-700 disabled:text-gray-400 transition-colors cursor-pointer"
                                              title="Refresh refund details"
                                            >
                                              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                              </svg>
                                            </button>
                                          </div>
                                          {loadingRefunds[`fine-tuning-${fineTuning.provider}`] ? (
                                            <div className="flex items-center text-gray-500">
                                              <div className="animate-spin rounded-full h-3 w-3 border-2 border-gray-300 border-t-purple-600 mr-2"></div>
                                              <span className="text-xs">Loading...</span>
                                            </div>
                                          ) : refundDetails[`fine-tuning-${fineTuning.provider}`]?.length > 0 ? (
                                            <div className="space-y-2">
                                              {refundDetails[`fine-tuning-${fineTuning.provider}`].map((refund, refundIndex) => (
                                                <div key={refundIndex} className="bg-gray-50 rounded p-3">
                                                  <div className="grid grid-cols-3 gap-4">
                                                    <div>
                                                      <div className="text-xs font-medium text-gray-500 mb-1">Amount</div>
                                                      <div className="text-xs font-medium text-gray-900">{formatNumber((Number(refund.amount) / 1e18).toString())} A0GI</div>
                                                    </div>
                                                    <div>
                                                      <div className="text-xs font-medium text-gray-500 mb-1">Lock Time</div>
                                                      <div className="text-xs font-medium text-gray-900">{formatTime(Number(refund.remainTime))}</div>
                                                    </div>
                                                    <div></div>
                                                  </div>
                                                </div>
                                              ))}
                                            </div>
                                          ) : (
                                            <div className="text-xs text-gray-500 italic">No pending refunds</div>
                                          )}
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <div className="text-sm text-gray-500 italic bg-white rounded-lg p-4 border border-gray-200">Fine-tuning services details are temporarily unavailable. Support coming soon.</div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                  


                {/* Display error message if any */}
                {error && (
                  <div className="bg-red-50 border border-red-200 rounded-xl p-4">
                    <div className="flex items-start">
                      <svg className="w-5 h-5 text-red-500 mr-3 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <div>
                        <h3 className="text-sm font-medium text-red-800">Error</h3>
                        <p className="text-sm text-red-700 mt-1">{error}</p>
                      </div>
                    </div>
                  </div>
                )}

              </div>
            )}

            {/* Withdraw Modal */}
            {showWithdrawModal && (
              <div className="fixed inset-0 bg-black/30 backdrop-blur-sm flex items-center justify-center z-50">
                <div className="bg-white rounded-xl p-6 w-full max-w-md mx-4">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-xl font-semibold text-gray-900">Withdraw Funds</h2>
                    <button
                      onClick={() => {
                        setShowWithdrawModal(false);
                        setWithdrawAmount("");
                        setError(null);
                      }}
                      className="text-gray-400 hover:text-gray-600 cursor-pointer"
                    >
                      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>

                  <div className="mb-6">
                    <div className="mb-4">
                      <label htmlFor="withdraw-amount" className="block text-sm font-medium text-gray-700 mb-2">
                        Amount to Withdraw
                      </label>
                      <div className="relative">
                        <input
                          type="number"
                          id="withdraw-amount"
                          value={withdrawAmount}
                          onChange={(e) => setWithdrawAmount(e.target.value)}
                          placeholder="0.0"
                          step="0.01"
                          min="0"
                          max={displayLedgerInfo.availableBalance}
                          className="w-full px-4 py-3 pr-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 transition-colors"
                        />
                        <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                          <span className="text-gray-500 text-sm">A0GI</span>
                        </div>
                      </div>
                      <p className="text-xs text-gray-500 mt-1">
                        Available: {formatNumber(displayLedgerInfo.availableBalance)} A0GI
                      </p>
                    </div>

                    {error && (
                      <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                        <p className="text-sm text-red-600">{error}</p>
                      </div>
                    )}

                    <div className="flex gap-3">
                      <button
                        onClick={() => {
                          setShowWithdrawModal(false);
                          setWithdrawAmount("");
                          setError(null);
                        }}
                        className="flex-1 px-4 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 font-medium transition-colors cursor-pointer"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={async () => {
                          if (!withdrawAmount || !broker) return;
                          
                          const amount = parseFloat(withdrawAmount);
                          const availableAmount = parseFloat(displayLedgerInfo.availableBalance);
                          
                          if (amount <= 0) {
                            setError("Amount must be greater than 0");
                            return;
                          }
                          
                          if (amount > availableAmount) {
                            setError("Amount cannot exceed available balance");
                            return;
                          }
                          
                          setIsAdding(true);
                          setError(null);
                          
                          try {
                            if (typeof broker.ledger.refund === 'function') {
                              await broker.ledger.refund(amount);
                              setShowWithdrawModal(false);
                              setWithdrawAmount("");
                              await refreshLedgerInfo();
                            } else {
                              setError('Withdraw functionality is not available yet.');
                            }
                          } catch (err: unknown) {
                            const errorMessage = err instanceof Error ? err.message : 'Failed to withdraw';
                            setError(errorMessage);
                                          } finally {
                            setIsAdding(false);
                          }
                        }}
                        disabled={!withdrawAmount || isAdding || parseFloat(withdrawAmount) <= 0 || parseFloat(withdrawAmount) > parseFloat(displayLedgerInfo.availableBalance)}
                        className="flex-1 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white px-4 py-3 rounded-lg font-medium transition-all flex items-center justify-center cursor-pointer"
                      >
                        {isAdding && (
                          <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2"></div>
                        )}
                        {isAdding ? "Withdrawing..." : "Withdraw"}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}
      </div>
    </div>
  );
}

export default function LedgerPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <LedgerContent />
    </Suspense>
  );
}
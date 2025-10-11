"use client";

import * as React from "react";
import { useState, useEffect, useRef, useCallback } from "react";
import { useAccount } from "wagmi";
import { useRouter } from "next/navigation";
import { use0GBroker } from "../../../../hooks/use0GBroker";
import { useChatHistory } from "../../../../hooks/useChatHistory";
import { useErrorWithTimeout } from "../../../../hooks/useErrorWithTimeout";
import { useProviderSearch } from "../../../../hooks/useProviderSearch";
import { useStreamingState } from "../../../../hooks/useStreamingState";
import { useProviderManagement } from "../../../../hooks/useProviderManagement";
import { useMessageHandling } from "../../../../hooks/useMessageHandling";
import { CHAT_CONFIG } from "../../../../constants/chat";
import { ChatInput } from "./ChatInput";
import { ProviderSelector } from "./ProviderSelector";
import { MessageList } from "./MessageList";
import { ChatSidebar } from "./ChatSidebar";
import { TopUpModal } from "./TopUpModal";
import { TutorialOverlay } from "./TutorialOverlay";



interface Message {
  role: "system" | "user" | "assistant";
  content: string;
  timestamp?: number;
  chatId?: string;
  isVerified?: boolean | null;
  isVerifying?: boolean;
}


export function OptimizedChatPage() {
  const { isConnected, address } = useAccount();
  const { broker, isInitializing, ledgerInfo, refreshLedgerInfo } = use0GBroker();
  const router = useRouter();
  const { error, setErrorWithTimeout } = useErrorWithTimeout();
  
  // Tutorial state
  const [showTutorial, setShowTutorial] = useState(false);
  const [tutorialStep, setTutorialStep] = useState<'verify' | 'top-up' | null>(null);
  
  // Provider state management
  const {
    providers,
    selectedProvider,
    serviceMetadata,
    providerAcknowledged,
    isVerifyingProvider,
    providerBalance,
    providerBalanceNeuron,
    providerPendingRefund,
    setSelectedProvider,
    verifyProvider,
    refreshProviderBalance,
  } = useProviderManagement(
    broker,
    refreshLedgerInfo,
    showTutorial,
    tutorialStep,
    setShowTutorial,
    setTutorialStep,
    setErrorWithTimeout
  );
  
  // Provider dropdown state (UI only)
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "system",
      content:
        "You are a helpful assistant that provides accurate information.",
      timestamp: Date.now(),
    },
  ]);
  // Streaming state management
  const {
    inputMessage,
    setInputMessage,
    isLoading,
    setIsLoading,
    isStreaming,
    setIsStreaming,
    isProcessing,
  } = useStreamingState();
  // Note: Deposit modal is now handled globally in LayoutContent
  const [showFundingAlert, setShowFundingAlert] = useState(false);
  const [fundingAlertMessage, setFundingAlertMessage] = useState("");
  const [showTopUpModal, setShowTopUpModal] = useState(false);
  const [topUpAmount, setTopUpAmount] = useState("");
  const [isTopping, setIsTopping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const isUserScrollingRef = useRef(false);
  
  // Initialize chat history hook first - shared across all providers for the same wallet
  const chatHistory = useChatHistory({
    walletAddress: address || '',
    autoSave: true,
  });

  // Chat history state
  const [showHistorySidebar, setShowHistorySidebar] = useState(false);
  const { searchQuery, setSearchQuery, searchResults, isSearching, clearSearch } = useProviderSearch(chatHistory);
  
  // Message handling hook
  const { sendMessage, verifyResponse } = useMessageHandling({
    broker,
    selectedProvider,
    serviceMetadata,
    chatHistory,
    messages,
    setMessages,
    inputMessage,
    setInputMessage,
    setIsLoading,
    setIsStreaming,
    setErrorWithTimeout,
    isUserScrollingRef,
    messagesEndRef,
  });

  // Handle provider change - clear current session to start fresh
  const previousProviderRef = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (selectedProvider?.address && 
        previousProviderRef.current !== undefined && 
        previousProviderRef.current !== selectedProvider.address) {
      // Only clear when we actually switch providers, not on initial load
      setMessages([
        {
          role: "system",
          content: "You are a helpful assistant that provides accurate information.",
          timestamp: Date.now(),
        },
      ]);
    }
    previousProviderRef.current = selectedProvider?.address;
  }, [selectedProvider?.address]);


  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Element;
      if (!target.closest(".provider-dropdown")) {
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


  // Note: Global ledger check is now handled in LayoutContent component

  // Refresh ledger info when broker is available
  useEffect(() => {
    if (broker && refreshLedgerInfo) {
      refreshLedgerInfo();
    }
  }, [broker, refreshLedgerInfo]);


  // Function to scroll to a specific message
  const scrollToMessage = useCallback((targetContent: string) => {
    const messageElements = document.querySelectorAll('[data-message-content]');
    for (const element of messageElements) {
      if (element.getAttribute('data-message-content')?.includes(targetContent.substring(0, 50))) {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        // Highlight the message temporarily
        element.classList.add('bg-yellow-100');
        setTimeout(() => {
          element.classList.remove('bg-yellow-100');
        }, CHAT_CONFIG.HIGHLIGHT_DURATION);
        break;
      }
    }
  }, []);

  // Function to handle history clicks with optional message targeting
  const handleHistoryClick = useCallback(async (sessionId: string, targetMessageContent?: string) => {
    
    // Clear any previous message targeting when clicking regular history
    if (!targetMessageContent) {
      lastTargetMessageRef.current = null;
    }
    
    try {
      // Reset loading/streaming states for history navigation
      setIsLoading(false);
      setIsStreaming(false);
      
      // Set flag to prevent auto-scrolling to bottom
      isLoadingHistoryRef.current = true;
      
      
      // Load session and get messages directly from database
      await chatHistory.loadSession(sessionId);
      
      // Import dbManager directly to get fresh data
      const { dbManager } = await import('../../../../shared/lib/database');
      const sessionMessages = await dbManager.getMessages(sessionId);
      
      
      // Convert database messages to UI format
      const historyMessages: Message[] = sessionMessages.map(msg => ({
        role: msg.role,
        content: msg.content,
        timestamp: msg.timestamp,
        chatId: msg.session_id, // Use session_id for chatId
        isVerified: msg.is_verified,
        isVerifying: msg.is_verifying,
      }));

      // Add system message if needed
      const hasSystemMessage = historyMessages.some(msg => msg.role === 'system');
      if (!hasSystemMessage && historyMessages.length > 0) {
        historyMessages.unshift({
          role: "system",
          content: "You are a helpful assistant that provides accurate information.",
          timestamp: Date.now(),
        });
      }

      setMessages(historyMessages);
      
      // If we have a target message, scroll to it after a delay
      if (targetMessageContent) {
        lastTargetMessageRef.current = targetMessageContent;
        setTimeout(() => {
          scrollToMessage(targetMessageContent);
        }, 300);
      } else {
        // Clear highlighting from previous targeted messages
        setTimeout(() => {
          const highlightedElements = document.querySelectorAll('.bg-yellow-100');
          highlightedElements.forEach(el => el.classList.remove('bg-yellow-100'));
        }, CHAT_CONFIG.HIGHLIGHT_REMOVAL_DELAY);
      }
      
      // Reset flags
      setTimeout(() => {
        isLoadingHistoryRef.current = false;
        isUserScrollingRef.current = false;
      }, 200);
      
    } catch {
      isLoadingHistoryRef.current = false;
    }
  }, [chatHistory, scrollToMessage]);


  // Track sessions for reference
  const lastLoadedSessionRef = useRef<string | null>(null);

  // Auto scroll to bottom when messages change (but not for verification updates or history navigation)
  const previousMessagesRef = useRef<Message[]>([]);
  const isLoadingHistoryRef = useRef(false);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const lastTargetMessageRef = useRef<string | null>(null);
  const lastClickTimeRef = useRef<number>(0);
  const lastClickedSessionRef = useRef<string | null>(null);
  
  // Initialize click tracking on component mount
  useEffect(() => {
    lastClickTimeRef.current = 0;
    lastClickedSessionRef.current = null;
    lastTargetMessageRef.current = null;
  }, []);
  
  // Track user scroll behavior to stop auto-scroll when user manually scrolls up
  useEffect(() => {
    const messagesContainer = messagesContainerRef.current;
    if (!messagesContainer) return;

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = messagesContainer;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < CHAT_CONFIG.SCROLL_THRESHOLD;
      
      if (!isNearBottom && isStreaming) {
        // User scrolled up during streaming, stop auto-scroll
        isUserScrollingRef.current = true;
      } else if (isNearBottom) {
        // User is back near bottom, resume auto-scroll
        isUserScrollingRef.current = false;
      }
    };

    messagesContainer.addEventListener('scroll', handleScroll, { passive: true });
    return () => messagesContainer.removeEventListener('scroll', handleScroll);
  }, [isStreaming]);
  
  useEffect(() => {
    const scrollToBottom = () => {
      if (isUserScrollingRef.current) return; // Don't scroll if user is manually scrolling
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    // Check if this is just a verification status update
    const isVerificationUpdate = () => {
      const prev = previousMessagesRef.current;
      if (prev.length !== messages.length) return false;
      
      // Check if only verification fields changed
      for (let i = 0; i < messages.length; i++) {
        const current = messages[i];
        const previous = prev[i];
        
        // If content, role, or timestamp changed, it's not just verification
        if (current.content !== previous.content || 
            current.role !== previous.role ||
            current.timestamp !== previous.timestamp ||
            current.chatId !== previous.chatId) {
          return false;
        }
      }
      return true;
    };

    // Don't auto-scroll if:
    // 1. It's just a verification update
    // 2. It's a history navigation (loading history)
    // 3. User is manually scrolling during streaming
    if (!isVerificationUpdate() && !isLoadingHistoryRef.current && !isUserScrollingRef.current) {
      const timeoutId = setTimeout(scrollToBottom, CHAT_CONFIG.SCROLL_DELAY);
      // Update the ref after scrolling decision
      previousMessagesRef.current = [...messages];
      return () => clearTimeout(timeoutId);
    }
    
    // Update the ref even if we don't scroll
    previousMessagesRef.current = [...messages];
  }, [messages, isLoading, isStreaming]);


  // Remove clearChat function since we removed the Clear Chat button

  const startNewChat = async () => {
    // Create new session (this won't trigger sync due to hasManuallyLoadedSession flag)
    await chatHistory.createNewSession();
    
    // Reset UI to clean state
    setMessages([
      {
        role: "system",
        content:
          "You are a helpful assistant that provides accurate information.",
        timestamp: Date.now(),
      },
    ]);
    setErrorWithTimeout(null);
    
    // Reset click tracking to ensure first history click works
    lastClickTimeRef.current = 0;
    lastClickedSessionRef.current = null;
    lastTargetMessageRef.current = null;
    
    // Update tracking to prevent sync on this new session
    lastLoadedSessionRef.current = chatHistory.currentSessionId;
  };


  // Note: handleDeposit is now handled globally in LayoutContent


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

  return (
    <div className="w-full">
      <div className="mb-3">
        <div className="flex items-center space-x-3 mb-2">
          <button
            onClick={() => router.push('/inference')}
            className="text-gray-600 hover:text-purple-600 transition-colors p-1.5 border border-gray-300 rounded-lg hover:bg-purple-50 cursor-pointer"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 19l-7-7 7-7"
              />
            </svg>
          </button>
          <div>
            <h1 className="text-lg font-semibold text-gray-900">Inference</h1>
            <p className="text-xs text-gray-500">
              Chat with AI models from decentralized providers
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-6">
          <div className="flex items-start">
            <svg
              className="w-5 h-5 text-red-500 mr-3 mt-0.5 flex-shrink-0"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <div className="flex-1 min-w-0">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="text-sm text-red-700 mt-1 break-words whitespace-pre-wrap">
                {(() => {
                  try {
                    // Try to parse as JSON if it looks like JSON
                    if (error.trim().startsWith('{') && error.trim().endsWith('}')) {
                      const parsed = JSON.parse(error);
                      return JSON.stringify(parsed, null, 2);
                    }
                    return error;
                  } catch {
                    return error;
                  }
                })()}
              </p>
            </div>
            <button
              onClick={() => setErrorWithTimeout(null)}
              className="ml-2 text-red-400 hover:text-red-600 flex-shrink-0"
              title="Close error message"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
      )}

      {showFundingAlert && (
        <div className="bg-purple-50 border border-purple-200 rounded-xl p-4 mb-6">
          <div className="flex items-start">
            <svg
              className="w-5 h-5 text-purple-500 mr-3 mt-0.5 flex-shrink-0"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <div>
              <h3 className="text-sm font-medium text-purple-800">Provider Funding</h3>
              <p className="text-sm text-purple-700 mt-1">{fundingAlertMessage}</p>
            </div>
          </div>
        </div>
      )}

      <div className="flex bg-white rounded-xl border border-gray-200" style={{ height: CHAT_CONFIG.CHAT_HEIGHT }}>
        {/* History Sidebar */}
        <ChatSidebar
          showHistorySidebar={showHistorySidebar}
          isProcessing={isProcessing}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          searchResults={searchResults}
          isSearching={isSearching}
          clearSearch={clearSearch}
          chatHistory={chatHistory}
          handleHistoryClick={handleHistoryClick}
        />
        
        {/* Main Chat Area */}
        <div className="flex-1 flex flex-col">
        {/* Chat Header with Provider Selection */}
        <div className="p-4 border-b border-gray-200 bg-gray-50 rounded-t-lg">
          <div className="flex justify-between items-center flex-wrap gap-2 sm:flex-nowrap">
            <ProviderSelector
              providers={providers}
              selectedProvider={selectedProvider}
              onProviderSelect={setSelectedProvider}
              isDropdownOpen={isDropdownOpen}
              setIsDropdownOpen={setIsDropdownOpen}
              isInitializing={isInitializing}
              providerBalance={providerBalance}
              providerBalanceNeuron={providerBalanceNeuron}
              providerPendingRefund={providerPendingRefund}
              onAddFunds={() => {
                // Use the existing top-up modal logic
                setShowTopUpModal(true);
              }}
            />

            <div className="flex items-center space-x-2">
              <div className="relative group">
                <button
                  onClick={() => {
                    if (!isProcessing) {
                      setShowHistorySidebar(!showHistorySidebar);
                    }
                  }}
                  disabled={isProcessing}
                  className={`px-3 py-1.5 rounded-md text-sm font-medium transition-all flex items-center space-x-1 cursor-pointer ${
                    isProcessing
                      ? 'text-gray-400 cursor-not-allowed'
                      : showHistorySidebar
                        ? 'text-purple-600 bg-purple-50'
                        : 'text-gray-600 hover:text-purple-600 hover:bg-purple-50'
                  }`}
                >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>History</span>
                </button>
                
                {/* History Tooltip */}
                <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-20 whitespace-nowrap">
                  Toggle chat history
                  <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
                    <div className="w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
                  </div>
                </div>
              </div>
              
              <div className="relative group">
                <button
                onClick={() => {
                  if (!isProcessing) {
                    startNewChat();
                  }
                }}
                disabled={isProcessing}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-all flex items-center space-x-1 cursor-pointer ${
                  isProcessing
                    ? 'text-gray-400 cursor-not-allowed'
                    : 'text-gray-600 hover:text-purple-600 hover:bg-purple-50'
                }`}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
                <span>New</span>
                </button>
                
                {/* New Tooltip */}
                <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-20 whitespace-nowrap">
                  Start new chat
                  <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
                    <div className="w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Messages */}
        <MessageList
          messages={messages}
          isLoading={isLoading}
          isStreaming={isStreaming}
          verifyResponse={verifyResponse}
        />

        {/* Input */}
        <ChatInput
          inputMessage={inputMessage}
          setInputMessage={setInputMessage}
          isProcessing={isProcessing}
          isVerifyingProvider={isVerifyingProvider}
          providerAcknowledged={providerAcknowledged}
          showTutorial={showTutorial}
          tutorialStep={tutorialStep}
          setShowTutorial={setShowTutorial}
          setTutorialStep={setTutorialStep}
          onSendMessage={sendMessage}
          onVerifyProvider={verifyProvider}
        />
        </div>
      </div>

      {/* Note: Deposit modal is now handled globally in LayoutContent */}

      <TopUpModal
        isOpen={showTopUpModal}
        onClose={() => setShowTopUpModal(false)}
        broker={broker}
        selectedProvider={selectedProvider}
        topUpAmount={topUpAmount}
        setTopUpAmount={setTopUpAmount}
        isTopping={isTopping}
        setIsTopping={setIsTopping}
        providerBalance={providerBalance}
        providerPendingRefund={providerPendingRefund}
        ledgerInfo={ledgerInfo}
        refreshLedgerInfo={refreshLedgerInfo}
        refreshProviderBalance={refreshProviderBalance}
        setErrorWithTimeout={setErrorWithTimeout}
        showTutorial={showTutorial}
        tutorialStep={tutorialStep}
        setShowTutorial={setShowTutorial}
        setTutorialStep={setTutorialStep}
      />

      <TutorialOverlay
        isVisible={showTutorial}
        step={tutorialStep}
        onClose={() => {
          setShowTutorial(false);
          setTutorialStep(null);
        }}
      />
    </div>
  );
}

"use client";

import * as React from "react";
import { useState, useEffect, useRef, useCallback } from "react";
import { useAccount } from "wagmi";
import { useSearchParams, useRouter } from "next/navigation";
import { use0GBroker } from "../../../../hooks/use0GBroker";
import { useChatHistory } from "../../../../hooks/useChatHistory";
import { useErrorWithTimeout } from "../../../../hooks/useErrorWithTimeout";
import { useProviderSearch } from "../../../../hooks/useProviderSearch";
import { useProviderState } from "../../../../hooks/useProviderState";
import { useStreamingState } from "../../../../hooks/useStreamingState";
import { a0giToNeuron, neuronToA0gi } from "../../../../utils/currency";
import { transformBrokerServicesToProviders } from "../../../../utils/providerTransform";
import { ChatInput } from "./ChatInput";
import { ProviderSelector } from "./ProviderSelector";
import { MessageList } from "./MessageList";
import { ChatSidebar } from "./ChatSidebar";



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
  const searchParams = useSearchParams();
  const router = useRouter();
  // Provider state management
  const {
    providers,
    setProviders,
    selectedProvider,
    setSelectedProvider,
    serviceMetadata,
    setServiceMetadata,
    providerAcknowledged,
    setProviderAcknowledged,
    isVerifyingProvider,
    setIsVerifyingProvider,
    providerBalance,
    setProviderBalance,
    providerBalanceNeuron,
    setProviderBalanceNeuron,
    providerPendingRefund,
    setProviderPendingRefund,
    isDropdownOpen,
    setIsDropdownOpen,
  } = useProviderState();
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
  const { error, setErrorWithTimeout } = useErrorWithTimeout();
  // Note: Deposit modal is now handled globally in LayoutContent
  const [showFundingAlert, setShowFundingAlert] = useState(false);
  const [fundingAlertMessage, setFundingAlertMessage] = useState("");
  const [showTopUpModal, setShowTopUpModal] = useState(false);
  const [topUpAmount, setTopUpAmount] = useState("");
  const [isTopping, setIsTopping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  // Tutorial state
  const [showTutorial, setShowTutorial] = useState(false);
  const [tutorialStep, setTutorialStep] = useState<'verify' | 'top-up' | null>(null);
  
  // Initialize chat history hook first - shared across all providers for the same wallet
  const chatHistory = useChatHistory({
    walletAddress: address || '',
    autoSave: true,
  });

  // Chat history state
  const [showHistorySidebar, setShowHistorySidebar] = useState(false);
  const { searchQuery, setSearchQuery, searchResults, isSearching, clearSearch } = useProviderSearch(chatHistory);

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

  // Fetch real providers when broker is available
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
          // Keep the providers list empty on error
          setProviders([]);
          setSelectedProvider(null);
        }
      }
    };

    fetchProviders();
  }, [broker, selectedProvider]);

  // Note: Global ledger check is now handled in LayoutContent component

  // Refresh ledger info when broker is available
  useEffect(() => {
    if (broker && refreshLedgerInfo) {
      refreshLedgerInfo();
    }
  }, [broker, refreshLedgerInfo]);

  // Fetch service metadata when provider is selected
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
  }, [broker, selectedProvider, showTutorial]);

  // Fetch provider balance when provider is selected
  useEffect(() => {
    const fetchProviderBalance = async () => {
      if (broker && selectedProvider) {
        try {
          const account = await broker.inference.getAccount(selectedProvider.address);
          if (account && account.balance) {
            const balanceInA0gi = neuronToA0gi(account.balance - account.pendingRefund);
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

    fetchProviderBalance();
  }, [broker, selectedProvider]);

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
  }, [selectedProvider, providerAcknowledged]);

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
        }, 2000);
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
      const { dbManager } = await import('../../../../lib/database');
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
        }, 100);
      }
      
      // Reset flags
      setTimeout(() => {
        isLoadingHistoryRef.current = false;
        isUserScrollingRef.current = false;
      }, 200);
      
    } catch (err) {
      isLoadingHistoryRef.current = false;
    }
  }, [chatHistory, scrollToMessage]);


  // Track sessions for reference
  const lastLoadedSessionRef = useRef<string | null>(null);

  // Auto scroll to bottom when messages change (but not for verification updates or history navigation)
  const previousMessagesRef = useRef<Message[]>([]);
  const isUserScrollingRef = useRef(false);
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
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
      
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
      const timeoutId = setTimeout(scrollToBottom, 100);
      // Update the ref after scrolling decision
      previousMessagesRef.current = [...messages];
      return () => clearTimeout(timeoutId);
    }
    
    // Update the ref even if we don't scroll
    previousMessagesRef.current = [...messages];
  }, [messages, isLoading, isStreaming]);

  const sendMessage = async () => {

    if (!inputMessage.trim() || !selectedProvider || !broker) {
      return;
    }

    // For now, let's add a simple demo response to test if the function works
    const userMessage: Message = {
      role: "user",
      content: inputMessage,
      timestamp: Date.now(),
    };

    // Add user message to UI immediately
    setMessages((prev) => [...prev, userMessage]);
    
    // Save user message to database and get session ID (await to ensure session is created)
    let currentSessionForAssistant: string | null = null;
    try {
      currentSessionForAssistant = await chatHistory.addMessage({
        role: userMessage.role,
        content: userMessage.content,
        chat_id: undefined,
        is_verified: null,
        is_verifying: false,
      });
    } catch (err) {
    }
    setInputMessage("");
    setIsLoading(true);
    setIsStreaming(true);
    setErrorWithTimeout(null);
    
    // Reset textarea height
    setTimeout(() => {
      const textarea = document.querySelector('textarea') as HTMLTextAreaElement;
      if (textarea) {
        textarea.style.height = '40px';
      }
    }, 0);
    
    let firstContentReceived = false;

    try {
      // If serviceMetadata is not available, try to fetch it first
      let currentMetadata = serviceMetadata;
      if (!currentMetadata) {
        currentMetadata = await broker.inference.getServiceMetadata(
          selectedProvider.address
        );
        if (currentMetadata?.endpoint && currentMetadata?.model) {
          setServiceMetadata({
            endpoint: currentMetadata.endpoint,
            model: currentMetadata.model
          });
        } else {
          setServiceMetadata(null);
        }
        if (!currentMetadata) {
          throw new Error("Failed to get service metadata");
        }
      }

      // Step 5.2: Get the request headers (may trigger auto-funding)
      
      // Funding operations removed
      
      // Prepare the actual messages array that will be sent to the API
      const messagesToSend = [
        ...messages
          .filter((m) => m.role !== "system")
          .map((m) => ({ role: m.role, content: m.content })),
        { role: userMessage.role, content: userMessage.content },
      ];
      
      let headers;
      try {
        headers = await broker.inference.getRequestHeaders(
          selectedProvider.address,
          JSON.stringify(messagesToSend)
        );
        
        
      } catch (headerError) {
        throw headerError;
      }

      // Step 6: Send a request to the service use stream
      const { endpoint, model } = currentMetadata;

      const response = await fetch(`${endpoint}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...headers,
        },
        body: JSON.stringify({
          messages: [
            ...messages
              .filter((m) => m.role !== "system")
              .map((m) => ({ role: m.role, content: m.content })),
            { role: userMessage.role, content: userMessage.content },
          ],
          model: model,
          stream: true,
        }),
      });

      if (!response.ok) {
        // Try to get detailed error message from response body
        let errorMessage = `HTTP error! status: ${response.status}`;
        try {
          const errorBody = await response.text();
          if (errorBody) {
            // Try to parse as JSON first
            try {
              const errorJson = JSON.parse(errorBody);
              errorMessage = JSON.stringify(errorJson, null, 2);
            } catch {
              // If not JSON, use the raw text
              errorMessage = errorBody;
            }
          }
        } catch {
          // If can't read body, keep original message
        }
        throw new Error(errorMessage);
      }

      const reader = response.body?.getReader();
      if (!reader) {
        throw new Error("Failed to get response reader");
      }

      // Initialize streaming response
      const assistantMessage: Message = {
        role: "assistant",
        content: "",
        timestamp: Date.now(),
        isVerified: null,
        isVerifying: false,
      };

      setMessages((prev) => [...prev, assistantMessage]);

      const decoder = new TextDecoder();
      let buffer = "";
      let chatId = "";
      let completeContent = "";

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              const data = line.slice(6);
              if (data === "[DONE]") continue;

              try {
                const parsed = JSON.parse(data);
                if (!chatId && parsed.id) {
                  chatId = parsed.id;
                }

                const content = parsed.choices?.[0]?.delta?.content;
                if (content) {
                  // Hide loading indicator on first content received
                  if (!firstContentReceived) {
                    setIsLoading(false);
                    firstContentReceived = true;
                  }
                  
                  completeContent += content;
                  setMessages((prev) =>
                    prev.map((msg, index) =>
                      index === prev.length - 1
                        ? {
                            ...msg,
                            content: completeContent,
                            chatId,
                            isVerified: msg.isVerified,
                            isVerifying: msg.isVerifying,
                          }
                        : msg
                    )
                  );

                  // Trigger auto-scroll during streaming only if user isn't manually scrolling
                  setTimeout(() => {
                    if (!isUserScrollingRef.current) {
                      messagesEndRef.current?.scrollIntoView({
                        behavior: "smooth",
                      });
                    }
                  }, 50);
                }
              } catch {
                // Skip invalid JSON
              }
            }
          }
        }
      } finally {
        reader.releaseLock();
      }

      // Update final message with complete content and chatId
      setMessages((prev) =>
        prev.map((msg, index) =>
          index === prev.length - 1
            ? {
                ...msg,
                content: completeContent,
                chatId,
                isVerified: msg.isVerified || null,
                isVerifying: msg.isVerifying || false,
              }
            : msg
        )
      );

      // Save assistant message to database in the background using the same session
      if (completeContent.trim() && currentSessionForAssistant) {
        // Directly save to database using the session ID we got from user message
        try {
          const { dbManager } = await import('../../../../lib/database');
          await dbManager.saveMessage(currentSessionForAssistant, {
            role: "assistant",
            content: completeContent,
            timestamp: Date.now(),
            chat_id: chatId,
            is_verified: null,
            is_verifying: false,
            provider_address: selectedProvider?.address || '',
          });
        } catch (err) {
        }
      }

      // Ensure loading is stopped even if no content was received
      if (!firstContentReceived) {
        setIsLoading(false);
      }
      // Always stop streaming when done
      setIsStreaming(false);
    } catch (err: unknown) {
      let errorMessage = "Failed to send message. Please try again.";
      
      if (err instanceof Error) {
        errorMessage = err.message;
      } else if (typeof err === 'string') {
        errorMessage = err;
      } else if (err && typeof err === 'object') {
        try {
          errorMessage = JSON.stringify(err, null, 2);
        } catch {
          errorMessage = String(err);
        }
      }
      
      setErrorWithTimeout(`Chat error: ${errorMessage}`);


      // Remove the loading message if it exists
      setMessages((prev) =>
        prev.filter((msg) => msg.role !== "assistant" || msg.content !== "")
      );
      
      // Ensure loading is stopped in case of error
      if (!firstContentReceived) {
        setIsLoading(false);
      }
      // Always stop streaming in case of error
      setIsStreaming(false);
    }
  };

  // Step 7: Process the response (verification function)
  const verifyResponse = async (message: Message, messageIndex: number) => {

    if (!broker || !selectedProvider || !message.chatId) {
      return;
    }

    // Set verifying state and reset previous verification result
    setMessages((prev) => {
      const updated = prev.map((msg, index) =>
        index === messageIndex
          ? { ...msg, isVerifying: true, isVerified: null }
          : msg
      );
      return updated;
    });

    // Force a re-render to ensure state change is visible
    await new Promise((resolve) => setTimeout(resolve, 100));

    try {

      // Add minimum loading time to ensure user sees the loading effect
      const [isValid] = await Promise.all([
        broker.inference.processResponse(
          selectedProvider.address,
          message.content,
          message.chatId
        ),
        new Promise((resolve) => setTimeout(resolve, 1000)), // Minimum 1 second loading
      ]);


      // Update verification result with visual feedback
      setMessages((prev) => {
        const updated = prev.map((msg, index) =>
          index === messageIndex
            ? { ...msg, isVerified: isValid, isVerifying: false }
            : msg
        );
        return updated;
      });

      // Show visual feedback notification
      if (isValid) {
      } else {
      }
    } catch (err: unknown) {
      // Mark as verification failed with minimum loading time
      await new Promise((resolve) => setTimeout(resolve, 1000));
      setMessages((prev) => {
        const updated = prev.map((msg, index) =>
          index === messageIndex
            ? { ...msg, isVerified: false, isVerifying: false }
            : msg
        );
        return updated;
      });
    }
  };

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

      
      // Refresh ledger info after successful verification
      if (acknowledged) {
        await refreshLedgerInfo();
      }
      
      // Progress tutorial to top-up step if tutorial is active
      if (showTutorial && tutorialStep === 'verify' && acknowledged) {
        setTutorialStep('top-up');
      }
    } catch (err: unknown) {
      const errorMessage =
        err instanceof Error
          ? err.message
          : "Failed to verify provider. Please try again.";
      setErrorWithTimeout(`Verification error: ${errorMessage}`);
    } finally {
      setIsVerifyingProvider(false);
    }
  };

  // Note: handleDeposit is now handled globally in LayoutContent

  const handleTopUp = async () => {
    if (!broker || !selectedProvider || !topUpAmount || parseFloat(topUpAmount) <= 0) {
      return;
    }

    setIsTopping(true);
    setErrorWithTimeout(null);

    try {
      const amountInA0gi = parseFloat(topUpAmount);
      const amountInNeuron = a0giToNeuron(amountInA0gi);
      
      
      // Call the transfer function with neuron amount
      await broker.ledger.transferFund(
        selectedProvider.address,
        'inference',
        amountInNeuron
      );

      
      // Refresh both ledger info and provider balance in parallel for better performance
      const [, account] = await Promise.all([
        refreshLedgerInfo(), // Refresh ledger info to update available balance
        broker.inference.getAccount(selectedProvider.address) // Get updated provider account
      ]);
      
      // Update provider balance state
      if (account && account.balance) {
        const balanceInA0gi = neuronToA0gi(account.balance - account.pendingRefund);
        const pendingRefundInA0gi = neuronToA0gi(account.pendingRefund);
        setProviderBalance(balanceInA0gi);
        setProviderBalanceNeuron(account.balance);
        setProviderPendingRefund(pendingRefundInA0gi);
      }
      
      // Close modal and reset amount
      setShowTopUpModal(false);
      setTopUpAmount("");
      
      // Complete tutorial if active
      if (showTutorial && tutorialStep === 'top-up') {
        setShowTutorial(false);
        setTutorialStep(null);
        // Mark tutorial as seen for this provider
        localStorage.setItem(`tutorial_seen_${selectedProvider.address}`, 'true');
      }
    } catch (err: unknown) {
      const errorMessage =
        err instanceof Error
          ? err.message
          : "Failed to top up. Please try again.";
      setErrorWithTimeout(`Top up error: ${errorMessage}`);
    } finally {
      setIsTopping(false);
    }
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

      <div className="flex bg-white rounded-xl border border-gray-200" style={{ height: 'calc(100vh - 175px)' }}>
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

      {/* Top Up Modal */}
      {showTopUpModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop with blur effect */}
          <div
            className="absolute inset-0"
            style={{
              backgroundColor: "rgba(255, 255, 255, 0.5)",
              backdropFilter: "blur(4px)",
              WebkitBackdropFilter: "blur(4px)",
            }}
            onClick={() => {
              if (!isTopping) {
                setShowTopUpModal(false);
                setTopUpAmount("");
              }
            }}
          />

          {/* Modal content */}
          <div className="relative z-10 mx-auto p-8 w-96 bg-white rounded-xl shadow-2xl border border-gray-100">
            <div className="flex flex-col">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold text-gray-900">
                  Add Funds for the Current Provider Service
                </h3>
                <button
                  onClick={() => {
                    if (!isTopping) {
                      setShowTopUpModal(false);
                      setTopUpAmount("");
                    }
                  }}
                  className="text-gray-400 hover:text-gray-600"
                  disabled={isTopping}
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              <div className="space-y-4">
                {/* Transfer Amount Input */}
                <div>
                  <p className="mb-3 text-sm text-gray-600">
                    Transfer funds from your available balance to pay for this provider's services. Current funds: <span className="font-semibold">{(providerBalance ?? 0).toFixed(6)} A0GI</span>
                  </p>
                  
                  {/* Check if there's pending refund */}
                  {providerPendingRefund && providerPendingRefund > 0 ? (
                    <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                      <div className="text-sm text-yellow-800">
                        <p className="mb-2">
                          <span className="font-semibold">Pending Refund: {providerPendingRefund.toFixed(6)} A0GI</span>
                        </p>
                        <p className="text-xs mb-3">
                          You previously requested to withdraw funds from this provider. Please cancel the withdrawal request to replenish the fund.
                        </p>
                        <button
                          onClick={() => {
                            setTopUpAmount(providerPendingRefund.toFixed(6));
                          }}
                          className="px-3 py-1 bg-yellow-600 text-white text-xs font-medium rounded hover:bg-yellow-700 transition-colors cursor-pointer"
                          disabled={isTopping}
                        >
                          Use Pending Refund ({providerPendingRefund.toFixed(6)} A0GI)
                        </button>
                      </div>
                    </div>
                  ) : null}
                  
                  <div className="text-xs text-gray-500 mb-3">
                    Available for Transfer: {ledgerInfo && providerPendingRefund !== null ? (
                      <span className="font-medium">{(parseFloat(ledgerInfo.availableBalance) + (providerPendingRefund || 0)).toFixed(6)} A0GI</span>
                    ) : (
                      <span>Loading...</span>
                    )} 
                    (<a 
                      href="/ledger" 
                      className="text-purple-500 hover:text-purple-700 hover:underline cursor-pointer"
                      title="Go to ledger page to view details and deposit funds"
                    >
                      view details and deposit in account page
                    </a>)
                  </div>
                  <div className="relative">
                    <input
                      type="number"
                      id="top-up-amount"
                      value={topUpAmount}
                      onChange={(e) => setTopUpAmount(e.target.value)}
                      placeholder={providerPendingRefund && providerPendingRefund > 0 ? "" : "Enter amount"}
                      min="0"
                      step="0.000001"
                      className="w-full px-4 py-3 pr-16 border border-gray-200 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent text-lg disabled:bg-gray-100 disabled:cursor-not-allowed"
                      disabled={isTopping || !!(providerPendingRefund && providerPendingRefund > 0)}
                    />
                    <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                      <span className="text-gray-500 sm:text-sm">A0GI</span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={handleTopUp}
                  disabled={
                    isTopping ||
                    !topUpAmount ||
                    parseFloat(topUpAmount) <= 0 ||
                    !ledgerInfo ||
                    parseFloat(topUpAmount) > parseFloat(ledgerInfo.totalBalance)
                  }
                  className="w-full px-4 py-3 bg-purple-600 text-white text-base font-medium rounded-lg shadow-sm hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors cursor-pointer"
                >
                  {isTopping ? (
                    <span className="flex items-center justify-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2"></div>
                      Processing...
                    </span>
                  ) : (
                    "Transfer"
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tutorial Overlay */}
      {showTutorial && tutorialStep && (
        <>
          {/* Dark overlay */}
          <div 
            className="fixed inset-0 bg-black/50 z-40"
            onClick={() => {
              setShowTutorial(false);
              setTutorialStep(null);
            }}
          />
          
          {/* Floating tutorial message */}
          <div className="fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-50">
            <div className="bg-white rounded-lg shadow-xl p-6 max-w-sm mx-4">
              {tutorialStep === 'verify' && (
                <>
                  <h3 className="font-semibold text-gray-900 mb-2">
                    Verify Provider
                  </h3>
                  <p className="text-sm text-gray-600 mb-4">
                    Verify that the provider is running in a verifiable TEE environment
                  </p>
                </>
              )}
              {tutorialStep === 'top-up' && (
                <>
                  <h3 className="font-semibold text-gray-900 mb-2">
                    Top Up Provider
                  </h3>
                  <p className="text-sm text-gray-600 mb-4">
                    Fund the provider with a certain amount (excess funds can be refunded)
                  </p>
                </>
              )}
              <button
                onClick={() => {
                  setShowTutorial(false);
                  setTutorialStep(null);
                }}
                className="w-full px-4 py-2 bg-purple-600 text-white text-sm font-medium rounded-lg hover:bg-purple-700 transition-colors cursor-pointer"
              >
                Got it
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

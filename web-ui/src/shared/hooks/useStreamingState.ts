import { useState } from 'react';

interface UseStreamingStateReturn {
  // Input state
  inputMessage: string;
  setInputMessage: (message: string) => void;
  
  // Loading states
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
  isStreaming: boolean;
  setIsStreaming: (streaming: boolean) => void;
  
  // Computed states
  isProcessing: boolean;
}

export function useStreamingState(): UseStreamingStateReturn {
  // Input state
  const [inputMessage, setInputMessage] = useState("");
  
  // Loading states
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  
  // Computed states
  const isProcessing = isLoading || isStreaming;

  return {
    // Input state
    inputMessage,
    setInputMessage,
    
    // Loading states
    isLoading,
    setIsLoading,
    isStreaming,
    setIsStreaming,
    
    // Computed states
    isProcessing,
  };
}
import { useState, useRef, useEffect, useCallback } from 'react';

interface UseErrorWithTimeoutOptions {
  timeoutMs?: number;
}

interface UseErrorWithTimeoutReturn {
  error: string | null;
  setError: (error: string | null) => void;
  setErrorWithTimeout: (error: string | null) => void;
  clearError: () => void;
}

export function useErrorWithTimeout(
  options: UseErrorWithTimeoutOptions = {}
): UseErrorWithTimeoutReturn {
  const { timeoutMs = 8000 } = options;
  
  const [error, setError] = useState<string | null>(null);
  const errorTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const clearError = useCallback(() => {
    setError(null);
    if (errorTimeoutRef.current) {
      clearTimeout(errorTimeoutRef.current);
      errorTimeoutRef.current = null;
    }
  }, []);

  const setErrorWithTimeout = useCallback((errorMessage: string | null) => {
    // Clear existing timeout
    if (errorTimeoutRef.current) {
      clearTimeout(errorTimeoutRef.current);
      errorTimeoutRef.current = null;
    }
    
    setError(errorMessage);
    
    // Set timeout to clear error after specified time
    if (errorMessage) {
      errorTimeoutRef.current = setTimeout(() => {
        setError(null);
        errorTimeoutRef.current = null;
      }, timeoutMs);
    }
  }, [timeoutMs]);

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (errorTimeoutRef.current) {
        clearTimeout(errorTimeoutRef.current);
      }
    };
  }, []);

  return {
    error,
    setError,
    setErrorWithTimeout,
    clearError,
  };
}
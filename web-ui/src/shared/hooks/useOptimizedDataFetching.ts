import { useState, useEffect, useCallback, useRef } from 'react';

interface DataFetchingOptions<T> {
  fetchFn: () => Promise<T>;
  cacheKey?: string;
  cacheTTL?: number; // Time to live in milliseconds
  dependencies?: unknown[];
  initialData?: T | null;
  skip?: boolean;
}

interface DataFetchingResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

// Simple cache implementation
class DataCache {
  private cache = new Map<string, { data: unknown; timestamp: number; ttl: number }>();

  set<T>(key: string, data: T, ttl: number = 5 * 60 * 1000): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl,
    });
  }

  get<T>(key: string): T | null {
    const cached = this.cache.get(key);
    if (!cached) return null;

    const now = Date.now();
    if (now - cached.timestamp > cached.ttl) {
      this.cache.delete(key);
      return null;
    }

    return cached.data as T;
  }

  clear(key?: string): void {
    if (key) {
      this.cache.delete(key);
    } else {
      this.cache.clear();
    }
  }
}

const dataCache = new DataCache();

export function useOptimizedDataFetching<T>({
  fetchFn,
  cacheKey,
  cacheTTL = 5 * 60 * 1000, // 5 minutes default
  dependencies = [],
  initialData = null,
  skip = false,
}: DataFetchingOptions<T>): DataFetchingResult<T> {
  const [data, setData] = useState<T | null>(initialData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Use ref to track the current request to prevent race conditions
  const currentRequestRef = useRef<symbol | null>(null);
  const mountedRef = useRef(true);

  const fetchData = useCallback(async (skipCache = false) => {
    if (skip) return;

    // Check cache first if cacheKey is provided and we're not skipping cache
    if (!skipCache && cacheKey) {
      const cachedData = dataCache.get<T>(cacheKey);
      if (cachedData) {
        setData(cachedData);
        setError(null);
        return;
      }
    }

    setLoading(true);
    setError(null);

    const currentRequest = Symbol('currentRequest');
    currentRequestRef.current = currentRequest;
    
    (async () => {
      try {
        const result = await fetchFn();
        
        // Only update state if this component is still mounted and this is the current request
        if (mountedRef.current && currentRequestRef.current === currentRequest) {
          setData(result);
          setError(null);
          
          // Cache the result if cacheKey is provided
          if (cacheKey) {
            dataCache.set(cacheKey, result, cacheTTL);
          }
        }
      } catch (err) {
        if (mountedRef.current && currentRequestRef.current === currentRequest) {
          const errorMessage = err instanceof Error ? err.message : 'An error occurred';
          setError(errorMessage);
          setData(null);
        }
      } finally {
        if (mountedRef.current && currentRequestRef.current === currentRequest) {
          setLoading(false);
        }
      }
    })();

    return currentRequest;
  }, [fetchFn, cacheKey, cacheTTL, skip]);

  const refetch = useCallback(async () => {
    await fetchData(true); // Skip cache on manual refetch
  }, [fetchData]);

  // Effect for dependency-based fetching
  useEffect(() => {
    if (!skip) {
      fetchData();
    }
    
    return () => {
      currentRequestRef.current = null;
    };
  }, dependencies);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  return {
    data,
    loading,
    error,
    refetch,
  };
}

// Hook for parallel data fetching
export function useParallelDataFetching<T extends Record<string, unknown>>(
  fetchFunctions: Record<keyof T, () => Promise<T[keyof T]>>,
  options: {
    skip?: boolean;
    dependencies?: unknown[];
  } = {}
) {
  const [data, setData] = useState<Partial<T>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  const fetchAll = useCallback(async () => {
    if (options.skip) return;

    setLoading(true);
    setError(null);

    try {
      const promises = Object.entries(fetchFunctions).map(async ([key, fetchFn]) => {
        try {
          const result = await (fetchFn as () => Promise<unknown>)();
          return [key, result];
        } catch (err) {
          return [key, null];
        }
      });

      const results = await Promise.all(promises);
      
      if (mountedRef.current) {
        const newData: Partial<T> = {};
        results.forEach(([key, value]) => {
          newData[key as keyof T] = value as T[keyof T];
        });
        setData(newData);
      }
    } catch (err) {
      if (mountedRef.current) {
        const errorMessage = err instanceof Error ? err.message : 'An error occurred';
        setError(errorMessage);
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [fetchFunctions, options.skip]);

  useEffect(() => {
    fetchAll();
  }, options.dependencies || []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  return {
    data,
    loading,
    error,
    refetch: fetchAll,
  };
}

// Clear cache utility
export const clearDataCache = (key?: string) => {
  dataCache.clear(key);
};
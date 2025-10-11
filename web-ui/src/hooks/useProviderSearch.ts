import { useState, useEffect, useCallback } from 'react';
import { type ChatMessage } from '../lib/database';

interface Message {
  role: "system" | "user" | "assistant";
  content: string;
  timestamp?: number;
  chatId?: string;
  isVerified?: boolean | null;
  isVerifying?: boolean;
}

interface SearchResult extends Message {
  sessionId: string;
}

interface ChatHistoryService {
  searchMessages: (query: string) => Promise<ChatMessage[]>;
}

interface UseProviderSearchOptions {
  debounceMs?: number;
}

interface UseProviderSearchReturn {
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  searchResults: SearchResult[];
  isSearching: boolean;
  clearSearch: () => void;
}

export function useProviderSearch(
  chatHistory: ChatHistoryService,
  options: UseProviderSearchOptions = {}
): UseProviderSearchReturn {
  const { debounceMs = 300 } = options;
  
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);

  // Debounced search implementation
  useEffect(() => {
    const timeoutId = setTimeout(async () => {
      if (!searchQuery.trim()) {
        setSearchResults([]);
        setIsSearching(false);
        return;
      }

      setIsSearching(true);
      try {
        const results = await chatHistory.searchMessages(searchQuery);
        const searchMessages: SearchResult[] = results.map(msg => ({
          role: msg.role,
          content: msg.content,
          timestamp: msg.timestamp,
          chatId: msg.chat_id,
          isVerified: msg.is_verified,
          isVerifying: msg.is_verifying,
          sessionId: msg.session_id || '',
        }));
        setSearchResults(searchMessages);
      } catch (err) {
        setSearchResults([]);
      } finally {
        setIsSearching(false);
      }
    }, debounceMs);

    return () => clearTimeout(timeoutId);
  }, [searchQuery, debounceMs]);

  const clearSearch = useCallback(() => {
    setSearchQuery('');
    setSearchResults([]);
    setIsSearching(false);
  }, []);

  return {
    searchQuery,
    setSearchQuery,
    searchResults,
    isSearching,
    clearSearch,
  };
}
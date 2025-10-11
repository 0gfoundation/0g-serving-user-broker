import { useState, useEffect, useCallback } from 'react';
import { dbManager, type ChatMessage, type ChatSession } from '../lib/database';

export interface UseChatHistoryOptions {
  walletAddress: string;
  providerAddress?: string;
  autoSave?: boolean;
}

export interface UseChatHistoryReturn {
  // Current session
  currentSessionId: string | null;
  messages: ChatMessage[];
  
  // Session management
  sessions: ChatSession[];
  createNewSession: (title?: string) => Promise<string>;
  loadSession: (sessionId: string) => Promise<void>;
  deleteSession: (sessionId: string) => Promise<void>;
  updateSessionTitle: (sessionId: string, title: string) => Promise<void>;
  
  // Message management
  addMessage: (message: Omit<ChatMessage, 'id' | 'timestamp'>) => Promise<string | null>;
  updateMessage: (index: number, updates: Partial<ChatMessage>) => void;
  clearCurrentSession: () => Promise<void>;
  
  // Search and history
  searchMessages: (query: string) => Promise<ChatMessage[]>;
  
  // State
  isLoading: boolean;
  error: string | null;
}

export function useChatHistory({ walletAddress, providerAddress, autoSave = true }: UseChatHistoryOptions): UseChatHistoryReturn {
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Initialize database and load sessions
  useEffect(() => {
    const initializeDatabase = async () => {
      try {
        setIsLoading(true);
        await dbManager.init();
        await loadSessions();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Database initialization failed');
      } finally {
        setIsLoading(false);
      }
    };

    initializeDatabase();
  }, [walletAddress]);

  // Load sessions for current wallet (all providers)
  const loadSessions = useCallback(async () => {
    try {
      // Only pass walletAddress if it's not empty, don't filter by provider
      const effectiveWalletAddress = walletAddress || undefined;
      const walletSessions = await dbManager.getChatSessions(effectiveWalletAddress);
      setSessions(walletSessions);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load sessions');
    }
  }, [walletAddress]);

  // Create new session (not tied to specific provider)
  const createNewSession = useCallback(async (title?: string): Promise<string> => {
    try {
      // Use empty string for provider_address as sessions are now shared across providers
      const sessionId = await dbManager.createChatSession('', walletAddress || '', title);
      setCurrentSessionId(sessionId);
      setMessages([]);
      await loadSessions(); // Refresh sessions list
      return sessionId;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create session');
      throw err;
    }
  }, [walletAddress, loadSessions]);

  // Load existing session
  const loadSession = useCallback(async (sessionId: string) => {
    try {
      setIsLoading(true);
      const sessionMessages = await dbManager.getMessages(sessionId);
      setCurrentSessionId(sessionId);
      setMessages(sessionMessages);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load session');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Delete session
  const deleteSession = useCallback(async (sessionId: string) => {
    try {
      await dbManager.deleteChatSession(sessionId);
      
      // If we deleted the current session, clear it
      if (currentSessionId === sessionId) {
        setCurrentSessionId(null);
        setMessages([]);
      }
      
      // Refresh sessions list
      await loadSessions();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete session');
    }
  }, [currentSessionId, loadSessions]);

  // Update session title
  const updateSessionTitle = useCallback(async (sessionId: string, title: string) => {
    try {
      await dbManager.updateChatSessionTitle(sessionId, title);
      await loadSessions(); // Refresh sessions list
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update session title');
    }
  }, [loadSessions]);

  // Generate chat title from first user message
  const generateChatTitle = useCallback((content: string): string => {
    // Take first 30 characters and add ellipsis if longer
    const maxLength = 30;
    const cleanContent = content.trim().replace(/\n/g, ' ');
    if (cleanContent.length <= maxLength) {
      return cleanContent;
    }
    return cleanContent.substring(0, maxLength).trim() + '...';
  }, []);

  // Add message to current session
  const addMessage = useCallback(async (messageData: Omit<ChatMessage, 'id' | 'timestamp'>): Promise<string | null> => {
    try {
      // If no current session, create one
      let sessionId = currentSessionId;
      if (!sessionId) {
        sessionId = await createNewSession();
        // Update the current session ID immediately
        setCurrentSessionId(sessionId);
      }

      const message: Omit<ChatMessage, 'id'> = {
        ...messageData,
        timestamp: Date.now(),
        provider_address: providerAddress,
      };

      // Save to database if autoSave is enabled
      if (autoSave) {
        await dbManager.saveMessage(sessionId, message);
        
        // If this is the first user message, update session title
        if (messageData.role === 'user') {
          // Check if session already has a title by checking messages in database
          const existingMessages = await dbManager.getMessages(sessionId);
          const userMessages = existingMessages.filter(m => m.role === 'user');
          
          // Only set title if this is the first user message
          if (userMessages.length === 1) { // Just saved one user message
            const title = generateChatTitle(messageData.content);
            await dbManager.updateChatSessionTitle(sessionId, title);
            await loadSessions(); // Refresh sessions to show new title
          }
        }
      }

      // Return the session ID for the caller to use
      return sessionId;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add message');
      return null;
    }
  }, [currentSessionId, autoSave, createNewSession, messages, generateChatTitle, loadSessions]);

  // Update message in current session
  const updateMessage = useCallback((index: number, updates: Partial<ChatMessage>) => {
    setMessages(prev => {
      const newMessages = [...prev];
      if (index >= 0 && index < newMessages.length) {
        newMessages[index] = { ...newMessages[index], ...updates };
        
        // Update in database if message has ID and verification status changed
        const message = newMessages[index];
        if (message.id && (updates.is_verified !== undefined || updates.is_verifying !== undefined)) {
          dbManager.updateMessageVerification(
            message.id,
            message.is_verified ?? false,
            message.is_verifying ?? false
          ).catch(err => {
            // Silently handle verification update errors
          });
        }
      }
      return newMessages;
    });
  }, []);

  // Clear current session messages
  const clearCurrentSession = useCallback(async () => {
    if (currentSessionId) {
      try {
        await dbManager.clearMessages(currentSessionId);
        setMessages([]);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to clear session');
      }
    } else {
      setMessages([]);
    }
  }, [currentSessionId]);

  // Search messages
  const searchMessages = useCallback(async (query: string): Promise<ChatMessage[]> => {
    try {
      // Only pass walletAddress if it's not empty
      const effectiveWalletAddress = walletAddress || undefined;
      return await dbManager.searchMessages(query, effectiveWalletAddress, providerAddress);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to search messages');
      return [];
    }
  }, [walletAddress, providerAddress]);

  return {
    // Current session
    currentSessionId,
    messages,
    
    // Session management
    sessions,
    createNewSession,
    loadSession,
    deleteSession,
    updateSessionTitle,
    
    // Message management
    addMessage,
    updateMessage,
    clearCurrentSession,
    
    // Search and history
    searchMessages,
    
    // State
    isLoading,
    error,
  };
}
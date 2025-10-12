"use client";

import React from 'react';

interface ChatInputProps {
  inputMessage: string;
  setInputMessage: (message: string) => void;
  isProcessing: boolean;
  isVerifyingProvider: boolean;
  providerAcknowledged: boolean | null;
  showTutorial: boolean;
  tutorialStep: 'verify' | 'top-up' | null;
  setShowTutorial: (show: boolean) => void;
  setTutorialStep: (step: 'verify' | 'top-up' | null) => void;
  onSendMessage: () => void;
  onVerifyProvider: () => void;
}

export function ChatInput({
  inputMessage,
  setInputMessage,
  isProcessing,
  isVerifyingProvider,
  providerAcknowledged,
  showTutorial,
  tutorialStep,
  setShowTutorial,
  setTutorialStep,
  onSendMessage,
  onVerifyProvider,
}: ChatInputProps) {
  return (
    <div className="p-4 border-t border-gray-200">
      <div className="flex space-x-3 items-end">
        <textarea
          value={inputMessage}
          onChange={(e) => {
            setInputMessage(e.target.value);
            // Auto-resize textarea
            const textarea = e.target as HTMLTextAreaElement;
            textarea.style.height = 'auto';
            textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              if (providerAcknowledged === false) {
                onVerifyProvider();
              } else if (inputMessage.trim() && !isProcessing) {
                onSendMessage();
              }
            }
          }}
          placeholder={isProcessing ? "AI is responding..." : "Type your message... (Shift+Enter for new line)"}
          className="flex-1 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-purple-500 focus:border-purple-500 resize-none overflow-y-auto disabled:bg-gray-100 disabled:text-gray-500 disabled:cursor-not-allowed"
          style={{ minHeight: '40px', maxHeight: '120px' }}
          rows={1}
          disabled={isProcessing}
        />
        <button
          onClick={() => {
            if (providerAcknowledged === false) {
              // Close tutorial when verify button is clicked
              if (showTutorial && tutorialStep === 'verify') {
                setShowTutorial(false);
                setTutorialStep(null);
              }
              onVerifyProvider();
            } else {
              onSendMessage();
            }
          }}
          disabled={
            providerAcknowledged === false
              ? isVerifyingProvider
              : !inputMessage.trim() || isProcessing
          }
          className={`${
            providerAcknowledged === false
              ? "bg-yellow-600 hover:bg-yellow-700 disabled:bg-yellow-400"
              : "bg-purple-600 hover:bg-purple-700 disabled:bg-purple-400"
          } text-white px-4 py-2 rounded-md font-medium flex items-center space-x-2 cursor-pointer ${
            showTutorial && tutorialStep === 'verify' && providerAcknowledged === false
              ? 'ring-4 ring-yellow-400 ring-opacity-75 animate-pulse relative z-50'
              : ''
          }`}
          title={
            providerAcknowledged === false
              ? "Verify provider to enable messaging"
              : `Button status: ${
                  !inputMessage.trim() || isProcessing ? "disabled" : "enabled"
                }`
          }
        >
          {isProcessing || isVerifyingProvider ? (
            <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>
          ) : (
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              {providerAcknowledged === false ? (
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              ) : (
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
                />
              )}
            </svg>
          )}
          <span>
            {providerAcknowledged === false ? "Verify Provider" : "Send"}
          </span>
        </button>
      </div>
    </div>
  );
}
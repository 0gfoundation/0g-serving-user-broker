"use client";

import * as React from "react";
import { useRef, useEffect } from "react";
import ReactMarkdown from "react-markdown";

interface Message {
  role: "system" | "user" | "assistant";
  content: string;
  timestamp?: number;
  chatId?: string;
  isVerified?: boolean | null;
  isVerifying?: boolean;
}

interface MessageListProps {
  messages: Message[];
  isLoading: boolean;
  isStreaming: boolean;
  verifyResponse: (message: Message, originalIndex: number) => void;
}

export function MessageList({
  messages,
  isLoading,
  isStreaming,
  verifyResponse,
}: MessageListProps) {
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isLoading]);

  return (
    <div ref={messagesContainerRef} className="flex-1 overflow-y-auto p-4 space-y-4">
      {messages
        .map((message, originalIndex) => ({ message, originalIndex }))
        .filter(({ message }) => message.role !== "system")
        .map(({ message, originalIndex }, index) => (
          <div
            key={index}
            className={`flex ${
              message.role === "user" ? "justify-end" : "justify-start"
            }`}
          >
            <div className="flex items-start space-x-2 max-w-[85%] sm:max-w-[80%]">
              <div
                className={`rounded-lg px-4 py-2 break-words transition-colors ${
                  message.role === "user"
                    ? "bg-purple-600 text-white"
                    : "bg-gray-100 text-gray-900"
                }`}
                style={{ maxWidth: '100%', overflowWrap: 'break-word' }}
                data-message-content={message.content.substring(0, 100)}
              >
                <div className="text-sm">
                  {message.role === "assistant" ? (
                    <div className="markdown-content">
                      <ReactMarkdown
                        components={{
                          h1: ({ children }) => (
                            <h1 className="text-xl font-bold mb-3 mt-4 text-gray-900">
                              {children}
                            </h1>
                          ),
                          h2: ({ children }) => (
                            <h2 className="text-lg font-semibold mb-2 mt-3 text-gray-900">
                              {children}
                            </h2>
                          ),
                          h3: ({ children }) => (
                            <h3 className="text-base font-semibold mb-2 mt-3 text-gray-900">
                              {children}
                            </h3>
                          ),
                          p: ({ children }) => (
                            <p className="mb-2 text-gray-800 leading-relaxed">
                              {children}
                            </p>
                          ),
                          strong: ({ children }) => (
                            <strong className="font-semibold text-gray-900">
                              {children}
                            </strong>
                          ),
                          em: ({ children }) => (
                            <em className="italic text-gray-800">
                              {children}
                            </em>
                          ),
                          code: ({ children }) => (
                            <code className="bg-purple-50 text-purple-600 px-1 py-0.5 rounded text-xs font-mono">
                              {children}
                            </code>
                          ),
                          pre: ({ children }) => (
                            <pre className="bg-gray-50 border border-gray-200 rounded-md p-3 my-3 overflow-x-auto text-sm">
                              {children}
                            </pre>
                          ),
                          ul: ({ children }) => (
                            <ul className="list-disc list-inside mb-2 text-gray-800">
                              {children}
                            </ul>
                          ),
                          ol: ({ children }) => (
                            <ol className="list-decimal list-inside mb-2 text-gray-800">
                              {children}
                            </ol>
                          ),
                          li: ({ children }) => (
                            <li className="mb-1 text-gray-800">
                              {children}
                            </li>
                          ),
                          blockquote: ({ children }) => (
                            <blockquote className="border-l-4 border-purple-500 pl-4 my-3 text-gray-700 italic">
                              {children}
                            </blockquote>
                          ),
                          a: ({ href, children }) => (
                            <a
                              href={href}
                              className="text-purple-600 hover:underline"
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              {children}
                            </a>
                          ),
                        }}
                      >
                        {message.content}
                      </ReactMarkdown>
                    </div>
                  ) : (
                    <div className="whitespace-pre-wrap break-words" style={{ whiteSpace: 'pre-wrap', wordWrap: 'break-word', maxWidth: '100%' }}>
                      {message.content}
                    </div>
                  )}
                </div>
                {message.timestamp && (
                  <div
                    className={`flex items-center justify-between text-xs mt-1 ${
                      message.role === "user"
                        ? "text-purple-200"
                        : "text-gray-500"
                    }`}
                  >
                    <span className="whitespace-nowrap">
                      {new Date(message.timestamp).toLocaleTimeString()}
                    </span>

                    {/* Verification controls - only show for assistant messages that are complete */}
                    {message.role === "assistant" &&
                      message.chatId &&
                      !isLoading &&
                      !isStreaming &&
                      (() => {
                        const isExpired =
                          message.timestamp &&
                          Date.now() - message.timestamp > 20 * 60 * 1000; // 20 minutes
                        return (
                          <div className="flex items-center">
                            {/* Verification button for initial verification */}
                            {!message.isVerifying &&
                              (message.isVerified === null ||
                                message.isVerified === undefined) && (
                                <button
                                  onClick={() => {
                                    if (!isExpired) {
                                      verifyResponse(
                                        message,
                                        originalIndex
                                      );
                                    }
                                  }}
                                  className={`px-1.5 py-0.5 rounded-full border transition-colors text-xs ${
                                    isExpired
                                      ? "bg-gray-50 text-gray-400 border-gray-200 cursor-not-allowed"
                                      : "bg-purple-50 hover:bg-purple-100 text-purple-600 hover:text-purple-700 border-purple-200"
                                  }`}
                                  title={
                                    isExpired
                                      ? "Verification information is only retained for 20 minutes"
                                      : "Verify response authenticity with TEE"
                                  }
                                  disabled={!!isExpired}
                                >
                                  Verify
                                </button>
                              )}

                            {/* Verification loading indicator */}
                            {message.isVerifying && (
                              <div className="inline-flex items-center px-1.5 py-0.5 bg-purple-50 rounded-full border border-purple-200">
                                <div className="animate-spin rounded-full h-2.5 w-2.5 border border-purple-400 border-t-transparent mr-1"></div>
                                <span className="text-xs text-purple-600">
                                  Verifying...
                                </span>
                              </div>
                            )}

                            {/* Verification status display */}
                            {!message.isVerifying &&
                              message.isVerified !== null &&
                              message.isVerified !== undefined && (
                                <button
                                  onClick={() => {
                                    if (!isExpired) {
                                      verifyResponse(
                                        message,
                                        originalIndex
                                      );
                                    }
                                  }}
                                  className={`px-1.5 py-0.5 rounded-full border transition-all duration-300 group relative text-xs ${
                                    isExpired
                                      ? "bg-gray-50 text-gray-400 border-gray-200 cursor-not-allowed"
                                      : message.isVerified
                                      ? "bg-green-50 hover:bg-purple-100 text-green-600 hover:text-purple-600 border-green-200 hover:border-purple-200"
                                      : "bg-red-50 hover:bg-purple-100 text-red-600 hover:text-purple-600 border-red-200 hover:border-purple-200"
                                  }`}
                                  title={
                                    isExpired
                                      ? "Verification information is only retained for 20 minutes"
                                      : message.isVerified
                                      ? "TEE Verified - Click to verify again"
                                      : "TEE Verification Failed - Click to retry"
                                  }
                                  disabled={!!isExpired}
                                >
                                  {/* Default text - shown when not hovering */}
                                  <span
                                    className={
                                      isExpired ? "" : "group-hover:hidden"
                                    }
                                  >
                                    {isExpired
                                      ? "Expired"
                                      : message.isVerified
                                      ? "Valid"
                                      : "Invalid"}
                                  </span>

                                  {/* Hover text - shown when hovering and not expired */}
                                  {!isExpired && (
                                    <span className="hidden group-hover:inline">
                                      Verify
                                    </span>
                                  )}
                                </button>
                              )}
                          </div>
                        );
                      })()}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}

      {isLoading && (
        <div className="flex justify-start">
          <div className="bg-gray-100 rounded-lg px-4 py-2">
            <div className="flex items-center space-x-2">
              <div className="animate-spin rounded-full h-4 w-4 border-2 border-gray-400 border-t-transparent"></div>
              <span className="text-sm text-gray-600">
                AI is thinking...
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Invisible element for auto-scroll */}
      <div ref={messagesEndRef} />
    </div>
  );
}
import React from 'react';
import ReactMarkdown from 'react-markdown';
import type { Message } from '../../../../shared/types/broker';
import { APP_CONSTANTS } from '../../../../shared/constants/app';

interface ChatMessageProps {
  message: Message;
  onVerify?: (chatId: string) => void;
  onAcknowledge?: (chatId: string) => void;
  onDispute?: (chatId: string) => void;
  onWithdrawFee?: (chatId: string) => void;
}

export const ChatMessage: React.FC<ChatMessageProps> = ({
  message,
  onVerify,
  onAcknowledge,
  onDispute,
  onWithdrawFee,
}) => {
  const isVerificationExpired = (timestamp: number): boolean => {
    const now = Date.now();
    const expiryTime = timestamp + (APP_CONSTANTS.UI.VERIFICATION_EXPIRY_MINUTES * 60 * 1000);
    return now > expiryTime;
  };

  const shouldShowVerificationButton = (message: Message): boolean => {
    return (
      message.role === "assistant" &&
      message.chatId !== undefined &&
      !message.isVerified &&
      !message.isVerifying &&
      message.timestamp !== undefined &&
      !isVerificationExpired(message.timestamp)
    );
  };

  const shouldShowAcknowledgeButton = (message: Message): boolean => {
    return (
      message.role === "assistant" &&
      message.chatId !== undefined &&
      message.isVerified === true &&
      !message.isVerifying
    );
  };

  const shouldShowDisputeButton = (message: Message): boolean => {
    return (
      message.role === "assistant" &&
      message.chatId !== undefined &&
      message.isVerified === false &&
      !message.isVerifying
    );
  };

  const getVerificationStatus = (message: Message) => {
    if (message.isVerifying) {
      return { text: "Verifying...", className: "text-yellow-600" };
    }
    if (message.isVerified === true) {
      return { text: "✓ Verified", className: "text-green-600" };
    }
    if (message.isVerified === false) {
      return { text: "✗ Verification Failed", className: "text-red-600" };
    }
    if (message.timestamp && isVerificationExpired(message.timestamp)) {
      return { text: "⏰ Verification Expired", className: "text-gray-500" };
    }
    return null;
  };

  return (
    <div
      className={`flex ${
        message.role === "user" ? "justify-end" : "justify-start"
      } mb-4`}
    >
      <div
        className={`max-w-[85%] sm:max-w-[70%] p-3 rounded-lg ${
          message.role === "user"
            ? "bg-purple-600 text-white"
            : "bg-gray-100 text-gray-900"
        }`}
      >
        <ReactMarkdown>
          {message.content}
        </ReactMarkdown>
        
        {message.role === "assistant" && (
          <div className="mt-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-gray-500 whitespace-nowrap">
                {new Date(message.timestamp || Date.now()).toLocaleTimeString()}
              </span>
              
              {(() => {
                const status = getVerificationStatus(message);
                return status ? (
                  <span className={status.className}>{status.text}</span>
                ) : null;
              })()}
            </div>
            
            {/* Verification Controls */}
            <div className="flex flex-wrap gap-1 mt-2">
              {shouldShowVerificationButton(message) && (
                <button
                  onClick={() => onVerify?.(message.chatId!)}
                  className="px-2 py-1 text-xs bg-purple-500 text-white rounded hover:bg-purple-600"
                >
                  Verify
                </button>
              )}
              
              {shouldShowAcknowledgeButton(message) && (
                <button
                  onClick={() => onAcknowledge?.(message.chatId!)}
                  className="px-2 py-1 text-xs bg-green-500 text-white rounded hover:bg-green-600"
                >
                  Acknowledge
                </button>
              )}
              
              {shouldShowDisputeButton(message) && (
                <>
                  <button
                    onClick={() => onDispute?.(message.chatId!)}
                    className="px-2 py-1 text-xs bg-red-500 text-white rounded hover:bg-red-600"
                  >
                    Dispute
                  </button>
                  <button
                    onClick={() => onWithdrawFee?.(message.chatId!)}
                    className="px-2 py-1 text-xs bg-gray-500 text-white rounded hover:bg-gray-600"
                  >
                    Withdraw Fee
                  </button>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
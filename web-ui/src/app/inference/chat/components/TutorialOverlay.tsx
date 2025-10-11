"use client";

import * as React from "react";

interface TutorialOverlayProps {
  isVisible: boolean;
  step: 'verify' | 'top-up' | null;
  onClose: () => void;
}

export function TutorialOverlay({
  isVisible,
  step,
  onClose,
}: TutorialOverlayProps) {
  if (!isVisible || !step) {
    return null;
  }

  return (
    <>
      {/* Dark overlay */}
      <div 
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />
      
      {/* Floating tutorial message */}
      <div className="fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-50">
        <div className="bg-white rounded-lg shadow-xl p-6 max-w-sm mx-4">
          {step === 'verify' && (
            <>
              <h3 className="font-semibold text-gray-900 mb-2">
                Verify Provider
              </h3>
              <p className="text-sm text-gray-600 mb-4">
                Verify that the provider is running in a verifiable TEE environment
              </p>
            </>
          )}
          {step === 'top-up' && (
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
            onClick={onClose}
            className="w-full px-4 py-2 bg-purple-600 text-white text-sm font-medium rounded-lg hover:bg-purple-700 transition-colors cursor-pointer"
          >
            Got it
          </button>
        </div>
      </div>
    </>
  );
}
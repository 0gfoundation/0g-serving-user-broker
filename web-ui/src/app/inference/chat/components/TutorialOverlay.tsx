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
                Provider verification requires two blockchain transactions:
              </p>
              <div className="text-sm text-gray-600 mb-4 space-y-2">
                <div className="flex items-start space-x-2">
                  <span className="inline-block w-5 h-5 bg-purple-100 text-purple-600 rounded-full text-xs font-semibold flex items-center justify-center mt-0.5">1</span>
                  <div>
                    <span className="font-medium">Account Creation</span> - Creates a payment account for this provider
                  </div>
                </div>
                <div className="flex items-start space-x-2">
                  <span className="inline-block w-5 h-5 bg-purple-100 text-purple-600 rounded-full text-xs font-semibold flex items-center justify-center mt-0.5">2</span>
                  <div>
                    <span className="font-medium">TEE Verification</span> - Confirms the provider runs in a secure environment
                  </div>
                </div>
              </div>
              <p className="text-xs text-gray-500 mb-4">
                Click "Verify Provider" to start the process.
              </p>
            </>
          )}
          {step === 'top-up' && (
            <>
              <h3 className="font-semibold text-gray-900 mb-2">
                Top Up Provider
              </h3>
              <p className="text-sm text-gray-600 mb-4">
                Now you need to fund the provider to start using its services:
              </p>
              <div className="text-sm text-gray-600 mb-4 space-y-2">
                <div className="flex items-start space-x-2">
                  <span className="inline-block w-5 h-5 bg-purple-100 text-purple-600 rounded-full text-xs font-semibold flex items-center justify-center mt-0.5">•</span>
                  <div>
                    <span className="font-medium">Transfer funds</span> from your account balance to the provider
                  </div>
                </div>
                <div className="flex items-start space-x-2">
                  <span className="inline-block w-5 h-5 bg-purple-100 text-purple-600 rounded-full text-xs font-semibold flex items-center justify-center mt-0.5">•</span>
                  <div>
                    <span className="font-medium">Excess funds</span> can be refunded at any time
                  </div>
                </div>
              </div>
              <p className="text-xs text-gray-500 mb-4">
                Click "Add Funds" to transfer funds to this provider.
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
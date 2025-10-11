"use client";

import { createLazyPage } from '../ui/PageLoader';

export const LazyChatPage = createLazyPage(
  () => import('../../../app/inference/chat/components/OptimizedChatPage').then(module => ({ default: module.OptimizedChatPage })),
  <div className="w-full h-full">
    <div className="mb-3">
      <div className="animate-pulse">
        <div className="h-6 bg-gray-200 rounded w-32 mb-2"></div>
        <div className="h-4 bg-gray-200 rounded w-96"></div>
      </div>
    </div>
    <div className="bg-white rounded-xl border border-gray-200 h-[calc(100vh-200px)] flex flex-col">
      {/* Provider selector */}
      <div className="border-b border-gray-200 p-4">
        <div className="animate-pulse">
          <div className="h-5 bg-gray-200 rounded w-24 mb-2"></div>
          <div className="h-10 bg-gray-200 rounded w-64"></div>
        </div>
      </div>
      
      {/* Chat messages area */}
      <div className="flex-1 p-4 space-y-4">
        <div className="animate-pulse">
          {/* User message */}
          <div className="flex justify-end mb-4">
            <div className="max-w-xs lg:max-w-md">
              <div className="bg-gray-200 rounded-2xl rounded-tr-sm p-3">
                <div className="h-4 bg-gray-300 rounded mb-1"></div>
                <div className="h-4 bg-gray-300 rounded w-3/4"></div>
              </div>
            </div>
          </div>
          
          {/* Assistant message */}
          <div className="flex justify-start mb-4">
            <div className="max-w-xs lg:max-w-md">
              <div className="bg-gray-200 rounded-2xl rounded-tl-sm p-3">
                <div className="h-4 bg-gray-300 rounded mb-2"></div>
                <div className="h-4 bg-gray-300 rounded mb-2"></div>
                <div className="h-4 bg-gray-300 rounded w-2/3"></div>
              </div>
            </div>
          </div>
          
          {/* Another user message */}
          <div className="flex justify-end mb-4">
            <div className="max-w-xs lg:max-w-md">
              <div className="bg-gray-200 rounded-2xl rounded-tr-sm p-3">
                <div className="h-4 bg-gray-300 rounded"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {/* Input area */}
      <div className="border-t border-gray-200 p-4">
        <div className="animate-pulse">
          <div className="flex space-x-3">
            <div className="flex-1 h-12 bg-gray-200 rounded-xl"></div>
            <div className="w-12 h-12 bg-gray-200 rounded-xl"></div>
          </div>
        </div>
      </div>
    </div>
  </div>
);
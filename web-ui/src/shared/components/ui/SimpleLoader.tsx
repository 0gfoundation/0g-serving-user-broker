"use client";

import React from "react";

interface SimpleLoaderProps {
  message?: string;
}

export const SimpleLoader: React.FC<SimpleLoaderProps> = ({ message }) => {
  return (
    <div className="w-full h-full min-h-[400px] flex items-center justify-center">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-purple-600 border-t-transparent mx-auto mb-4"></div>
        {message && (
          <p className="text-gray-600 text-sm">{message}</p>
        )}
      </div>
    </div>
  );
};

export default SimpleLoader;
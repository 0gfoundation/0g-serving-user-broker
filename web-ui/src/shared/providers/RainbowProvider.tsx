"use client";

import '@rainbow-me/rainbowkit/styles.css';
import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { WagmiProvider } from 'wagmi';
import { RainbowKitProvider, lightTheme } from '@rainbow-me/rainbowkit';
import { wagmiConfig } from '../config/wagmi';

const queryClient = new QueryClient();

interface RainbowProviderProps {
  children: React.ReactNode;
}

export function RainbowProvider({ children }: RainbowProviderProps) {
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider
          theme={lightTheme({
            accentColor: '#9333ea',
            accentColorForeground: 'white',
            borderRadius: 'medium',
            fontStack: 'system',
            overlayBlur: 'small',
          })}
          locale="en-US"
          showRecentTransactions={true}
          appInfo={{
            appName: '0G Compute Network',
            learnMoreUrl: 'https://0g.ai',
          }}
        >
          {children}
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

import { getDefaultConfig } from '@rainbow-me/rainbowkit';
import { defineChain } from 'viem';

export const zgTestnet = defineChain({
  id: 16602,
  name: '0G Testnet',
  nativeCurrency: {
    decimals: 18,
    name: '0G',
    symbol: '0G',
  },
  rpcUrls: {
    default: {
      http: ['https://evmrpc-testnet.0g.ai'],
    },
  },
  blockExplorers: {
    default: {
      name: '0G Testnet Explorer',
      url: 'https://chainscan-galileo.0g.ai/',
    },
  },
  testnet: true,
});

// // Local mock RPC configuration
// export const localMockChain = defineChain({
//   id: 31337, // Hardhat default chain ID
//   name: 'Hardhat Local',
//   nativeCurrency: {
//     decimals: 18,
//     name: 'ETH',
//     symbol: 'ETH',
//   },
//   rpcUrls: {
//     default: {
//       http: ['http://localhost:8545'],
//     },
//   },
//   blockExplorers: {
//     default: {
//       name: 'Local Explorer',
//       url: 'http://localhost:8545',
//     },
//   },
//   testnet: true,
// });

export const wagmiConfig = getDefaultConfig({
  appName: '0G Compute Network',
  projectId: process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || 'demo-project-id',
  chains: [zgTestnet],
  ssr: true,
});

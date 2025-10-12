"use client";

import React from "react";
import Link from "next/link";
import { ConnectButton } from '@rainbow-me/rainbowkit';

export const Navbar: React.FC = () => {

  return (
    <nav className="bg-white border-b border-purple-200 fixed top-0 left-0 right-0 z-20">
      <div className="px-4">
        <div className="flex justify-between items-center py-4">
          {/* Logo - always show */}
          <Link href="/" className="flex items-center space-x-2">
            <img src="/favicon.svg" alt="0G" className="w-8 h-8" />
            <span className="text-xl font-bold text-gray-800">Compute Network</span>
            <span className="ml-2 px-2 py-1 text-xs font-medium text-purple-600 bg-purple-100 rounded-full border border-purple-200">
              beta
            </span>
          </Link>

          {/* Links and Connect Button */}
          <div className="flex items-center space-x-4">
            {/* External Links */}
            <div className="flex items-center space-x-3">
              {/* GitHub Link */}
              <a 
                href="https://github.com/0glabs/0g-serving-user-broker" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-gray-600 hover:text-purple-600 transition-colors duration-200"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                  <path fillRule="evenodd" d="M10 0C4.477 0 0 4.484 0 10.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0110 4.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0020 10.017C20 4.484 15.522 0 10 0z" clipRule="evenodd" />
                </svg>
              </a>
              
              {/* Official Website Link */}
              <a 
                href="https://hub.0g.ai/" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-gray-600 hover:text-purple-600 transition-colors duration-200"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                  <path d="M10 1.67C5.4 1.67 1.67 5.4 1.67 10S5.4 18.33 10 18.33 18.33 14.6 18.33 10 14.6 1.67 10 1.67zm-.83 14.94c-3.28-.41-5.83-3.21-5.83-6.61 0-.52.07-1.01.18-1.49L7.5 12.5v.83c0 .92.75 1.67 1.67 1.67v1.61zm5.75-2.12c-.22-.67-.83-1.16-1.58-1.16h-.84v-2.5c0-.46-.37-.83-.83-.83H6.67v-1.67h1.66c.46 0 .84-.37.84-.83V5.83h1.66c.92 0 1.67-.75 1.67-1.67v-.34c2.44.99 4.17 3.38 4.17 6.18 0 1.73-.67 3.31-1.75 4.49z"/>
                </svg>
              </a>
            </div>

            {/* RainbowKit Connect Button */}
            <ConnectButton 
              chainStatus="icon"
              accountStatus={{
                smallScreen: 'avatar',
                largeScreen: 'full',
              }}
              showBalance={{
                smallScreen: false,
                largeScreen: true,
              }}
            />
          </div>
        </div>
      </div>
    </nav>
  );
};

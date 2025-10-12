"use client";

import React from "react";
import Link from "next/link";
import { useAccount } from 'wagmi';

export default function Home() {
  useAccount();

  return (
    <>
      {/* Full Page Gradient Background */}
      <div className="fixed inset-0 bg-gradient-to-br from-purple-50 via-pink-50 to-purple-100 dark:from-purple-950 dark:via-pink-950 dark:to-purple-900" />
      
      {/* Decorative Blur Elements */}
      <div className="fixed top-20 left-10 w-96 h-96 bg-purple-300 rounded-full mix-blend-multiply filter blur-[100px] opacity-20 animate-blob" />
      <div className="fixed top-40 right-10 w-96 h-96 bg-pink-300 rounded-full mix-blend-multiply filter blur-[100px] opacity-20 animate-blob animation-delay-2000" />
      <div className="fixed bottom-0 left-20 w-96 h-96 bg-purple-200 rounded-full mix-blend-multiply filter blur-[100px] opacity-20 animate-blob animation-delay-4000" />
      
      <div className="relative min-h-screen">
        <div className="max-w-6xl mx-auto px-4 py-12">
        {/* Hero Section */}
        <div className="text-center mb-16">
          <h1 className="text-2xl md:text-3xl lg:text-4xl font-semibold mb-6 bg-gradient-to-r from-gray-900 to-purple-600 dark:from-white dark:to-purple-400 bg-clip-text text-transparent whitespace-nowrap">
            Discover decentralized AI using the 0G Compute Network
          </h1>
          <div className="flex gap-4 justify-center">
            <Link href="/inference" className="px-8 py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-white font-semibold rounded-full hover:shadow-xl transition-all duration-300 hover:scale-105">
              Quick Start
            </Link>
            <a href="https://docs.0g.ai/concepts/compute" target="_blank" rel="noopener noreferrer" className="px-8 py-3 bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm text-purple-600 dark:text-purple-400 font-semibold rounded-full border border-purple-200 dark:border-purple-800 hover:shadow-xl transition-all duration-300 hover:scale-105">
              Learn Concepts
            </a>
          </div>
        </div>

        {/* Feature Cards */}
        <div className="grid md:grid-cols-3 gap-8 mb-12">
          <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm rounded-2xl shadow-xl p-6 border border-purple-100 dark:border-purple-900 hover:shadow-2xl transition-all duration-300 hover:scale-105">
          <div className="w-12 h-12 bg-gradient-to-br from-purple-100 to-pink-100 dark:from-purple-900 dark:to-pink-900 rounded-lg flex items-center justify-center mb-4">
            <svg className="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold mb-2">Account Management</h3>
          <p className="text-gray-600 mb-4">
            Manage your account balance, add funds for AI services.
          </p>
          <Link
            href="/wallet"
            className="text-purple-600 hover:text-purple-700 font-medium"
          >
            Go to Account →
          </Link>
        </div>

        <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm rounded-2xl shadow-xl p-6 border border-purple-100 dark:border-purple-900 hover:shadow-2xl transition-all duration-300 hover:scale-105">
          <div className="w-12 h-12 bg-gradient-to-br from-purple-100 to-pink-100 dark:from-purple-900 dark:to-pink-900 rounded-lg flex items-center justify-center mb-4">
            <svg className="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.9L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold mb-2">AI Inference</h3>
          <p className="text-gray-600 mb-4">
            Chat with various AI models, test different providers, and experience decentralized AI.
          </p>
          <Link
            href="/inference"
            className="text-purple-600 hover:text-purple-700 font-medium"
          >
            Go to Inference →
          </Link>
        </div>

        <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm rounded-2xl shadow-xl p-6 border border-purple-100 dark:border-purple-900 hover:shadow-2xl transition-all duration-300 hover:scale-105">
          <div className="w-12 h-12 bg-gradient-to-br from-purple-100 to-pink-100 dark:from-purple-900 dark:to-pink-900 rounded-lg flex items-center justify-center mb-4">
            <svg className="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold mb-2">Fine-tuning</h3>
          <p className="text-gray-600 mb-4">
          Customize AI models with your own data for personalized use cases.
          </p>
          <Link
            href="/fine-tuning"
            className="text-purple-600 hover:text-purple-700 font-medium"
          >
            Go to Fine-tuning →
          </Link>
        </div>
      </div>

        {/* Documentation */}
        <div className="bg-white/60 dark:bg-gray-900/60 backdrop-blur-sm rounded-2xl p-8 border border-purple-100 dark:border-purple-900">
        <h2 className="text-2xl font-bold text-gray-900 mb-4">Getting Started</h2>
        <div className="space-y-4">
          <div className="flex items-start space-x-3">
            <div className="w-6 h-6 bg-purple-600 text-white rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 mt-0.5">
              1
            </div>
            <div>
              <h3 className="font-semibold text-gray-900">Connect Your Wallet</h3>
              <p className="text-gray-600">Connect your MetaMask wallet and switch to the 0G testnet.</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <div className="w-6 h-6 bg-purple-600 text-white rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 mt-0.5">
              2
            </div>
            <div>
              <h3 className="font-semibold text-gray-900">Fund Your Account</h3>
              <p className="text-gray-600">Add some 0G tokens to your account to pay for AI services.</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <div className="w-6 h-6 bg-purple-600 text-white rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 mt-0.5">
              3
            </div>
            <div>
              <h3 className="font-semibold text-gray-900">Start Using AI</h3>
              <p className="text-gray-600">Choose a provider and start chatting with AI models or fine-tune your own.</p>
            </div>
          </div>
        </div>
      </div>
        </div>
      </div>
    </>
  );
}

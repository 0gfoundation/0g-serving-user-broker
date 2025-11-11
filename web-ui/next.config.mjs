/** @type {import('next').NextConfig} */
const nextConfig = {
    // Optimize for production performance
    reactStrictMode: false, // Disable in production to avoid double renders
    poweredByHeader: false, // Remove X-Powered-By header
    compress: true, // Enable gzip compression
    
    // Static export requires unoptimized images
    images: {
        unoptimized: true,
    },
    
    webpack: (config, { isServer }) => {
        if (!isServer) {
            config.resolve.fallback = {
                ...config.resolve.fallback,
                fs: false,
                net: false,
                tls: false,
                child_process: false,
                'fs/promises': false,
                crypto: false,
            }
            // Handle node: protocol imports
            config.resolve.alias = {
                ...config.resolve.alias,
                'node:crypto': false,
                'node:buffer': false,
                'node:stream': false,
                'node:util': false,
            }
            
        }
        
        return config
    },
    transpilePackages: ['@0glabs/0g-serving-broker'],
    output: 'export',
    trailingSlash: true,
    
    // Optimize bundle splitting
    experimental: {
        optimizePackageImports: ['dexie', '@0glabs/0g-serving-broker'],
    },
}

export default nextConfig

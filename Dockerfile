# Use the official Node.js runtime as base image
FROM node:18-alpine AS base

# Build the broker SDK first
FROM base AS broker-builder
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY package.json pnpm-lock.yaml* ./
COPY src.ts ./src.ts
COPY tsconfig*.json ./
COPY rollup.config.mjs ./
COPY binary ./binary
RUN corepack enable pnpm && pnpm i
RUN pnpm run build

# Prepare web UI dependencies
FROM base AS web-deps
RUN apk add --no-cache libc6-compat
WORKDIR /app/web-ui
COPY web-ui/package.json web-ui/pnpm-lock.yaml* ./
RUN corepack enable pnpm && pnpm i

# Build web UI
FROM base AS web-builder
WORKDIR /app
# Copy broker build output
COPY --from=broker-builder /app/lib.esm ./lib.esm
COPY --from=broker-builder /app/lib.commonjs ./lib.commonjs
COPY --from=broker-builder /app/types ./types
COPY --from=broker-builder /app/package.json ./package.json

# Copy web UI files and dependencies
COPY --from=web-deps /app/web-ui/node_modules ./web-ui/node_modules
COPY web-ui ./web-ui

# Create proper package structure for 0g-serving-broker by copying all built files
RUN mkdir -p ./web-ui/node_modules/0g-serving-broker
# Copy the original package.json with all exports
RUN cp ./package.json ./web-ui/node_modules/0g-serving-broker/package.json
# Copy all built files to maintain file dependencies
RUN cp -r ./lib.esm ./web-ui/node_modules/0g-serving-broker/lib.esm
RUN cp -r ./lib.commonjs ./web-ui/node_modules/0g-serving-broker/lib.commonjs
RUN cp -r ./types ./web-ui/node_modules/0g-serving-broker/types

WORKDIR /app/web-ui
ENV NEXT_TELEMETRY_DISABLED 1
RUN corepack enable pnpm && pnpm run build

# Production image
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production
ENV NEXT_TELEMETRY_DISABLED 1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=web-builder /app/web-ui/public ./public

RUN mkdir .next
RUN chown nextjs:nodejs .next

# Copy the standalone build
COPY --from=web-builder --chown=nextjs:nodejs /app/web-ui/.next/standalone ./
COPY --from=web-builder --chown=nextjs:nodejs /app/web-ui/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

# Performance optimizations for production
ENV NODE_OPTIONS="--max-old-space-size=4096"

CMD ["node", "server.js"]
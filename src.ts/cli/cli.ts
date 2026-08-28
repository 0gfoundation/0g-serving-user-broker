#!/usr/bin/env node

import { Command } from 'commander'
import fineTuning from './fine-tuning'
import ledger from './ledger'
import inference from './inference'
import webUIEmbedded from './web-ui-embedded'
import network from './network'
import auth from './auth'
import controller from './controller'
import completion from './completion'
import { showCompletionHintIfNeeded } from './tips'
import packageJson from '../../package.json'

export const program = new Command()

program
    .name('0g-compute-cli')
    .description('CLI for interacting with ZG Compute Network')
    .version(packageJson.version)

ledger(program)

// Create subcommands for each service
const fineTuningCmd = program
    .command('fine-tuning')
    .alias('ft')
    .description('Fine-tuning service commands')

const inferenceCmd = program
    .command('inference')
    .alias('inf')
    .description('Inference service commands')

const webUICmd = program
    .command('web-ui')
    .alias('ui')
    .description('Web UI embedded commands')

const controllerCmd = program
    .command('controller')
    .alias('ctrl')
    .description('Controller commands for managing provider containers')

// Register commands to their respective groups
fineTuning(fineTuningCmd)
inference(inferenceCmd)
webUIEmbedded(webUICmd)
controller(controllerCmd)

// Register network configuration commands at the root level
network(program)

// Register auth commands at the root level
auth(program)

// Register completion command at the root level
completion(program)

// Detect package manager
function getPackageManager(): string {
    const userAgent = process.env.npm_config_user_agent || ''
    if (userAgent.includes('pnpm')) return 'pnpm'
    if (userAgent.includes('yarn')) return 'yarn'
    if (userAgent.includes('bun')) return 'bun'
    return 'npm'
}

// Display update notification
function showUpdateNotification(updateInfo: {
    current: string
    latest: string
    name: string
}) {
    const { current, latest, name } = updateInfo
    const pm = getPackageManager()
    const installCmd =
        pm === 'yarn' ? `yarn global add ${name}` : `${pm} add -g ${name}`

    const line1 = `Update available: ${current} → ${latest}`
    const line2 = `Run: ${installCmd}`
    const width = Math.max(line1.length, line2.length) + 4

    process.stderr.write('\n' + '╭' + '─'.repeat(width) + '╮\n')
    process.stderr.write('│ ' + line1.padEnd(width - 1) + '│\n')
    process.stderr.write('│ ' + line2.padEnd(width - 1) + '│\n')
    process.stderr.write('╰' + '─'.repeat(width) + '╯\n\n')
}

// Check for updates (non-blocking on first run)
;(async () => {
    try {
        // Dynamic import to handle environments where update-notifier is not compatible (e.g., Yarn PnP)
        const { default: updateNotifier } = await import('update-notifier')

        const notifier = updateNotifier({
            pkg: packageJson,
            updateCheckInterval: 1000 * 60 * 60 * 24, // Check once per day
        })

        // Strategy: Use cache first (instant), fallback to fetch with timeout
        let updateInfo = notifier.update

        if (!updateInfo) {
            // No cache, fetch with timeout to avoid blocking too long
            const fetchPromise = notifier.fetchInfo()
            const timeoutPromise = new Promise<undefined>((resolve) =>
                setTimeout(() => resolve(undefined), 2000)
            )
            updateInfo = await Promise.race([fetchPromise, timeoutPromise])
        }

        if (updateInfo?.type && updateInfo.type !== 'latest') {
            showUpdateNotification(updateInfo)
        }
    } catch {
        // Silently fail - don't block CLI usage (e.g., in Yarn PnP environments)
    }

    showCompletionHintIfNeeded(program.name())

    program.parse(process.argv)
})()

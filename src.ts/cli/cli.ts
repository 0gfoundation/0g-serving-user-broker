#!/usr/bin/env ts-node

import { Command } from 'commander'
import fineTuning from './fine-tuning'
import ledger from './ledger'
import inference from './inference'
import webUIEmbedded from './web-ui-embedded'
import network from './network'

export const program = new Command()

program
    .name('0g-compute-cli')
    .description('CLI for interacting with ZG Compute Network')
    .version('0.5.4')

// Create subcommands for each service
const fineTuningCmd = program.command('fine-tuning')
    .alias('ft')
    .description('Fine-tuning service commands')

const inferenceCmd = program.command('inference')
    .alias('inf')
    .description('Inference service commands')

const ledgerCmd = program.command('ledger')
    .alias('led')
    .description('Ledger management commands')

const webUICmd = program.command('web-ui')
    .alias('ui')
    .description('Web UI embedded commands')

// Register commands to their respective groups
fineTuning(fineTuningCmd)
inference(inferenceCmd)
ledger(ledgerCmd)
webUIEmbedded(webUICmd)

// Register network configuration commands at the root level
network(program)

program.parse(process.argv)

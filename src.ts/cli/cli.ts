#!/usr/bin/env node

import { Command } from 'commander'
import fineTuning from './fine-tuning'
import ledger from './ledger'
import inference from './inference'
import webUIEmbedded from './web-ui-embedded'
import network from './network'
import auth from './auth'

export const program = new Command()

program
    .name('0g-compute-cli')
    .description('CLI for interacting with ZG Compute Network')
    .version('0.5.4')

ledger(program)

// Create subcommands for each service
const fineTuningCmd = program.command('fine-tuning')
    .alias('ft')
    .description('Fine-tuning service commands')

const inferenceCmd = program.command('inference')
    .alias('inf')
    .description('Inference service commands')


const webUICmd = program.command('web-ui')
    .alias('ui')
    .description('Web UI embedded commands')

// Register commands to their respective groups
fineTuning(fineTuningCmd)
inference(inferenceCmd)
webUIEmbedded(webUICmd)

// Register network configuration commands at the root level
network(program)

// Register auth commands at the root level
auth(program)

program.parse(process.argv)

#!/usr/bin/env ts-node

import type { Command } from 'commander'
import { withFineTuningBroker, neuronToA0gi, splitIntoChunks } from './util'
import Table from 'cli-table3'
import chalk from 'chalk'
import { ZG_RPC_ENDPOINT_TESTNET } from './const'
import * as path from 'path'
import * as fs from 'fs/promises'
import { download } from '../sdk/fine-tuning/zg-storage'
import { TOKEN_COUNTER_MERKLE_ROOT } from '../sdk/fine-tuning/const'

export default function fineTuning(program: Command) {
    program
        .command('verify')
        .description('verify TEE remote attestation of service')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                await broker.fineTuning!.acknowledgeProviderSigner(
                    options.provider,
                    options.gasPrice
                )
                console.log('Provider verified')
            })
        })

    program
        .command('list-models')
        .description('List available models')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                const models = await broker.fineTuning!.listModel()

                console.log(`Predefined Model:`)
                let table = new Table({
                    head: [chalk.blue('Name'), chalk.blue('Description')],
                    colWidths: [30, 75],
                })
                models[0].forEach((model) => {
                    table.push([
                        splitIntoChunks(model[0], 28),
                        splitIntoChunks(model[1].description, 73),
                    ])
                })

                console.log(table.toString())

                console.log(`Provider's Model:`)
                table = new Table({
                    head: [
                        chalk.blue('Name'),
                        chalk.blue('Description'),
                        chalk.blue('Provider'),
                    ],
                    colWidths: [30, 75, 45],
                })
                models[1].forEach((model) => {
                    table.push([
                        splitIntoChunks(model[0], 28),
                        splitIntoChunks(model[1].description, 73),
                        splitIntoChunks(model[1].provider, 42),
                    ])
                })

                console.log(table.toString())
            })
        })

    program
        .command('model-usage')
        .description('Download detailed customized model usage')
        .requiredOption('--provider <address>', 'Provider address for the task')
        .requiredOption('--model <name>', 'Pre-trained model name to use')
        .requiredOption('--output <path>', 'Download path')
        .option(
            `--rpc <url>', '0G Chain RPC endpoint, default is ${ZG_RPC_ENDPOINT_TESTNET}`,
            ZG_RPC_ENDPOINT_TESTNET
        )
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                await broker.fineTuning!.modelUsage(
                    options.provider,
                    options.model,
                    options.output
                )
            })
        })

    program
        .command('upload')
        .description('Upload a dataset for fine-tuning')
        .requiredOption('--data-path <path>', 'Path to the dataset')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option(
            '--ledger-ca <address>',
            'Account (ledger) contract address, use default address if not provided'
        )
        .option(
            '--fine-tuning-ca <address>',
            'Fine Tuning contract address, use default address if not provided'
        )
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price adjustment')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                await broker.fineTuning!.uploadDataset(options.dataPath)
            })
        })

    program
        .command('download')
        .description('Download a data')
        .requiredOption('--data-path <path>', 'Path to the dataset')
        .requiredOption('--data-root <hash>', 'Root hash of the dataset')
        .option(
            `--rpc <url>', '0G Chain RPC endpoint, default is ${ZG_RPC_ENDPOINT_TESTNET}`,
            ZG_RPC_ENDPOINT_TESTNET
        )
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                await broker.fineTuning!.downloadDataset(
                    options.dataPath,
                    options.dataRoot
                )
            })
        })

    program
        .command('calculate-token')
        .description('Download token-counter')
        .requiredOption('--model <name>', 'Pre-trained model name to use')
        .requiredOption(
            '--dataset-path <path>',
            'Path to the zip file containing the fine-tuning dataset'
        )
        .option('--provider <address>', 'Provider address for the task')
        .action(async (options) => {
            withFineTuningBroker(options, async (broker) => {
                await broker.fineTuning!.calculateToken(
                    options.datasetPath,
                    options.model,
                    false,
                    options.provider
                )
            })
        })

    program
        .command('create-task')
        .description('Create a fine-tuning task')
        .requiredOption('--provider <address>', 'Provider address for the task')
        .requiredOption('--model <name>', 'Pre-trained model name to use')
        .requiredOption(
            '--data-size <size>',
            'Token number of the dataset. Use calculate-token command for the calculation'
        )
        .requiredOption('--dataset <hash>', 'Hash of the dataset')
        .requiredOption(
            '--config-path <path>',
            'Fine-tuning configuration path'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price adjustment')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                console.log('Verify provider...')
                await broker.fineTuning!.acknowledgeProviderSigner(
                    options.provider,
                    options.gasPrice
                )
                console.log('Provider verified')

                console.log('Creating task...')
                const taskId = await broker.fineTuning!.createTask(
                    options.provider,
                    options.model,
                    parseInt(options.dataSize, 10),
                    options.dataset,
                    options.configPath,
                    options.gasPrice
                )
                console.log('Created Task ID:', taskId)
            })
        })

    program
        .command('cancel-task')
        .description('Cancel a fine-tuning task')
        .requiredOption(
            '--task <id>',
            'Task ID, if not provided, the latest task will be retrieved'
        )
        .requiredOption('--provider <address>', 'Provider address for the task')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                const r = await broker.fineTuning!.cancelTask(
                    options.provider,
                    options.task
                )
                console.log(r)
            })
        })

    program
        .command('list-tasks')
        .description('Retrieve all fine-tuning task')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                const tasks = await broker.fineTuning!.listTask(
                    options.provider
                )
                const table = new Table({
                    head: [
                        chalk.blue('ID'),
                        chalk.blue('Created At'),
                        chalk.blue('Status'),
                    ],
                    colWidths: [50, 30, 30],
                })
                for (const task of tasks) {
                    table.push([task.id, task.createdAt, task.progress])
                }
                console.log(table.toString())
            })
        })

    program
        .command('get-task')
        .description('Retrieve fine-tuning task information')
        .requiredOption('--provider <address>', 'Provider address')
        .option(
            '--task <id>',
            'Task ID, if not provided, the latest task will be retrieved'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                const task = await broker.fineTuning!.getTask(
                    options.provider,
                    options.task
                )
                const table = new Table({
                    head: [chalk.blue('Field'), chalk.blue('Value')],
                    colWidths: [35, 85],
                })
                table.push(['ID', task.id])
                table.push(['Created At', task.createdAt])
                table.push(['Pre-trained Model Hash', task.preTrainedModelHash])
                table.push(['Dataset Hash', task.datasetHash])
                table.push([
                    'Training Params',
                    splitIntoChunks(task.trainingParams, 80),
                ])
                table.push(['Fee (neuron)', task.fee])
                table.push(['Progress', task.progress])
                console.log(table.toString())
            })
        })

    program
        .command('get-log')
        .description('Retrieve fine-tuning task log')
        .requiredOption('--provider <address>', 'Provider address')
        .option(
            '--task <id>',
            'Task ID, if not provided, the latest task will be retrieved'
        )
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                const log = await broker.fineTuning!.getLog(
                    options.provider,
                    options.task
                )
                console.log(log)
            })
        })

    program
        .command('acknowledge-model')
        .description('Acknowledge the availability of a model')
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption('--task-id <id>', 'Task ID')
        .requiredOption('--data-path <path>', 'Path to store the model')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price adjustment')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                await broker.fineTuning!.acknowledgeModel(
                    options.provider,
                    options.taskId,
                    options.dataPath,
                    options.gasPrice
                )
                console.log('Acknowledged model')
            })
        })

    program
        .command('decrypt-model')
        .description('Decrypt a model')
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption('--task-id <id>', 'Task ID')
        .requiredOption(
            '--encrypted-model <path>',
            'Path to the encrypted model'
        )
        .requiredOption('--output <path>', 'Path to the decrypted model')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Ledger contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
            withFineTuningBroker(options, async (broker) => {
                await broker.fineTuning!.decryptModel(
                    options.provider,
                    options.taskId,
                    options.encryptedModel,
                    options.output
                )
                console.log('Decrypted model')
            })
        })

    program
        .command('download-counter')
        .description('Download token-counter')
        .action(async (options) => {
            let binaryDir = path.join(__dirname, '..', '..', 'binary')
            let executorDir = binaryDir

            const binaryFile = path.join(executorDir, 'token_counter')

            const storageClient = path.join(binaryDir, '0g-storage-client')
            try {
                await fs.access(storageClient, fs.constants.X_OK)
            } catch (err) {
                console.log(
                    `Grant execute permission (755) to the file ${storageClient}`
                )
                await fs.chmod(storageClient, 0o755)
            }

            await download(binaryFile, TOKEN_COUNTER_MERKLE_ROOT)
            await fs.chmod(binaryFile, 0o755)
        })

    program
        .command('list-providers')
        .description('List fine-tuning providers')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options: any) => {
            const table = new Table({
                colWidths: [50, 50],
            })
            withFineTuningBroker(options, async (broker) => {
                const services = await broker.fineTuning!.listService()
                services.forEach((service, index) => {
                    table.push([
                        chalk.blue(`Provider ${index + 1}`),
                        chalk.blue(service.provider),
                    ])
                    let available = !service.occupied ? '\u2713' : `\u2717`
                    table.push(['Available', available])
                    table.push([
                        'Price Per Byte in Dataset (0G)',
                        service.pricePerToken
                            ? neuronToA0gi(
                                  BigInt(service.pricePerToken)
                              ).toFixed(18)
                            : 'N/A',
                    ])
                })
                console.log(table.toString())
            })
        })
}

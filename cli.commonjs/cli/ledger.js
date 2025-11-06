#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getLedgerTable = void 0;
exports.default = ledger;
const tslib_1 = require("tslib");
const util_1 = require("./util");
const cli_table3_1 = tslib_1.__importDefault(require("cli-table3"));
const chalk_1 = tslib_1.__importDefault(require("chalk"));
const utils_1 = require("../sdk/common/utils");
function ledger(program) {
    program
        .command('get-account')
        .description('Retrieve account information')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            await (0, exports.getLedgerTable)(broker);
            // Add helpful information about sub-account details
            console.log(chalk_1.default.yellow('\n💡 To get detailed sub-account information:'));
            console.log(chalk_1.default.gray('• For inference sub-account details:'));
            console.log(chalk_1.default.cyan('  0g-compute-cli ledger get-sub-account --provider <provider_address> --service inference'));
            console.log(chalk_1.default.gray('• For fine-tuning sub-account details:'));
            console.log(chalk_1.default.cyan('  0g-compute-cli ledger get-sub-account --provider <provider_address> --service fine-tuning'));
            console.log(chalk_1.default.gray('\nExample:'));
            console.log(chalk_1.default.green('  0g-compute-cli ledger get-sub-account --provider 0x4f371f6eff4cb5a9471c9cf9bE32c729024b063C --service inference'));
        });
    });
    program
        .command('add-account')
        .description('Add account balance')
        .requiredOption('--amount <A0GI>', 'Amount to add')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            console.log('Adding account...');
            await broker.ledger.addLedger(parseFloat(options.amount));
            console.log('Account Created!');
            (0, exports.getLedgerTable)(broker);
        });
    });
    program
        .command('deposit')
        .description('Deposit funds into the account')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption('--amount <A0GI>', 'Amount of funds to deposit')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            console.log('Depositing...');
            await broker.ledger.depositFund(parseFloat(options.amount));
            console.log('Deposited funds:', options.amount, 'A0GI');
        });
    });
    program
        .command('refund')
        .description('Refund an amount from the account')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption('-a, --amount <A0GI>', 'Amount to refund')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            console.log('Refunding...');
            await broker.ledger.refund(parseFloat(options.amount));
            console.log('Refunded amount:', options.amount, 'A0GI');
        });
    });
    program
        .command('retrieve-fund')
        .description('Retrieve fund from sub account')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--infer', 'Retrieve fund from sub accounts for inference, default is fine-tuning')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            console.log('Retrieving funds from sub accounts...');
            await broker.ledger.retrieveFund(options.infer ? 'inference' : 'fine-tuning');
            console.log('Funds retrieved from sub accounts');
        });
    });
    program
        .command('transfer-fund')
        .description('Transfer funds to a provider for a specific service')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption('--provider <address>', 'Provider address to transfer funds to')
        .requiredOption('--amount <neuron>', 'Amount to transfer in neuron')
        .option('--service <type>', 'Service type: inference or fine-tuning', 'inference')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--gas-price <price>', 'Gas price for transactions')
        .option('--max-gas-price <price>', 'Max gas price for transactions')
        .option('--step <step>', 'Step for gas price calculation')
        .action((options) => {
        (0, util_1.withBroker)(options, async (broker) => {
            const serviceType = options.service;
            if (serviceType !== 'inference' &&
                serviceType !== 'fine-tuning') {
                console.error('Invalid service type. Must be "inference" or "fine-tuning"');
                process.exit(1);
            }
            console.log(`Transferring ${options.amount} neuron to ${options.provider} for ${serviceType}...`);
            await broker.ledger.transferFund(options.provider, serviceType, BigInt(options.amount), options.gasPrice ? parseFloat(options.gasPrice) : undefined);
            console.log(`Successfully transferred ${options.amount} neuron to ${options.provider}`);
        });
    });
    program
        .command('get-sub-account')
        .description('Retrieve detailed sub account information for a specific provider and service')
        .option('--key <key>', 'Wallet private key', process.env.ZG_PRIVATE_KEY)
        .requiredOption('--provider <address>', 'Provider address')
        .requiredOption('--service <type>', 'Service type: inference or fine-tuning')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .action((options) => {
        if (options.service !== 'inference' && options.service !== 'fine-tuning') {
            console.error(chalk_1.default.red('Error: --service must be either "inference" or "fine-tuning"'));
            process.exit(1);
        }
        (0, util_1.withBroker)(options, async (broker) => {
            if (options.service === 'inference') {
                const [account, refunds] = await broker.inference.getAccountWithDetail(options.provider);
                renderSubAccountOverview({
                    provider: account.provider,
                    balance: account.balance,
                    pendingRefund: account.pendingRefund,
                    service: 'Inference'
                });
                renderSubAccountRefunds(refunds);
            }
            else if (options.service === 'fine-tuning') {
                if (!broker.fineTuning) {
                    console.log(chalk_1.default.red('Fine tuning broker is not available.'));
                    return;
                }
                const { account, refunds } = await broker.fineTuning.getAccountWithDetail(options.provider);
                renderSubAccountOverview({
                    provider: account.provider,
                    balance: account.balance,
                    pendingRefund: account.pendingRefund,
                    service: 'Fine-tuning'
                });
                renderSubAccountRefunds(refunds);
                renderDeliverables(account.deliverables);
            }
        });
    });
}
const getLedgerTable = async (broker) => {
    // Ledger information
    const { ledgerInfo, infers, fines } = await broker.ledger.ledger.getLedgerWithDetail();
    let table = new cli_table3_1.default({
        head: [chalk_1.default.blue('Balance'), chalk_1.default.blue('Value (A0GI)')],
        colWidths: [50, 81],
    });
    table.push(['Total', (0, util_1.neuronToA0gi)(ledgerInfo[0]).toFixed(18)]);
    table.push([
        'Locked (transferred to sub-accounts)',
        (0, util_1.neuronToA0gi)(ledgerInfo[1]).toFixed(18),
    ]);
    (0, util_1.printTableWithTitle)('Overview', table);
    // Inference information
    if (infers && infers.length !== 0) {
        let table = new cli_table3_1.default({
            head: [
                chalk_1.default.blue('Provider'),
                chalk_1.default.blue('Balance (A0GI)'),
                chalk_1.default.blue('Requested Return to Main Account (A0GI)'),
            ],
            colWidths: [50, 30, 50],
        });
        for (const infer of infers) {
            table.push([
                infer[0],
                (0, util_1.neuronToA0gi)(infer[1]).toFixed(18),
                (0, util_1.neuronToA0gi)(infer[2]).toFixed(18),
            ]);
        }
        (0, util_1.printTableWithTitle)('Inference sub-accounts (Dynamically Created per Used Provider)', table);
    }
    // Fine tuning information
    if (fines && fines.length !== 0) {
        let table = new cli_table3_1.default({
            head: [
                chalk_1.default.blue('Provider'),
                chalk_1.default.blue('Balance (A0GI)'),
                chalk_1.default.blue('Requested Return to Main Account (A0GI)'),
            ],
            colWidths: [50, 30, 50],
        });
        for (const fine of fines) {
            table.push([
                fine[0],
                (0, util_1.neuronToA0gi)(fine[1]).toFixed(18),
                (0, util_1.neuronToA0gi)(fine[2]).toFixed(18),
            ]);
        }
        (0, util_1.printTableWithTitle)('Fine-tuning sub-accounts (Dynamically Created per Used Provider)', table);
    }
};
exports.getLedgerTable = getLedgerTable;
// Helper functions for detailed sub-account information
function renderSubAccountOverview(account) {
    const table = new cli_table3_1.default({
        head: [chalk_1.default.blue('Field'), chalk_1.default.blue('Value')],
        colWidths: [50, 50],
    });
    table.push(['Service Type', account.service]);
    table.push(['Provider', account.provider]);
    table.push(['Balance (A0GI)', (0, util_1.neuronToA0gi)(account.balance).toFixed(18)]);
    table.push([
        'Funds Applied for Return to Main Account (A0GI)',
        (0, util_1.neuronToA0gi)(account.pendingRefund).toFixed(18),
    ]);
    (0, util_1.printTableWithTitle)(`${account.service} Sub-Account Overview`, table);
}
function renderSubAccountRefunds(refunds) {
    if (!refunds || refunds.length === 0) {
        console.log(chalk_1.default.gray('\nNo pending refunds found.'));
        return;
    }
    const table = new cli_table3_1.default({
        head: [
            chalk_1.default.blue('Amount (A0GI)'),
            chalk_1.default.blue('Remaining Locked Time'),
        ],
        colWidths: [50, 50],
    });
    refunds.forEach((refund) => {
        const totalSeconds = Number(refund.remainTime);
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const secs = totalSeconds % 60;
        table.push([
            (0, util_1.neuronToA0gi)(refund.amount).toFixed(18),
            `${hours}h ${minutes}min ${secs}s`,
        ]);
    });
    (0, util_1.printTableWithTitle)('Details of Each Amount Applied for Return to Main Account', table);
}
function renderDeliverables(deliverables) {
    if (!deliverables || deliverables.length === 0) {
        console.log(chalk_1.default.gray('\nNo deliverables found.'));
        return;
    }
    const table = new cli_table3_1.default({
        head: [chalk_1.default.blue('Root Hash'), chalk_1.default.blue('Access Confirmed')],
        colWidths: [75, 25],
    });
    deliverables.forEach((d) => {
        table.push([
            (0, util_1.splitIntoChunks)((0, utils_1.hexToRoots)(d.modelRootHash), 60),
            d.acknowledged ? chalk_1.default.greenBright.bold('\u2713') : '',
        ]);
    });
    (0, util_1.printTableWithTitle)('Deliverables', table);
}
//# sourceMappingURL=ledger.js.map
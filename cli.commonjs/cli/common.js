#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = default_1;
const tslib_1 = require("tslib");
const util_1 = require("./util");
const cli_table3_1 = tslib_1.__importDefault(require("cli-table3"));
const chalk_1 = tslib_1.__importDefault(require("chalk"));
const utils_1 = require("../sdk/common/utils");
function default_1(program) {
    program
        .command('get-sub-account')
        .description('Retrieve sub account information')
        .option('--key <key>', 'Wallet private key')
        .requiredOption('--provider <address>', 'Provider address')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--infer', 'get sub-account for inference, default is fine-tuning')
        .action((options) => {
        if (options.infer) {
            (0, util_1.withBroker)(options, async (broker) => {
                const [account, refunds] = await broker.inference.getAccountWithDetail(options.provider);
                renderOverview({
                    provider: account.provider,
                    balance: account.balance,
                    pendingRefund: account.pendingRefund,
                });
                renderRefunds(refunds);
            });
        }
        else {
            (0, util_1.withFineTuningBroker)(options, async (broker) => {
                if (!broker.fineTuning) {
                    console.log('Fine tuning broker is not available.');
                    return;
                }
                const { account, refunds } = await broker.fineTuning.getAccountWithDetail(options.provider);
                renderOverview({
                    provider: account.provider,
                    balance: account.balance,
                    pendingRefund: account.pendingRefund,
                });
                renderRefunds(refunds);
                renderDeliverables(account.deliverables);
            });
        }
    });
    program
        .command('list-providers')
        .description('List providers')
        .option('--key <key>', 'Wallet private key')
        .option('--rpc <url>', '0G Chain RPC endpoint')
        .option('--ledger-ca <address>', 'Account (ledger) contract address')
        .option('--inference-ca <address>', 'Inference contract address')
        .option('--fine-tuning-ca <address>', 'Fine Tuning contract address')
        .option('--infer', 'list inference providers, default is fine-tuning')
        .action((options) => {
        const table = new cli_table3_1.default({
            colWidths: [50, 50],
        });
        if (options.infer) {
            (0, util_1.withBroker)(options, async (broker) => {
                const services = await broker.inference.listService();
                services.forEach((service, index) => {
                    table.push([
                        chalk_1.default.blue(`Provider ${index + 1}`),
                        chalk_1.default.blue(service.provider),
                    ]);
                    table.push(['Model', service.model || 'N/A']);
                    table.push([
                        'Input Price Per Byte (0G)',
                        service.inputPrice
                            ? (0, util_1.neuronToA0gi)(BigInt(service.inputPrice)).toFixed(18)
                            : 'N/A',
                    ]);
                    table.push([
                        'Output Price Per Byte (0G)',
                        service.outputPrice
                            ? (0, util_1.neuronToA0gi)(BigInt(service.outputPrice)).toFixed(18)
                            : 'N/A',
                    ]);
                    table.push([
                        'Verifiability',
                        service.verifiability || 'N/A',
                    ]);
                });
                console.log(table.toString());
            });
            return;
        }
        (0, util_1.withFineTuningBroker)(options, async (broker) => {
            const services = await broker.fineTuning.listService();
            services.forEach((service, index) => {
                table.push([
                    chalk_1.default.blue(`Provider ${index + 1}`),
                    chalk_1.default.blue(service.provider),
                ]);
                const available = !service.occupied ? '\u2713' : `\u2717`;
                table.push(['Available', available]);
                table.push([
                    'Price Per Byte in Dataset (0G)',
                    service.pricePerToken
                        ? (0, util_1.neuronToA0gi)(BigInt(service.pricePerToken)).toFixed(18)
                        : 'N/A',
                ]);
                // TODO: Show quota when backend ready
                // table.push([
                //     'Quota(CPU, Memory, GPU Count, Storage, CPU Type)',
                //     service.quota.toString(),
                // ])
            });
            console.log(table.toString());
        });
    });
}
function renderOverview(account) {
    const table = new cli_table3_1.default({
        head: [chalk_1.default.blue('Field'), chalk_1.default.blue('Value')],
        colWidths: [50, 50],
    });
    table.push(['Provider', account.provider]);
    table.push(['Balance (0G)', (0, util_1.neuronToA0gi)(account.balance).toFixed(18)]);
    table.push([
        'Funds Applied for Return to Main Account (0G)',
        (0, util_1.neuronToA0gi)(account.pendingRefund).toFixed(18),
    ]);
    (0, util_1.printTableWithTitle)('Overview', table);
}
function renderRefunds(refunds) {
    const table = new cli_table3_1.default({
        head: [chalk_1.default.blue('Amount (0G)'), chalk_1.default.blue('Remaining Locked Time')],
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
//# sourceMappingURL=common.js.map
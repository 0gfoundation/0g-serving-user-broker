#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.program = void 0;
const tslib_1 = require("tslib");
const commander_1 = require("commander");
const fine_tuning_1 = tslib_1.__importDefault(require("./fine-tuning"));
const ledger_1 = tslib_1.__importDefault(require("./ledger"));
const inference_1 = tslib_1.__importDefault(require("./inference"));
const web_ui_embedded_1 = tslib_1.__importDefault(require("./web-ui-embedded"));
const network_1 = tslib_1.__importDefault(require("./network"));
const auth_1 = tslib_1.__importDefault(require("./auth"));
exports.program = new commander_1.Command();
exports.program
    .name('0g-compute-cli')
    .description('CLI for interacting with ZG Compute Network')
    .version('0.5.4');
(0, ledger_1.default)(exports.program);
// Create subcommands for each service
const fineTuningCmd = exports.program.command('fine-tuning')
    .alias('ft')
    .description('Fine-tuning service commands');
const inferenceCmd = exports.program.command('inference')
    .alias('inf')
    .description('Inference service commands');
const webUICmd = exports.program.command('web-ui')
    .alias('ui')
    .description('Web UI embedded commands');
// Register commands to their respective groups
(0, fine_tuning_1.default)(fineTuningCmd);
(0, inference_1.default)(inferenceCmd);
(0, web_ui_embedded_1.default)(webUICmd);
// Register network configuration commands at the root level
(0, network_1.default)(exports.program);
// Register auth commands at the root level
(0, auth_1.default)(exports.program);
exports.program.parse(process.argv);
//# sourceMappingURL=cli.js.map
#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.program = void 0;
const tslib_1 = require("tslib");
const commander_1 = require("commander");
const fine_tuning_1 = tslib_1.__importDefault(require("./fine-tuning"));
const ledger_1 = tslib_1.__importDefault(require("./ledger"));
const common_1 = tslib_1.__importDefault(require("./common"));
const inference_1 = tslib_1.__importDefault(require("./inference"));
const web_ui_embedded_1 = tslib_1.__importDefault(require("./web-ui-embedded"));
exports.program = new commander_1.Command();
exports.program
    .name('0g-compute-cli')
    .description('CLI for interacting with ZG Compute Network')
    .version('0.4.3');
(0, fine_tuning_1.default)(exports.program);
(0, inference_1.default)(exports.program);
(0, ledger_1.default)(exports.program);
(0, common_1.default)(exports.program);
(0, web_ui_embedded_1.default)(exports.program);
exports.program.parse(process.argv);
//# sourceMappingURL=cli.js.map
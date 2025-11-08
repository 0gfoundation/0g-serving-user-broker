#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.interactiveSelect = interactiveSelect;
exports.textInput = textInput;
exports.passwordInput = passwordInput;
const tslib_1 = require("tslib");
const prompts_1 = tslib_1.__importDefault(require("prompts"));
const chalk_1 = tslib_1.__importDefault(require("chalk"));
/**
 * Interactive selection using prompts library
 */
async function interactiveSelect(config) {
    const response = await (0, prompts_1.default)({
        type: 'select',
        name: 'selection',
        message: config.message,
        choices: config.options.map((option) => ({
            title: option.title,
            description: option.description,
            value: option.value,
        })),
        initial: 0,
    });
    // Handle Ctrl+C (user cancellation)
    if (response.selection === undefined) {
        console.log(chalk_1.default.yellow('\nOperation cancelled.'));
        process.exit(0);
    }
    return response.selection;
}
/**
 * Simple text input prompt
 */
async function textInput(message, placeholder) {
    const response = await (0, prompts_1.default)({
        type: 'text',
        name: 'input',
        message: message,
        initial: placeholder ? '' : undefined,
        style: 'default',
    });
    // Handle Ctrl+C (user cancellation)
    if (response.input === undefined) {
        console.log(chalk_1.default.yellow('\nOperation cancelled.'));
        process.exit(0);
    }
    return response.input.trim();
}
/**
 * Password input prompt (masked input)
 */
async function passwordInput(message, placeholder) {
    const response = await (0, prompts_1.default)({
        type: 'password',
        name: 'password',
        message: message,
        mask: '*',
    });
    // Handle Ctrl+C (user cancellation)
    if (response.password === undefined) {
        console.log(chalk_1.default.yellow('\nOperation cancelled.'));
        process.exit(0);
    }
    return response.password.trim();
}
//# sourceMappingURL=interactive-selection.js.map
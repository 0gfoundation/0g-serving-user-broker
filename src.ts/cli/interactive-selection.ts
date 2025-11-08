#!/usr/bin/env ts-node

import prompts from 'prompts'
import chalk from 'chalk'

interface SelectionOption {
    title: string
    value: string
    description?: string
}

interface SelectionConfig {
    message: string
    options: SelectionOption[]
}

/**
 * Interactive selection using prompts library
 */
export async function interactiveSelect(
    config: SelectionConfig
): Promise<string> {
    const response = await prompts({
        type: 'select',
        name: 'selection',
        message: config.message,
        choices: config.options.map((option) => ({
            title: option.title,
            description: option.description,
            value: option.value,
        })),
        initial: 0,
    })

    // Handle Ctrl+C (user cancellation)
    if (response.selection === undefined) {
        console.log(chalk.yellow('\nOperation cancelled.'))
        process.exit(0)
    }

    return response.selection
}

/**
 * Simple text input prompt
 */
export async function textInput(
    message: string,
    placeholder?: string
): Promise<string> {
    const response = await prompts({
        type: 'text',
        name: 'input',
        message: message,
        initial: placeholder ? '' : undefined,
        style: 'default',
    })

    // Handle Ctrl+C (user cancellation)
    if (response.input === undefined) {
        console.log(chalk.yellow('\nOperation cancelled.'))
        process.exit(0)
    }

    return response.input.trim()
}

/**
 * Password input prompt (masked input)
 */
export async function passwordInput(
    message: string,
    placeholder?: string
): Promise<string> {
    const response = await prompts({
        type: 'password',
        name: 'password',
        message: message,
        mask: '*',
    })

    // Handle Ctrl+C (user cancellation)
    if (response.password === undefined) {
        console.log(chalk.yellow('\nOperation cancelled.'))
        process.exit(0)
    }

    return response.password.trim()
}

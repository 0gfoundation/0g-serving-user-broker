#!/usr/bin/env ts-node
interface SelectionOption {
    title: string;
    value: string;
    description?: string;
}
interface SelectionConfig {
    message: string;
    options: SelectionOption[];
}
/**
 * Interactive selection using prompts library
 */
export declare function interactiveSelect(config: SelectionConfig): Promise<string>;
/**
 * Simple text input prompt
 */
export declare function textInput(message: string, placeholder?: string): Promise<string>;
export {};
//# sourceMappingURL=interactive-selection.d.ts.map
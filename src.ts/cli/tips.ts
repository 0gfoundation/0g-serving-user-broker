import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import chalk from 'chalk'

const TIPS_DIR = path.join(os.homedir(), '.0g-compute-cli')
const TIPS_FILE = path.join(TIPS_DIR, 'tips-seen')

function hasOptedOut(): boolean {
    // ZG_NO_TIPS is the documented name (POSIX-compatible). 0G_NO_TIPS is kept
    // as an undocumented fallback — shells reject identifiers starting with a
    // digit in `VAR=value cmd` / `export VAR=...`, so it can only be set via
    // tools like `env` and isn't something we want to point users at.
    const optOut = process.env.ZG_NO_TIPS ?? process.env['0G_NO_TIPS']
    return optOut === '1' || optOut === 'true'
}

function isInteractive(): boolean {
    // Both stdout and stderr should be TTY so the hint reaches a real user and
    // doesn't contaminate piped output (e.g. `eval "$(... completion zsh)"`).
    return Boolean(process.stdout.isTTY && process.stderr.isTTY)
}

function isCompletionInvocation(argv: string[]): boolean {
    // Skip the tip when the user already knows about completion (or when the
    // invocation itself is generating a script that must keep stdout/stderr
    // clean for `eval`). Match only the first positional arg so user-supplied
    // values like `inference send --message "completion"` don't suppress it.
    const firstPositional = argv.slice(2).find((a) => !a.startsWith('-'))
    return firstPositional === 'completion'
}

function readSeenTips(): Set<string> {
    try {
        const raw = fs.readFileSync(TIPS_FILE, 'utf8')
        return new Set(
            raw
                .split('\n')
                .map((l) => l.trim())
                .filter(Boolean)
        )
    } catch {
        return new Set()
    }
}

function markTipSeen(tip: string, seen: Set<string>): void {
    try {
        seen.add(tip)
        fs.mkdirSync(TIPS_DIR, { recursive: true })
        fs.writeFileSync(TIPS_FILE, Array.from(seen).join('\n') + '\n')
    } catch {
        // Non-fatal: we just won't persist the flag this run. The hint may
        // appear again, which is acceptable.
    }
}

/**
 * Emits a one-time hint about shell completion the first time the CLI is run
 * in an interactive terminal. Silently skipped in non-TTY / CI contexts, when
 * the user has opted out via ZG_NO_TIPS=1, or when the current invocation is
 * itself the completion command.
 */
export function showCompletionHintIfNeeded(cliName: string): void {
    if (hasOptedOut()) return
    if (!isInteractive()) return
    if (isCompletionInvocation(process.argv)) return

    const seen = readSeenTips()
    if (seen.has('completion')) return

    process.stderr.write(
        `\n${chalk.cyan('Tip:')} Enable shell completion (zsh/bash) with ` +
            `\`${cliName} completion --help\`.\n` +
            `     Set ZG_NO_TIPS=1 to silence future hints.\n\n`
    )

    markTipSeen('completion', seen)
}

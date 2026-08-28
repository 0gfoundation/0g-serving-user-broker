import { describe, it } from 'mocha'
import { expect } from 'chai'
import { Command } from 'commander'
import { execFileSync } from 'child_process'
import { generateBashCompletion, generateZshCompletion } from '../completion'

function buildFixture(): Command {
    const program = new Command()
    program.name('0g-compute-cli').version('0.7.5').description('test')
    program.option('-v, --verbose', 'verbose output')

    const inf = program
        .command('inference')
        .alias('inf')
        .description('Inference')
    inf.command('list-providers')
        .option('-d, --detail', 'detail')
        .option('--json', 'json output')
    inf.command('verify').option('--chat-id <id>', 'chat id')

    const ft = program
        .command('fine-tuning')
        .alias('ft')
        .description('Fine-tuning')
    ft.command('create-task').option('-p, --provider <addr>', 'provider')

    return program
}

describe('completion - bash generator', () => {
    it('emits a top-level dispatcher function and compdef registration', () => {
        const script = generateBashCompletion(buildFixture())
        expect(script).to.include('_0g_compute_cli() {')
        expect(script).to.include('complete -F _0g_compute_cli 0g-compute-cli')
    })

    it('includes -h / --help at every node (commander omits these from options)', () => {
        const script = generateBashCompletion(buildFixture())
        // Root
        const rootArm = script.match(/"\"\)[\s\S]*?;;/)?.[0] ?? ''
        expect(rootArm).to.match(/-h.*--help/)
        // Inference group
        const infArm = script.match(/"inference"\|"inf"\)[\s\S]*?;;/)?.[0] ?? ''
        expect(infArm).to.match(/-h.*--help/)
        // Leaf (list-providers)
        const leafArm =
            script.match(
                /"inference list-providers"\|"inf list-providers"\)[\s\S]*?;;/
            )?.[0] ?? ''
        expect(leafArm).to.match(/-h.*--help/)
    })

    it('includes -V / --version exactly once at the root (not duplicated)', () => {
        const script = generateBashCompletion(buildFixture())
        const rootArm = script.match(/"\"\)[\s\S]*?;;/)?.[0] ?? ''
        const vOccurrences = (rootArm.match(/--version/g) ?? []).length
        expect(vOccurrences).to.equal(1)
    })

    it('deduplicates aliases into a single case arm with | alternation', () => {
        const script = generateBashCompletion(buildFixture())
        // Alias group should be a single arm
        expect(script).to.include('"inference"|"inf")')
        expect(script).to.include(
            '"fine-tuning create-task"|"ft create-task")'
        )
        // Alias path must never start its own arm (would indicate it was
        // walked as a separate subtree). It should only ever appear after `|`.
        const standaloneAliasArm = script.match(
            /^\s*"inf list-providers"\)/m
        )
        expect(standaloneAliasArm, 'aliases must share one arm').to.be.null
    })

    it('emits subcommands + aliases as completion words at their parent node', () => {
        const script = generateBashCompletion(buildFixture())
        const rootArm = script.match(/"\"\)[\s\S]*?;;/)?.[0] ?? ''
        expect(rootArm).to.include('inference')
        expect(rootArm).to.include('inf')
        expect(rootArm).to.include('fine-tuning')
        expect(rootArm).to.include('ft')
    })

    it('produces a script that bash can source and complete via compgen', () => {
        const script = generateBashCompletion(buildFixture())
        // Run: source script, invoke the completion function with COMP_WORDS
        // simulating `0g-compute-cli inference <TAB>`, then echo COMPREPLY.
        const driver = `
set +e
${script}
COMP_WORDS=(0g-compute-cli inference "")
COMP_CWORD=2
COMPREPLY=()
_0g_compute_cli
printf '%s\\n' "\${COMPREPLY[@]}"
`
        const out = execFileSync('bash', ['-c', driver], {
            encoding: 'utf8',
        })
        const replies = out.split('\n').filter(Boolean)
        expect(replies).to.include('list-providers')
        expect(replies).to.include('verify')
        expect(replies).to.include('--help')
    })

    it('escapes dangerous chars ($ ` " \\) in generated words', () => {
        const program = new Command()
        program.name('x').version('1.0')
        program.command('weird $(cmd)').option('-a', 'desc')
        const script = generateBashCompletion(program)
        // No un-escaped $( in the generated words, which would cause shell
        // injection when the script is sourced.
        expect(script).to.not.match(/completions="[^"]*\$\([^)]*\)/)
    })
})

describe('completion - zsh generator (smoke)', () => {
    it('emits a compdef header and registration (unchanged by bash work)', () => {
        const script = generateZshCompletion(buildFixture())
        expect(script.startsWith('#compdef 0g-compute-cli')).to.equal(true)
        expect(script).to.include('compdef _0g_compute_cli_main 0g-compute-cli')
    })
})

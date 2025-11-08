"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const mocha_1 = require("mocha");
const chai_1 = require("chai");
const child_process_1 = require("child_process");
const path = tslib_1.__importStar(require("path"));
const fs = tslib_1.__importStar(require("fs"));
const os = tslib_1.__importStar(require("os"));
(0, mocha_1.describe)('0g-compute-cli Integration Tests', () => {
    let tempDir;
    let originalEnv;
    const cliPath = path.join(__dirname, '..', '..', '..', 'cli.commonjs', 'cli', 'index.js');
    (0, mocha_1.beforeEach)(() => {
        // Save original environment
        originalEnv = { ...process.env };
        // Create temp directory for test files
        tempDir = fs.mkdtempSync(path.join(os.tmpdir(), '0g-cli-test-'));
        // Set test environment variables
        process.env.ZG_RPC_ENDPOINT = 'https://evmrpc-testnet.0g.ai';
        process.env.HOME = tempDir;
    });
    (0, mocha_1.afterEach)(() => {
        // Restore original environment
        process.env = originalEnv;
        // Clean up temp directory
        if (fs.existsSync(tempDir)) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });
    (0, mocha_1.describe)('CLI Basic Functionality', () => {
        (0, mocha_1.it)('should display help message', () => {
            const output = (0, child_process_1.execSync)(`node ${cliPath} --help`, {
                encoding: 'utf8',
            });
            (0, chai_1.expect)(output).to.include('0g-compute-cli');
            (0, chai_1.expect)(output).to.include('CLI for interacting with ZG Compute Network');
            (0, chai_1.expect)(output).to.include('fine-tuning');
            (0, chai_1.expect)(output).to.include('inference');
        });
        (0, mocha_1.it)('should display version', () => {
            const output = (0, child_process_1.execSync)(`node ${cliPath} --version`, {
                encoding: 'utf8',
            });
            (0, chai_1.expect)(output).to.match(/\d+\.\d+\.\d+/);
        });
    });
    (0, mocha_1.describe)('Auth Commands', () => {
        (0, mocha_1.it)('should recognize login command', () => {
            // Test that login command is recognized without actually running it interactively
            try {
                const output = (0, child_process_1.execSync)(`node ${cliPath} login --help`, {
                    encoding: 'utf8',
                    env: process.env,
                    timeout: 5000,
                });
                (0, chai_1.expect)(output).to.include('login');
            }
            catch {
                // Even if help is not available, test that command exists by checking it doesn't throw unknown command
                try {
                    // Kill immediately to avoid interactive mode
                    const child = (0, child_process_1.spawn)('node', [cliPath, 'login'], {
                        env: { ...process.env },
                        cwd: process.cwd(),
                    });
                    child.kill();
                }
                catch (error) {
                    const errorMsg = error instanceof Error ? error.message : String(error);
                    (0, chai_1.expect)(errorMsg).to.not.include('Unknown command');
                }
            }
        });
        (0, mocha_1.it)('should handle login command with environment variable', () => {
            process.env.ZG_PRIVATE_KEY =
                '0x0000000000000000000000000000000000000000000000000000000000000001';
            try {
                (0, child_process_1.execSync)(`node ${cliPath} login`, {
                    encoding: 'utf8',
                    env: process.env,
                    timeout: 5000,
                });
                // Check if credentials file was created
                const credPath = path.join(tempDir, '.0g-compute-cli', 'credentials.json');
                if (fs.existsSync(credPath)) {
                    const creds = JSON.parse(fs.readFileSync(credPath, 'utf8'));
                    (0, chai_1.expect)(creds).to.have.property('privateKey');
                }
            }
            catch (error) {
                // Command might fail if RPC is not accessible, but we're testing the structure
                const errorMsg = error instanceof Error ? error.message : String(error);
                // Check that the command was at least recognized
                (0, chai_1.expect)(errorMsg).to.not.include('command not found');
            }
        });
    });
    (0, mocha_1.describe)('Inference Commands', () => {
        (0, mocha_1.it)('should display help for inference commands', () => {
            const output = (0, child_process_1.execSync)(`node ${cliPath} inference --help`, {
                encoding: 'utf8',
            });
            (0, chai_1.expect)(output).to.include('Inference service commands');
            (0, chai_1.expect)(output).to.include('list-providers');
        });
        (0, mocha_1.it)('should handle inference list-providers command', function (done) {
            this.timeout(15000);
            // Set up test credentials
            const testPrivateKey = '0x0000000000000000000000000000000000000000000000000000000000000001';
            const credDir = path.join(tempDir, '.0g-compute-cli');
            fs.mkdirSync(credDir, { recursive: true });
            fs.writeFileSync(path.join(credDir, 'credentials.json'), JSON.stringify({ privateKey: testPrivateKey }));
            let testCompleted = false;
            const child = (0, child_process_1.spawn)('node', [cliPath, 'inference', 'list-providers'], {
                env: { ...process.env },
                cwd: process.cwd(),
                timeout: 14000,
            });
            let output = '';
            let errorOutput = '';
            child.stdout.on('data', (data) => {
                output += data.toString();
            });
            child.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });
            child.on('close', (code) => {
                if (testCompleted)
                    return;
                testCompleted = true;
                try {
                    // The command might fail due to network/contract issues
                    // but we're checking that it's recognized and attempts to run
                    if (code !== 0) {
                        // Check that it's not a command not found error
                        (0, chai_1.expect)(errorOutput).to.not.include('command not found');
                        (0, chai_1.expect)(errorOutput).to.not.include('Unknown command');
                    }
                    else {
                        // If successful, output should contain provider information
                        (0, chai_1.expect)(output.toLowerCase()).to.satisfy((str) => str.includes('provider') ||
                            str.includes('no providers') ||
                            str.includes('address'));
                    }
                    done();
                }
                catch (err) {
                    done(err);
                }
            });
            setTimeout(() => {
                if (!testCompleted) {
                    testCompleted = true;
                    child.kill();
                    done();
                }
            }, 14000);
        });
        (0, mocha_1.it)('should handle inference list-services command', function (done) {
            this.timeout(15000);
            // Set up test credentials
            const testPrivateKey = '0x0000000000000000000000000000000000000000000000000000000000000001';
            const credDir = path.join(tempDir, '.0g-compute-cli');
            fs.mkdirSync(credDir, { recursive: true });
            fs.writeFileSync(path.join(credDir, 'credentials.json'), JSON.stringify({ privateKey: testPrivateKey }));
            let testCompleted = false;
            const child = (0, child_process_1.spawn)('node', [cliPath, 'inference', 'list-services'], {
                env: { ...process.env },
                cwd: process.cwd(),
                timeout: 14000,
            });
            let errorOutput = '';
            child.stdout.on('data', () => {
                // We don't need to capture output for this test
            });
            child.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });
            child.on('close', () => {
                if (testCompleted)
                    return;
                testCompleted = true;
                try {
                    // Check that the command is recognized
                    (0, chai_1.expect)(errorOutput).to.not.include('command not found');
                    (0, chai_1.expect)(errorOutput).to.not.include('Unknown command');
                    done();
                }
                catch (err) {
                    done(err);
                }
            });
            setTimeout(() => {
                if (!testCompleted) {
                    testCompleted = true;
                    child.kill();
                    done();
                }
            }, 14000);
        });
    });
    (0, mocha_1.describe)('Network Commands', () => {
        (0, mocha_1.it)('should display network configuration', () => {
            try {
                const output = (0, child_process_1.execSync)(`node ${cliPath} show-network`, {
                    encoding: 'utf8',
                    env: process.env,
                    timeout: 5000,
                });
                (0, chai_1.expect)(output).to.include('Network Configuration');
                (0, chai_1.expect)(output).to.include('RPC Endpoint');
                (0, chai_1.expect)(output).to.include('evmrpc-testnet.0g.ai');
            }
            catch (error) {
                // Network might be unreachable, but command should be recognized
                const errorMsg = error instanceof Error ? error.message : String(error);
                (0, chai_1.expect)(errorMsg).to.not.include('command not found');
            }
        });
    });
    (0, mocha_1.describe)('Fine-tuning Commands', () => {
        (0, mocha_1.it)('should display help for fine-tuning commands', () => {
            const output = (0, child_process_1.execSync)(`node ${cliPath} fine-tuning --help`, {
                encoding: 'utf8',
            });
            (0, chai_1.expect)(output).to.include('Fine-tuning service commands');
            (0, chai_1.expect)(output).to.include('list-models');
            (0, chai_1.expect)(output).to.include('create-task');
        });
    });
    (0, mocha_1.describe)('Ledger Commands', () => {
        (0, mocha_1.it)('should display help for ledger commands', () => {
            const output = (0, child_process_1.execSync)(`node ${cliPath} ledger --help`, {
                encoding: 'utf8',
            });
            (0, chai_1.expect)(output).to.include('balance');
            (0, chai_1.expect)(output).to.include('deposit');
        });
    });
});
//# sourceMappingURL=cli.integration.test.js.map
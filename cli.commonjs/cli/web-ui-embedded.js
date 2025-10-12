#!/usr/bin/env ts-node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = webUIEmbedded;
const tslib_1 = require("tslib");
const child_process_1 = require("child_process");
const path_1 = tslib_1.__importDefault(require("path"));
const fs_1 = require("fs");
function detectPackageManager() {
    try {
        (0, child_process_1.execSync)('pnpm --version', { stdio: 'ignore' });
        return 'pnpm';
    }
    catch {
        try {
            (0, child_process_1.execSync)('yarn --version', { stdio: 'ignore' });
            return 'yarn';
        }
        catch {
            return 'npm';
        }
    }
}
function webUIEmbedded(program) {
    program
        .command('clean-web')
        .description('Clean web UI build artifacts')
        .option('--all', 'Also remove node_modules')
        .action((options) => {
        const embeddedUIPath = path_1.default.join(__dirname, '../../web-ui');
        const defaultBuildPath = path_1.default.join(embeddedUIPath, '.next');
        let cleaned = false;
        // Check if .next is a symlink
        if ((0, fs_1.existsSync)(defaultBuildPath)) {
            try {
                const stats = (0, fs_1.lstatSync)(defaultBuildPath);
                if (stats.isSymbolicLink()) {
                    const target = (0, fs_1.readlinkSync)(defaultBuildPath);
                    const targetPath = path_1.default.isAbsolute(target)
                        ? target
                        : path_1.default.resolve(path_1.default.dirname(defaultBuildPath), target);
                    console.log(`🔗 Found symlink .next -> ${targetPath}`);
                    // Remove the symlink
                    (0, fs_1.unlinkSync)(defaultBuildPath);
                    console.log('✅ Symlink removed');
                    // Remove the target directory if it exists
                    if ((0, fs_1.existsSync)(targetPath)) {
                        (0, child_process_1.execSync)(`rm -rf "${targetPath}"`);
                        console.log(`✅ Target build directory removed: ${targetPath}`);
                    }
                    cleaned = true;
                }
                else {
                    // It's a real directory
                    (0, child_process_1.execSync)(`rm -rf "${defaultBuildPath}"`);
                    console.log(`✅ Build directory removed: ${defaultBuildPath}`);
                    cleaned = true;
                }
            }
            catch (error) {
                console.error('❌ Failed to clean build directory:', error);
                process.exit(1);
            }
        }
        // Clean node_modules if --all flag is used
        if (options.all) {
            const nodeModulesPath = path_1.default.join(embeddedUIPath, 'node_modules');
            if ((0, fs_1.existsSync)(nodeModulesPath)) {
                console.log('🗑️  Removing node_modules...');
                (0, child_process_1.execSync)(`rm -rf "${nodeModulesPath}"`);
                console.log('✅ node_modules removed');
                cleaned = true;
            }
        }
        if (!cleaned) {
            console.log('ℹ️  No build artifacts found to clean');
        }
        else {
            console.log('\n🎉 Cleanup completed successfully!');
            console.log('   Run "0g-compute-cli start-web --auto-build" to rebuild');
        }
    });
    program
        .command('web-info')
        .description('Show web UI build information')
        .action(() => {
        const embeddedUIPath = path_1.default.join(__dirname, '../../web-ui');
        const defaultBuildPath = path_1.default.join(embeddedUIPath, '.next');
        console.log('📊 Web UI Information:');
        console.log(`   UI Source: ${embeddedUIPath}`);
        if ((0, fs_1.existsSync)(defaultBuildPath)) {
            try {
                const stats = (0, fs_1.lstatSync)(defaultBuildPath);
                if (stats.isSymbolicLink()) {
                    const target = path_1.default.resolve(path_1.default.dirname(defaultBuildPath), (0, fs_1.readlinkSync)(defaultBuildPath));
                    console.log(`   Build Directory: ${target} (symlinked)`);
                }
                else {
                    console.log(`   Build Directory: ${defaultBuildPath}`);
                }
                const buildIdPath = path_1.default.join(defaultBuildPath, 'BUILD_ID');
                if ((0, fs_1.existsSync)(buildIdPath)) {
                    const buildId = (0, fs_1.readFileSync)(buildIdPath, 'utf-8').trim();
                    console.log(`   Build ID: ${buildId}`);
                    console.log(`   Build Status: ✅ Ready`);
                    try {
                        const size = (0, child_process_1.execSync)(`du -sh "${defaultBuildPath}" 2>/dev/null | cut -f1`, { encoding: 'utf-8' }).trim();
                        console.log(`   Build Size: ${size}`);
                    }
                    catch { }
                }
                else {
                    console.log(`   Build Status: ❌ Not built`);
                }
            }
            catch {
                console.log(`   Build Directory: ${defaultBuildPath}`);
                console.log(`   Build Status: ⚠️  Unknown`);
            }
        }
        else {
            console.log(`   Build Status: ❌ Not found`);
            console.log(`   Run "0g-compute-cli start-web --auto-build" to build`);
        }
    });
    program
        .command('start-web')
        .description('Start the embedded web UI')
        .option('--port <port>', 'Port to run the web UI on', '3000')
        .option('--host <host>', 'Host to bind the web UI', 'localhost')
        .option('--mode <mode>', 'Run mode: "development" or "production"', 'production')
        .option('--auto-build', 'Automatically build if needed in production mode')
        .option('--build-dir <dir>', 'Custom directory for Next.js build artifacts')
        .action(async (options) => {
        // 检测包管理器
        const packageManager = detectPackageManager();
        // 查找嵌入的 Web UI
        const embeddedUIPath = path_1.default.join(__dirname, '../../web-ui');
        if (!(0, fs_1.existsSync)(embeddedUIPath)) {
            console.error('❌ Embedded Web UI not found.');
            console.error('This usually means the package was not built correctly.');
            console.error(`Please run: ${packageManager} run build`);
            process.exit(1);
        }
        if (!(0, fs_1.existsSync)(path_1.default.join(embeddedUIPath, 'package.json'))) {
            console.error('❌ Invalid embedded Web UI structure.');
            process.exit(1);
        }
        const defaultBuildPath = path_1.default.join(embeddedUIPath, '.next');
        let actualBuildPath = defaultBuildPath;
        if (options.buildDir) {
            actualBuildPath = path_1.default.isAbsolute(options.buildDir)
                ? options.buildDir
                : path_1.default.resolve(process.cwd(), options.buildDir);
            console.log(`📁 Using custom build directory: ${actualBuildPath}`);
            if (!(0, fs_1.existsSync)(path_1.default.dirname(actualBuildPath))) {
                (0, fs_1.mkdirSync)(path_1.default.dirname(actualBuildPath), {
                    recursive: true,
                });
            }
            if ((0, fs_1.existsSync)(defaultBuildPath)) {
                try {
                    const stats = (0, fs_1.lstatSync)(defaultBuildPath);
                    if (stats.isSymbolicLink()) {
                        (0, fs_1.unlinkSync)(defaultBuildPath);
                    }
                }
                catch { }
            }
            if (!(0, fs_1.existsSync)(defaultBuildPath) &&
                actualBuildPath !== defaultBuildPath) {
                try {
                    (0, fs_1.symlinkSync)(actualBuildPath, defaultBuildPath, 'dir');
                    console.log(`🔗 Created symlink: .next -> ${actualBuildPath}`);
                }
                catch {
                    console.warn('⚠️  Could not create symlink, Next.js will use the custom directory directly');
                }
            }
        }
        const nodeModulesPath = path_1.default.join(embeddedUIPath, 'node_modules');
        if (!(0, fs_1.existsSync)(nodeModulesPath)) {
            console.log('📦 Installing dependencies for embedded UI...');
            try {
                await new Promise((resolve, reject) => {
                    const installProcess = (0, child_process_1.spawn)(packageManager, ['install'], {
                        cwd: embeddedUIPath,
                        stdio: 'inherit',
                    });
                    installProcess.on('close', (code) => {
                        if (code === 0)
                            resolve(undefined);
                        else
                            reject(new Error(`${packageManager} install failed with code ${code}`));
                    });
                });
            }
            catch (error) {
                console.error('❌ Failed to install dependencies:', error.message);
                process.exit(1);
            }
        }
        if (options.mode === 'production') {
            const buildIdPath = path_1.default.join(actualBuildPath, 'BUILD_ID');
            const shouldAutoBuild = options.autoBuild !== false;
            if (!(0, fs_1.existsSync)(buildIdPath) && shouldAutoBuild) {
                console.log('🔨 Building production version (this may take a few minutes)...');
                if (actualBuildPath !== defaultBuildPath) {
                    console.log(`   Build output will be saved to: ${actualBuildPath}`);
                }
                try {
                    await new Promise((resolve, reject) => {
                        const buildProcess = (0, child_process_1.spawn)(packageManager, ['run', 'build'], {
                            cwd: embeddedUIPath,
                            stdio: 'inherit',
                            env: {
                                ...process.env,
                                NEXT_BUILD_DIR: actualBuildPath !== defaultBuildPath
                                    ? actualBuildPath
                                    : undefined,
                            },
                        });
                        buildProcess.on('close', (code) => {
                            if (code === 0) {
                                console.log('✅ Production build completed successfully!');
                                resolve(undefined);
                            }
                            else {
                                reject(new Error(`Build failed with code ${code}`));
                            }
                        });
                    });
                }
                catch (error) {
                    console.error('❌ Failed to build production version:', error.message);
                    console.log('💡 Falling back to development mode...');
                    options.mode = 'development';
                }
            }
            else if (!(0, fs_1.existsSync)(buildIdPath)) {
                console.error('❌ Production build not found or incomplete.');
                console.error('   Run with --auto-build flag to build automatically');
                console.error('   Or use --mode development for development mode');
                process.exit(1);
            }
        }
        // 设置环境变量
        const env = {
            ...process.env,
            NODE_ENV: options.mode === 'production'
                ? 'production'
                : 'development',
            NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID: process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID ||
                'demo-project-id',
            PORT: options.port,
            HOSTNAME: options.host,
        };
        console.log(`🚀 Starting embedded 0G Compute Web UI in ${options.mode} mode...`);
        console.log(`🌐 Server will start on http://${options.host}:${options.port}`);
        let runCommand;
        let runArgs;
        if (options.mode === 'production') {
            runCommand = packageManager === 'pnpm' ? 'pnpm' : 'npx';
            runArgs =
                packageManager === 'pnpm'
                    ? [
                        'next',
                        'start',
                        '--port',
                        options.port,
                        '--hostname',
                        options.host,
                    ]
                    : [
                        'next',
                        'start',
                        '--port',
                        options.port,
                        '--hostname',
                        options.host,
                    ];
        }
        else {
            runCommand = packageManager === 'pnpm' ? 'pnpm' : 'npx';
            runArgs =
                packageManager === 'pnpm'
                    ? [
                        'next',
                        'dev',
                        '--port',
                        options.port,
                        '--hostname',
                        options.host,
                    ]
                    : [
                        'next',
                        'dev',
                        '--port',
                        options.port,
                        '--hostname',
                        options.host,
                    ];
        }
        const nextProcess = (0, child_process_1.spawn)(runCommand, runArgs, {
            cwd: embeddedUIPath,
            stdio: 'inherit',
            env: env,
        });
        nextProcess.on('error', (err) => {
            console.error('❌ Failed to start Web UI:', err);
            process.exit(1);
        });
        process.on('SIGINT', () => {
            console.log('\n🛑 Stopping Web UI...');
            nextProcess.kill('SIGINT');
            process.exit(0);
        });
        process.on('SIGTERM', () => {
            nextProcess.kill('SIGTERM');
            process.exit(0);
        });
    });
}
//# sourceMappingURL=web-ui-embedded.js.map
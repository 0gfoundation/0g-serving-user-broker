"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.startEmbeddedWebUI = startEmbeddedWebUI;
exports.default = webUIEmbedded;
const tslib_1 = require("tslib");
const child_process_1 = require("child_process");
const path_1 = tslib_1.__importDefault(require("path"));
const fs_1 = require("fs");
const express_1 = tslib_1.__importDefault(require("express"));
function getPackageRoot() {
    let currentDir = __dirname;
    while (currentDir !== path_1.default.dirname(currentDir)) {
        const packageJsonPath = path_1.default.join(currentDir, 'package.json');
        if ((0, fs_1.existsSync)(packageJsonPath)) {
            try {
                const packageJsonContent = (0, fs_1.readFileSync)(packageJsonPath, 'utf-8');
                const packageJson = JSON.parse(packageJsonContent);
                if (packageJson.name === '0g-serving-broker') {
                    return currentDir;
                }
            }
            catch {
                // Continue searching
            }
        }
        currentDir = path_1.default.dirname(currentDir);
    }
    // Fallback to relative path
    return path_1.default.resolve(__dirname, '../..');
}
async function startEmbeddedWebUI(port = 3090) {
    const packageRoot = getPackageRoot();
    console.log(`📦 Package root: ${packageRoot}`);
    const webUIRoot = path_1.default.join(packageRoot, 'web-ui');
    if (!(0, fs_1.existsSync)(webUIRoot)) {
        console.error('❌ Web UI not found. Please ensure the package includes the web UI.');
        return;
    }
    console.log(`🌐 Web UI root: ${webUIRoot}`);
    // Check for static export first (new preferred method)
    const staticExportPath = path_1.default.join(webUIRoot, 'out');
    if ((0, fs_1.existsSync)(staticExportPath)) {
        console.log('✅ Using static export build (fastest startup, smallest size)');
        await serveStaticExport(staticExportPath, port);
        return;
    }
    // Fallback to standalone build
    const standaloneBuildPath = path_1.default.join(webUIRoot, '.next', 'standalone');
    if ((0, fs_1.existsSync)(standaloneBuildPath)) {
        console.log('⚠️  Using standalone build (fallback)');
        await serveStandaloneBuild(standaloneBuildPath, webUIRoot, port);
        return;
    }
    // No valid build found
    console.error('❌ No valid build found.');
    console.error(`Expected either:`);
    console.error(`  - Static export: ${staticExportPath}`);
    console.error(`  - Standalone build: ${standaloneBuildPath}`);
    console.error('Please build the web UI first with: npm run build:with-ui-fast');
}
async function serveStaticExport(staticPath, port) {
    console.log(`📁 Serving static files from: ${staticPath}`);
    const app = (0, express_1.default)();
    // Security headers
    app.use((_req, res, next) => {
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        next();
    });
    // Serve static files
    app.use(express_1.default.static(staticPath, {
        maxAge: '1y', // Cache static assets for 1 year
        etag: true,
        lastModified: true,
        setHeaders: (res, filePath) => {
            // Set proper MIME types
            if (filePath.endsWith('.html')) {
                res.setHeader('Cache-Control', 'no-cache');
            }
        },
    }));
    // Handle SPA routing - all non-static requests go to index.html
    app.use((req, res, next) => {
        // Skip if it's a static file request
        if (req.path.includes('.')) {
            next();
            return;
        }
        // Serve index.html for SPA routes
        const indexPath = path_1.default.join(staticPath, 'index.html');
        if ((0, fs_1.existsSync)(indexPath)) {
            res.sendFile(indexPath);
        }
        else {
            res.status(404).send('Static export not found');
        }
    });
    const server = app.listen(port, () => {
        console.log(`🚀 Static web UI server running on http://localhost:${port}`);
        console.log(`📊 Serving from: ${staticPath}`);
    });
    // Handle process termination
    const gracefulShutdown = () => {
        console.log('\n🛑 Shutting down server...');
        server.close(() => {
            console.log('✅ Server shut down gracefully');
            process.exit(0);
        });
    };
    process.on('SIGINT', gracefulShutdown);
    process.on('SIGTERM', gracefulShutdown);
}
async function serveStandaloneBuild(standalonePath, webUIRoot, port) {
    const standaloneServerPath = path_1.default.join(standalonePath, 'server.js');
    // Check if it's a valid embedded Web UI structure
    const expectedFiles = [
        path_1.default.join(standalonePath, 'package.json'),
        standaloneServerPath,
    ];
    const missingFiles = expectedFiles.filter((file) => !(0, fs_1.existsSync)(file));
    if (missingFiles.length > 0) {
        console.error('❌ Invalid embedded Web UI structure');
        console.error('Missing files:', missingFiles);
        return;
    }
    // Smart dependency installation with fallback
    const packageManagers = [
        ['pnpm', ['install', '--prod']],
        ['npm', ['install', '--production']],
        ['yarn', ['install']],
    ];
    let installSuccess = false;
    for (const [cmd, args] of packageManagers) {
        try {
            console.log(`🔧 Using ${cmd} to install dependencies...`);
            const installProcess = (0, child_process_1.spawn)(cmd, args, {
                cwd: standalonePath,
                stdio: 'inherit',
                shell: process.platform === 'win32',
            });
            const installCode = await new Promise((resolve) => {
                installProcess.on('close', resolve);
                installProcess.on('error', () => resolve(null));
            });
            if (installCode === 0) {
                console.log(`✅ Dependencies installed successfully with ${cmd}`);
                installSuccess = true;
                break;
            }
            else {
                throw new Error(`Installation failed with code ${installCode}`);
            }
        }
        catch (error) {
            console.warn(`⚠️  ${cmd} installation failed: ${error.message}`);
            continue;
        }
    }
    if (!installSuccess) {
        console.error('❌ Failed to install dependencies with any package manager');
        return;
    }
    // Copy static files if they exist
    const staticSourcePath = path_1.default.join(webUIRoot, '.next', 'static');
    const staticTargetPath = path_1.default.join(standalonePath, '.next', 'static');
    if ((0, fs_1.existsSync)(staticSourcePath) && !(0, fs_1.existsSync)(staticTargetPath)) {
        try {
            console.log('📁 Copying static files...');
            // Ensure target directory exists
            (0, fs_1.mkdirSync)(path_1.default.dirname(staticTargetPath), { recursive: true });
            // Copy directory recursively
            function copyDir(src, dest) {
                (0, fs_1.mkdirSync)(dest, { recursive: true });
                for (const file of (0, fs_1.readdirSync)(src)) {
                    const srcPath = path_1.default.join(src, file);
                    const destPath = path_1.default.join(dest, file);
                    if ((0, fs_1.statSync)(srcPath).isDirectory()) {
                        copyDir(srcPath, destPath);
                    }
                    else {
                        (0, fs_1.copyFileSync)(srcPath, destPath);
                    }
                }
            }
            copyDir(staticSourcePath, staticTargetPath);
            console.log('✅ Static files copied successfully');
        }
        catch (copyError) {
            console.warn('⚠️  Failed to copy static files:', copyError);
        }
    }
    // Set environment and start the server
    console.log(`🚀 Starting Next.js standalone server on http://localhost:${port}`);
    const serverProcess = (0, child_process_1.spawn)('node', ['server.js'], {
        cwd: standalonePath,
        stdio: 'inherit',
        env: {
            ...process.env,
            PORT: port.toString(),
            NODE_ENV: 'production',
        },
        shell: process.platform === 'win32',
    });
    // Handle process termination
    process.on('SIGINT', () => {
        console.log('\n🛑 Shutting down server...');
        serverProcess.kill('SIGTERM');
    });
    process.on('SIGTERM', () => {
        console.log('\n🛑 Shutting down server...');
        serverProcess.kill('SIGTERM');
    });
    // Wait for the server process to exit
    await new Promise((resolve) => {
        serverProcess.on('close', () => {
            console.log('✅ Server shut down gracefully');
            resolve();
        });
    });
}
function webUIEmbedded(cmd) {
    cmd.command('start-web')
        .description('Start embedded web UI server')
        .option('-p, --port <port>', 'Port to run the server on', '3090')
        .action(async (options) => {
        const port = parseInt(options.port, 10);
        await startEmbeddedWebUI(port);
    });
}
//# sourceMappingURL=web-ui-embedded.js.map
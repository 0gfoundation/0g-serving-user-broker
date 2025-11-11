import { spawn } from 'child_process'
import path from 'path'
import {
    existsSync,
    readFileSync,
    copyFileSync,
    mkdirSync,
    readdirSync,
    statSync,
} from 'fs'
import express from 'express'
import type { Command } from 'commander'

function getPackageRoot(): string {
    let currentDir = __dirname
    while (currentDir !== path.dirname(currentDir)) {
        const packageJsonPath = path.join(currentDir, 'package.json')
        if (existsSync(packageJsonPath)) {
            try {
                const packageJsonContent = readFileSync(
                    packageJsonPath,
                    'utf-8'
                )
                const packageJson = JSON.parse(packageJsonContent)
                if (packageJson.name === '0g-serving-broker') {
                    return currentDir
                }
            } catch {
                // Continue searching
            }
        }
        currentDir = path.dirname(currentDir)
    }
    // Fallback to relative path
    return path.resolve(__dirname, '../..')
}

export async function startEmbeddedWebUI(port = 3090): Promise<void> {
    const packageRoot = getPackageRoot()
    console.log(`📦 Package root: ${packageRoot}`)

    const webUIRoot = path.join(packageRoot, 'web-ui')

    if (!existsSync(webUIRoot)) {
        console.error(
            '❌ Web UI not found. Please ensure the package includes the web UI.'
        )
        return
    }

    console.log(`🌐 Web UI root: ${webUIRoot}`)

    // Check for static export first (new preferred method)
    const staticExportPath = path.join(webUIRoot, 'out')
    if (existsSync(staticExportPath)) {
        console.log(
            '✅ Using static export build (fastest startup, smallest size)'
        )
        await serveStaticExport(staticExportPath, port)
        return
    }

    // Fallback to standalone build
    const standaloneBuildPath = path.join(webUIRoot, '.next', 'standalone')
    if (existsSync(standaloneBuildPath)) {
        console.log('⚠️  Using standalone build (fallback)')
        await serveStandaloneBuild(standaloneBuildPath, webUIRoot, port)
        return
    }

    // No valid build found
    console.error('❌ No valid build found.')
    console.error(`Expected either:`)
    console.error(`  - Static export: ${staticExportPath}`)
    console.error(`  - Standalone build: ${standaloneBuildPath}`)
    console.error(
        'Please build the web UI first with: npm run build:with-ui-fast'
    )
}

async function serveStaticExport(
    staticPath: string,
    port: number
): Promise<void> {
    console.log(`📁 Serving static files from: ${staticPath}`)

    const app = express()

    // Security headers
    app.use((_req: any, res: any, next: any) => {
        res.setHeader('X-Frame-Options', 'DENY')
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.setHeader('X-XSS-Protection', '1; mode=block')
        next()
    })

    // Serve static files
    app.use(
        express.static(staticPath, {
            maxAge: '1y', // Cache static assets for 1 year
            etag: true,
            lastModified: true,
            setHeaders: (res: any, filePath: string) => {
                // Set proper MIME types
                if (filePath.endsWith('.html')) {
                    res.setHeader('Cache-Control', 'no-cache')
                }
            },
        })
    )

    // Handle SPA routing - all non-static requests go to index.html
    app.use((req: any, res: any, next: any) => {
        // Skip if it's a static file request
        if (req.path.includes('.')) {
            next()
            return
        }

        // Serve index.html for SPA routes
        const indexPath = path.join(staticPath, 'index.html')
        if (existsSync(indexPath)) {
            res.sendFile(indexPath)
        } else {
            res.status(404).send('Static export not found')
        }
    })

    const server = app.listen(port, () => {
        console.log(
            `🚀 Static web UI server running on http://localhost:${port}`
        )
        console.log(`📊 Serving from: ${staticPath}`)
    })

    // Handle process termination
    const gracefulShutdown = () => {
        console.log('\n🛑 Shutting down server...')
        server.close(() => {
            console.log('✅ Server shut down gracefully')
            process.exit(0)
        })
    }

    process.on('SIGINT', gracefulShutdown)
    process.on('SIGTERM', gracefulShutdown)
}

async function serveStandaloneBuild(
    standalonePath: string,
    webUIRoot: string,
    port: number
): Promise<void> {
    const standaloneServerPath = path.join(standalonePath, 'server.js')

    // Check if it's a valid embedded Web UI structure
    const expectedFiles = [
        path.join(standalonePath, 'package.json'),
        standaloneServerPath,
    ]

    const missingFiles = expectedFiles.filter((file) => !existsSync(file))
    if (missingFiles.length > 0) {
        console.error('❌ Invalid embedded Web UI structure')
        console.error('Missing files:', missingFiles)
        return
    }

    // Smart dependency installation with fallback
    const packageManagers = [
        ['pnpm', ['install', '--prod']],
        ['npm', ['install', '--production']],
        ['yarn', ['install']],
    ]

    let installSuccess = false
    for (const [cmd, args] of packageManagers) {
        try {
            console.log(`🔧 Using ${cmd} to install dependencies...`)
            const installProcess = spawn(cmd as string, args as string[], {
                cwd: standalonePath,
                stdio: 'inherit',
                shell: process.platform === 'win32',
            })

            const installCode = await new Promise<number | null>((resolve) => {
                installProcess.on('close', resolve)
                installProcess.on('error', () => resolve(null))
            })

            if (installCode === 0) {
                console.log(
                    `✅ Dependencies installed successfully with ${cmd}`
                )
                installSuccess = true
                break
            } else {
                throw new Error(`Installation failed with code ${installCode}`)
            }
        } catch (error) {
            console.warn(
                `⚠️  ${cmd} installation failed: ${(error as Error).message}`
            )
            continue
        }
    }

    if (!installSuccess) {
        console.error(
            '❌ Failed to install dependencies with any package manager'
        )
        return
    }

    // Copy static files if they exist
    const staticSourcePath = path.join(webUIRoot, '.next', 'static')
    const staticTargetPath = path.join(standalonePath, '.next', 'static')

    if (existsSync(staticSourcePath) && !existsSync(staticTargetPath)) {
        try {
            console.log('📁 Copying static files...')

            // Ensure target directory exists
            mkdirSync(path.dirname(staticTargetPath), { recursive: true })

            // Copy directory recursively
            function copyDir(src: string, dest: string) {
                mkdirSync(dest, { recursive: true })

                for (const file of readdirSync(src)) {
                    const srcPath = path.join(src, file)
                    const destPath = path.join(dest, file)

                    if (statSync(srcPath).isDirectory()) {
                        copyDir(srcPath, destPath)
                    } else {
                        copyFileSync(srcPath, destPath)
                    }
                }
            }

            copyDir(staticSourcePath, staticTargetPath)
            console.log('✅ Static files copied successfully')
        } catch (copyError) {
            console.warn('⚠️  Failed to copy static files:', copyError)
        }
    }

    // Set environment and start the server

    console.log(
        `🚀 Starting Next.js standalone server on http://localhost:${port}`
    )

    const serverProcess = spawn('node', ['server.js'], {
        cwd: standalonePath,
        stdio: 'inherit',
        env: {
            ...process.env,
            PORT: port.toString(),
            NODE_ENV: 'production',
        },
        shell: process.platform === 'win32',
    })

    // Handle process termination
    process.on('SIGINT', () => {
        console.log('\n🛑 Shutting down server...')
        serverProcess.kill('SIGTERM')
    })

    process.on('SIGTERM', () => {
        console.log('\n🛑 Shutting down server...')
        serverProcess.kill('SIGTERM')
    })

    // Wait for the server process to exit
    await new Promise<void>((resolve) => {
        serverProcess.on('close', () => {
            console.log('✅ Server shut down gracefully')
            resolve()
        })
    })
}

export default function webUIEmbedded(cmd: Command): void {
    cmd.command('start-web')
        .description('Start embedded web UI server')
        .option('-p, --port <port>', 'Port to run the server on', '3090')
        .action(async (options) => {
            const port = parseInt(options.port, 10)
            await startEmbeddedWebUI(port)
        })
}

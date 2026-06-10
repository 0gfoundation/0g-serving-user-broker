import { spawn } from 'child_process'
import path from 'path'
import {
    existsSync,
    readFileSync,
    copyFileSync,
    mkdirSync,
    readdirSync,
    statSync,
    createReadStream,
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
                if (packageJson.name === '@0gfoundation/0g-compute-ts-sdk') {
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

export async function startEmbeddedWebUI(
    port = 3090,
    host = 'localhost'
): Promise<void> {
    console.log(
        '✨ A new and improved web experience is now available at:'
    )
    console.log('   👉 https://pc.0g.ai/sdk')
    console.log(
        '   This embedded web UI is in maintenance mode and will not receive new features.'
    )
    console.log()

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
        await serveStaticExport(staticExportPath, port, host)
        return
    }

    // Fallback to standalone build
    const standaloneBuildPath = path.join(webUIRoot, '.next', 'standalone')
    if (existsSync(standaloneBuildPath)) {
        console.log('⚠️  Using standalone build (fallback)')
        await serveStandaloneBuild(standaloneBuildPath, webUIRoot, port, host)
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
    port: number,
    host: string
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

    // Handle Next.js static export routing with optimal file serving
    app.use((req: any, res: any, next: any) => {
        // Skip if it's a static asset request (JS, CSS, images, etc.)
        if (
            req.path.startsWith('/_next/') ||
            req.path.match(
                /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|txt)$/
            )
        ) {
            next()
            return
        }

        // Normalize the path and look for corresponding HTML file
        let htmlPath = req.path

        // Handle root path
        if (htmlPath === '/') {
            htmlPath = 'index.html'
        } else {
            // Remove trailing slash if present
            htmlPath = htmlPath.replace(/\/$/, '')

            // Check if direct HTML file exists (e.g., /inference -> inference.html)
            const directFile = path.join(
                staticPath,
                htmlPath.substring(1) + '.html'
            )
            if (existsSync(directFile)) {
                htmlPath = htmlPath.substring(1) + '.html'
            } else {
                // Check if nested HTML file exists (e.g., /inference/chat -> inference/chat.html)
                const nestedFile = path.join(
                    staticPath,
                    htmlPath.substring(1) + '.html'
                )
                if (existsSync(nestedFile)) {
                    htmlPath = htmlPath.substring(1) + '.html'
                } else {
                    // Fallback to index.html for client-side routing
                    htmlPath = 'index.html'
                }
            }
        }

        const fullPath = path.resolve(staticPath, htmlPath)
        if (existsSync(fullPath)) {
            // Get file stats for better caching
            const stat = statSync(fullPath)

            // Set proper headers
            res.setHeader('Content-Type', 'text/html; charset=utf-8')
            res.setHeader('Content-Length', stat.size.toString())

            // For HTML files, prevent caching to ensure fresh content
            res.setHeader(
                'Cache-Control',
                'no-cache, no-store, must-revalidate'
            )
            res.setHeader('Pragma', 'no-cache')
            res.setHeader('Expires', '0')

            // Use stream for better memory efficiency
            const stream = createReadStream(fullPath)

            stream.on('error', (err) => {
                console.error(`Error reading file: ${err}`)
                if (!res.headersSent) {
                    res.status(500).send('Internal server error')
                }
            })

            stream.pipe(res)
        } else {
            res.status(404).send('Page not found')
        }
    })

    // Serve static assets only (after SPA routing to prevent directory redirects)
    app.use(
        express.static(staticPath, {
            maxAge: '1y', // Cache static assets for 1 year
            etag: true,
            lastModified: true,
            index: false, // Disable index.html serving to prevent conflicts
            setHeaders: (res: any, filePath: string) => {
                // Set proper cache headers for static assets
                if (
                    filePath.match(
                        /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/
                    )
                ) {
                    res.setHeader('Cache-Control', 'public, max-age=31536000') // 1 year
                }
            },
        })
    )

    const server = app.listen(port, host, () => {
        const displayHost = host === '0.0.0.0' ? 'all interfaces' : host
        console.log(
            `🚀 Static web UI server running on http://${displayHost}:${port}`
        )
        if (host === '0.0.0.0') {
            console.log(
                `📡 Accessible from LAN at http://<your-local-ip>:${port}`
            )
        }
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
    port: number,
    host: string
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
        `🚀 Starting Next.js standalone server on http://${host}:${port}`
    )
    if (host === '0.0.0.0') {
        console.log(`📡 Accessible from LAN at http://<your-local-ip>:${port}`)
    }

    const serverProcess = spawn('node', ['server.js'], {
        cwd: standalonePath,
        stdio: 'inherit',
        env: {
            ...process.env,
            PORT: port.toString(),
            HOSTNAME: host,
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
        .option(
            '-H, --host <host>',
            'Host to bind the server to (use 0.0.0.0 for LAN access)',
            'localhost'
        )
        .action(async (options) => {
            const port = parseInt(options.port, 10)
            const host = options.host
            await startEmbeddedWebUI(port, host)
        })
}

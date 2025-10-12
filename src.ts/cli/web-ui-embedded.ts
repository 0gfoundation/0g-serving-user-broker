#!/usr/bin/env ts-node

import type { Command } from 'commander'
import { spawn, execSync } from 'child_process'
import path from 'path'
import {
    existsSync,
    mkdirSync,
    symlinkSync,
    unlinkSync,
    lstatSync,
    readFileSync,
    readlinkSync,
} from 'fs'

function detectPackageManager(): 'pnpm' | 'yarn' | 'npm' {
    try {
        execSync('pnpm --version', { stdio: 'ignore' })
        return 'pnpm'
    } catch {
        try {
            execSync('yarn --version', { stdio: 'ignore' })
            return 'yarn'
        } catch {
            return 'npm'
        }
    }
}

export default function webUIEmbedded(program: Command) {
    program
        .command('clean-web')
        .description('Clean web UI build artifacts')
        .option('--all', 'Also remove node_modules')
        .action((options) => {
            const embeddedUIPath = path.join(__dirname, '../../web-ui')
            const defaultBuildPath = path.join(embeddedUIPath, '.next')
            let cleaned = false
            
            // Check if .next is a symlink
            if (existsSync(defaultBuildPath)) {
                try {
                    const stats = lstatSync(defaultBuildPath)
                    if (stats.isSymbolicLink()) {
                        const target = readlinkSync(defaultBuildPath)
                        const targetPath = path.isAbsolute(target) 
                            ? target 
                            : path.resolve(path.dirname(defaultBuildPath), target)
                        
                        console.log(`🔗 Found symlink .next -> ${targetPath}`)
                        
                        // Remove the symlink
                        unlinkSync(defaultBuildPath)
                        console.log('✅ Symlink removed')
                        
                        // Remove the target directory if it exists
                        if (existsSync(targetPath)) {
                            execSync(`rm -rf "${targetPath}"`)
                            console.log(`✅ Target build directory removed: ${targetPath}`)
                        }
                        cleaned = true
                    } else {
                        // It's a real directory
                        execSync(`rm -rf "${defaultBuildPath}"`)
                        console.log(`✅ Build directory removed: ${defaultBuildPath}`)
                        cleaned = true
                    }
                } catch (error) {
                    console.error('❌ Failed to clean build directory:', error)
                    process.exit(1)
                }
            }
            
            // Clean node_modules if --all flag is used
            if (options.all) {
                const nodeModulesPath = path.join(embeddedUIPath, 'node_modules')
                if (existsSync(nodeModulesPath)) {
                    console.log('🗑️  Removing node_modules...')
                    execSync(`rm -rf "${nodeModulesPath}"`)
                    console.log('✅ node_modules removed')
                    cleaned = true
                }
            }
            
            if (!cleaned) {
                console.log('ℹ️  No build artifacts found to clean')
            } else {
                console.log('\n🎉 Cleanup completed successfully!')
                console.log('   Run "0g-compute-cli start-web --auto-build" to rebuild')
            }
        })

    program
        .command('web-info')
        .description('Show web UI build information')
        .action(() => {
            const embeddedUIPath = path.join(__dirname, '../../web-ui')
            const defaultBuildPath = path.join(embeddedUIPath, '.next')

            console.log('📊 Web UI Information:')
            console.log(`   UI Source: ${embeddedUIPath}`)

            if (existsSync(defaultBuildPath)) {
                try {
                    const stats = lstatSync(defaultBuildPath)
                    if (stats.isSymbolicLink()) {
                        const target = path.resolve(
                            path.dirname(defaultBuildPath),
                            readlinkSync(defaultBuildPath)
                        )
                        console.log(`   Build Directory: ${target} (symlinked)`)
                    } else {
                        console.log(`   Build Directory: ${defaultBuildPath}`)
                    }

                    const buildIdPath = path.join(defaultBuildPath, 'BUILD_ID')
                    if (existsSync(buildIdPath)) {
                        const buildId = readFileSync(
                            buildIdPath,
                            'utf-8'
                        ).trim()
                        console.log(`   Build ID: ${buildId}`)
                        console.log(`   Build Status: ✅ Ready`)

                        try {
                            const size = execSync(
                                `du -sh "${defaultBuildPath}" 2>/dev/null | cut -f1`,
                                { encoding: 'utf-8' }
                            ).trim()
                            console.log(`   Build Size: ${size}`)
                        } catch {}
                    } else {
                        console.log(`   Build Status: ❌ Not built`)
                    }
                } catch {
                    console.log(`   Build Directory: ${defaultBuildPath}`)
                    console.log(`   Build Status: ⚠️  Unknown`)
                }
            } else {
                console.log(`   Build Status: ❌ Not found`)
                console.log(
                    `   Run "0g-compute-cli start-web --auto-build" to build`
                )
            }
        })

    program
        .command('start-web')
        .description('Start the embedded web UI')
        .option('--port <port>', 'Port to run the web UI on', '3000')
        .option('--host <host>', 'Host to bind the web UI', 'localhost')
        .option(
            '--mode <mode>',
            'Run mode: "development" or "production"',
            'production'
        )
        .option(
            '--auto-build',
            'Automatically build if needed in production mode'
        )
        .option(
            '--build-dir <dir>',
            'Custom directory for Next.js build artifacts'
        )
        .action(async (options) => {
            // 检测包管理器
            const packageManager = detectPackageManager()

            // 查找嵌入的 Web UI
            const embeddedUIPath = path.join(__dirname, '../../web-ui')

            if (!existsSync(embeddedUIPath)) {
                console.error('❌ Embedded Web UI not found.')
                console.error(
                    'This usually means the package was not built correctly.'
                )
                console.error(`Please run: ${packageManager} run build`)
                process.exit(1)
            }

            if (!existsSync(path.join(embeddedUIPath, 'package.json'))) {
                console.error('❌ Invalid embedded Web UI structure.')
                process.exit(1)
            }

            const defaultBuildPath = path.join(embeddedUIPath, '.next')
            let actualBuildPath = defaultBuildPath

            if (options.buildDir) {
                actualBuildPath = path.isAbsolute(options.buildDir)
                    ? options.buildDir
                    : path.resolve(process.cwd(), options.buildDir)

                console.log(
                    `📁 Using custom build directory: ${actualBuildPath}`
                )

                if (!existsSync(path.dirname(actualBuildPath))) {
                    mkdirSync(path.dirname(actualBuildPath), {
                        recursive: true,
                    })
                }

                if (existsSync(defaultBuildPath)) {
                    try {
                        const stats = lstatSync(defaultBuildPath)
                        if (stats.isSymbolicLink()) {
                            unlinkSync(defaultBuildPath)
                        }
                    } catch {}
                }

                if (
                    !existsSync(defaultBuildPath) &&
                    actualBuildPath !== defaultBuildPath
                ) {
                    try {
                        symlinkSync(actualBuildPath, defaultBuildPath, 'dir')
                        console.log(
                            `🔗 Created symlink: .next -> ${actualBuildPath}`
                        )
                    } catch {
                        console.warn(
                            '⚠️  Could not create symlink, Next.js will use the custom directory directly'
                        )
                    }
                }
            }

            const nodeModulesPath = path.join(embeddedUIPath, 'node_modules')
            if (!existsSync(nodeModulesPath)) {
                console.log('📦 Installing dependencies for embedded UI...')
                try {
                    await new Promise((resolve, reject) => {
                        const installProcess = spawn(
                            packageManager,
                            ['install'],
                            {
                                cwd: embeddedUIPath,
                                stdio: 'inherit',
                            }
                        )

                        installProcess.on('close', (code) => {
                            if (code === 0) resolve(undefined)
                            else
                                reject(
                                    new Error(
                                        `${packageManager} install failed with code ${code}`
                                    )
                                )
                        })
                    })
                } catch (error) {
                    console.error(
                        '❌ Failed to install dependencies:',
                        (error as Error).message
                    )
                    process.exit(1)
                }
            }

            if (options.mode === 'production') {
                const buildIdPath = path.join(actualBuildPath, 'BUILD_ID')
                const shouldAutoBuild = options.autoBuild !== false
                if (!existsSync(buildIdPath) && shouldAutoBuild) {
                    console.log(
                        '🔨 Building production version (this may take a few minutes)...'
                    )
                    if (actualBuildPath !== defaultBuildPath) {
                        console.log(
                            `   Build output will be saved to: ${actualBuildPath}`
                        )
                    }
                    try {
                        await new Promise((resolve, reject) => {
                            const buildProcess = spawn(
                                packageManager,
                                ['run', 'build'],
                                {
                                    cwd: embeddedUIPath,
                                    stdio: 'inherit',
                                    env: {
                                        ...process.env,
                                        NEXT_BUILD_DIR:
                                            actualBuildPath !== defaultBuildPath
                                                ? actualBuildPath
                                                : undefined,
                                    },
                                }
                            )

                            buildProcess.on('close', (code) => {
                                if (code === 0) {
                                    console.log(
                                        '✅ Production build completed successfully!'
                                    )
                                    resolve(undefined)
                                } else {
                                    reject(
                                        new Error(
                                            `Build failed with code ${code}`
                                        )
                                    )
                                }
                            })
                        })
                    } catch (error) {
                        console.error(
                            '❌ Failed to build production version:',
                            (error as Error).message
                        )
                        console.log('💡 Falling back to development mode...')
                        options.mode = 'development'
                    }
                } else if (!existsSync(buildIdPath)) {
                    console.error(
                        '❌ Production build not found or incomplete.'
                    )
                    console.error(
                        '   Run with --auto-build flag to build automatically'
                    )
                    console.error(
                        '   Or use --mode development for development mode'
                    )
                    process.exit(1)
                }
            }

            // 设置环境变量
            const env = {
                ...process.env,
                NODE_ENV:
                    options.mode === 'production'
                        ? 'production'
                        : 'development',
                NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID:
                    process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID ||
                    'demo-project-id',
                PORT: options.port,
                HOSTNAME: options.host,
            }

            console.log(
                `🚀 Starting embedded 0G Compute Web UI in ${options.mode} mode...`
            )
            console.log(
                `🌐 Server will start on http://${options.host}:${options.port}`
            )

            let runCommand: string
            let runArgs: string[]

            if (options.mode === 'production') {
                runCommand = packageManager === 'pnpm' ? 'pnpm' : 'npx'
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
                          ]
            } else {
                runCommand = packageManager === 'pnpm' ? 'pnpm' : 'npx'
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
                          ]
            }

            const nextProcess = spawn(runCommand, runArgs, {
                cwd: embeddedUIPath,
                stdio: 'inherit',
                env: env,
            })

            nextProcess.on('error', (err) => {
                console.error('❌ Failed to start Web UI:', err)
                process.exit(1)
            })

            process.on('SIGINT', () => {
                console.log('\n🛑 Stopping Web UI...')
                nextProcess.kill('SIGINT')
                process.exit(0)
            })

            process.on('SIGTERM', () => {
                nextProcess.kill('SIGTERM')
                process.exit(0)
            })
        })
}

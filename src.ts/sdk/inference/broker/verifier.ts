import type { TdxQuoteResponse } from './base'
import { ZGServingUserBrokerBase } from './base'
import { ethers } from 'ethers'
import { throwFormattedError } from '../../common/utils'
import type { InferenceServingContract } from '../contract'
import type { LedgerBroker } from '../../ledger'
import type { Cache, Metadata } from '../../common/storage'
import { createHash } from 'crypto'

export interface ResponseSignature {
    text: string
    signature: string
}

export interface SingerRAVerificationResult {
    /**
     * Whether the signer RA is valid
     * null means the RA has not been verified
     */
    valid: boolean | null
    /**
     * The signing address of the signer
     */
    signingAddress: string
}

export interface VerificationResult {
    success: boolean
    teeVerifier: string
    targetSeparated: boolean
    verifierURL?: string
    reportsGenerated: string[]
    outputDirectory: string
}

export interface AdditionalInfo {
    VerifierURL?: string
    TargetSeparated?: boolean
    TEEVerifier?: string
    TargetTeeAddress?: string
}

export interface AttestationReport {
    tcb_info?: Record<string, unknown>
    event_log?: EventLogEntry[]
    [key: string]: unknown
}

export interface EventLogEntry {
    event: string
    event_payload?: string
    [key: string]: unknown
}

export interface ComposeVerificationResult {
    isValid: boolean
    error?: string
    calculatedHash?: string
    eventLogHash?: string
    composeHashEvent?: EventLogEntry
}

export interface VerificationSummary {
    composeVerification: boolean
    signerAddressVerification: boolean
    signerAddressMatches: number
    totalReports: number
    allVerificationsPassed: boolean
}

/**
 * The Verifier class contains methods for verifying service reliability.
 */
export class Verifier extends ZGServingUserBrokerBase {
    constructor(
        contract: InferenceServingContract,
        ledger: LedgerBroker,
        metadata: Metadata,
        cache: Cache
    ) {
        super(contract, ledger, metadata, cache)
    }

    /**
     * Comprehensive TEE service verification guide
     * Guides users through verifying whether a provider is running in TEE
     *
     * @param providerAddress - The provider address to verify
     * @param outputDir - Directory to save attestation reports (default: current directory)
     * @returns Verification results and user guidance
     */
    async verifyService(
        providerAddress: string,
        outputDir: string = '.'
    ): Promise<VerificationResult> {
        try {
            console.log(
                `🔍 Starting TEE verification for provider: ${providerAddress}`
            )
            console.log('')

            // Step 1: Get service information from contract
            console.log(
                '📋 Step 1: Retrieving service information from contract...'
            )
            const svc = await this.getService(providerAddress)

            if (!svc.additionalInfo) {
                throw new Error(
                    'Service additionalInfo is missing - cannot proceed with verification'
                )
            }

            // Step 2: Parse additionalInfo and analyze service configuration
            console.log(
                '🔧 Step 2: Parsing and analyzing service configuration...'
            )
            let additionalInfo: AdditionalInfo
            try {
                additionalInfo = JSON.parse(
                    svc.additionalInfo
                ) as AdditionalInfo
            } catch {
                throw new Error(
                    'Failed to parse service additionalInfo as JSON'
                )
            }

            const verifierURL = additionalInfo.VerifierURL
            const targetSeparated = additionalInfo.TargetSeparated === true
            const teeVerifier = additionalInfo.TEEVerifier || 'dstack' // default to dstack

            if (!verifierURL) {
                console.warn(
                    '⚠️  Warning: VerifierURL not found in additionalInfo'
                )
            }

            // Display service verification configuration
            console.log(`   Provider URL: ${svc.url}`)
            console.log(`   TEE Verifier: ${teeVerifier}`)

            // TEE verification method information
            if (teeVerifier === 'dstack') {
                console.log('   Verification Method: DStack TEE (Intel TDX)')
                console.log(
                    '   Verification includes: Quote validation, Compose hash check, Image integrity'
                )
            } else if (teeVerifier === 'cryptopilot') {
                console.log('   Verification Method: CryptoPilot TEE')
                console.log(
                    '   ⚠️  CryptoPilot verification flow is not yet implemented'
                )
            } else {
                console.log(`   Verification Method: Unknown (${teeVerifier})`)
            }

            // Component architecture information
            if (targetSeparated) {
                console.log(
                    '   Architecture: Separated (Broker and LLM inference in different TEE nodes)'
                )
                console.log('   Required Reports: 2 (Broker + LLM inference)')
            } else {
                console.log(
                    '   Architecture: Combined (Broker and LLM inference in same TEE node)'
                )
                console.log('   Required Reports: 1 (Combined)')
            }

            if (verifierURL) {
                console.log(`   Verifier Image URL: ${verifierURL}`)
            }
            console.log('')

            // Step 3: Get attestation reports
            console.log('📥 Step 3: Downloading attestation reports...')
            const reports: Record<string, AttestationReport> = {}

            if (targetSeparated) {
                // Get both broker and LLM reports
                console.log('   Downloading broker attestation report...')
                const brokerReport = await this.getQuote(providerAddress)
                const brokerPath = `${outputDir}/broker_attestation_report.json`
                await this.saveReportToFile(brokerReport.rawReport, brokerPath)
                reports.broker = JSON.parse(
                    brokerReport.rawReport
                ) as AttestationReport
                console.log(`   ✅ Broker report saved to: ${brokerPath}`)

                console.log(
                    '   Downloading LLM inference attestation report...'
                )
                const llmReport = await this.getQuoteInLLMServer(
                    svc.url,
                    svc.model
                )
                const llmPath = `${outputDir}/llm_attestation_report.json`
                await this.saveReportToFile(llmReport.rawReport, llmPath)
                reports.llm = JSON.parse(
                    llmReport.rawReport
                ) as AttestationReport
                console.log(`   ✅ LLM report saved to: ${llmPath}`)
            } else {
                // Get single combined report via broker
                console.log('   Downloading combined attestation report...')
                const combinedReport = await this.getQuote(providerAddress)
                const combinedPath = `${outputDir}/attestation_report.json`
                await this.saveReportToFile(
                    combinedReport.rawReport,
                    combinedPath
                )
                reports.combined = JSON.parse(
                    combinedReport.rawReport
                ) as AttestationReport
                console.log(`   ✅ Combined report saved to: ${combinedPath}`)
            }
            console.log('')

            // Step 4: TEE Signer Address Verification
            console.log('🔑 Step 4: TEE Signer Address Verification')
            console.log(
                `   Contract TEE Signer Address: ${svc.teeSignerAddress}`
            )

            // Extract signer addresses from reports and verify
            let signerMatches = 0
            let totalSignerChecks = 0
            for (const [reportType, report] of Object.entries(reports)) {
                const reportSignerAddress = this.extractTeeSignerAddress(report)
                if (reportSignerAddress) {
                    totalSignerChecks++
                    const addressMatch =
                        reportSignerAddress.toLowerCase() ===
                        svc.teeSignerAddress.toLowerCase()
                    console.log(
                        `   ${
                            reportType.charAt(0).toUpperCase() +
                            reportType.slice(1)
                        } Report Signer: ${reportSignerAddress}`
                    )
                    console.log(
                        `   Address Match: ${
                            addressMatch ? '✅ MATCH' : '❌ MISMATCH'
                        }`
                    )

                    if (addressMatch) {
                        signerMatches++
                    } else {
                        console.log(
                            `   ⚠️  Warning: TEE signer address mismatch detected!`
                        )
                    }
                } else {
                    console.log(
                        `   ${
                            reportType.charAt(0).toUpperCase() +
                            reportType.slice(1)
                        } Report: No signer address found`
                    )
                }
            }
            console.log('')

            // Step 5: Process DStack verification if applicable
            let dockerImages: string[] = []
            let composeVerificationPassed = false
            if (teeVerifier === 'dstack') {
                console.log('🔍 Step 5: DStack Verification Process')
                const result = await this.processDStackVerification(reports)
                dockerImages = result.images
                composeVerificationPassed = result.composeVerificationPassed
            } else if (teeVerifier === 'cryptopilot') {
                console.log('🔍 Step 5: CryptoPilot Verification Process')
                console.log(
                    '   ⚠️  CryptoPilot verification is not yet implemented.'
                )
                console.log(
                    '   Please refer to CryptoPilot documentation for manual verification.'
                )
                composeVerificationPassed = false // Unknown for cryptopilot
            }
            console.log('')

            // Verification Summary
            const verificationSummary: VerificationSummary = {
                composeVerification: composeVerificationPassed,
                signerAddressVerification:
                    signerMatches === totalSignerChecks &&
                    totalSignerChecks > 0,
                signerAddressMatches: signerMatches,
                totalReports: totalSignerChecks,
                allVerificationsPassed:
                    composeVerificationPassed &&
                    signerMatches === totalSignerChecks &&
                    totalSignerChecks > 0,
            }

            console.log('📋 Automated Verification Summary')
            console.log(
                `   Docker Compose Verification: ${
                    verificationSummary.composeVerification
                        ? '✅ PASSED'
                        : '❌ FAILED'
                }`
            )
            console.log(
                `   TEE Signer Address Verification: ${
                    verificationSummary.signerAddressVerification
                        ? '✅ PASSED'
                        : '❌ FAILED'
                } (${verificationSummary.signerAddressMatches}/${
                    verificationSummary.totalReports
                } matches)`
            )
            console.log('')
            console.log(
                '🎯 ============================================================================'
            )
            console.log('🎯  AUTOMATED VERIFICATION CHECKS HAVE BEEN COMPLETED')
            console.log(
                '🎯  Please continue with the manual verification steps below to complete'
            )
            console.log('🎯  the full verification process.')
            console.log(
                '🎯 ============================================================================'
            )
            console.log('')

            // Step 6: Image verification guidance
            console.log('🖼️  Step 6: Image Verification')

            // Display found Docker images
            if (dockerImages.length > 0) {
                console.log(
                    `   Images Extracted from Docker Compose (${dockerImages.length}):`
                )

                const brokerImages: string[] = []
                const otherImages: string[] = []

                dockerImages.forEach((image, index) => {
                    const isBroker =
                        image.includes('broker') || image.includes('0g-serving')

                    if (isBroker) {
                        brokerImages.push(image)
                        console.log(`     ${index + 1}. ${image} (0G Broker)`)
                    } else {
                        otherImages.push(image)
                        console.log(`     ${index + 1}. ${image}`)
                    }
                })

                console.log('')

                // Show broker verification guidance only if broker images are found
                if (brokerImages.length > 0) {
                    console.log('   To verify 0G broker image integrity:')
                    console.log(
                        '   1. The broker image address has been extracted from the report'
                    )
                    console.log(
                        '   2. Visit: https://github.com/0gfoundation/0g-serving-broker/releases'
                    )
                    console.log(
                        '   3. Find the compute network broker image with matching Digest (SHA256)'
                    )
                    console.log(
                        '   4. Verify the build process at: https://search.sigstore.dev/'
                    )
                    console.log('')
                }

                if (otherImages.length > 0) {
                    console.log(
                        `   Note: Please verify the other images (${otherImages.join(
                            ', '
                        )}) according to their respective sources`
                    )
                    console.log('')
                }
            } else {
                console.log('   No images extracted from Docker Compose')
                console.log('')
            }

            // Step 7: Download and verify the verifier image
            if (verifierURL) {
                console.log('🔐 Step 7: Download and Verify the Verifier Image')
                console.log('')
                console.log(
                    '   The verifier image will be used in Step 8 to perform comprehensive verification.'
                )
                console.log(
                    '   Before using it, we need to ensure the verifier itself has a verifiable build process.'
                )
                console.log('')
                console.log(`   Verifier image download URL: ${verifierURL}`)
                console.log('   To verify the verifier image:')
                console.log(
                    '   1. Download the verifier image from the provided URL'
                )
                console.log('   2. Get the image hash/digest')
                console.log(
                    '   3. Verify the build process at: https://search.sigstore.dev/'
                )
                console.log('')
            }

            // Step 8: Verifier usage instructions
            console.log('🛠️  Step 8: Run Verifier for Complete Verification')

            if (teeVerifier === 'dstack') {
                console.log('')
                console.log(
                    '   The DStack verifier performs three main verification steps:'
                )
                console.log('')
                console.log('   1. Quote Verification:')
                console.log('      - Validates the TDX quote using dcap-qvl')
                console.log('      - Checks the quote signature and TCB status')
                console.log('')
                console.log('   2. Event Log Verification:')
                console.log(
                    '      - Replays event logs to ensure RTMR values match'
                )
                console.log('      - Extracts app information from the logs')
                console.log('')
                console.log('   3. OS Image Hash Verification:')
                console.log(
                    '      - Automatically downloads OS images if not cached locally'
                )
                console.log(
                    '      - Uses dstack-mr to compute expected measurements'
                )
                console.log(
                    '      - Compares against the verified measurements from the quote'
                )
                console.log('')
                console.log('   Usage Instructions:')
                console.log('')
                console.log(
                    '   1. Start the verifier service locally (example with dstack-verifier:0.5.4):'
                )
                console.log(
                    '      docker run -d -p 8080:8080 docker.io/dstacktee/dstack-verifier:0.5.4'
                )
                console.log('')
                console.log(
                    '   2. Verify the downloaded attestation report(s):'
                )

                // Show specific commands based on whether components are separated
                if (targetSeparated) {
                    console.log('      # Verify broker attestation report')
                    console.log(
                        `      curl -s -d @${outputDir}/broker_attestation_report.json localhost:8080/verify`
                    )
                    console.log('')
                    console.log('      # Verify LLM attestation report')
                    console.log(
                        `      curl -s -d @${outputDir}/llm_attestation_report.json localhost:8080/verify`
                    )
                } else {
                    console.log(
                        `      curl -s -d @${outputDir}/attestation_report.json localhost:8080/verify`
                    )
                }
                console.log('')
            } else if (teeVerifier === 'cryptopilot') {
                console.log('')
                console.log('   The CryptoPilot verifier verification process:')
                console.log(
                    '   [CryptoPilot verifier details to be implemented]'
                )
                console.log('')
            } else {
                console.log('')
                console.log(
                    '   [Verifier usage instructions for this TEE type]'
                )
            }

            return {
                success: true,
                teeVerifier,
                targetSeparated,
                verifierURL,
                reportsGenerated: Object.keys(reports),
                outputDirectory: outputDir,
            }
        } catch (error) {
            console.error('❌ TEE verification failed:', error)
            throwFormattedError(error)
        }
    }

    /**
     * Extract TEE signer address from attestation report
     */
    private extractTeeSignerAddress(report: AttestationReport): string | null {
        try {
            // Check if report_data exists in the report
            const reportData = (report as any).report_data
            if (!reportData) {
                return null
            }

            // Decode the base64 report_data to get the signer address
            const decodedData = Buffer.from(reportData, 'base64').toString(
                'utf-8'
            )
            // Remove NULL characters that pad the address
            const signingAddress = decodedData.replace(/\0/g, '')

            return signingAddress || null
        } catch {
            return null
        }
    }

    /**
     * Process DStack-specific verification steps
     */
    private async processDStackVerification(
        reports: Record<string, AttestationReport>
    ): Promise<{ images: string[]; composeVerificationPassed: boolean }> {
        const allImages: string[] = []
        let composeVerificationCount = 0
        let passedComposeVerifications = 0

        for (const [reportType, report] of Object.entries(reports)) {
            console.log(`   Processing ${reportType} report...`)

            if (!report.tcb_info || !report.event_log) {
                console.log(
                    `   ⚠️  Warning: ${reportType} report missing tcb_info or event_log`
                )
                continue
            }

            try {
                // Parse tcb_info if it's a string
                let tcbInfo: Record<string, unknown>
                if (typeof report.tcb_info === 'string') {
                    tcbInfo = JSON.parse(report.tcb_info) as Record<
                        string,
                        unknown
                    >
                } else {
                    tcbInfo = report.tcb_info
                }

                // Parse event_log if it's a string
                let eventLog: EventLogEntry[]
                if (typeof report.event_log === 'string') {
                    eventLog = JSON.parse(report.event_log) as EventLogEntry[]
                } else if (Array.isArray(report.event_log)) {
                    eventLog = report.event_log
                } else {
                    console.log(
                        `   ⚠️  Warning: event_log is not in expected format`
                    )
                    continue
                }

                // Verify compose hash against event log
                const composeResult = this.verifyComposeHash(tcbInfo, eventLog)
                composeVerificationCount++
                if (composeResult.isValid) {
                    passedComposeVerifications++
                }

                console.log(`   Docker Compose Verification:`)

                if (composeResult.calculatedHash) {
                    console.log(
                        `     Calculated Hash: ${composeResult.calculatedHash}`
                    )
                }
                if (composeResult.eventLogHash) {
                    console.log(
                        `     Event Log Hash:  ${composeResult.eventLogHash}`
                    )
                }
                console.log(
                    `     Status: ${
                        composeResult.isValid ? '✅ VALID' : '❌ INVALID'
                    }`
                )

                if (!composeResult.isValid && composeResult.error) {
                    console.log(`     Error: ${composeResult.error}`)
                }

                // Extract all images from tcb_info for later processing
                const images = this.extractAllImagesFromTcbInfo(tcbInfo)
                images.forEach((image) => {
                    if (!allImages.includes(image)) {
                        allImages.push(image)
                    }
                })
            } catch (error) {
                console.log(
                    `   ⚠️  Error processing ${reportType} report: ${error}`
                )
            }
        }

        const composeVerificationPassed =
            composeVerificationCount > 0 &&
            passedComposeVerifications === composeVerificationCount
        return {
            images: allImages,
            composeVerificationPassed,
        }
    }

    /**
     * Verify compose hash based on the dstack verification logic
     */
    private verifyComposeHash(
        tcbInfo: Record<string, unknown>,
        eventLog: EventLogEntry[]
    ): ComposeVerificationResult {
        try {
            if (!tcbInfo.app_compose) {
                return {
                    isValid: false,
                    error: 'app_compose not found in tcb_info',
                }
            }

            // Hash the app_compose JSON string
            const composeHash = createHash('sha256')
                .update(tcbInfo.app_compose as string)
                .digest('hex')

            // Find compose-hash event in the event log
            const composeHashEvent = eventLog.find(
                (entry) => entry.event === 'compose-hash'
            )

            if (!composeHashEvent) {
                return {
                    isValid: false,
                    error: 'No compose-hash event found in event log',
                    calculatedHash: composeHash,
                }
            }

            const expectedHash = composeHashEvent.event_payload
            return {
                isValid: composeHash === expectedHash,
                calculatedHash: composeHash,
                eventLogHash: expectedHash,
                composeHashEvent,
            }
        } catch (error) {
            return {
                isValid: false,
                error: `Compose hash verification failed: ${error}`,
            }
        }
    }

    /**
     * Extract all Docker images from tcb_info
     */
    private extractAllImagesFromTcbInfo(
        tcbInfo: Record<string, unknown>
    ): string[] {
        try {
            const images: string[] = []
            const tcbString = JSON.stringify(tcbInfo)

            // Match various image patterns in docker-compose format
            // Pattern 1: image: <image-address>
            const imageMatches = tcbString.match(/"image"\s*:\s*"([^"]+)"/g)

            if (imageMatches) {
                for (const match of imageMatches) {
                    // Extract the image address from the match
                    const imageMatch = match.match(/"image"\s*:\s*"([^"]+)"/)
                    if (imageMatch && imageMatch[1]) {
                        const imageAddr = imageMatch[1].trim()
                        // Avoid duplicates
                        if (!images.includes(imageAddr)) {
                            images.push(imageAddr)
                        }
                    }
                }
            }

            // Also try alternative pattern without quotes around key
            const altImageMatches = tcbString.match(/image:\s*([^",\s\}]+)/g)
            if (altImageMatches) {
                for (const match of altImageMatches) {
                    const imageAddr = match.replace(/^image:\s*/, '').trim()
                    // Remove any trailing quotes if present
                    const cleanAddr = imageAddr.replace(/["']/g, '')
                    // Avoid duplicates
                    if (cleanAddr && !images.includes(cleanAddr)) {
                        images.push(cleanAddr)
                    }
                }
            }

            return images
        } catch {
            return []
        }
    }

    /**
     * Save report to file
     */
    private async saveReportToFile(
        reportContent: string,
        filePath: string
    ): Promise<void> {
        const fs = await import('fs/promises')
        await fs.writeFile(filePath, reportContent, 'utf8')
    }

    async getSignerRaDownloadLink(providerAddress: string): Promise<string> {
        try {
            const svc = await this.getService(providerAddress)
            return `${svc.url}/v1/proxy/attestation/report`
        } catch (error) {
            throwFormattedError(error)
        }
    }

    async getChatSignatureDownloadLink(
        providerAddress: string,
        chatID: string
    ): Promise<string> {
        try {
            const svc = await this.getService(providerAddress)
            return `${svc.url}/v1/proxy/signature/${chatID}`
        } catch (error) {
            throwFormattedError(error)
        }
    }

    static async verifyRA(
        providerBrokerURL: string,
        nvidia_payload: Record<string, unknown>
    ): Promise<boolean> {
        return fetch(`${providerBrokerURL}/v1/quote/verify/gpu`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify(nvidia_payload),
        })
            .then((response) => {
                if (response.status === 200) {
                    return true
                }
                if (response.status === 404) {
                    throw new Error('verify RA error: 404')
                } else {
                    return false
                }
            })
            .catch((error) => {
                if (error instanceof Error) {
                    console.error(error.message)
                }
                return false
            })
    }

    async getQuoteInLLMServer(
        providerBrokerURL: string,
        model: string
    ): Promise<TdxQuoteResponse> {
        try {
            const rawReport = await this.fetchText(
                `${providerBrokerURL}/v1/proxy/attestation/report?model=${model}`,
                {
                    method: 'GET',
                }
            )
            const ret = JSON.parse(rawReport)
            return {
                rawReport,
                signingAddress: ret['signing_address'],
            } as TdxQuoteResponse
        } catch (error) {
            throwFormattedError(error)
        }
    }

    static async fetchSignatureByChatID(
        providerBrokerURL: string,
        chatID: string,
        model: string
    ): Promise<ResponseSignature> {
        return fetch(
            `${providerBrokerURL}/v1/proxy/signature/${chatID}?model=${model}`,
            {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
            }
        )
            .then((response) => {
                if (!response.ok) {
                    throw new Error('getting signature error')
                }
                return response.json()
            })
            .then((data) => {
                return data as ResponseSignature
            })
            .catch((error) => {
                throwFormattedError(error)
            })
    }

    static verifySignature(
        message: string,
        signature: string,
        expectedAddress: string
    ): boolean {
        const messageHash = ethers.hashMessage(message)

        const recoveredAddress = ethers.recoverAddress(messageHash, signature)

        return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase()
    }
}

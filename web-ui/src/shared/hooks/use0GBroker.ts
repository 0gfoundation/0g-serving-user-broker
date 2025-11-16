import { useCallback, useEffect, useState } from 'react'
import { useAccount, useWalletClient, useChainId } from 'wagmi'
import type { ZGComputeNetworkBroker } from '@0glabs/0g-serving-broker'
import { createZGComputeNetworkBroker } from '@0glabs/0g-serving-broker'
import type { JsonRpcSigner } from 'ethers'
import { BrowserProvider } from 'ethers'
import { APP_CONSTANTS } from '../constants/app'
import { errorHandler } from '../utils/errorHandling'
import { neuronToA0gi } from '../utils/currency'
import { clearDataCache } from './useOptimizedDataFetching'

const formatBalance = (value: number): string => {
    if (value === 0) return '0'

    if (value < 0.000001) {
        return value.toExponential(6)
    }

    const formatted = value.toFixed(18)
    return formatted.replace(/\.?0+$/, '')
}

interface InferenceInfo {
    provider: string
    balance: string
    requestedReturn: string
}

interface FineTuningInfo {
    provider: string
    balance: string
    requestedReturn: string
}

interface LedgerInfo {
    totalBalance: string
    availableBalance: string
    locked: string
    inferences: InferenceInfo[]
    fineTunings: FineTuningInfo[]
}

interface Use0GBrokerReturn {
    broker: ZGComputeNetworkBroker | null
    isInitializing: boolean
    error: string | null
    ledgerInfo: LedgerInfo | null
    initializeBroker: () => Promise<void>
    refreshLedgerInfo: () => Promise<void>
    addLedger: (balance: number) => Promise<void>
    depositFund: (amount: number) => Promise<void>
}

export function use0GBroker(): Use0GBrokerReturn {
    const { isConnected } = useAccount()
    const { data: walletClient } = useWalletClient()
    const chainId = useChainId()

    const [broker, setBroker] = useState<ZGComputeNetworkBroker | null>(null)
    const [isInitializing, setIsInitializing] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [ledgerInfo, setLedgerInfo] = useState<LedgerInfo | null>(null)

    const initializeBroker = useCallback(async () => {
        if (!walletClient || !isConnected) {
            return
        }

        setIsInitializing(true)
        setError(null)

        try {
            // Reduced delay for faster initialization
            await new Promise((resolve) => setTimeout(resolve, 500))

            // Verify walletClient is still available after delay
            if (!walletClient) {
                throw new Error('Wallet client became unavailable')
            }

            // Convert walletClient to ethers signer with retry
            let provider: BrowserProvider
            let signer: JsonRpcSigner | undefined
            let retryCount = 0
            const maxRetries = APP_CONSTANTS.BLOCKCHAIN.MAX_SIGNER_RETRIES

            while (retryCount < maxRetries) {
                try {
                    provider = new BrowserProvider(walletClient)
                    signer = await provider.getSigner()

                    // Verify signer connection and chain
                    await signer.getAddress()
                    await provider.getNetwork()

                    break
                } catch (signerError) {
                    retryCount++

                    if (retryCount >= maxRetries) {
                        throw signerError
                    }

                    // Reduced retry delay
                    await new Promise((resolve) => setTimeout(resolve, 1000))
                }
            }

            // Create broker instance (auto-detects network and contract addresses)
            if (!signer) {
                throw new Error('Failed to create signer')
            }

            const brokerInstance = await createZGComputeNetworkBroker(
                signer as any // TODO: Fix this type assertion when 0g-serving-broker types are available
            )
            setBroker(brokerInstance as unknown as ZGComputeNetworkBroker)
        } catch (err: unknown) {
            const appError = errorHandler.handle(err, 'BrokerInitialization')
            setError(appError.userMessage)
        } finally {
            setIsInitializing(false)
        }
    }, [walletClient, isConnected])

    const refreshLedgerInfo = useCallback(async () => {
        if (!broker) return

        try {
            const { ledgerInfo, infers, fines } =
                await broker.ledger.ledger.getLedgerWithDetail()

            const totalBalance = neuronToA0gi(BigInt(ledgerInfo[0])) // Convert from neuron to 0G
            const locked = neuronToA0gi(BigInt(ledgerInfo[1])) // Convert from neuron to 0G
            const available = totalBalance - locked

            // Process inference information
            const processedInferences: InferenceInfo[] = []
            if (infers && infers.length > 0) {
                for (const infer of infers) {
                    const provider = infer[0]
                    const balance = formatBalance(
                        neuronToA0gi(BigInt(infer[1]))
                    )
                    const requestedReturn = formatBalance(
                        neuronToA0gi(BigInt(infer[2]))
                    )
                    processedInferences.push({
                        provider,
                        balance,
                        requestedReturn,
                    })
                }
            }

            // Process fine tuning information
            const processedFineTunings: FineTuningInfo[] = []
            if (fines && fines.length > 0) {
                for (const fine of fines) {
                    const provider = fine[0]
                    const balance = formatBalance(neuronToA0gi(BigInt(fine[1])))
                    const requestedReturn = formatBalance(
                        neuronToA0gi(BigInt(fine[2]))
                    )
                    processedFineTunings.push({
                        provider,
                        balance,
                        requestedReturn,
                    })
                }
            }

            setLedgerInfo({
                totalBalance: formatBalance(totalBalance),
                availableBalance: formatBalance(available),
                locked: formatBalance(locked),
                inferences: processedInferences,
                fineTunings: processedFineTunings,
            })
        } catch (err: unknown) {
            setLedgerInfo(null)
        }
    }, [broker])

    const addLedger = useCallback(
        async (balance: number) => {
            if (!broker) {
                throw new Error('Broker not initialized')
            }

            try {
                await broker.ledger.addLedger(balance)
                await refreshLedgerInfo()
            } catch (err: unknown) {
                const errorMessage =
                    err instanceof Error ? err.message : 'Failed to add ledger'
                throw new Error(errorMessage)
            }
        },
        [broker, refreshLedgerInfo]
    )

    const depositFund = useCallback(
        async (amount: number) => {
            if (!broker) {
                throw new Error('Broker not initialized')
            }

            try {
                // First try to check if ledger exists
                let hasLedger = false
                try {
                    hasLedger = true
                } catch {
                    // Ledger doesn't exist yet
                    hasLedger = false
                }

                if (hasLedger) {
                    // Ledger exists, deposit funds
                    await broker.ledger.depositFund(amount)
                } else {
                    await broker.ledger.addLedger(amount)
                }

                await refreshLedgerInfo()
            } catch (err: unknown) {
                const errorMessage =
                    err instanceof Error
                        ? err.message
                        : 'Failed to deposit funds'
                throw new Error(errorMessage)
            }
        },
        [broker, refreshLedgerInfo]
    )

    // Auto-initialize when wallet connects with retry mechanism
    useEffect(() => {
        if (isConnected && walletClient && !broker && !isInitializing) {
            const initWithRetry = async () => {
                try {
                    await initializeBroker()
                } catch {
                    setTimeout(() => {
                        if (isConnected && walletClient && !broker) {
                            initializeBroker()
                        }
                    }, 2000)
                }
            }
            initWithRetry()
        }
    }, [isConnected, walletClient, broker, isInitializing, initializeBroker])

    // Reset state when wallet disconnects or chain changes
    useEffect(() => {
        if (!isConnected) {
            setBroker(null)
            setLedgerInfo(null)
            setError(null)
        }
    }, [isConnected])

    // Track current chainId to detect changes
    const [currentChainId, setCurrentChainId] = useState<number | undefined>(chainId)
    
    // Reset broker and reinitialize when chain changes
    useEffect(() => {
        // Only react to actual chain changes, not initial load
        if (currentChainId !== undefined && chainId !== currentChainId && isConnected && walletClient) {
            console.log('Chain switched from', currentChainId, 'to', chainId)
            
            // Clear current data immediately to show loading state
            setLedgerInfo(null)
            setBroker(null)
            setError(null)
            
            // Clear all cached data to prevent stale data from previous network
            clearDataCache() // Clear all cache
            
            // Update tracked chain ID
            setCurrentChainId(chainId)
            
            // Reinitialize broker for new chain
            const reinitialize = async () => {
                try {
                    await initializeBroker()
                } catch (err) {
                    console.error('Failed to reinitialize broker after chain switch:', err)
                }
            }
            
            // Small delay to allow chain switch to complete
            setTimeout(reinitialize, 1000)
        } else if (currentChainId === undefined) {
            // Set initial chain ID
            setCurrentChainId(chainId)
        }
    }, [chainId, isConnected, walletClient, currentChainId, initializeBroker])

    // Auto-refresh ledger info when broker is initialized
    useEffect(() => {
        if (broker && !isInitializing) {
            refreshLedgerInfo()
        }
    }, [broker, isInitializing, refreshLedgerInfo])

    return {
        broker,
        isInitializing,
        error,
        ledgerInfo,
        initializeBroker,
        refreshLedgerInfo,
        addLedger,
        depositFund,
    }
}

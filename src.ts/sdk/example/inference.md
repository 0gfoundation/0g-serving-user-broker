# Inference SDK Example

1. **Start the provider broker:**

    - Clone the repository:

        ```bash
        git clone https://github.com/0glabs/0g-serving-broker.git
        ```

    - Navigate to the directory and start the services using Docker Compose:

        ```bash
        docker compose -f ./0g-serving-broker/api/inference/integration/all-in-one/docker-compose.yml up -d
        ```

2. **Register a service:**

    - Use the following curl command to register a new service:

        ```bash
        curl -X POST http://127.0.0.1:3080/v1/service -d '{
           "url": "https://inference-api.phala.network/v1",
           "InputPrice": "10000",
           "outputPrice": "20000",
           "type": "chatbot",
           "name": "test",
           "model": "meta-llama/meta-llama-3.1-8b-instruct",
           "verifiability": "TeeML"
        }'
        ```

3. **Use the following code to test the inference SDK:**

    ```typescript
    import { ethers } from 'ethers'
    import { createZGComputeNetworkBroker } from '@0glabs/0g-serving-broker'
    import OpenAI from 'openai'

    async function main() {
        const provider = new ethers.JsonRpcProvider(
            'https://evmrpc-testnet.0g.ai'
        )

        // Step 1: Create a wallet with a private key
        const privateKey = '<YOUR_PRIVATE_KEY>'
        const wallet = new ethers.Wallet(privateKey, provider)

        // Step 2: Initialize the broker
        try {
            const broker = await createZGComputeNetworkBroker(wallet)

            // Step 3: Manage Accounts
            const initialBalance = 0.01
            // Step 3.1: Create a new account
            console.log('Creating a new account...')
            await broker.ledger.addLedger(initialBalance)
            console.log('Account created successfully.')

            // Step 3.2: Deposit funds into the account
            const depositAmount = 0.01
            console.log('Depositing funds...')
            await broker.ledger.depositFund(depositAmount)
            console.log('Funds deposited successfully.')

            // Step 3.3: Get the account
            await displayAccount(broker)

            // Step 4: List available services
            console.log('Listing available services...')
            const services = await broker.inference.listService()
            services.forEach((service: any) => {
                console.log(
                    `Provider: ${service.provider}\nType: ${service.serviceType}\nModel: ${service.model}\nURL: ${service.url}\nVerifiability: ${service.verifiability}\n`
                )
            })

            // Step 4.1: Select a service
            const PresetProvider = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
            const service = services.find(
                (service: any) => service.provider === PresetProvider
            )
            if (!service) {
                console.error('Service not found.')
                return
            }
            const providerAddress = PresetProvider

            // Step 5: Use the Provider's Services
            const content = 'hello world'

            // Step 5.1: Get the request metadata
            const { endpoint, model } =
                await broker.inference.getServiceMetadata(providerAddress)

            // Step 5.2: Get the request headers
            const headers = await broker.inference.getRequestHeaders(
                providerAddress,
                content
            )

            // Step 6: Send a request to the service
            const openai = new OpenAI({
                baseURL: endpoint,
                apiKey: '',
            })
            const completion = await openai.chat.completions.create(
                {
                    messages: [{ role: 'system', content }],
                    model: model,
                },
                {
                    headers: {
                        ...headers,
                    },
                }
            )

            const receivedContent = completion.choices[0].message.content
            const chatID = completion.id
            if (!receivedContent) {
                throw new Error('No content received.')
            }
            console.log(`Response: ${receivedContent}\n`)

            // Step 7: Process the response
            console.log('Processing the response...')
            const isValid = await broker.inference.processResponse(
                providerAddress,
                chatID,
                receivedContent
            )
            console.log(`Response validity: ${isValid ? 'Valid' : 'Invalid'}\n`)

            // Step 8: Retrieve the fund if needed
            await broker.ledger.retrieveFund('fine-tuning')
            await broker.ledger.retrieveFund('inference')

            await displayAccount(broker)
        } catch (error) {
            console.error('Error during execution:', error)
        }
    }

    async function displayAccount(broker: any) {
        const { ledgerInfo, infers, fines } = await broker.ledger.getLedger()

        console.log('\nAccount Overview')
        console.log(' Balance (neuron):', ledgerInfo[0])
        console.log(
            ' Locked Balance (transferred to sub-accounts):',
            ledgerInfo[1],
            '\n'
        )

        console.log(
            ' Inference sub-accounts (Dynamically Created per Used Provider)'
        )
        infers.forEach((infer: any) => {
            console.log(`   Provider Address: ${infer[0]}`)
            console.log(`   Balance (neuron): ${infer[1]}`)
            console.log(
                `   Requested Return to Main Account (neuron): ${infer[2]}\n`
            )
        })

        if (fines && fines.length > 0) {
            console.log(
                ' Fine-tuning sub-accounts (Dynamically Created per Used Provider)'
            )
            fines.forEach((fine: any) => {
                console.log(`   Provider Address: ${fine[0]}`)
                console.log(`   Balance (neuron): ${fine[1]}`)
                console.log(
                    `   Requested Return to Main Account (neuron): ${fine[2]}\n`
                )
            })
        }
    }

    main()
    ```

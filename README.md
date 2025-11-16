# 0G Serving Broker Documentation

## Overview

This document provides an overview of the 0G Serving Broker, including setup and usage instructions.

## Requirements

- Node.js >= 20.0.0

## Setup and Usage

To integrate the 0G Serving Broker into your project, follow these steps

### Step 1: Install the dependency

To get started, you need to install the `@0glabs/0g-serving-broker` package:

```bash
# Using npm
npm install @0glabs/0g-serving-broker @types/crypto-js@4.2.2 crypto-js@4.2.0

# Using yarn  
yarn add @0glabs/0g-serving-broker @types/crypto-js@4.2.2 crypto-js@4.2.0

# Using pnpm (recommended for development)
pnpm add @0glabs/0g-serving-broker @types/crypto-js@4.2.2 crypto-js@4.2.0
```

**Note for Contributors**: This project uses pnpm@9.15.4 for development. If you're contributing to this project, please use pnpm. For regular users installing as a dependency, any package manager works.

### Step 2: Initialize a Broker Instance

The broker instance is initialized with a `signer`. This signer is an instance that implements the `JsonRpcSigner` or `Wallet` interface from the ethers package and is used to sign transactions for a specific Ethereum account. You can create this instance using your private key via the ethers library or use a wallet framework tool like [wagmi](https://wagmi.sh/react/guides/ethers) to initialize the signer.

```typescript
import { createZGComputeNetworkBroker } from '@0glabs/0g-serving-broker'

/**
 * 'createZGComputeNetworkBroker' is used to initialize ZGServingUserBroker
 *
 * @param {JsonRpcSigner | Wallet} signer - A signer that implements the 'JsonRpcSigner' or 'Wallet' interface from the ethers package.
 * @param {string} contractAddress - 0G Serving contract address, use default address if not provided.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
const broker = await createZGComputeNetworkBroker(signer)
```

### Step 3: List Available Services

```typescript
/**
 * 'listService' retrieves a list of services from the contract.
 *
 * @returns {Promise<ServiceStructOutput[]>} A promise that resolves to an array of ServiceStructOutput objects.
 * @throws An error if the service list cannot be retrieved.
 *
 * type ServiceStructOutput = {
 *   provider: string;  // Address of the provider
 *   serviceType: string;
 *   url: string;
 *   inputPrice: bigint;
 *   outputPrice: bigint;
 *   updatedAt: bigint;
 *   model: string;
 *   verifiability: string; // Indicates how the service's outputs can be verified. 'TeeML' means it runs with verification in a Trusted Execution Environment. An empty value means no verification.
 *   additionalInfo: string // Provider-defined metadata, currently used to store the provider's encrypted key, but can be extended to include other custom information in future.
 * };
 */
const services = await broker.listService()
```

### Step 4: Manage Accounts

Before using the provider's services, you need to create an account specifically for the chosen provider. The provider checks the account balance before responding to requests. If the balance is insufficient, the request will be denied.

#### 4.1 Create an Account

```typescript
/**
 * 'addAccount' creates a new account in the contract.
 *
 * @param {number} balance - The initial balance to be assigned to the new account. The unit is 0G.
 *
 * @throws  An error if the account creation fails.
 */
await broker.ledger.addLedger(balance)
```

#### 4.2 Deposit Funds into the Account

```typescript
/**
 * 'depositFund' deposits a specified amount of funds into an existing account.
 *
 * @param {number} amount - The amount of funds to be deposited. The unit is 0G.
 *
 * @throws  An error if the deposit fails.
 */
await broker.ledger.depositFund(amount)
```

### Step 5: Use the Provider's Services

#### 5.1 Get Service metadata

```typescript
/**
 * 'getServiceMetadata' returns metadata for the provider service.
 * Includes:
 * 1. Service endpoint of the provider service
 * 2. Model information for the provider service
 *
 * @param {string} providerAddress - The address of the provider.
 *
 * @returns { endpoint, model } - Object containing endpoint and model.
 *
 * @throws An error if errors occur during the processing of the request.
 */
const { endpoint, model } = await broker.getServiceMetadata(providerAddress)
```

### 5.2 Acknowledge Provider
Before using a service provided by a provider, you must first acknowledge the provider on-chain by following API:

```typescript
/**
 * Acknowledge the given provider address.
 *
 * @param {string} providerAddress - The address of the provider identifying the account.
 * 
 *  @throws Will throw an error if failed to acknowledge.
 */
await broker.inference.acknowledgeProviderSigner(providerAddress)
```


#### 5.3 Get Request Headers

```typescript
/**
 * 'getRequestHeaders' generates billing-related headers for the request
 * when the user uses the provider service.
 *
 * In the 0G Serving system, a request with valid billing headers
 * is considered a settlement proof and will be used by the provider
 * for settlement in contract.
 *
 * @param {string} providerAddress - The address of the provider.
 * @param {string} content - The content being billed. For example, in a chatbot service, it is the text input by the user.
 *
 * @returns headers. Records information such as the request fee and user signature.
 *
 * @throws An error if errors occur during the processing of the request.
 */
const headers = await broker.inference.getRequestHeaders(
    providerAddress,
    content
)
```

#### 5.4 Send Request

After obtaining the `endpoint`, `model`, and `headers`, you can use client SDKs
compatible with the OpenAI interface to make requests.

**Note**: Fee settlement by the broker service occurs at scheduled intervals.

**Note**: Generated `headers` are valid for a single use only and cannot be reused.

```typescript
/**
 * Any SDK request methods that follow the OpenAI interface specifications can also be used.
 *
 * Here is an example using the OpenAI TS SDK.
 */
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

/**
 * Alternatively, you can also use `fetch` to make the request.
 */
await fetch(`${endpoint}/chat/completions`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        ...headers,
    },
    body: JSON.stringify({
        messages: [{ role: 'system', content }],
        model: model,
    }),
})
```

#### 5.5 Process Responses

```typescript
/**
 * 'processResponse' is used after the user successfully obtains a response from the provider service.
 *
 * Additionally, if the service is verifiable,
 * input the chat ID from the response and 'processResponse' will determine the validity of the
 * returned content by checking the provider service's response and corresponding signature associated
 * with the chat ID.
 *
 * @param {string} providerAddress - The address of the provider.
 * @param {string} content - The main content returned by the service. For example, in the case of a chatbot service,
 * it would be the response text.
 * @param {string} chatID - Only for verifiable services. You can provide the chat ID obtained from the response to
 * automatically download the response signature. The function will verify the reliability of the response
 * using the service's signing address.
 *
 * @returns A boolean value. True indicates the returned content is valid, otherwise it is invalid.
 *
 * @throws An error if any issues occur during the processing of the response.
 */
const valid = await broker.inference.processResponse(
    providerAddress,
    content,
    chatID
)
```

## Interface

Access the more details of interfaces via cloning the repo and opening [index.html](./docs/index.html) in browser.

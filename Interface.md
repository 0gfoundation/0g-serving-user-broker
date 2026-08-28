# Compute Network Customer Interface

## Inference

1. add ledger
2. deposit fund (optional)
3. refund fund (optional)
4. list services
5. acknowledge provider signer
6. generate header
    1. transfer fund to sub account
7. call openai SDK
8. verify response

## FineTuning

1. add ledger: 0g-compute-cli add-account
2. get ledger: 0g-compute-cli get-account
3. deposit fund (optional) 0g-compute-cli deposit -a <>
4. refund fund (optional) 0g-compute-cli refund -a <>
5. list services
6. acknowledge provider signer
    1. [`call provider url/v1/quote`] call provider quote api to download quote (contains provider signer)
    2. [`TBD`] verify the quote using third party service (TODO: Jiahao discuss with Phala)
    3. [`call contract`] acknowledge the provider signer in contract
7. [`use 0g storage sdk`] upload dataset, get dataset root hash
8. create task
    1. get preTrained model root hash based on the model
    2. [`call contract`] calculate fee
    3. [`call contract`] transfer fund from ledger to fine-tuning provider
    4. [`call provider url/v1/task`]call provider task creation api to create task
9. [`call provider url/v1/task-progress`] call provider task progress api to get task progress
10. acknowledge encrypted model with root hash
    1. [`call contract`] get deliverable with root hash
    2. [`use 0g storage sdk`] download model, calculate root hash, compare with provided root hash
    3. [`call contract`] acknowledge the model in contract
11. decrypt model
    1. [`call contract`] get deliverable with encryptedSecret
    2. decrypt the encryptedSecret
    3. decrypt model with secret [TODO: Discuss LiuYuan]

> **Note:** `acknowledgeModel` (step 10) is the only correct retrieval entry
> point for the normal happy path — it downloads, verifies, and acknowledges
> in one call. The lower-level `downloadModelFrom0GStorage` and `decryptModel`
> helpers are kept for advanced flows but **do not** acknowledge the
> deliverable on-chain. Forgetting the acknowledgement permanently locks
> the user's task queue ("previous deliverable not acknowledged" revert on
> the next `addDeliverable`). If the artifact is no longer retrievable, use
> the escape hatch `acknowledgeDeliverable(provider, taskId)` (or the CLI
> command `0g-compute-cli fine-tuning acknowledge-deliverable`) — see the
> recovery recipe below.

### Recovering a stuck deliverable queue

The on-chain fine-tuning account holds at most one **un-acknowledged**
deliverable per `(user, provider)` pair. Until that flag is set,
`addDeliverable` for the same pair reverts with `previous deliverable not
acknowledged`, and any new `createTask` to the same provider fails. Common
ways to land in this state:

1. The user retrieved the model out-of-band (legacy
   `downloadModelFrom0GStorage` + `decryptModel`) and never called
   `acknowledgeModel`.
2. `acknowledgeModel` started the download but it never finished — for
   example on macOS where `auto` falls back from the linux/x64 0G-Storage
   binary to the TEE HTTP path, and the TEE stream aborts a few minutes in
   for large models (`stream has been aborted`).
3. The artifact has aged out of both 0G Storage and the provider's TEE
   buffer, so no retry of `acknowledgeModel` can ever succeed.

In all three cases the fix is to acknowledge on-chain *without* downloading
the artifact. Since `@0gfoundation/0g-compute-ts-sdk@0.8.1` this is a
first-class public API — you do **not** need to call the contract directly:

```ts
// SDK (preferred — adds error decoration and gas-price handling)
await broker.acknowledgeDeliverable(providerAddress, taskId)
```

```bash
# CLI (same effect)
0g-compute-cli fine-tuning acknowledge-deliverable \
    --provider <provider-address> \
    --task-id  <task-id>
```

This is a **sanctioned, permanent escape hatch**, not a temporary
workaround — it has the same on-chain effect as the second half of
`acknowledgeModel`, and we will not change its shape. Once the call is
mined the provider auto-settles within ~10 minutes and the wallet can
queue another fine-tune to the same provider.

For the normal happy path always prefer `acknowledgeModel` — it
downloads the encrypted artifact, verifies its hash against the
`Deliverable.modelRootHash` recorded on-chain, and acknowledges in one
step. Use `acknowledgeDeliverable` only when the download cannot
complete or the artifact is no longer needed.

> **macOS users — bundled binary caveat.** The 0G-Storage binary shipped
> in `node_modules/@0gfoundation/0g-compute-ts-sdk/binary/` is a
> linux/x64 ELF; on darwin or linux/arm64 the SDK throws a friendly
> "platform/arch mismatch" error and `acknowledgeModel` with
> `downloadMethod: 'auto'` falls back to the TEE HTTP path. To make the
> 0G-Storage path work on macOS, build a darwin binary from
> [`0gfoundation/0g-storage-client`](https://github.com/0gfoundation/0g-storage-client)
> and drop it into the same `binary/` directory. Multi-arch shipping is
> tracked separately and is **not** required for the recovery recipe
> above — `acknowledgeDeliverable` does not invoke the binary at all.

### Code Structure

#### util

1. storage-client
2. provider-client
3. encryption

#### module

1. broker (main)
2. ledger (1-3)
3. service
   listService (4)
   acknowledgeProviderSigner (5)
   createTask (7)
   getTaskProgress (8)
4. model
   uploadDataset (6)
   acknowledgeModel (9)
   decryptModel (10)

### Structure

1. Leger structure

    ```solidity
    struct Ledger {
        address user;
        uint availableBalance;
        uint totalBalance;
        uint[2] inferenceSigner;
        string additionalInfo;
        address[] inferenceProviders;
        address[] fineTuningProviders;
    }
    ```

2. Service structure

    ```solidity
    struct Service {
        address provider;
        string name;
        string url;
        Quota quota;
        uint pricePerToken;
        address providerSigner;
        bool occupied;
    }
    ```

3. FineTuning account structure

    ```solidity
    struct Account {
        address user;
        address provider;
        uint nonce;
        uint balance;
        uint pendingRefund;
        Refund[] refunds;
        string additionalInfo;
        address providerSigner;
        Deliverable[] deliverables;
    }

    struct Deliverable {
        bytes modelRootHash;
        bytes encryptedSecret;
        bool acknowledged;
    }
    ```

### Provider interface

1. Endpoint: https://github.com/0gfoundation/0g-serving-broker/blob/main/api/fine-tuning/internal/handler/handler.go#L23
2. Task Model: https://github.com/0gfoundation/0g-serving-broker/blob/main/api/fine-tuning/schema/task.go#L12
3. Task creation example:

    ```bash
    curl -X POST http://Domain/v1/task -d '{
    "customerAddress": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "datasetHash": "0xe080961aa45248f8855dbd540fb40c4927b980c6dc773740da79f19c0b2570c2",
    "isTurbo": true,
    "preTrainedModelHash": "0xe080961aa45248f8855dbd540fb40c4927b980c6dc773740da79f19c0b2570c2",
    "trainingParams": "{
        "CustomerAddress": "0xabc",
        "PreTrainedModelHash": "0x7f2244b25cd2219dfd9d14c052982ecce409356e0f08e839b79796e270d110a7",
        "DatasetHash": "0xaae9b4e031e06f84b20f10ec629f36c57719ea512992a6b7e2baea93f447a5fa",
        "IsTurbo": true,
        "TrainingParams": "{\"num_train_epochs\": 3, \"per_device_train_batch_size\": 16, \"per_device_eval_batch_size\": 16, \"warmup_steps\": 500, \"weight_decay\": 0.01, \"logging_dir\": \"./logs\", \"logging_steps\": 100, \"evaluation_strategy\": \"no\", \"save_strategy\": \"steps\", \"save_steps\": 500, \"eval_steps\": 500, \"load_best_model_at_end\": false, \"metric_for_best_model\": \"accuracy\", \"greater_is_better\": true, \"report_to\": [\"none\"]}"
    }"
    }'
    ```

import type { BaseContract, BigNumberish, BytesLike, FunctionFragment, Result, Interface, EventFragment, AddressLike, ContractRunner, ContractMethod, Listener } from 'ethers';
import type { TypedContractEvent, TypedDeferredTopicFilter, TypedEventLog, TypedLogDescription, TypedListener, TypedContractMethod } from './common.js';
export type QuotaStruct = {
    cpuCount: BigNumberish;
    nodeMemory: BigNumberish;
    gpuCount: BigNumberish;
    nodeStorage: BigNumberish;
    gpuType: string;
};
export type QuotaStructOutput = [
    cpuCount: bigint,
    nodeMemory: bigint,
    gpuCount: bigint,
    nodeStorage: bigint,
    gpuType: string
] & {
    cpuCount: bigint;
    nodeMemory: bigint;
    gpuCount: bigint;
    nodeStorage: bigint;
    gpuType: string;
};
export type RefundStruct = {
    index: BigNumberish;
    amount: BigNumberish;
    createdAt: BigNumberish;
    processed: boolean;
};
export type RefundStructOutput = [
    index: bigint,
    amount: bigint,
    createdAt: bigint,
    processed: boolean
] & {
    index: bigint;
    amount: bigint;
    createdAt: bigint;
    processed: boolean;
};
export type DeliverableStruct = {
    id: string;
    modelRootHash: BytesLike;
    encryptedSecret: BytesLike;
    acknowledged: boolean;
    timestamp: BigNumberish;
};
export type DeliverableStructOutput = [
    id: string,
    modelRootHash: string,
    encryptedSecret: string,
    acknowledged: boolean,
    timestamp: bigint
] & {
    id: string;
    modelRootHash: string;
    encryptedSecret: string;
    acknowledged: boolean;
    timestamp: bigint;
};
export type AccountDetailsStruct = {
    user: AddressLike;
    provider: AddressLike;
    nonce: BigNumberish;
    balance: BigNumberish;
    pendingRefund: BigNumberish;
    refunds: RefundStruct[];
    additionalInfo: string;
    providerSigner: AddressLike;
    deliverables: DeliverableStruct[];
    validRefundsLength: BigNumberish;
    deliverablesHead: BigNumberish;
    deliverablesCount: BigNumberish;
};
export type AccountDetailsStructOutput = [
    user: string,
    provider: string,
    nonce: bigint,
    balance: bigint,
    pendingRefund: bigint,
    refunds: RefundStructOutput[],
    additionalInfo: string,
    providerSigner: string,
    deliverables: DeliverableStructOutput[],
    validRefundsLength: bigint,
    deliverablesHead: bigint,
    deliverablesCount: bigint
] & {
    user: string;
    provider: string;
    nonce: bigint;
    balance: bigint;
    pendingRefund: bigint;
    refunds: RefundStructOutput[];
    additionalInfo: string;
    providerSigner: string;
    deliverables: DeliverableStructOutput[];
    validRefundsLength: bigint;
    deliverablesHead: bigint;
    deliverablesCount: bigint;
};
export type AccountSummaryStruct = {
    user: AddressLike;
    provider: AddressLike;
    nonce: BigNumberish;
    balance: BigNumberish;
    pendingRefund: BigNumberish;
    additionalInfo: string;
    providerSigner: AddressLike;
    validRefundsLength: BigNumberish;
    deliverablesCount: BigNumberish;
};
export type AccountSummaryStructOutput = [
    user: string,
    provider: string,
    nonce: bigint,
    balance: bigint,
    pendingRefund: bigint,
    additionalInfo: string,
    providerSigner: string,
    validRefundsLength: bigint,
    deliverablesCount: bigint
] & {
    user: string;
    provider: string;
    nonce: bigint;
    balance: bigint;
    pendingRefund: bigint;
    additionalInfo: string;
    providerSigner: string;
    validRefundsLength: bigint;
    deliverablesCount: bigint;
};
export type ServiceStruct = {
    provider: AddressLike;
    url: string;
    quota: QuotaStruct;
    pricePerToken: BigNumberish;
    providerSigner: AddressLike;
    occupied: boolean;
    models: string[];
};
export type ServiceStructOutput = [
    provider: string,
    url: string,
    quota: QuotaStructOutput,
    pricePerToken: bigint,
    providerSigner: string,
    occupied: boolean,
    models: string[]
] & {
    provider: string;
    url: string;
    quota: QuotaStructOutput;
    pricePerToken: bigint;
    providerSigner: string;
    occupied: boolean;
    models: string[];
};
export type VerifierInputStruct = {
    id: string;
    encryptedSecret: BytesLike;
    modelRootHash: BytesLike;
    nonce: BigNumberish;
    providerSigner: AddressLike;
    signature: BytesLike;
    taskFee: BigNumberish;
    user: AddressLike;
};
export type VerifierInputStructOutput = [
    id: string,
    encryptedSecret: string,
    modelRootHash: string,
    nonce: bigint,
    providerSigner: string,
    signature: string,
    taskFee: bigint,
    user: string
] & {
    id: string;
    encryptedSecret: string;
    modelRootHash: string;
    nonce: bigint;
    providerSigner: string;
    signature: string;
    taskFee: bigint;
    user: string;
};
export interface FineTuningServingInterface extends Interface {
    getFunction(nameOrSignature: 'accountExists' | 'acknowledgeDeliverable' | 'acknowledgeProviderSigner' | 'addAccount' | 'addDeliverable' | 'addOrUpdateService' | 'deleteAccount' | 'depositFund' | 'getAccount' | 'getAccountsByProvider' | 'getAccountsByUser' | 'getAllAccounts' | 'getAllServices' | 'getBatchAccountsByUsers' | 'getDeliverable' | 'getDeliverables' | 'getPendingRefund' | 'getService' | 'initialize' | 'initialized' | 'ledgerAddress' | 'lockTime' | 'owner' | 'penaltyPercentage' | 'processRefund' | 'removeService' | 'renounceOwnership' | 'requestRefundAll' | 'settleFees' | 'supportsInterface' | 'transferOwnership' | 'updateLockTime' | 'updatePenaltyPercentage'): FunctionFragment;
    getEvent(nameOrSignatureOrTopic: 'BalanceUpdated' | 'OwnershipTransferred' | 'RefundRequested' | 'ServiceRemoved' | 'ServiceUpdated'): EventFragment;
    encodeFunctionData(functionFragment: 'accountExists', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'acknowledgeDeliverable', values: [AddressLike, string]): string;
    encodeFunctionData(functionFragment: 'acknowledgeProviderSigner', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'addAccount', values: [AddressLike, AddressLike, string]): string;
    encodeFunctionData(functionFragment: 'addDeliverable', values: [AddressLike, string, BytesLike]): string;
    encodeFunctionData(functionFragment: 'addOrUpdateService', values: [
        string,
        QuotaStruct,
        BigNumberish,
        AddressLike,
        boolean,
        string[]
    ]): string;
    encodeFunctionData(functionFragment: 'deleteAccount', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'depositFund', values: [AddressLike, AddressLike, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getAccount', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'getAccountsByProvider', values: [AddressLike, BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getAccountsByUser', values: [AddressLike, BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getAllAccounts', values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getAllServices', values?: undefined): string;
    encodeFunctionData(functionFragment: 'getBatchAccountsByUsers', values: [AddressLike[]]): string;
    encodeFunctionData(functionFragment: 'getDeliverable', values: [AddressLike, AddressLike, string]): string;
    encodeFunctionData(functionFragment: 'getDeliverables', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'getPendingRefund', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'getService', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'initialize', values: [BigNumberish, AddressLike, AddressLike, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'initialized', values?: undefined): string;
    encodeFunctionData(functionFragment: 'ledgerAddress', values?: undefined): string;
    encodeFunctionData(functionFragment: 'lockTime', values?: undefined): string;
    encodeFunctionData(functionFragment: 'owner', values?: undefined): string;
    encodeFunctionData(functionFragment: 'penaltyPercentage', values?: undefined): string;
    encodeFunctionData(functionFragment: 'processRefund', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'removeService', values?: undefined): string;
    encodeFunctionData(functionFragment: 'renounceOwnership', values?: undefined): string;
    encodeFunctionData(functionFragment: 'requestRefundAll', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'settleFees', values: [VerifierInputStruct]): string;
    encodeFunctionData(functionFragment: 'supportsInterface', values: [BytesLike]): string;
    encodeFunctionData(functionFragment: 'transferOwnership', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'updateLockTime', values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: 'updatePenaltyPercentage', values: [BigNumberish]): string;
    decodeFunctionResult(functionFragment: 'accountExists', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'acknowledgeDeliverable', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'acknowledgeProviderSigner', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'addAccount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'addDeliverable', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'addOrUpdateService', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'deleteAccount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'depositFund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAccount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAccountsByProvider', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAccountsByUser', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAllAccounts', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAllServices', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getBatchAccountsByUsers', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getDeliverable', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getDeliverables', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getPendingRefund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getService', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'initialize', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'initialized', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'ledgerAddress', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'lockTime', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'owner', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'penaltyPercentage', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'processRefund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'removeService', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'renounceOwnership', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'requestRefundAll', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'settleFees', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'supportsInterface', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'transferOwnership', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateLockTime', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updatePenaltyPercentage', data: BytesLike): Result;
}
export declare namespace BalanceUpdatedEvent {
    type InputTuple = [
        user: AddressLike,
        provider: AddressLike,
        amount: BigNumberish,
        pendingRefund: BigNumberish
    ];
    type OutputTuple = [
        user: string,
        provider: string,
        amount: bigint,
        pendingRefund: bigint
    ];
    interface OutputObject {
        user: string;
        provider: string;
        amount: bigint;
        pendingRefund: bigint;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace OwnershipTransferredEvent {
    type InputTuple = [previousOwner: AddressLike, newOwner: AddressLike];
    type OutputTuple = [previousOwner: string, newOwner: string];
    interface OutputObject {
        previousOwner: string;
        newOwner: string;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace RefundRequestedEvent {
    type InputTuple = [
        user: AddressLike,
        provider: AddressLike,
        index: BigNumberish,
        timestamp: BigNumberish
    ];
    type OutputTuple = [
        user: string,
        provider: string,
        index: bigint,
        timestamp: bigint
    ];
    interface OutputObject {
        user: string;
        provider: string;
        index: bigint;
        timestamp: bigint;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace ServiceRemovedEvent {
    type InputTuple = [user: AddressLike];
    type OutputTuple = [user: string];
    interface OutputObject {
        user: string;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace ServiceUpdatedEvent {
    type InputTuple = [
        user: AddressLike,
        url: string,
        quota: QuotaStruct,
        pricePerToken: BigNumberish,
        providerSigner: AddressLike,
        occupied: boolean
    ];
    type OutputTuple = [
        user: string,
        url: string,
        quota: QuotaStructOutput,
        pricePerToken: bigint,
        providerSigner: string,
        occupied: boolean
    ];
    interface OutputObject {
        user: string;
        url: string;
        quota: QuotaStructOutput;
        pricePerToken: bigint;
        providerSigner: string;
        occupied: boolean;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export interface FineTuningServing extends BaseContract {
    connect(runner?: ContractRunner | null): FineTuningServing;
    waitForDeployment(): Promise<this>;
    interface: FineTuningServingInterface;
    queryFilter<TCEvent extends TypedContractEvent>(event: TCEvent, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog<TCEvent>>>;
    queryFilter<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog<TCEvent>>>;
    on<TCEvent extends TypedContractEvent>(event: TCEvent, listener: TypedListener<TCEvent>): Promise<this>;
    on<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, listener: TypedListener<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent>(event: TCEvent, listener: TypedListener<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, listener: TypedListener<TCEvent>): Promise<this>;
    listeners<TCEvent extends TypedContractEvent>(event: TCEvent): Promise<Array<TypedListener<TCEvent>>>;
    listeners(eventName?: string): Promise<Array<Listener>>;
    removeAllListeners<TCEvent extends TypedContractEvent>(event?: TCEvent): Promise<this>;
    accountExists: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        boolean
    ], 'view'>;
    acknowledgeDeliverable: TypedContractMethod<[
        provider: AddressLike,
        id: string
    ], [
        void
    ], 'nonpayable'>;
    acknowledgeProviderSigner: TypedContractMethod<[
        provider: AddressLike,
        providerSigner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    addAccount: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike,
        additionalInfo: string
    ], [
        void
    ], 'payable'>;
    addDeliverable: TypedContractMethod<[
        user: AddressLike,
        id: string,
        modelRootHash: BytesLike
    ], [
        void
    ], 'nonpayable'>;
    addOrUpdateService: TypedContractMethod<[
        url: string,
        quota: QuotaStruct,
        pricePerToken: BigNumberish,
        providerSigner: AddressLike,
        occupied: boolean,
        models: string[]
    ], [
        void
    ], 'nonpayable'>;
    deleteAccount: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    depositFund: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike,
        cancelRetrievingAmount: BigNumberish
    ], [
        void
    ], 'payable'>;
    getAccount: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        AccountDetailsStructOutput
    ], 'view'>;
    getAccountsByProvider: TypedContractMethod<[
        provider: AddressLike,
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountSummaryStructOutput[],
            bigint
        ] & {
            accounts: AccountSummaryStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getAccountsByUser: TypedContractMethod<[
        user: AddressLike,
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountSummaryStructOutput[],
            bigint
        ] & {
            accounts: AccountSummaryStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getAllAccounts: TypedContractMethod<[
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountSummaryStructOutput[],
            bigint
        ] & {
            accounts: AccountSummaryStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getAllServices: TypedContractMethod<[], [ServiceStructOutput[]], 'view'>;
    getBatchAccountsByUsers: TypedContractMethod<[
        users: AddressLike[]
    ], [
        AccountSummaryStructOutput[]
    ], 'view'>;
    getDeliverable: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike,
        id: string
    ], [
        DeliverableStructOutput
    ], 'view'>;
    getDeliverables: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        DeliverableStructOutput[]
    ], 'view'>;
    getPendingRefund: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        bigint
    ], 'view'>;
    getService: TypedContractMethod<[
        provider: AddressLike
    ], [
        ServiceStructOutput
    ], 'view'>;
    initialize: TypedContractMethod<[
        _locktime: BigNumberish,
        _ledgerAddress: AddressLike,
        owner: AddressLike,
        _penaltyPercentage: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    initialized: TypedContractMethod<[], [boolean], 'view'>;
    ledgerAddress: TypedContractMethod<[], [string], 'view'>;
    lockTime: TypedContractMethod<[], [bigint], 'view'>;
    owner: TypedContractMethod<[], [string], 'view'>;
    penaltyPercentage: TypedContractMethod<[], [bigint], 'view'>;
    processRefund: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        [
            bigint,
            bigint,
            bigint
        ] & {
            totalAmount: bigint;
            balance: bigint;
            pendingRefund: bigint;
        }
    ], 'nonpayable'>;
    removeService: TypedContractMethod<[], [void], 'nonpayable'>;
    renounceOwnership: TypedContractMethod<[], [void], 'nonpayable'>;
    requestRefundAll: TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    settleFees: TypedContractMethod<[
        verifierInput: VerifierInputStruct
    ], [
        void
    ], 'nonpayable'>;
    supportsInterface: TypedContractMethod<[
        interfaceId: BytesLike
    ], [
        boolean
    ], 'view'>;
    transferOwnership: TypedContractMethod<[
        newOwner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    updateLockTime: TypedContractMethod<[
        _locktime: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    updatePenaltyPercentage: TypedContractMethod<[
        _penaltyPercentage: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction<T extends ContractMethod = ContractMethod>(key: string | FunctionFragment): T;
    getFunction(nameOrSignature: 'accountExists'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        boolean
    ], 'view'>;
    getFunction(nameOrSignature: 'acknowledgeDeliverable'): TypedContractMethod<[
        provider: AddressLike,
        id: string
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'acknowledgeProviderSigner'): TypedContractMethod<[
        provider: AddressLike,
        providerSigner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'addAccount'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike,
        additionalInfo: string
    ], [
        void
    ], 'payable'>;
    getFunction(nameOrSignature: 'addDeliverable'): TypedContractMethod<[
        user: AddressLike,
        id: string,
        modelRootHash: BytesLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'addOrUpdateService'): TypedContractMethod<[
        url: string,
        quota: QuotaStruct,
        pricePerToken: BigNumberish,
        providerSigner: AddressLike,
        occupied: boolean,
        models: string[]
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'deleteAccount'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'depositFund'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike,
        cancelRetrievingAmount: BigNumberish
    ], [
        void
    ], 'payable'>;
    getFunction(nameOrSignature: 'getAccount'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        AccountDetailsStructOutput
    ], 'view'>;
    getFunction(nameOrSignature: 'getAccountsByProvider'): TypedContractMethod<[
        provider: AddressLike,
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountSummaryStructOutput[],
            bigint
        ] & {
            accounts: AccountSummaryStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getFunction(nameOrSignature: 'getAccountsByUser'): TypedContractMethod<[
        user: AddressLike,
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountSummaryStructOutput[],
            bigint
        ] & {
            accounts: AccountSummaryStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getFunction(nameOrSignature: 'getAllAccounts'): TypedContractMethod<[
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountSummaryStructOutput[],
            bigint
        ] & {
            accounts: AccountSummaryStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getFunction(nameOrSignature: 'getAllServices'): TypedContractMethod<[], [ServiceStructOutput[]], 'view'>;
    getFunction(nameOrSignature: 'getBatchAccountsByUsers'): TypedContractMethod<[
        users: AddressLike[]
    ], [
        AccountSummaryStructOutput[]
    ], 'view'>;
    getFunction(nameOrSignature: 'getDeliverable'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike,
        id: string
    ], [
        DeliverableStructOutput
    ], 'view'>;
    getFunction(nameOrSignature: 'getDeliverables'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        DeliverableStructOutput[]
    ], 'view'>;
    getFunction(nameOrSignature: 'getPendingRefund'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        bigint
    ], 'view'>;
    getFunction(nameOrSignature: 'getService'): TypedContractMethod<[
        provider: AddressLike
    ], [
        ServiceStructOutput
    ], 'view'>;
    getFunction(nameOrSignature: 'initialize'): TypedContractMethod<[
        _locktime: BigNumberish,
        _ledgerAddress: AddressLike,
        owner: AddressLike,
        _penaltyPercentage: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'initialized'): TypedContractMethod<[], [boolean], 'view'>;
    getFunction(nameOrSignature: 'ledgerAddress'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'lockTime'): TypedContractMethod<[], [bigint], 'view'>;
    getFunction(nameOrSignature: 'owner'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'penaltyPercentage'): TypedContractMethod<[], [bigint], 'view'>;
    getFunction(nameOrSignature: 'processRefund'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        [
            bigint,
            bigint,
            bigint
        ] & {
            totalAmount: bigint;
            balance: bigint;
            pendingRefund: bigint;
        }
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'removeService'): TypedContractMethod<[], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'renounceOwnership'): TypedContractMethod<[], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'requestRefundAll'): TypedContractMethod<[
        user: AddressLike,
        provider: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'settleFees'): TypedContractMethod<[
        verifierInput: VerifierInputStruct
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'supportsInterface'): TypedContractMethod<[interfaceId: BytesLike], [boolean], 'view'>;
    getFunction(nameOrSignature: 'transferOwnership'): TypedContractMethod<[newOwner: AddressLike], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateLockTime'): TypedContractMethod<[_locktime: BigNumberish], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'updatePenaltyPercentage'): TypedContractMethod<[
        _penaltyPercentage: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getEvent(key: 'BalanceUpdated'): TypedContractEvent<BalanceUpdatedEvent.InputTuple, BalanceUpdatedEvent.OutputTuple, BalanceUpdatedEvent.OutputObject>;
    getEvent(key: 'OwnershipTransferred'): TypedContractEvent<OwnershipTransferredEvent.InputTuple, OwnershipTransferredEvent.OutputTuple, OwnershipTransferredEvent.OutputObject>;
    getEvent(key: 'RefundRequested'): TypedContractEvent<RefundRequestedEvent.InputTuple, RefundRequestedEvent.OutputTuple, RefundRequestedEvent.OutputObject>;
    getEvent(key: 'ServiceRemoved'): TypedContractEvent<ServiceRemovedEvent.InputTuple, ServiceRemovedEvent.OutputTuple, ServiceRemovedEvent.OutputObject>;
    getEvent(key: 'ServiceUpdated'): TypedContractEvent<ServiceUpdatedEvent.InputTuple, ServiceUpdatedEvent.OutputTuple, ServiceUpdatedEvent.OutputObject>;
    filters: {
        'BalanceUpdated(address,address,uint256,uint256)': TypedContractEvent<BalanceUpdatedEvent.InputTuple, BalanceUpdatedEvent.OutputTuple, BalanceUpdatedEvent.OutputObject>;
        BalanceUpdated: TypedContractEvent<BalanceUpdatedEvent.InputTuple, BalanceUpdatedEvent.OutputTuple, BalanceUpdatedEvent.OutputObject>;
        'OwnershipTransferred(address,address)': TypedContractEvent<OwnershipTransferredEvent.InputTuple, OwnershipTransferredEvent.OutputTuple, OwnershipTransferredEvent.OutputObject>;
        OwnershipTransferred: TypedContractEvent<OwnershipTransferredEvent.InputTuple, OwnershipTransferredEvent.OutputTuple, OwnershipTransferredEvent.OutputObject>;
        'RefundRequested(address,address,uint256,uint256)': TypedContractEvent<RefundRequestedEvent.InputTuple, RefundRequestedEvent.OutputTuple, RefundRequestedEvent.OutputObject>;
        RefundRequested: TypedContractEvent<RefundRequestedEvent.InputTuple, RefundRequestedEvent.OutputTuple, RefundRequestedEvent.OutputObject>;
        'ServiceRemoved(address)': TypedContractEvent<ServiceRemovedEvent.InputTuple, ServiceRemovedEvent.OutputTuple, ServiceRemovedEvent.OutputObject>;
        ServiceRemoved: TypedContractEvent<ServiceRemovedEvent.InputTuple, ServiceRemovedEvent.OutputTuple, ServiceRemovedEvent.OutputObject>;
        'ServiceUpdated(address,string,tuple,uint256,address,bool)': TypedContractEvent<ServiceUpdatedEvent.InputTuple, ServiceUpdatedEvent.OutputTuple, ServiceUpdatedEvent.OutputObject>;
        ServiceUpdated: TypedContractEvent<ServiceUpdatedEvent.InputTuple, ServiceUpdatedEvent.OutputTuple, ServiceUpdatedEvent.OutputObject>;
    };
}
//# sourceMappingURL=FineTuningServing.d.ts.map
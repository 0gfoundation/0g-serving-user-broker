import { DeferredTopicFilter, EventFragment, EventLog, ContractTransactionResponse, FunctionFragment, ContractTransaction, LogDescription, Typed, TransactionRequest, BaseContract, ContractRunner, Listener, AddressLike, BigNumberish, ContractMethod, BytesLike, Interface, Result, JsonRpcSigner, Wallet, ContractMethodArgs as ContractMethodArgs$3, ContractTransactionReceipt, ethers } from 'ethers';

interface TypedDeferredTopicFilter$2<_TCEvent extends TypedContractEvent$2> extends DeferredTopicFilter {
}
interface TypedContractEvent$2<InputTuple extends Array<any> = any, OutputTuple extends Array<any> = any, OutputObject = any> {
    (...args: Partial<InputTuple>): TypedDeferredTopicFilter$2<TypedContractEvent$2<InputTuple, OutputTuple, OutputObject>>;
    name: string;
    fragment: EventFragment;
    getFragment(...args: Partial<InputTuple>): EventFragment;
}
type __TypechainAOutputTuple$2<T> = T extends TypedContractEvent$2<infer _U, infer W> ? W : never;
type __TypechainOutputObject$2<T> = T extends TypedContractEvent$2<infer _U, infer _W, infer V> ? V : never;
interface TypedEventLog$2<TCEvent extends TypedContractEvent$2> extends Omit<EventLog, 'args'> {
    args: __TypechainAOutputTuple$2<TCEvent> & __TypechainOutputObject$2<TCEvent>;
}
interface TypedLogDescription$2<TCEvent extends TypedContractEvent$2> extends Omit<LogDescription, 'args'> {
    args: __TypechainAOutputTuple$2<TCEvent> & __TypechainOutputObject$2<TCEvent>;
}
type TypedListener$2<TCEvent extends TypedContractEvent$2> = (...listenerArg: [
    ...__TypechainAOutputTuple$2<TCEvent>,
    TypedEventLog$2<TCEvent>,
    ...undefined[]
]) => void;
type StateMutability$2 = 'nonpayable' | 'payable' | 'view';
type BaseOverrides$2 = Omit<TransactionRequest, 'to' | 'data'>;
type NonPayableOverrides$2 = Omit<BaseOverrides$2, 'value' | 'blockTag' | 'enableCcipRead'>;
type PayableOverrides$2 = Omit<BaseOverrides$2, 'blockTag' | 'enableCcipRead'>;
type ViewOverrides$2 = Omit<TransactionRequest, 'to' | 'data'>;
type Overrides$2<S extends StateMutability$2> = S extends 'nonpayable' ? NonPayableOverrides$2 : S extends 'payable' ? PayableOverrides$2 : ViewOverrides$2;
type PostfixOverrides$2<A extends Array<any>, S extends StateMutability$2> = A | [...A, Overrides$2<S>];
type ContractMethodArgs$2<A extends Array<any>, S extends StateMutability$2> = PostfixOverrides$2<{
    [I in keyof A]-?: A[I] | Typed;
}, S>;
type DefaultReturnType$2<R> = R extends Array<any> ? R[0] : R;
interface TypedContractMethod$2<A extends Array<any> = Array<any>, R = any, S extends StateMutability$2 = 'payable'> {
    (...args: ContractMethodArgs$2<A, S>): S extends 'view' ? Promise<DefaultReturnType$2<R>> : Promise<ContractTransactionResponse>;
    name: string;
    fragment: FunctionFragment;
    getFragment(...args: ContractMethodArgs$2<A, S>): FunctionFragment;
    populateTransaction(...args: ContractMethodArgs$2<A, S>): Promise<ContractTransaction>;
    staticCall(...args: ContractMethodArgs$2<A, 'view'>): Promise<DefaultReturnType$2<R>>;
    send(...args: ContractMethodArgs$2<A, S>): Promise<ContractTransactionResponse>;
    estimateGas(...args: ContractMethodArgs$2<A, S>): Promise<bigint>;
    staticCallResult(...args: ContractMethodArgs$2<A, 'view'>): Promise<R>;
}

type ServiceParamsStruct = {
    serviceType: string;
    url: string;
    model: string;
    verifiability: string;
    inputPrice: BigNumberish;
    outputPrice: BigNumberish;
    additionalInfo: string;
};
type RefundStructOutput$1 = [
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
type AccountStructOutput = [
    user: string,
    provider: string,
    nonce: bigint,
    balance: bigint,
    pendingRefund: bigint,
    signer: [bigint, bigint],
    refunds: RefundStructOutput$1[],
    additionalInfo: string,
    providerPubKey: [bigint, bigint],
    teeSignerAddress: string,
    validRefundsLength: bigint
] & {
    user: string;
    provider: string;
    nonce: bigint;
    balance: bigint;
    pendingRefund: bigint;
    signer: [bigint, bigint];
    refunds: RefundStructOutput$1[];
    additionalInfo: string;
    providerPubKey: [bigint, bigint];
    teeSignerAddress: string;
    validRefundsLength: bigint;
};
type ServiceStructOutput$1 = [
    provider: string,
    serviceType: string,
    url: string,
    inputPrice: bigint,
    outputPrice: bigint,
    updatedAt: bigint,
    model: string,
    verifiability: string,
    additionalInfo: string
] & {
    provider: string;
    serviceType: string;
    url: string;
    inputPrice: bigint;
    outputPrice: bigint;
    updatedAt: bigint;
    model: string;
    verifiability: string;
    additionalInfo: string;
};
type TEESettlementDataStruct = {
    user: AddressLike;
    provider: AddressLike;
    totalFee: BigNumberish;
    requestsHash: BytesLike;
    nonce: BigNumberish;
    signature: BytesLike;
};
interface InferenceServingInterface extends Interface {
    getFunction(nameOrSignature: 'accountExists' | 'acknowledgeProviderSigner' | 'acknowledgeTEESigner' | 'addAccount' | 'addOrUpdateService' | 'deleteAccount' | 'depositFund' | 'getAccount' | 'getAccountsByProvider' | 'getAccountsByUser' | 'getAllAccounts' | 'getAllServices' | 'getBatchAccountsByUsers' | 'getPendingRefund' | 'getService' | 'initialize' | 'initialized' | 'ledgerAddress' | 'lockTime' | 'owner' | 'previewSettlementResults' | 'processRefund' | 'removeService' | 'renounceOwnership' | 'requestRefundAll' | 'settleFeesWithTEE' | 'transferOwnership' | 'updateLockTime'): FunctionFragment;
    getEvent(nameOrSignatureOrTopic: 'BalanceUpdated' | 'BatchBalanceUpdated' | 'OwnershipTransferred' | 'RefundRequested' | 'ServiceRemoved' | 'ServiceUpdated' | 'TEESettlementResult'): EventFragment;
    encodeFunctionData(functionFragment: 'accountExists', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'acknowledgeProviderSigner', values: [AddressLike, [BigNumberish, BigNumberish]]): string;
    encodeFunctionData(functionFragment: 'acknowledgeTEESigner', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'addAccount', values: [AddressLike, AddressLike, [BigNumberish, BigNumberish], string]): string;
    encodeFunctionData(functionFragment: 'addOrUpdateService', values: [ServiceParamsStruct]): string;
    encodeFunctionData(functionFragment: 'deleteAccount', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'depositFund', values: [AddressLike, AddressLike, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getAccount', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'getAccountsByProvider', values: [AddressLike, BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getAccountsByUser', values: [AddressLike, BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getAllAccounts', values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getAllServices', values?: undefined): string;
    encodeFunctionData(functionFragment: 'getBatchAccountsByUsers', values: [AddressLike[]]): string;
    encodeFunctionData(functionFragment: 'getPendingRefund', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'getService', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'initialize', values: [BigNumberish, AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'initialized', values?: undefined): string;
    encodeFunctionData(functionFragment: 'ledgerAddress', values?: undefined): string;
    encodeFunctionData(functionFragment: 'lockTime', values?: undefined): string;
    encodeFunctionData(functionFragment: 'owner', values?: undefined): string;
    encodeFunctionData(functionFragment: 'previewSettlementResults', values: [TEESettlementDataStruct[]]): string;
    encodeFunctionData(functionFragment: 'processRefund', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'removeService', values?: undefined): string;
    encodeFunctionData(functionFragment: 'renounceOwnership', values?: undefined): string;
    encodeFunctionData(functionFragment: 'requestRefundAll', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'settleFeesWithTEE', values: [TEESettlementDataStruct[]]): string;
    encodeFunctionData(functionFragment: 'transferOwnership', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'updateLockTime', values: [BigNumberish]): string;
    decodeFunctionResult(functionFragment: 'accountExists', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'acknowledgeProviderSigner', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'acknowledgeTEESigner', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'addAccount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'addOrUpdateService', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'deleteAccount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'depositFund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAccount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAccountsByProvider', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAccountsByUser', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAllAccounts', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAllServices', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getBatchAccountsByUsers', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getPendingRefund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getService', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'initialize', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'initialized', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'ledgerAddress', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'lockTime', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'owner', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'previewSettlementResults', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'processRefund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'removeService', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'renounceOwnership', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'requestRefundAll', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'settleFeesWithTEE', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'transferOwnership', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateLockTime', data: BytesLike): Result;
}
declare namespace BalanceUpdatedEvent$1 {
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
    type Event = TypedContractEvent$2<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter$2<Event>;
    type Log = TypedEventLog$2<Event>;
    type LogDescription = TypedLogDescription$2<Event>;
}
declare namespace BatchBalanceUpdatedEvent {
    type InputTuple = [
        users: AddressLike[],
        balances: BigNumberish[],
        pendingRefunds: BigNumberish[]
    ];
    type OutputTuple = [
        users: string[],
        balances: bigint[],
        pendingRefunds: bigint[]
    ];
    interface OutputObject {
        users: string[];
        balances: bigint[];
        pendingRefunds: bigint[];
    }
    type Event = TypedContractEvent$2<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter$2<Event>;
    type Log = TypedEventLog$2<Event>;
    type LogDescription = TypedLogDescription$2<Event>;
}
declare namespace OwnershipTransferredEvent$2 {
    type InputTuple = [previousOwner: AddressLike, newOwner: AddressLike];
    type OutputTuple = [previousOwner: string, newOwner: string];
    interface OutputObject {
        previousOwner: string;
        newOwner: string;
    }
    type Event = TypedContractEvent$2<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter$2<Event>;
    type Log = TypedEventLog$2<Event>;
    type LogDescription = TypedLogDescription$2<Event>;
}
declare namespace RefundRequestedEvent$1 {
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
    type Event = TypedContractEvent$2<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter$2<Event>;
    type Log = TypedEventLog$2<Event>;
    type LogDescription = TypedLogDescription$2<Event>;
}
declare namespace ServiceRemovedEvent$1 {
    type InputTuple = [service: AddressLike];
    type OutputTuple = [service: string];
    interface OutputObject {
        service: string;
    }
    type Event = TypedContractEvent$2<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter$2<Event>;
    type Log = TypedEventLog$2<Event>;
    type LogDescription = TypedLogDescription$2<Event>;
}
declare namespace ServiceUpdatedEvent$1 {
    type InputTuple = [
        service: AddressLike,
        serviceType: string,
        url: string,
        inputPrice: BigNumberish,
        outputPrice: BigNumberish,
        updatedAt: BigNumberish,
        model: string,
        verifiability: string
    ];
    type OutputTuple = [
        service: string,
        serviceType: string,
        url: string,
        inputPrice: bigint,
        outputPrice: bigint,
        updatedAt: bigint,
        model: string,
        verifiability: string
    ];
    interface OutputObject {
        service: string;
        serviceType: string;
        url: string;
        inputPrice: bigint;
        outputPrice: bigint;
        updatedAt: bigint;
        model: string;
        verifiability: string;
    }
    type Event = TypedContractEvent$2<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter$2<Event>;
    type Log = TypedEventLog$2<Event>;
    type LogDescription = TypedLogDescription$2<Event>;
}
declare namespace TEESettlementResultEvent {
    type InputTuple = [
        user: AddressLike,
        status: BigNumberish,
        unsettledAmount: BigNumberish
    ];
    type OutputTuple = [
        user: string,
        status: bigint,
        unsettledAmount: bigint
    ];
    interface OutputObject {
        user: string;
        status: bigint;
        unsettledAmount: bigint;
    }
    type Event = TypedContractEvent$2<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter$2<Event>;
    type Log = TypedEventLog$2<Event>;
    type LogDescription = TypedLogDescription$2<Event>;
}
interface InferenceServing extends BaseContract {
    connect(runner?: ContractRunner | null): InferenceServing;
    waitForDeployment(): Promise<this>;
    interface: InferenceServingInterface;
    queryFilter<TCEvent extends TypedContractEvent$2>(event: TCEvent, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog$2<TCEvent>>>;
    queryFilter<TCEvent extends TypedContractEvent$2>(filter: TypedDeferredTopicFilter$2<TCEvent>, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog$2<TCEvent>>>;
    on<TCEvent extends TypedContractEvent$2>(event: TCEvent, listener: TypedListener$2<TCEvent>): Promise<this>;
    on<TCEvent extends TypedContractEvent$2>(filter: TypedDeferredTopicFilter$2<TCEvent>, listener: TypedListener$2<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent$2>(event: TCEvent, listener: TypedListener$2<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent$2>(filter: TypedDeferredTopicFilter$2<TCEvent>, listener: TypedListener$2<TCEvent>): Promise<this>;
    listeners<TCEvent extends TypedContractEvent$2>(event: TCEvent): Promise<Array<TypedListener$2<TCEvent>>>;
    listeners(eventName?: string): Promise<Array<Listener>>;
    removeAllListeners<TCEvent extends TypedContractEvent$2>(event?: TCEvent): Promise<this>;
    accountExists: TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        boolean
    ], 'view'>;
    acknowledgeProviderSigner: TypedContractMethod$2<[
        provider: AddressLike,
        providerPubKey: [BigNumberish, BigNumberish]
    ], [
        void
    ], 'nonpayable'>;
    acknowledgeTEESigner: TypedContractMethod$2<[
        provider: AddressLike,
        teeSignerAddress: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    addAccount: TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike,
        signer: [BigNumberish, BigNumberish],
        additionalInfo: string
    ], [
        void
    ], 'payable'>;
    addOrUpdateService: TypedContractMethod$2<[
        params: ServiceParamsStruct
    ], [
        void
    ], 'nonpayable'>;
    deleteAccount: TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    depositFund: TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike,
        cancelRetrievingAmount: BigNumberish
    ], [
        void
    ], 'payable'>;
    getAccount: TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        AccountStructOutput
    ], 'view'>;
    getAccountsByProvider: TypedContractMethod$2<[
        provider: AddressLike,
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountStructOutput[],
            bigint
        ] & {
            accounts: AccountStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getAccountsByUser: TypedContractMethod$2<[
        user: AddressLike,
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountStructOutput[],
            bigint
        ] & {
            accounts: AccountStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getAllAccounts: TypedContractMethod$2<[
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountStructOutput[],
            bigint
        ] & {
            accounts: AccountStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getAllServices: TypedContractMethod$2<[], [ServiceStructOutput$1[]], 'view'>;
    getBatchAccountsByUsers: TypedContractMethod$2<[
        users: AddressLike[]
    ], [
        AccountStructOutput[]
    ], 'view'>;
    getPendingRefund: TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        bigint
    ], 'view'>;
    getService: TypedContractMethod$2<[
        provider: AddressLike
    ], [
        ServiceStructOutput$1
    ], 'view'>;
    initialize: TypedContractMethod$2<[
        _locktime: BigNumberish,
        _ledgerAddress: AddressLike,
        owner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    initialized: TypedContractMethod$2<[], [boolean], 'view'>;
    ledgerAddress: TypedContractMethod$2<[], [string], 'view'>;
    lockTime: TypedContractMethod$2<[], [bigint], 'view'>;
    owner: TypedContractMethod$2<[], [string], 'view'>;
    previewSettlementResults: TypedContractMethod$2<[
        settlements: TEESettlementDataStruct[]
    ], [
        [
            string[],
            bigint[],
            string[],
            bigint[]
        ] & {
            failedUsers: string[];
            failureReasons: bigint[];
            partialUsers: string[];
            partialAmounts: bigint[];
        }
    ], 'view'>;
    processRefund: TypedContractMethod$2<[
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
    removeService: TypedContractMethod$2<[], [void], 'nonpayable'>;
    renounceOwnership: TypedContractMethod$2<[], [void], 'nonpayable'>;
    requestRefundAll: TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    settleFeesWithTEE: TypedContractMethod$2<[
        settlements: TEESettlementDataStruct[]
    ], [
        [
            string[],
            bigint[],
            string[],
            bigint[]
        ] & {
            failedUsers: string[];
            failureReasons: bigint[];
            partialUsers: string[];
            partialAmounts: bigint[];
        }
    ], 'nonpayable'>;
    transferOwnership: TypedContractMethod$2<[
        newOwner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    updateLockTime: TypedContractMethod$2<[
        _locktime: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction<T extends ContractMethod = ContractMethod>(key: string | FunctionFragment): T;
    getFunction(nameOrSignature: 'accountExists'): TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        boolean
    ], 'view'>;
    getFunction(nameOrSignature: 'acknowledgeProviderSigner'): TypedContractMethod$2<[
        provider: AddressLike,
        providerPubKey: [BigNumberish, BigNumberish]
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'acknowledgeTEESigner'): TypedContractMethod$2<[
        provider: AddressLike,
        teeSignerAddress: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'addAccount'): TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike,
        signer: [BigNumberish, BigNumberish],
        additionalInfo: string
    ], [
        void
    ], 'payable'>;
    getFunction(nameOrSignature: 'addOrUpdateService'): TypedContractMethod$2<[params: ServiceParamsStruct], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'deleteAccount'): TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'depositFund'): TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike,
        cancelRetrievingAmount: BigNumberish
    ], [
        void
    ], 'payable'>;
    getFunction(nameOrSignature: 'getAccount'): TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        AccountStructOutput
    ], 'view'>;
    getFunction(nameOrSignature: 'getAccountsByProvider'): TypedContractMethod$2<[
        provider: AddressLike,
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountStructOutput[],
            bigint
        ] & {
            accounts: AccountStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getFunction(nameOrSignature: 'getAccountsByUser'): TypedContractMethod$2<[
        user: AddressLike,
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountStructOutput[],
            bigint
        ] & {
            accounts: AccountStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getFunction(nameOrSignature: 'getAllAccounts'): TypedContractMethod$2<[
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            AccountStructOutput[],
            bigint
        ] & {
            accounts: AccountStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getFunction(nameOrSignature: 'getAllServices'): TypedContractMethod$2<[], [ServiceStructOutput$1[]], 'view'>;
    getFunction(nameOrSignature: 'getBatchAccountsByUsers'): TypedContractMethod$2<[
        users: AddressLike[]
    ], [
        AccountStructOutput[]
    ], 'view'>;
    getFunction(nameOrSignature: 'getPendingRefund'): TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        bigint
    ], 'view'>;
    getFunction(nameOrSignature: 'getService'): TypedContractMethod$2<[
        provider: AddressLike
    ], [
        ServiceStructOutput$1
    ], 'view'>;
    getFunction(nameOrSignature: 'initialize'): TypedContractMethod$2<[
        _locktime: BigNumberish,
        _ledgerAddress: AddressLike,
        owner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'initialized'): TypedContractMethod$2<[], [boolean], 'view'>;
    getFunction(nameOrSignature: 'ledgerAddress'): TypedContractMethod$2<[], [string], 'view'>;
    getFunction(nameOrSignature: 'lockTime'): TypedContractMethod$2<[], [bigint], 'view'>;
    getFunction(nameOrSignature: 'owner'): TypedContractMethod$2<[], [string], 'view'>;
    getFunction(nameOrSignature: 'previewSettlementResults'): TypedContractMethod$2<[
        settlements: TEESettlementDataStruct[]
    ], [
        [
            string[],
            bigint[],
            string[],
            bigint[]
        ] & {
            failedUsers: string[];
            failureReasons: bigint[];
            partialUsers: string[];
            partialAmounts: bigint[];
        }
    ], 'view'>;
    getFunction(nameOrSignature: 'processRefund'): TypedContractMethod$2<[
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
    getFunction(nameOrSignature: 'removeService'): TypedContractMethod$2<[], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'renounceOwnership'): TypedContractMethod$2<[], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'requestRefundAll'): TypedContractMethod$2<[
        user: AddressLike,
        provider: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'settleFeesWithTEE'): TypedContractMethod$2<[
        settlements: TEESettlementDataStruct[]
    ], [
        [
            string[],
            bigint[],
            string[],
            bigint[]
        ] & {
            failedUsers: string[];
            failureReasons: bigint[];
            partialUsers: string[];
            partialAmounts: bigint[];
        }
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'transferOwnership'): TypedContractMethod$2<[newOwner: AddressLike], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateLockTime'): TypedContractMethod$2<[_locktime: BigNumberish], [void], 'nonpayable'>;
    getEvent(key: 'BalanceUpdated'): TypedContractEvent$2<BalanceUpdatedEvent$1.InputTuple, BalanceUpdatedEvent$1.OutputTuple, BalanceUpdatedEvent$1.OutputObject>;
    getEvent(key: 'BatchBalanceUpdated'): TypedContractEvent$2<BatchBalanceUpdatedEvent.InputTuple, BatchBalanceUpdatedEvent.OutputTuple, BatchBalanceUpdatedEvent.OutputObject>;
    getEvent(key: 'OwnershipTransferred'): TypedContractEvent$2<OwnershipTransferredEvent$2.InputTuple, OwnershipTransferredEvent$2.OutputTuple, OwnershipTransferredEvent$2.OutputObject>;
    getEvent(key: 'RefundRequested'): TypedContractEvent$2<RefundRequestedEvent$1.InputTuple, RefundRequestedEvent$1.OutputTuple, RefundRequestedEvent$1.OutputObject>;
    getEvent(key: 'ServiceRemoved'): TypedContractEvent$2<ServiceRemovedEvent$1.InputTuple, ServiceRemovedEvent$1.OutputTuple, ServiceRemovedEvent$1.OutputObject>;
    getEvent(key: 'ServiceUpdated'): TypedContractEvent$2<ServiceUpdatedEvent$1.InputTuple, ServiceUpdatedEvent$1.OutputTuple, ServiceUpdatedEvent$1.OutputObject>;
    getEvent(key: 'TEESettlementResult'): TypedContractEvent$2<TEESettlementResultEvent.InputTuple, TEESettlementResultEvent.OutputTuple, TEESettlementResultEvent.OutputObject>;
    filters: {
        'BalanceUpdated(address,address,uint256,uint256)': TypedContractEvent$2<BalanceUpdatedEvent$1.InputTuple, BalanceUpdatedEvent$1.OutputTuple, BalanceUpdatedEvent$1.OutputObject>;
        BalanceUpdated: TypedContractEvent$2<BalanceUpdatedEvent$1.InputTuple, BalanceUpdatedEvent$1.OutputTuple, BalanceUpdatedEvent$1.OutputObject>;
        'BatchBalanceUpdated(address[],uint256[],uint256[])': TypedContractEvent$2<BatchBalanceUpdatedEvent.InputTuple, BatchBalanceUpdatedEvent.OutputTuple, BatchBalanceUpdatedEvent.OutputObject>;
        BatchBalanceUpdated: TypedContractEvent$2<BatchBalanceUpdatedEvent.InputTuple, BatchBalanceUpdatedEvent.OutputTuple, BatchBalanceUpdatedEvent.OutputObject>;
        'OwnershipTransferred(address,address)': TypedContractEvent$2<OwnershipTransferredEvent$2.InputTuple, OwnershipTransferredEvent$2.OutputTuple, OwnershipTransferredEvent$2.OutputObject>;
        OwnershipTransferred: TypedContractEvent$2<OwnershipTransferredEvent$2.InputTuple, OwnershipTransferredEvent$2.OutputTuple, OwnershipTransferredEvent$2.OutputObject>;
        'RefundRequested(address,address,uint256,uint256)': TypedContractEvent$2<RefundRequestedEvent$1.InputTuple, RefundRequestedEvent$1.OutputTuple, RefundRequestedEvent$1.OutputObject>;
        RefundRequested: TypedContractEvent$2<RefundRequestedEvent$1.InputTuple, RefundRequestedEvent$1.OutputTuple, RefundRequestedEvent$1.OutputObject>;
        'ServiceRemoved(address)': TypedContractEvent$2<ServiceRemovedEvent$1.InputTuple, ServiceRemovedEvent$1.OutputTuple, ServiceRemovedEvent$1.OutputObject>;
        ServiceRemoved: TypedContractEvent$2<ServiceRemovedEvent$1.InputTuple, ServiceRemovedEvent$1.OutputTuple, ServiceRemovedEvent$1.OutputObject>;
        'ServiceUpdated(address,string,string,uint256,uint256,uint256,string,string)': TypedContractEvent$2<ServiceUpdatedEvent$1.InputTuple, ServiceUpdatedEvent$1.OutputTuple, ServiceUpdatedEvent$1.OutputObject>;
        ServiceUpdated: TypedContractEvent$2<ServiceUpdatedEvent$1.InputTuple, ServiceUpdatedEvent$1.OutputTuple, ServiceUpdatedEvent$1.OutputObject>;
        'TEESettlementResult(address,uint8,uint256)': TypedContractEvent$2<TEESettlementResultEvent.InputTuple, TEESettlementResultEvent.OutputTuple, TEESettlementResultEvent.OutputObject>;
        TEESettlementResult: TypedContractEvent$2<TEESettlementResultEvent.InputTuple, TEESettlementResultEvent.OutputTuple, TEESettlementResultEvent.OutputObject>;
    };
}

declare class InferenceServingContract {
    serving: InferenceServing;
    signer: JsonRpcSigner | Wallet;
    private _userAddress;
    constructor(signer: JsonRpcSigner | Wallet, contractAddress: string, userAddress: string);
    lockTime(): Promise<bigint>;
    listService(): Promise<ServiceStructOutput$1[]>;
    listAccount(offset?: number, limit?: number): Promise<AccountStructOutput[]>;
    getAccount(provider: AddressLike): Promise<AccountStructOutput>;
    acknowledgeTEESigner(providerAddress: AddressLike, providerSigner: AddressLike): Promise<void>;
    getService(providerAddress: string): Promise<ServiceStructOutput$1>;
    getUserAddress(): string;
}

declare abstract class Extractor {
    abstract getSvcInfo(): Promise<ServiceStructOutput$1>;
    abstract getInputCount(content: string): Promise<number>;
    abstract getOutputCount(content: string): Promise<number>;
}

declare class Metadata {
    private nodeStorage;
    private initialized;
    private isBrowser;
    private storagePrefix;
    constructor();
    initialize(): Promise<void>;
    private setItem;
    private getItem;
    storeSigningKey(key: string, value: string): Promise<void>;
    getSigningKey(key: string): Promise<string | null>;
}

declare enum CacheValueTypeEnum {
    Service = "service",
    BigInt = "bigint",
    Other = "other"
}
type CacheValueType = CacheValueTypeEnum.Service | CacheValueTypeEnum.BigInt | CacheValueTypeEnum.Other;
declare class Cache {
    private nodeStorage;
    private initialized;
    private isBrowser;
    private storagePrefix;
    constructor();
    setLock(key: string, value: string, ttl: number, type: CacheValueType): boolean;
    removeLock(key: string): void;
    setItem(key: string, value: any, ttl: number, type: CacheValueType): void;
    getItem(key: string): any | null;
    private initialize;
    private setStorageItem;
    private getStorageItem;
    private removeStorageItem;
    private cleanupExpiredItems;
    static encodeValue(value: any): string;
    static decodeValue(encodedValue: string, type: CacheValueType): any;
    static createServiceStructOutput(fields: [
        string,
        string,
        string,
        bigint,
        bigint,
        bigint,
        string,
        string,
        string
    ]): ServiceStructOutput$1;
}

interface TypedDeferredTopicFilter$1<_TCEvent extends TypedContractEvent$1> extends DeferredTopicFilter {
}
interface TypedContractEvent$1<InputTuple extends Array<any> = any, OutputTuple extends Array<any> = any, OutputObject = any> {
    (...args: Partial<InputTuple>): TypedDeferredTopicFilter$1<TypedContractEvent$1<InputTuple, OutputTuple, OutputObject>>;
    name: string;
    fragment: EventFragment;
    getFragment(...args: Partial<InputTuple>): EventFragment;
}
type __TypechainAOutputTuple$1<T> = T extends TypedContractEvent$1<infer _U, infer W> ? W : never;
type __TypechainOutputObject$1<T> = T extends TypedContractEvent$1<infer _U, infer _W, infer V> ? V : never;
interface TypedEventLog$1<TCEvent extends TypedContractEvent$1> extends Omit<EventLog, 'args'> {
    args: __TypechainAOutputTuple$1<TCEvent> & __TypechainOutputObject$1<TCEvent>;
}
interface TypedLogDescription$1<TCEvent extends TypedContractEvent$1> extends Omit<LogDescription, 'args'> {
    args: __TypechainAOutputTuple$1<TCEvent> & __TypechainOutputObject$1<TCEvent>;
}
type TypedListener$1<TCEvent extends TypedContractEvent$1> = (...listenerArg: [
    ...__TypechainAOutputTuple$1<TCEvent>,
    TypedEventLog$1<TCEvent>,
    ...undefined[]
]) => void;
type StateMutability$1 = 'nonpayable' | 'payable' | 'view';
type BaseOverrides$1 = Omit<TransactionRequest, 'to' | 'data'>;
type NonPayableOverrides$1 = Omit<BaseOverrides$1, 'value' | 'blockTag' | 'enableCcipRead'>;
type PayableOverrides$1 = Omit<BaseOverrides$1, 'blockTag' | 'enableCcipRead'>;
type ViewOverrides$1 = Omit<TransactionRequest, 'to' | 'data'>;
type Overrides$1<S extends StateMutability$1> = S extends 'nonpayable' ? NonPayableOverrides$1 : S extends 'payable' ? PayableOverrides$1 : ViewOverrides$1;
type PostfixOverrides$1<A extends Array<any>, S extends StateMutability$1> = A | [...A, Overrides$1<S>];
type ContractMethodArgs$1<A extends Array<any>, S extends StateMutability$1> = PostfixOverrides$1<{
    [I in keyof A]-?: A[I] | Typed;
}, S>;
type DefaultReturnType$1<R> = R extends Array<any> ? R[0] : R;
interface TypedContractMethod$1<A extends Array<any> = Array<any>, R = any, S extends StateMutability$1 = 'payable'> {
    (...args: ContractMethodArgs$1<A, S>): S extends 'view' ? Promise<DefaultReturnType$1<R>> : Promise<ContractTransactionResponse>;
    name: string;
    fragment: FunctionFragment;
    getFragment(...args: ContractMethodArgs$1<A, S>): FunctionFragment;
    populateTransaction(...args: ContractMethodArgs$1<A, S>): Promise<ContractTransaction>;
    staticCall(...args: ContractMethodArgs$1<A, 'view'>): Promise<DefaultReturnType$1<R>>;
    send(...args: ContractMethodArgs$1<A, S>): Promise<ContractTransactionResponse>;
    estimateGas(...args: ContractMethodArgs$1<A, S>): Promise<bigint>;
    staticCallResult(...args: ContractMethodArgs$1<A, 'view'>): Promise<R>;
}

type LedgerStructOutput = [
    user: string,
    availableBalance: bigint,
    totalBalance: bigint,
    inferenceSigner: [bigint, bigint],
    additionalInfo: string,
    inferenceProviders: string[],
    fineTuningProviders: string[]
] & {
    user: string;
    availableBalance: bigint;
    totalBalance: bigint;
    inferenceSigner: [bigint, bigint];
    additionalInfo: string;
    inferenceProviders: string[];
    fineTuningProviders: string[];
};
interface LedgerManagerInterface extends Interface {
    getFunction(nameOrSignature: 'MAX_PROVIDERS_PER_BATCH' | 'addLedger' | 'deleteLedger' | 'depositFund' | 'fineTuningAddress' | 'getAllLedgers' | 'getLedger' | 'inferenceAddress' | 'initialize' | 'initialized' | 'owner' | 'refund' | 'renounceOwnership' | 'retrieveFund' | 'spendFund' | 'transferFund' | 'transferOwnership'): FunctionFragment;
    getEvent(nameOrSignatureOrTopic: 'OwnershipTransferred'): EventFragment;
    encodeFunctionData(functionFragment: 'MAX_PROVIDERS_PER_BATCH', values?: undefined): string;
    encodeFunctionData(functionFragment: 'addLedger', values: [[BigNumberish, BigNumberish], string]): string;
    encodeFunctionData(functionFragment: 'deleteLedger', values?: undefined): string;
    encodeFunctionData(functionFragment: 'depositFund', values?: undefined): string;
    encodeFunctionData(functionFragment: 'fineTuningAddress', values?: undefined): string;
    encodeFunctionData(functionFragment: 'getAllLedgers', values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'getLedger', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'inferenceAddress', values?: undefined): string;
    encodeFunctionData(functionFragment: 'initialize', values: [AddressLike, AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'initialized', values?: undefined): string;
    encodeFunctionData(functionFragment: 'owner', values?: undefined): string;
    encodeFunctionData(functionFragment: 'refund', values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: 'renounceOwnership', values?: undefined): string;
    encodeFunctionData(functionFragment: 'retrieveFund', values: [AddressLike[], string]): string;
    encodeFunctionData(functionFragment: 'spendFund', values: [AddressLike, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'transferFund', values: [AddressLike, string, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'transferOwnership', values: [AddressLike]): string;
    decodeFunctionResult(functionFragment: 'MAX_PROVIDERS_PER_BATCH', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'addLedger', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'deleteLedger', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'depositFund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'fineTuningAddress', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAllLedgers', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getLedger', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'inferenceAddress', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'initialize', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'initialized', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'owner', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'refund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'renounceOwnership', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'retrieveFund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'spendFund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'transferFund', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'transferOwnership', data: BytesLike): Result;
}
declare namespace OwnershipTransferredEvent$1 {
    type InputTuple = [previousOwner: AddressLike, newOwner: AddressLike];
    type OutputTuple = [previousOwner: string, newOwner: string];
    interface OutputObject {
        previousOwner: string;
        newOwner: string;
    }
    type Event = TypedContractEvent$1<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter$1<Event>;
    type Log = TypedEventLog$1<Event>;
    type LogDescription = TypedLogDescription$1<Event>;
}
interface LedgerManager extends BaseContract {
    connect(runner?: ContractRunner | null): LedgerManager;
    waitForDeployment(): Promise<this>;
    interface: LedgerManagerInterface;
    queryFilter<TCEvent extends TypedContractEvent$1>(event: TCEvent, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog$1<TCEvent>>>;
    queryFilter<TCEvent extends TypedContractEvent$1>(filter: TypedDeferredTopicFilter$1<TCEvent>, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog$1<TCEvent>>>;
    on<TCEvent extends TypedContractEvent$1>(event: TCEvent, listener: TypedListener$1<TCEvent>): Promise<this>;
    on<TCEvent extends TypedContractEvent$1>(filter: TypedDeferredTopicFilter$1<TCEvent>, listener: TypedListener$1<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent$1>(event: TCEvent, listener: TypedListener$1<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent$1>(filter: TypedDeferredTopicFilter$1<TCEvent>, listener: TypedListener$1<TCEvent>): Promise<this>;
    listeners<TCEvent extends TypedContractEvent$1>(event: TCEvent): Promise<Array<TypedListener$1<TCEvent>>>;
    listeners(eventName?: string): Promise<Array<Listener>>;
    removeAllListeners<TCEvent extends TypedContractEvent$1>(event?: TCEvent): Promise<this>;
    MAX_PROVIDERS_PER_BATCH: TypedContractMethod$1<[], [bigint], 'view'>;
    addLedger: TypedContractMethod$1<[
        inferenceSigner: [BigNumberish, BigNumberish],
        additionalInfo: string
    ], [
        [bigint, bigint]
    ], 'payable'>;
    deleteLedger: TypedContractMethod$1<[], [void], 'nonpayable'>;
    depositFund: TypedContractMethod$1<[], [void], 'payable'>;
    fineTuningAddress: TypedContractMethod$1<[], [string], 'view'>;
    getAllLedgers: TypedContractMethod$1<[
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            LedgerStructOutput[],
            bigint
        ] & {
            ledgers: LedgerStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getLedger: TypedContractMethod$1<[
        user: AddressLike
    ], [
        LedgerStructOutput
    ], 'view'>;
    inferenceAddress: TypedContractMethod$1<[], [string], 'view'>;
    initialize: TypedContractMethod$1<[
        _inferenceAddress: AddressLike,
        _fineTuningAddress: AddressLike,
        owner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    initialized: TypedContractMethod$1<[], [boolean], 'view'>;
    owner: TypedContractMethod$1<[], [string], 'view'>;
    refund: TypedContractMethod$1<[amount: BigNumberish], [void], 'nonpayable'>;
    renounceOwnership: TypedContractMethod$1<[], [void], 'nonpayable'>;
    retrieveFund: TypedContractMethod$1<[
        providers: AddressLike[],
        serviceType: string
    ], [
        void
    ], 'nonpayable'>;
    spendFund: TypedContractMethod$1<[
        user: AddressLike,
        amount: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    transferFund: TypedContractMethod$1<[
        provider: AddressLike,
        serviceTypeStr: string,
        amount: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    transferOwnership: TypedContractMethod$1<[
        newOwner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction<T extends ContractMethod = ContractMethod>(key: string | FunctionFragment): T;
    getFunction(nameOrSignature: 'MAX_PROVIDERS_PER_BATCH'): TypedContractMethod$1<[], [bigint], 'view'>;
    getFunction(nameOrSignature: 'addLedger'): TypedContractMethod$1<[
        inferenceSigner: [BigNumberish, BigNumberish],
        additionalInfo: string
    ], [
        [bigint, bigint]
    ], 'payable'>;
    getFunction(nameOrSignature: 'deleteLedger'): TypedContractMethod$1<[], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'depositFund'): TypedContractMethod$1<[], [void], 'payable'>;
    getFunction(nameOrSignature: 'fineTuningAddress'): TypedContractMethod$1<[], [string], 'view'>;
    getFunction(nameOrSignature: 'getAllLedgers'): TypedContractMethod$1<[
        offset: BigNumberish,
        limit: BigNumberish
    ], [
        [
            LedgerStructOutput[],
            bigint
        ] & {
            ledgers: LedgerStructOutput[];
            total: bigint;
        }
    ], 'view'>;
    getFunction(nameOrSignature: 'getLedger'): TypedContractMethod$1<[user: AddressLike], [LedgerStructOutput], 'view'>;
    getFunction(nameOrSignature: 'inferenceAddress'): TypedContractMethod$1<[], [string], 'view'>;
    getFunction(nameOrSignature: 'initialize'): TypedContractMethod$1<[
        _inferenceAddress: AddressLike,
        _fineTuningAddress: AddressLike,
        owner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'initialized'): TypedContractMethod$1<[], [boolean], 'view'>;
    getFunction(nameOrSignature: 'owner'): TypedContractMethod$1<[], [string], 'view'>;
    getFunction(nameOrSignature: 'refund'): TypedContractMethod$1<[amount: BigNumberish], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'renounceOwnership'): TypedContractMethod$1<[], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'retrieveFund'): TypedContractMethod$1<[
        providers: AddressLike[],
        serviceType: string
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'spendFund'): TypedContractMethod$1<[
        user: AddressLike,
        amount: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'transferFund'): TypedContractMethod$1<[
        provider: AddressLike,
        serviceTypeStr: string,
        amount: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'transferOwnership'): TypedContractMethod$1<[newOwner: AddressLike], [void], 'nonpayable'>;
    getEvent(key: 'OwnershipTransferred'): TypedContractEvent$1<OwnershipTransferredEvent$1.InputTuple, OwnershipTransferredEvent$1.OutputTuple, OwnershipTransferredEvent$1.OutputObject>;
    filters: {
        'OwnershipTransferred(address,address)': TypedContractEvent$1<OwnershipTransferredEvent$1.InputTuple, OwnershipTransferredEvent$1.OutputTuple, OwnershipTransferredEvent$1.OutputObject>;
        OwnershipTransferred: TypedContractEvent$1<OwnershipTransferredEvent$1.InputTuple, OwnershipTransferredEvent$1.OutputTuple, OwnershipTransferredEvent$1.OutputObject>;
    };
}

declare class LedgerManagerContract {
    ledger: LedgerManager;
    signer: JsonRpcSigner | Wallet;
    private _userAddress;
    private _gasPrice?;
    private _maxGasPrice?;
    private _step;
    constructor(signer: JsonRpcSigner | Wallet, contractAddress: string, userAddress: string, gasPrice?: number, maxGasPrice?: number, step?: number);
    sendTx(name: string, txArgs: ContractMethodArgs$3<any[]>, txOptions: any): Promise<void>;
    addLedger(signer: [BigNumberish, BigNumberish], balance: bigint, settleSignerEncryptedPrivateKey: string, gasPrice?: number): Promise<void>;
    listLedger(offset?: number, limit?: number): Promise<LedgerStructOutput[]>;
    getLedger(): Promise<LedgerStructOutput>;
    depositFund(balance: string, gasPrice?: number): Promise<void>;
    refund(amount: BigNumberish, gasPrice?: number): Promise<void>;
    transferFund(provider: AddressLike, serviceTypeStr: 'inference' | 'fine-tuning', amount: BigNumberish, gasPrice?: number): Promise<void>;
    retrieveFund(providers: AddressLike[], serviceTypeStr: 'inference' | 'fine-tuning', gasPrice?: number): Promise<void>;
    deleteLedger(gasPrice?: number): Promise<void>;
    getUserAddress(): string;
    checkReceipt(receipt: ContractTransactionReceipt | null): void;
}

interface TypedDeferredTopicFilter<_TCEvent extends TypedContractEvent> extends DeferredTopicFilter {
}
interface TypedContractEvent<InputTuple extends Array<any> = any, OutputTuple extends Array<any> = any, OutputObject = any> {
    (...args: Partial<InputTuple>): TypedDeferredTopicFilter<TypedContractEvent<InputTuple, OutputTuple, OutputObject>>;
    name: string;
    fragment: EventFragment;
    getFragment(...args: Partial<InputTuple>): EventFragment;
}
type __TypechainAOutputTuple<T> = T extends TypedContractEvent<infer _U, infer W> ? W : never;
type __TypechainOutputObject<T> = T extends TypedContractEvent<infer _U, infer _W, infer V> ? V : never;
interface TypedEventLog<TCEvent extends TypedContractEvent> extends Omit<EventLog, 'args'> {
    args: __TypechainAOutputTuple<TCEvent> & __TypechainOutputObject<TCEvent>;
}
interface TypedLogDescription<TCEvent extends TypedContractEvent> extends Omit<LogDescription, 'args'> {
    args: __TypechainAOutputTuple<TCEvent> & __TypechainOutputObject<TCEvent>;
}
type TypedListener<TCEvent extends TypedContractEvent> = (...listenerArg: [
    ...__TypechainAOutputTuple<TCEvent>,
    TypedEventLog<TCEvent>,
    ...undefined[]
]) => void;
type StateMutability = 'nonpayable' | 'payable' | 'view';
type BaseOverrides = Omit<TransactionRequest, 'to' | 'data'>;
type NonPayableOverrides = Omit<BaseOverrides, 'value' | 'blockTag' | 'enableCcipRead'>;
type PayableOverrides = Omit<BaseOverrides, 'blockTag' | 'enableCcipRead'>;
type ViewOverrides = Omit<TransactionRequest, 'to' | 'data'>;
type Overrides<S extends StateMutability> = S extends 'nonpayable' ? NonPayableOverrides : S extends 'payable' ? PayableOverrides : ViewOverrides;
type PostfixOverrides<A extends Array<any>, S extends StateMutability> = A | [...A, Overrides<S>];
type ContractMethodArgs<A extends Array<any>, S extends StateMutability> = PostfixOverrides<{
    [I in keyof A]-?: A[I] | Typed;
}, S>;
type DefaultReturnType<R> = R extends Array<any> ? R[0] : R;
interface TypedContractMethod<A extends Array<any> = Array<any>, R = any, S extends StateMutability = 'payable'> {
    (...args: ContractMethodArgs<A, S>): S extends 'view' ? Promise<DefaultReturnType<R>> : Promise<ContractTransactionResponse>;
    name: string;
    fragment: FunctionFragment;
    getFragment(...args: ContractMethodArgs<A, S>): FunctionFragment;
    populateTransaction(...args: ContractMethodArgs<A, S>): Promise<ContractTransaction>;
    staticCall(...args: ContractMethodArgs<A, 'view'>): Promise<DefaultReturnType<R>>;
    send(...args: ContractMethodArgs<A, S>): Promise<ContractTransactionResponse>;
    estimateGas(...args: ContractMethodArgs<A, S>): Promise<bigint>;
    staticCallResult(...args: ContractMethodArgs<A, 'view'>): Promise<R>;
}

type QuotaStruct = {
    cpuCount: BigNumberish;
    nodeMemory: BigNumberish;
    gpuCount: BigNumberish;
    nodeStorage: BigNumberish;
    gpuType: string;
};
type QuotaStructOutput = [
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
type RefundStructOutput = [
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
type DeliverableStructOutput = [
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
type AccountDetailsStructOutput = [
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
type AccountSummaryStructOutput = [
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
type ServiceStructOutput = [
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
type VerifierInputStruct = {
    id: string;
    encryptedSecret: BytesLike;
    modelRootHash: BytesLike;
    nonce: BigNumberish;
    providerSigner: AddressLike;
    signature: BytesLike;
    taskFee: BigNumberish;
    user: AddressLike;
};
interface FineTuningServingInterface extends Interface {
    getFunction(nameOrSignature: 'accountExists' | 'acknowledgeDeliverable(address,string)' | 'acknowledgeDeliverable(address,address,string)' | 'acknowledgeProviderSigner' | 'addAccount' | 'addDeliverable' | 'addOrUpdateService' | 'deleteAccount' | 'depositFund' | 'getAccount' | 'getAccountsByProvider' | 'getAccountsByUser' | 'getAllAccounts' | 'getAllServices' | 'getBatchAccountsByUsers' | 'getDeliverable' | 'getDeliverables' | 'getPendingRefund' | 'getService' | 'initialize' | 'initialized' | 'ledgerAddress' | 'lockTime' | 'owner' | 'penaltyPercentage' | 'processRefund' | 'removeService' | 'renounceOwnership' | 'requestRefundAll' | 'settleFees' | 'transferOwnership' | 'updateLockTime' | 'updatePenaltyPercentage'): FunctionFragment;
    getEvent(nameOrSignatureOrTopic: 'BalanceUpdated' | 'OwnershipTransferred' | 'RefundRequested' | 'ServiceRemoved' | 'ServiceUpdated'): EventFragment;
    encodeFunctionData(functionFragment: 'accountExists', values: [AddressLike, AddressLike]): string;
    encodeFunctionData(functionFragment: 'acknowledgeDeliverable(address,string)', values: [AddressLike, string]): string;
    encodeFunctionData(functionFragment: 'acknowledgeDeliverable(address,address,string)', values: [AddressLike, AddressLike, string]): string;
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
    encodeFunctionData(functionFragment: 'transferOwnership', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'updateLockTime', values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: 'updatePenaltyPercentage', values: [BigNumberish]): string;
    decodeFunctionResult(functionFragment: 'accountExists', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'acknowledgeDeliverable(address,string)', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'acknowledgeDeliverable(address,address,string)', data: BytesLike): Result;
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
    decodeFunctionResult(functionFragment: 'transferOwnership', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateLockTime', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updatePenaltyPercentage', data: BytesLike): Result;
}
declare namespace BalanceUpdatedEvent {
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
declare namespace OwnershipTransferredEvent {
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
declare namespace RefundRequestedEvent {
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
declare namespace ServiceRemovedEvent {
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
declare namespace ServiceUpdatedEvent {
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
interface FineTuningServing extends BaseContract {
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
    'acknowledgeDeliverable(address,string)': TypedContractMethod<[
        provider: AddressLike,
        id: string
    ], [
        void
    ], 'nonpayable'>;
    'acknowledgeDeliverable(address,address,string)': TypedContractMethod<[
        user: AddressLike,
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
    getFunction(nameOrSignature: 'acknowledgeDeliverable(address,string)'): TypedContractMethod<[
        provider: AddressLike,
        id: string
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'acknowledgeDeliverable(address,address,string)'): TypedContractMethod<[
        user: AddressLike,
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

declare class FineTuningServingContract {
    serving: FineTuningServing;
    signer: Wallet;
    private _userAddress;
    private _gasPrice?;
    private _maxGasPrice?;
    private _step;
    constructor(signer: Wallet, contractAddress: string, userAddress: string, gasPrice?: number, maxGasPrice?: number, step?: number);
    lockTime(): Promise<bigint>;
    sendTx(name: string, txArgs: ContractMethodArgs$3<any[]>, txOptions: any): Promise<void>;
    listService(): Promise<ServiceStructOutput[]>;
    listAccount(offset?: number, limit?: number): Promise<AccountSummaryStructOutput[]>;
    getAccount(provider: AddressLike): Promise<AccountDetailsStructOutput>;
    acknowledgeProviderSigner(providerAddress: AddressLike, providerSigner: AddressLike, gasPrice?: number): Promise<void>;
    acknowledgeDeliverable(providerAddress: AddressLike, id: string, gasPrice?: number): Promise<void>;
    getService(providerAddress: string): Promise<ServiceStructOutput>;
    getDeliverable(providerAddress: AddressLike, id: string): Promise<DeliverableStructOutput>;
    getUserAddress(): string;
    checkReceipt(receipt: ContractTransactionReceipt | null): void;
}

interface LedgerDetailStructOutput {
    ledgerInfo: bigint[];
    infers: [string, bigint, bigint][];
    fines: [string, bigint, bigint][] | null;
}
/**
 * LedgerProcessor contains methods for creating, depositing funds, and retrieving 0G Compute Network Ledgers.
 */
declare class LedgerProcessor {
    protected metadata: Metadata;
    protected cache: Cache;
    protected ledgerContract: LedgerManagerContract;
    protected inferenceContract: InferenceServingContract;
    protected fineTuningContract: FineTuningServingContract | undefined;
    constructor(metadata: Metadata, cache: Cache, ledgerContract: LedgerManagerContract, inferenceContract: InferenceServingContract, fineTuningContract?: FineTuningServingContract);
    getLedger(): Promise<LedgerStructOutput>;
    getLedgerWithDetail(): Promise<LedgerDetailStructOutput>;
    listLedger(): Promise<LedgerStructOutput[]>;
    addLedger(balance: number, gasPrice?: number): Promise<void>;
    deleteLedger(gasPrice?: number): Promise<void>;
    depositFund(balance: number, gasPrice?: number): Promise<void>;
    refund(balance: number, gasPrice?: number): Promise<void>;
    transferFund(to: AddressLike, serviceTypeStr: 'inference' | 'fine-tuning', balance: bigint, gasPrice?: number): Promise<void>;
    retrieveFund(serviceTypeStr: 'inference' | 'fine-tuning', gasPrice?: number): Promise<void>;
    protected a0giToNeuron(value: number): bigint;
    protected neuronToA0gi(value: bigint): number;
}

declare class LedgerBroker {
    ledger: LedgerProcessor;
    private signer;
    private ledgerCA;
    private inferenceCA;
    private fineTuningCA;
    private gasPrice;
    private maxGasPrice;
    private step;
    constructor(signer: JsonRpcSigner | Wallet, ledgerCA: string, inferenceCA: string, fineTuningCA: string, gasPrice?: number, maxGasPrice?: number, step?: number);
    initialize(): Promise<void>;
    /**
     * Adds a new ledger to the contract.
     *
     * @param {number} balance - The initial balance to be assigned to the new ledger. Units are in A0GI.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the ledger creation fails.
     *
     * @remarks
     * When creating an ledger, a key pair is also created to sign the request.
     */
    addLedger: (balance: number, gasPrice?: number) => Promise<void>;
    /**
     * Retrieves the ledger information for current wallet address.
     *
     * @returns A promise that resolves to the ledger information.
     *
     * @throws Will throw an error if the ledger retrieval process fails.
     */
    getLedger: () => Promise<LedgerStructOutput>;
    /**
     * Deposits a specified amount of funds into Ledger corresponding to the current wallet address.
     *
     * @param {string} amount - The amount of funds to be deposited. Units are in A0GI.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deposit fails.
     */
    depositFund: (amount: number, gasPrice?: number) => Promise<void>;
    /**
     * Refunds a specified amount using the ledger.
     *
     * @param amount - The amount to be refunded.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves when the refund is processed.
     * @throws Will throw an error if the refund process fails.
     *
     * @remarks The amount should be a positive number.
     */
    refund: (amount: number, gasPrice?: number) => Promise<void>;
    /**
     * Transfers a specified amount of funds to a provider for a given service type.
     *
     * @param provider - The address of the provider to whom the funds are being transferred.
     * @param serviceTypeStr - The type of service for which the funds are being transferred.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param amount - The amount of funds to be transferred. Units are in neuron.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund transfer operation.
     * @throws Will throw an error if the fund transfer operation fails.
     */
    transferFund: (provider: AddressLike, serviceTypeStr: "inference" | "fine-tuning", amount: bigint, gasPrice?: number) => Promise<void>;
    /**
     * Retrieves funds from the all sub-accounts (for inference and fine-tuning) of the current wallet address.
     *
     * @param serviceTypeStr - The type of service for which the funds are being retrieved.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund retrieval operation.
     * @throws Will throw an error if the fund retrieval operation fails.
     */
    retrieveFund: (serviceTypeStr: "inference" | "fine-tuning", gasPrice?: number) => Promise<void>;
    /**
     * Deletes the ledger corresponding to the current wallet address.
     *
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                           the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deletion fails.
     */
    deleteLedger: (gasPrice?: number) => Promise<void>;
}
/**
 * createLedgerBroker is used to initialize LedgerBroker
 *
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - Ledger contract address, use default address if not provided.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
declare function createLedgerBroker(signer: JsonRpcSigner | Wallet, ledgerCA: string, inferenceCA: string, fineTuningCA: string, gasPrice?: number, maxGasPrice?: number, step?: number): Promise<LedgerBroker>;

declare class Automata {
    protected provider: any;
    protected contract: ethers.Contract;
    constructor();
    verifyQuote(rawQuote: string): Promise<boolean | undefined>;
}

/**
 * ServingRequestHeaders contains headers related to request.
 * Only Address and VLLM-Proxy are required now.
 */
interface ServingRequestHeaders {
    /**
     * @deprecated This field is no longer used but kept for backwards compatibility
     */
    'X-Phala-Signature-Type'?: 'StandaloneApi';
    /**
     * User's address
     */
    Address: string;
    /**
     * @deprecated Total fee for the request - no longer used
     */
    Fee?: string;
    /**
     * @deprecated Fee required for the input - no longer used
     */
    'Input-Fee'?: string;
    /**
     * @deprecated Pedersen hash - no longer used
     */
    'Request-Hash'?: string;
    /**
     * @deprecated Nonce - no longer used
     */
    Nonce?: string;
    /**
     * @deprecated User's signature - no longer used
     */
    Signature?: string;
    /**
     * Broker service use a proxy for chat signature
     */
    'VLLM-Proxy': string;
}
/**
 * RequestProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
declare class RequestProcessor extends ZGServingUserBrokerBase {
    protected automata: Automata;
    constructor(contract: InferenceServingContract, metadata: Metadata, cache: Cache, ledger: LedgerBroker);
    getServiceMetadata(providerAddress: string): Promise<{
        endpoint: string;
        model: string;
    }>;
    getRequestHeaders(providerAddress: string, content: string, vllmProxy?: boolean): Promise<ServingRequestHeaders>;
    acknowledgeProviderSigner(providerAddress: string, gasPrice?: number): Promise<void>;
}

interface QuoteResponse {
    quote: string;
    provider_signer: string;
    key: [bigint, bigint];
    nvidia_payload: string;
}
declare abstract class ZGServingUserBrokerBase {
    protected contract: InferenceServingContract;
    protected metadata: Metadata;
    protected cache: Cache;
    private checkAccountThreshold;
    private topUpTriggerThreshold;
    private topUpTargetThreshold;
    protected ledger: LedgerBroker;
    constructor(contract: InferenceServingContract, ledger: LedgerBroker, metadata: Metadata, cache: Cache);
    protected getService(providerAddress: string, useCache?: boolean): Promise<ServiceStructOutput$1>;
    getQuote(providerAddress: string): Promise<QuoteResponse>;
    userAcknowledged(providerAddress: string): Promise<boolean>;
    fetchText(endpoint: string, options: RequestInit): Promise<string>;
    protected getExtractor(providerAddress: string, useCache?: boolean): Promise<Extractor>;
    protected createExtractor(svc: ServiceStructOutput$1): Extractor;
    protected a0giToNeuron(value: number): bigint;
    protected neuronToA0gi(value: bigint): number;
    getHeader(providerAddress: string, vllmProxy: boolean): Promise<ServingRequestHeaders>;
    calculateInputFees(extractor: Extractor, content: string): Promise<bigint>;
    updateCachedFee(provider: string, fee: bigint): Promise<void>;
    clearCacheFee(provider: string, fee: bigint): Promise<void>;
    /**
     * Transfer fund from ledger if fund in the inference account is less than a topUpTriggerThreshold * (inputPrice + outputPrice)
     */
    topUpAccountIfNeeded(provider: string, content: string, gasPrice?: number): Promise<void>;
    private handleFirstRound;
    /**
     * Check the cache fund for this provider, return true if the fund is above checkAccountThreshold * (inputPrice + outputPrice)
     * @param svc
     */
    shouldCheckAccount(svc: ServiceStructOutput$1): Promise<boolean>;
}

/**
 * AccountProcessor contains methods for creating, depositing funds, and retrieving 0G Serving Accounts.
 */
declare class AccountProcessor extends ZGServingUserBrokerBase {
    getAccount(provider: AddressLike): Promise<AccountStructOutput>;
    getAccountWithDetail(provider: AddressLike): Promise<[
        AccountStructOutput,
        {
            amount: bigint;
            remainTime: bigint;
        }[]
    ]>;
    listAccount(): Promise<AccountStructOutput[]>;
}

/**
 * ResponseProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
declare class ResponseProcessor extends ZGServingUserBrokerBase {
    private verifier;
    constructor(contract: InferenceServingContract, ledger: LedgerBroker, metadata: Metadata, cache: Cache);
    processResponse(providerAddress: string, content: string, chatID?: string, vllmProxy?: boolean): Promise<boolean | null>;
    private calculateOutputFees;
}

interface ResponseSignature {
    text: string;
    signature: string;
}
interface SignerRA {
    signing_address: string;
    nvidia_payload: string;
    intel_quote: string;
}
interface SingerRAVerificationResult {
    /**
     * Whether the signer RA is valid
     * null means the RA has not been verified
     */
    valid: boolean | null;
    /**
     * The signing address of the signer
     */
    signingAddress: string;
}
/**
 * The Verifier class contains methods for verifying service reliability.
 */
declare class Verifier extends ZGServingUserBrokerBase {
    protected automata: Automata;
    constructor(contract: InferenceServingContract, ledger: LedgerBroker, metadata: Metadata, cache: Cache);
    verifyService(providerAddress: string): Promise<boolean | null>;
    /**
     * getSigningAddress verifies whether the signing address
     * of the signer corresponds to a valid RA.
     *
     * It also stores the signing address of the RA in
     * localStorage and returns it.
     *
     * @param providerAddress - provider address.
     * @param verifyRA - whether to verify the RA， default is false.
     * @returns The first return value indicates whether the RA is valid,
     * and the second return value indicates the signing address of the RA.
     */
    getSigningAddress(providerAddress: string, verifyRA?: boolean, vllmProxy?: boolean): Promise<SingerRAVerificationResult>;
    getSignerRaDownloadLink(providerAddress: string): Promise<string>;
    getChatSignatureDownloadLink(providerAddress: string, chatID: string): Promise<string>;
    static verifyRA(providerBrokerURL: string, nvidia_payload: any): Promise<boolean>;
    static fetSignerRA(providerBrokerURL: string, model: string): Promise<SignerRA>;
    static fetSignatureByChatID(providerBrokerURL: string, chatID: string, model: string, vllmProxy: boolean): Promise<ResponseSignature>;
    static verifySignature(message: string, signature: string, expectedAddress: string): boolean;
}

declare class ModelProcessor extends ZGServingUserBrokerBase {
    listService(): Promise<ServiceStructOutput$1[]>;
}

declare class InferenceBroker {
    requestProcessor: RequestProcessor;
    responseProcessor: ResponseProcessor;
    verifier: Verifier;
    accountProcessor: AccountProcessor;
    modelProcessor: ModelProcessor;
    private signer;
    private contractAddress;
    private ledger;
    constructor(signer: JsonRpcSigner | Wallet, contractAddress: string, ledger: LedgerBroker);
    initialize(): Promise<void>;
    /**
     * Retrieves a list of services from the contract.
     *
     * @returns {Promise<ServiceStructOutput[]>} A promise that resolves to an array of ServiceStructOutput objects.
     * @throws An error if the service list cannot be retrieved.
     */
    listService: () => Promise<ServiceStructOutput$1[]>;
    /**
     * Retrieves the account information for a given provider address.
     *
     * @param {string} providerAddress - The address of the provider identifying the account.
     *
     * @returns A promise that resolves to the account information.
     *
     * @throws Will throw an error if the account retrieval process fails.
     */
    getAccount: (providerAddress: string) => Promise<AccountStructOutput>;
    getAccountWithDetail: (providerAddress: string) => Promise<[AccountStructOutput, {
        amount: bigint;
        remainTime: bigint;
    }[]]>;
    /**
     * checks if the user has acknowledged the provider signer.
     *
     * @param {string} providerAddress - The address of the provider.
     * @returns {Promise<boolean>} A promise that resolves to a boolean indicating whether the user
     * has acknowledged the provider signer.
     * @throws Will throw an error if the acknowledgment check fails.
     */
    userAcknowledged: (providerAddress: string) => Promise<boolean>;
    /**
     * Acknowledge the given provider address.
     *
     * @param {string} providerAddress - The address of the provider identifying the account.
     *
     *
     * @throws Will throw an error if failed to acknowledge.
     */
    acknowledgeProviderSigner: (providerAddress: string, gasPrice?: number) => Promise<void>;
    /**
     * Generates request metadata for the provider service.
     * Includes:
     * 1. Request endpoint for the provider service
     * 2. Model information for the provider service
     *
     * @param {string} providerAddress - The address of the provider.
     *
     * @returns { endpoint, model } - Object containing endpoint and model.
     *
     * @throws An error if errors occur during the processing of the request.
     */
    getServiceMetadata: (providerAddress: string) => Promise<{
        endpoint: string;
        model: string;
    }>;
    /**
     * getRequestHeaders generates billing-related headers for the request
     * when the user uses the provider service.
     *
     * In the 0G Serving system, a request with valid billing headers
     * is considered a settlement proof and will be used by the provider
     * for contract settlement.
     *
     * @param {string} providerAddress - The address of the provider.
     * @param {string} content - The content being billed. For example, in a chatbot service, it is the text input by the user.
     * @param {boolean} vllmProxy - Chat signature proxy, default is false
     *
     * @returns headers. Records information such as the request fee and user signature.
     *
     * @example
     *
     * const { endpoint, model } = await broker.getServiceMetadata(
     *   providerAddress,
     *   serviceName,
     * );
     *
     * const headers = await broker.getServiceMetadata(
     *   providerAddress,
     *   serviceName,
     *   content,
     * );
     *
     * const openai = new OpenAI({
     *   baseURL: endpoint,
     *   apiKey: "",
     * });
     *
     * const completion = await openai.chat.completions.create(
     *   {
     *     messages: [{ role: "system", content }],
     *     model,
     *   },
     *   headers: {
     *     ...headers,
     *   },
     * );
     *
     * @throws An error if errors occur during the processing of the request.
     */
    getRequestHeaders: (providerAddress: string, content: string, vllmProxy?: boolean) => Promise<ServingRequestHeaders>;
    /**
     * processResponse is used after the user successfully obtains a response from the provider service.
     *
     * It will settle the fee for the response content. Additionally, if the service is verifiable,
     * input the chat ID from the response and processResponse will determine the validity of the
     * returned content by checking the provider service's response and corresponding signature associated
     * with the chat ID.
     *
     * @param {string} providerAddress - The address of the provider.
     * @param {string} content - The main content returned by the service. For example, in the case of a chatbot service,
     * it would be the response text.
     * @param {string} chatID - Only for verifiable services. You can provide the chat ID obtained from the response to
     * automatically download the response signature. The function will verify the reliability of the response
     * using the service's signing address.
     * @param {boolean} vllmProxy - Chat signature proxy, default is true
     *
     * @returns A boolean value. True indicates the returned content is valid, otherwise it is invalid.
     *
     * @throws An error if any issues occur during the processing of the response.
     */
    processResponse: (providerAddress: string, content: string, chatID?: string, vllmProxy?: boolean) => Promise<boolean | null>;
    /**
     * verifyService is used to verify the reliability of the service.
     *
     * @param {string} providerAddress - The address of the provider.
     *
     * @returns A <boolean | null> value. True indicates the service is reliable, otherwise it is unreliable.
     *
     * @throws An error if errors occur during the verification process.
     */
    verifyService: (providerAddress: string) => Promise<boolean | null>;
    /**
     * getSignerRaDownloadLink returns the download link for the Signer RA.
     *
     * It can be provided to users who wish to manually verify the Signer RA.
     *
     * @param {string} providerAddress - provider address.
     *
     * @returns Download link.
     */
    getSignerRaDownloadLink: (providerAddress: string) => Promise<string>;
    /**
     * getChatSignatureDownloadLink returns the download link for the signature of a single chat.
     *
     * It can be provided to users who wish to manually verify the content of a single chat.
     *
     * @param {string} providerAddress - provider address.
     * @param {string} chatID - ID of the chat.
     *
     * @remarks To verify the chat signature, use the following code:
     *
     * ```typescript
     * const messageHash = ethers.hashMessage(messageToBeVerified)
     * const recoveredAddress = ethers.recoverAddress(messageHash, signature)
     * const isValid = recoveredAddress.toLowerCase() === signingAddress.toLowerCase()
     * ```
     *
     * @returns Download link.
     */
    getChatSignatureDownloadLink: (providerAddress: string, chatID: string) => Promise<string>;
}
/**
 * createInferenceBroker is used to initialize ZGServingUserBroker
 *
 * @param signer - Signer from ethers.js.
 * @param contractAddress - 0G Serving contract address, use default address if not provided.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
declare function createInferenceBroker(signer: JsonRpcSigner | Wallet, contractAddress: string, ledger: LedgerBroker): Promise<InferenceBroker>;

interface Task {
    readonly id?: string;
    readonly createdAt?: string;
    readonly updatedAt?: string;
    userAddress: string;
    preTrainedModelHash: string;
    datasetHash: string;
    trainingParams: string;
    fee: string;
    nonce: string;
    signature: string;
    readonly progress?: string;
    readonly deliverIndex?: string;
    wait?: boolean;
}

interface FineTuningAccountDetail {
    account: AccountDetailsStructOutput;
    refunds: {
        amount: bigint;
        remainTime: bigint;
    }[];
}

declare class FineTuningBroker {
    private signer;
    private fineTuningCA;
    private ledger;
    private modelProcessor;
    private serviceProcessor;
    private serviceProvider;
    private _gasPrice?;
    private _maxGasPrice?;
    private _step?;
    constructor(signer: Wallet, fineTuningCA: string, ledger: LedgerBroker, gasPrice?: number, maxGasPrice?: number, step?: number);
    initialize(): Promise<void>;
    listService: () => Promise<ServiceStructOutput[]>;
    getLockedTime: () => Promise<bigint>;
    getAccount: (providerAddress: string) => Promise<AccountDetailsStructOutput>;
    getAccountWithDetail: (providerAddress: string) => Promise<FineTuningAccountDetail>;
    acknowledgeProviderSigner: (providerAddress: string, gasPrice?: number) => Promise<void>;
    listModel: () => Promise<[string, {
        [key: string]: string;
    }][][]>;
    modelUsage: (providerAddress: string, preTrainedModelName: string, output: string) => Promise<void>;
    uploadDataset: (dataPath: string, gasPrice?: number, maxGasPrice?: number) => Promise<void>;
    downloadDataset: (dataPath: string, dataRoot: string) => Promise<void>;
    calculateToken: (datasetPath: string, preTrainedModelName: string, usePython: boolean, providerAddress?: string) => Promise<void>;
    createTask: (providerAddress: string, preTrainedModelName: string, dataSize: number, datasetHash: string, trainingPath: string, gasPrice?: number) => Promise<string>;
    cancelTask: (providerAddress: string, taskID: string) => Promise<string>;
    listTask: (providerAddress: string) => Promise<Task[]>;
    getTask: (providerAddress: string, taskID?: string) => Promise<Task>;
    getLog: (providerAddress: string, taskID?: string) => Promise<string>;
    acknowledgeModel: (providerAddress: string, taskId: string, dataPath: string, gasPrice?: number) => Promise<void>;
    decryptModel: (providerAddress: string, taskId: string, encryptedModelPath: string, decryptedModelPath: string) => Promise<void>;
}
/**
 * createFineTuningBroker is used to initialize ZGServingUserBroker
 *
 * @param signer - Signer from ethers.js.
 * @param contractAddress - 0G Serving contract address, use default address if not provided.
 * @param ledger - Ledger broker instance.
 * @param gasPrice - Gas price for transactions. If not provided, the gas price will be calculated automatically.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
declare function createFineTuningBroker(signer: Wallet, contractAddress: string, ledger: LedgerBroker, gasPrice?: number, maxGasPrice?: number, step?: number): Promise<FineTuningBroker>;

declare class ZGComputeNetworkBroker {
    ledger: LedgerBroker;
    inference: InferenceBroker;
    fineTuning?: FineTuningBroker;
    constructor(ledger: LedgerBroker, inferenceBroker: InferenceBroker, fineTuningBroker?: FineTuningBroker);
}
/**
 * createZGComputeNetworkBroker is used to initialize ZGComputeNetworkBroker
 *
 * @param signer - Signer from ethers.js.
 * @param ledgerCA - 0G Compute Network Ledger Contact address, use default address if not provided.
 * @param inferenceCA - 0G Compute Network Inference Serving contract address, use default address if not provided.
 * @param fineTuningCA - 0G Compute Network Fine Tuning Serving contract address, use default address if not provided.
 * @param gasPrice - Gas price for transactions. If not provided, the gas price will be calculated automatically.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
declare function createZGComputeNetworkBroker(signer: JsonRpcSigner | Wallet, ledgerCA?: string, inferenceCA?: string, fineTuningCA?: string, gasPrice?: number, maxGasPrice?: number, step?: number): Promise<ZGComputeNetworkBroker>;

/**
 * Environment detection utility
 * Helps distinguish between Node.js and browser environments
 */
declare const isBrowser: () => boolean;
declare const isNode: () => boolean;
declare const isWebWorker: () => boolean;
declare const hasWebCrypto: () => boolean;

/**
 * Crypto adapter that provides unified encryption/decryption interface
 * for both Node.js and browser environments
 */
interface CryptoAdapter {
    aesGCMEncrypt(key: Buffer, data: Buffer, iv: Buffer): Promise<{
        encrypted: Buffer;
        authTag: Buffer;
    }>;
    aesGCMDecrypt(key: Buffer, encryptedData: Buffer, iv: Buffer, authTag: Buffer): Promise<Buffer>;
    randomBytes(length: number): Buffer;
}
declare function getCryptoAdapter(): CryptoAdapter;

export { type CryptoAdapter, FineTuningBroker, type ServiceStructOutput as FineTuningServiceStructOutput, AccountProcessor as InferenceAccountProcessor, type AccountStructOutput as InferenceAccountStructOutput, InferenceBroker, ModelProcessor as InferenceModelProcessor, RequestProcessor as InferenceRequestProcessor, ResponseProcessor as InferenceResponseProcessor, type ServiceStructOutput$1 as InferenceServiceStructOutput, type ServingRequestHeaders as InferenceServingRequestHeaders, type SingerRAVerificationResult as InferenceSingerRAVerificationResult, Verifier as InferenceVerifier, LedgerBroker, ZGComputeNetworkBroker, createFineTuningBroker, createInferenceBroker, createLedgerBroker, createZGComputeNetworkBroker, getCryptoAdapter, hasWebCrypto, isBrowser, isNode, isWebWorker };

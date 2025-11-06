import type { ZGComputeNetworkBroker } from '../sdk';
import type { Table } from 'cli-table3';
export declare function initBroker(options: any): Promise<ZGComputeNetworkBroker>;
export declare function withBroker(options: any, action: (broker: ZGComputeNetworkBroker) => Promise<void>): Promise<void>;
export declare function withFineTuningBroker(options: any, action: (broker: ZGComputeNetworkBroker) => Promise<void>): Promise<void>;
export declare const neuronToA0gi: (value: bigint) => number;
export declare const a0giToNeuron: (value: number) => bigint;
export declare const splitIntoChunks: (str: string, size: number) => string;
export declare const printTableWithTitle: (title: string, table: Table) => void;
//# sourceMappingURL=util.d.ts.map
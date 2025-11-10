/**
 * Provider service transformation utilities
 */
import type { Provider } from '../../../shared/types/broker';
import { neuronToA0gi } from '../../../shared/utils/currency';

/**
 * Service object structure from broker
 * Note: Runtime values might be string/number even though types say bigint
 */
export interface BrokerServiceObject {
  provider?: string;
  model?: string;
  name?: string;
  verifiability?: string;
  url?: string;
  inputPrice?: bigint | string | number;
  outputPrice?: bigint | string | number;
  teeSignerAcknowledged?: boolean;
}

/**
 * Transform a broker service to a Provider object (Chat page version)
 * @param service - Raw service data from broker
 * @returns Transformed Provider object
 */
export function transformBrokerServiceToProvider(service: unknown): Provider {
  // Type assertion for service properties (exactly as in original ChatPage)
  const serviceObj = service as {
    provider?: string;
    model?: string;
    name?: string;
    verifiability?: string;
    url?: string;
    inputPrice?: bigint;
    outputPrice?: bigint;
    teeSignerAcknowledged?: boolean;
  };
  
  // Type guard to ensure service has the required properties
  const providerAddress = serviceObj.provider || "";
  const modelName = serviceObj.model || "Unknown Model";
  // const modelName = rawModel.includes('/') ? rawModel.split('/').slice(1).join('/') : rawModel;
  const rawProviderName = serviceObj.name || serviceObj.model || "Unknown Provider";
  const providerName = rawProviderName.includes('/') ? rawProviderName.split('/').slice(1).join('/') : rawProviderName;
  const verifiability = serviceObj.verifiability || "TEE";
  const serviceUrl = serviceObj.url || "";

  // Convert prices from neuron to A0GI per million tokens
  // EXACTLY as in original ChatPage - with BigInt() wrapper
  const inputPrice = serviceObj.inputPrice
    ? neuronToA0gi(serviceObj.inputPrice * BigInt(1000000))
    : undefined;
  const outputPrice = serviceObj.outputPrice
    ? neuronToA0gi(serviceObj.outputPrice * BigInt(1000000))
    : undefined;

  return {
    address: providerAddress,
    model: modelName,
    name: providerName,
    verifiability: verifiability,
    url: serviceUrl,
    inputPrice,
    outputPrice,
    inputPriceNeuron: serviceObj.inputPrice ? BigInt(serviceObj.inputPrice) : undefined,
    outputPriceNeuron: serviceObj.outputPrice ? BigInt(serviceObj.outputPrice) : undefined,
    teeSignerAcknowledged: serviceObj.teeSignerAcknowledged ?? false,
  };
}

/**
 * Transform an array of broker services to Provider objects
 * @param services - Array of raw service data from broker
 * @returns Array of transformed Provider objects
 */
export function transformBrokerServicesToProviders(services: unknown[]): Provider[] {
  return services.map(transformBrokerServiceToProvider);
}
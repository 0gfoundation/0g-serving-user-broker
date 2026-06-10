/**
 * Provider service transformation utilities
 */
import type { Provider, ServiceType, TieredPricingInfo, CacheTokenBillingInfo } from '../../../shared/types/broker';
import { neuronToA0gi } from '../../../shared/utils/currency';
import { parseTieredPricing, parseCacheTokenBilling } from '@0gfoundation/0g-compute-ts-sdk';

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
  serviceType?: ServiceType; // Added for UI conditional rendering
  additionalInfo?: string;
  tieredPricing?: TieredPricingInfo; // Pre-parsed from additionalInfo (ServiceWithDetail)
  modelInfo?: {
    owned_by?: string;
  };
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
    serviceType?: ServiceType;
    additionalInfo?: string;
    tieredPricing?: TieredPricingInfo;
    cacheTokenBilling?: CacheTokenBillingInfo;
    modelInfo?: {
      owned_by?: string;
    };
  };
  
  // Type guard to ensure service has the required properties
  const providerAddress = serviceObj.provider || "";
  const modelName = serviceObj.model || "Unknown Model";
  // const modelName = rawModel.includes('/') ? rawModel.split('/').slice(1).join('/') : rawModel;
  const rawProviderName = serviceObj.name || serviceObj.model || "Unknown Provider";
  const providerName = rawProviderName.includes('/') ? rawProviderName.split('/').slice(1).join('/') : rawProviderName;
  const verifiability = serviceObj.verifiability || "TEE";
  const serviceUrl = serviceObj.url || "";

  // Convert prices from neuron to 0G
  // For image services (text-to-image, image-editing), prices are per image, not per million tokens
  // For speech-to-text, prices are per second of audio (duration billing), not per million tokens
  const isImageService = serviceObj.serviceType === 'text-to-image' ||
                         serviceObj.serviceType === 'image-editing' ||
                         serviceObj.serviceType?.includes('image');
  const isSpeechService = serviceObj.serviceType === 'speech-to-text';
  const priceMultiplier = isImageService || isSpeechService ? BigInt(1) : BigInt(1000000);
  const inputPrice = serviceObj.inputPrice
    ? neuronToA0gi(serviceObj.inputPrice * priceMultiplier)
    : undefined;
  const outputPrice = serviceObj.outputPrice
    ? neuronToA0gi(serviceObj.outputPrice * priceMultiplier)
    : undefined;

  // Parse tiered pricing: prefer pre-parsed (from ServiceWithDetail), fallback to additionalInfo via SDK
  let tieredPricing: TieredPricingInfo | undefined = serviceObj.tieredPricing;
  if (!tieredPricing && serviceObj.additionalInfo) {
    tieredPricing = parseTieredPricing(serviceObj.additionalInfo);
  }

  // Parse cache token billing: prefer pre-parsed, fallback to additionalInfo via SDK
  let cacheTokenBilling: CacheTokenBillingInfo | undefined = serviceObj.cacheTokenBilling;
  if (!cacheTokenBilling && serviceObj.additionalInfo) {
    cacheTokenBilling = parseCacheTokenBilling(serviceObj.additionalInfo);
  }

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
    serviceType: serviceObj.serviceType, // Pass through for UI conditional rendering
    ownedBy: serviceObj.modelInfo?.owned_by,
    tieredPricing,
    cacheTokenBilling,
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

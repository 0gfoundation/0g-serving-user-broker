/**
 * Official provider constants for the 0G Broker system
 */
import type { Provider } from '../../../shared/types/broker';

/**
 * Official providers based on the documentation
 * These are default providers that can be used when broker services are not available
 */
export const OFFICIAL_PROVIDERS: Provider[] = [
  {
    address: "0xf07240Efa67755B5311bc75784a061eDB47165Dd",
    model: "gpt-oss-120b",
    name: "GPT OSS 120B",
    verifiability: "TEE (TeeML)",
  },
  {
    address: "0x3feE5a4dd5FDb8a32dDA97Bed899830605dBD9D3",
    model: "deepseek-chat-v3-0324",
    name: "DeepSeek R1 V3 0324",
    verifiability: "TEE (TeeML)",
  },
  {
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    model: "qwen2.5-vl-72b-instruct",
    name: "QWEN2.5 VL 72B Instruct",
    verifiability: "TEE (TeeML)",
  },
];
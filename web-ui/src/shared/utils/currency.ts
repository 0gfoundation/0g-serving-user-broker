import { APP_CONSTANTS } from '../constants/app';

/**
 * Converts neuron units to 0G units
 * @param value - Value in neuron (wei equivalent for 0G)
 * @returns Value in 0G (ether equivalent for 0G)
 * @example
 * ```typescript
 * const a0gi = neuronToA0gi(BigInt('1000000000000000000')); // Returns 1
 * ```
 */
export const neuronToA0gi = (value: bigint): number => {
  const divisor = BigInt(10 ** APP_CONSTANTS.BLOCKCHAIN.NEURON_DECIMALS);
  const integerPart = value / divisor;
  const remainder = value % divisor;
  const decimalPart = Number(remainder) / Number(divisor);
  return Number(integerPart) + decimalPart;
};

/**
 * Converts 0G units to neuron units
 * @param value - Value in 0G (ether equivalent for 0G)
 * @returns Value in neuron (wei equivalent for 0G)
 * @example
 * ```typescript
 * const neuron = a0giToNeuron(1); // Returns BigInt('1000000000000000000')
 * ```
 */
export const a0giToNeuron = (value: number): bigint => {
  const valueStr = value.toFixed(APP_CONSTANTS.BLOCKCHAIN.NEURON_DECIMALS);
  const parts = valueStr.split('.');
  
  // Handle integer part
  const integerPart = parts[0];
  let integerPartAsBigInt = BigInt(integerPart) * BigInt(10 ** APP_CONSTANTS.BLOCKCHAIN.NEURON_DECIMALS);
  
  // Handle fractional part if it exists
  if (parts.length > 1) {
    let fractionalPart = parts[1];
    while (fractionalPart.length < APP_CONSTANTS.BLOCKCHAIN.NEURON_DECIMALS) {
      fractionalPart += '0';
    }
    if (fractionalPart.length > APP_CONSTANTS.BLOCKCHAIN.NEURON_DECIMALS) {
      fractionalPart = fractionalPart.slice(0, APP_CONSTANTS.BLOCKCHAIN.NEURON_DECIMALS);
    }
    
    const fractionalPartAsBigInt = BigInt(fractionalPart);
    integerPartAsBigInt += fractionalPartAsBigInt;
  }
  
  return integerPartAsBigInt;
};

/**
 * Formats a balance for display with appropriate decimal places
 * @param balance - Balance in 0G
 * @param maxDecimals - Maximum decimal places to show (default: 4)
 * @returns Formatted balance string
 */
export const formatBalance = (balance: number, maxDecimals: number = 4): string => {
  if (balance === 0) return '0';
  
  const formatted = balance.toFixed(maxDecimals);
  // Remove trailing zeros
  return formatted.replace(/\.?0+$/, '');
};
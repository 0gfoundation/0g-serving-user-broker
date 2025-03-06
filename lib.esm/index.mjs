import { ethers, ContractFactory, Interface, Contract, Wallet } from 'ethers';
import CryptoJS from 'crypto-js';
import require$$1 from 'node:crypto';
import * as crypto$2 from 'crypto';
import { promises } from 'fs';
import { buildBabyjub, buildEddsa } from 'circomlibjs';
import { spawn } from 'child_process';
import path from 'path';
import * as fs from 'fs/promises';

class Extractor {
}

class ChatBot extends Extractor {
    svcInfo;
    constructor(svcInfo) {
        super();
        this.svcInfo = svcInfo;
    }
    getSvcInfo() {
        return Promise.resolve(this.svcInfo);
    }
    async getInputCount(content) {
        if (!content) {
            return 0;
        }
        return content.split(/\s+/).length;
    }
    async getOutputCount(content) {
        if (!content) {
            return 0;
        }
        return content.split(/\s+/).length;
    }
}

/**
 * MESSAGE_FOR_ENCRYPTION_KEY is a fixed message used to derive the encryption key.
 *
 * Background:
 * To ensure a consistent and unique encryption key can be generated from a user's Ethereum wallet,
 * we utilize a fixed message combined with a signing mechanism.
 *
 * Purpose:
 * - This string is provided to the Ethereum signing function to generate a digital signature based on the user's private key.
 * - The produced signature is then hashed (using SHA-256) to create a consistent 256-bit encryption key from the same wallet.
 * - This process offers a way to protect data without storing additional keys.
 *
 * Note:
 * - The uniqueness and stability of this message are crucial; do not change it unless you fully understand the impact
 *   on the key derivation and encryption process.
 * - Because the signature is derived from the wallet's private key, it ensures that different wallets cannot produce the same key.
 */
const MESSAGE_FOR_ENCRYPTION_KEY = 'MESSAGE_FOR_ENCRYPTION_KEY';

var dist = {};

var utils$3 = {};

var _assert$1 = {};

var hasRequired_assert$1;

function require_assert$1 () {
	if (hasRequired_assert$1) return _assert$1;
	hasRequired_assert$1 = 1;
	/**
	 * Internal assertion helpers.
	 * @module
	 */
	Object.defineProperty(_assert$1, "__esModule", { value: true });
	_assert$1.abool = abool;
	_assert$1.abytes = abytes;
	_assert$1.aexists = aexists;
	_assert$1.ahash = ahash;
	_assert$1.anumber = anumber;
	_assert$1.aoutput = aoutput;
	_assert$1.isBytes = isBytes;
	function anumber(n) {
	    if (!Number.isSafeInteger(n) || n < 0)
	        throw new Error('positive integer expected, got ' + n);
	}
	// copied from utils
	function isBytes(a) {
	    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
	}
	function abytes(b, ...lengths) {
	    if (!isBytes(b))
	        throw new Error('Uint8Array expected');
	    if (lengths.length > 0 && !lengths.includes(b.length))
	        throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
	}
	function ahash(h) {
	    if (typeof h !== 'function' || typeof h.create !== 'function')
	        throw new Error('Hash should be wrapped by utils.wrapConstructor');
	    anumber(h.outputLen);
	    anumber(h.blockLen);
	}
	function aexists(instance, checkFinished = true) {
	    if (instance.destroyed)
	        throw new Error('Hash instance has been destroyed');
	    if (checkFinished && instance.finished)
	        throw new Error('Hash#digest() has already been called');
	}
	function aoutput(out, instance) {
	    abytes(out);
	    const min = instance.outputLen;
	    if (out.length < min) {
	        throw new Error('digestInto() expects output buffer of length at least ' + min);
	    }
	}
	function abool(b) {
	    if (typeof b !== 'boolean')
	        throw new Error(`boolean expected, not ${b}`);
	}
	
	return _assert$1;
}

var hasRequiredUtils$3;

function requireUtils$3 () {
	if (hasRequiredUtils$3) return utils$3;
	hasRequiredUtils$3 = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.wrapCipher = exports.Hash = exports.nextTick = exports.isLE = exports.createView = exports.u32 = exports.u8 = void 0;
		exports.bytesToHex = bytesToHex;
		exports.hexToBytes = hexToBytes;
		exports.hexToNumber = hexToNumber;
		exports.bytesToNumberBE = bytesToNumberBE;
		exports.numberToBytesBE = numberToBytesBE;
		exports.utf8ToBytes = utf8ToBytes;
		exports.bytesToUtf8 = bytesToUtf8;
		exports.toBytes = toBytes;
		exports.overlapBytes = overlapBytes;
		exports.complexOverlapBytes = complexOverlapBytes;
		exports.concatBytes = concatBytes;
		exports.checkOpts = checkOpts;
		exports.equalBytes = equalBytes;
		exports.getOutput = getOutput;
		exports.setBigUint64 = setBigUint64;
		exports.u64Lengths = u64Lengths;
		exports.isAligned32 = isAligned32;
		exports.copyBytes = copyBytes;
		exports.clean = clean;
		/**
		 * Utilities for hex, bytes, CSPRNG.
		 * @module
		 */
		/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */
		const _assert_js_1 = /*@__PURE__*/ require_assert$1();
		// Cast array to different type
		const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
		exports.u8 = u8;
		const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
		exports.u32 = u32;
		// Cast array to view
		const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
		exports.createView = createView;
		// big-endian hardware is rare. Just in case someone still decides to run ciphers:
		// early-throw an error because we don't support BE yet.
		exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
		if (!exports.isLE)
		    throw new Error('Non little-endian hardware is not supported');
		// Array where index 0xf0 (240) is mapped to string 'f0'
		const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
		/**
		 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
		 */
		function bytesToHex(bytes) {
		    (0, _assert_js_1.abytes)(bytes);
		    // pre-caching improves the speed 6x
		    let hex = '';
		    for (let i = 0; i < bytes.length; i++) {
		        hex += hexes[bytes[i]];
		    }
		    return hex;
		}
		// We use optimized technique to convert hex string to byte array
		const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
		function asciiToBase16(ch) {
		    if (ch >= asciis._0 && ch <= asciis._9)
		        return ch - asciis._0; // '2' => 50-48
		    if (ch >= asciis.A && ch <= asciis.F)
		        return ch - (asciis.A - 10); // 'B' => 66-(65-10)
		    if (ch >= asciis.a && ch <= asciis.f)
		        return ch - (asciis.a - 10); // 'b' => 98-(97-10)
		    return;
		}
		/**
		 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
		 */
		function hexToBytes(hex) {
		    if (typeof hex !== 'string')
		        throw new Error('hex string expected, got ' + typeof hex);
		    const hl = hex.length;
		    const al = hl / 2;
		    if (hl % 2)
		        throw new Error('hex string expected, got unpadded hex of length ' + hl);
		    const array = new Uint8Array(al);
		    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
		        const n1 = asciiToBase16(hex.charCodeAt(hi));
		        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
		        if (n1 === undefined || n2 === undefined) {
		            const char = hex[hi] + hex[hi + 1];
		            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
		        }
		        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
		    }
		    return array;
		}
		function hexToNumber(hex) {
		    if (typeof hex !== 'string')
		        throw new Error('hex string expected, got ' + typeof hex);
		    return BigInt(hex === '' ? '0' : '0x' + hex); // Big Endian
		}
		// BE: Big Endian, LE: Little Endian
		function bytesToNumberBE(bytes) {
		    return hexToNumber(bytesToHex(bytes));
		}
		function numberToBytesBE(n, len) {
		    return hexToBytes(n.toString(16).padStart(len * 2, '0'));
		}
		// There is no setImmediate in browser and setTimeout is slow.
		// call of async fn will return Promise, which will be fullfiled only on
		// next scheduler queue processing step and this is exactly what we need.
		const nextTick = async () => { };
		exports.nextTick = nextTick;
		/**
		 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
		 */
		function utf8ToBytes(str) {
		    if (typeof str !== 'string')
		        throw new Error('string expected');
		    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
		}
		/**
		 * @example bytesToUtf8(new Uint8Array([97, 98, 99])) // 'abc'
		 */
		function bytesToUtf8(bytes) {
		    return new TextDecoder().decode(bytes);
		}
		/**
		 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
		 * Warning: when Uint8Array is passed, it would NOT get copied.
		 * Keep in mind for future mutable operations.
		 */
		function toBytes(data) {
		    if (typeof data === 'string')
		        data = utf8ToBytes(data);
		    else if ((0, _assert_js_1.isBytes)(data))
		        data = copyBytes(data);
		    else
		        throw new Error('Uint8Array expected, got ' + typeof data);
		    return data;
		}
		/**
		 * Checks if two U8A use same underlying buffer and overlaps (will corrupt and break if input and output same)
		 */
		function overlapBytes(a, b) {
		    return (a.buffer === b.buffer && // probably will fail with some obscure proxies, but this is best we can do
		        a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
		        b.byteOffset < a.byteOffset + a.byteLength // b starts before a end
		    );
		}
		/**
		 * If input and output overlap and input starts before output, we will overwrite end of input before
		 * we start processing it, so this is not supported for most ciphers (except chacha/salse, which designed with this)
		 */
		function complexOverlapBytes(input, output) {
		    // This is very cursed. It works somehow, but I'm completely unsure,
		    // reasoning about overlapping aligned windows is very hard.
		    if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
		        throw new Error('complex overlap of input and output is not supported');
		}
		/**
		 * Copies several Uint8Arrays into one.
		 */
		function concatBytes(...arrays) {
		    let sum = 0;
		    for (let i = 0; i < arrays.length; i++) {
		        const a = arrays[i];
		        (0, _assert_js_1.abytes)(a);
		        sum += a.length;
		    }
		    const res = new Uint8Array(sum);
		    for (let i = 0, pad = 0; i < arrays.length; i++) {
		        const a = arrays[i];
		        res.set(a, pad);
		        pad += a.length;
		    }
		    return res;
		}
		function checkOpts(defaults, opts) {
		    if (opts == null || typeof opts !== 'object')
		        throw new Error('options must be defined');
		    const merged = Object.assign(defaults, opts);
		    return merged;
		}
		// Compares 2 u8a-s in kinda constant time
		function equalBytes(a, b) {
		    if (a.length !== b.length)
		        return false;
		    let diff = 0;
		    for (let i = 0; i < a.length; i++)
		        diff |= a[i] ^ b[i];
		    return diff === 0;
		}
		// For runtime check if class implements interface
		class Hash {
		}
		exports.Hash = Hash;
		/**
		 * @__NO_SIDE_EFFECTS__
		 */
		const wrapCipher = (params, constructor) => {
		    function wrappedCipher(key, ...args) {
		        // Validate key
		        (0, _assert_js_1.abytes)(key);
		        // Validate nonce if nonceLength is present
		        if (params.nonceLength !== undefined) {
		            const nonce = args[0];
		            if (!nonce)
		                throw new Error('nonce / iv required');
		            if (params.varSizeNonce)
		                (0, _assert_js_1.abytes)(nonce);
		            else
		                (0, _assert_js_1.abytes)(nonce, params.nonceLength);
		        }
		        // Validate AAD if tagLength present
		        const tagl = params.tagLength;
		        if (tagl && args[1] !== undefined) {
		            (0, _assert_js_1.abytes)(args[1]);
		        }
		        const cipher = constructor(key, ...args);
		        const checkOutput = (fnLength, output) => {
		            if (output !== undefined) {
		                if (fnLength !== 2)
		                    throw new Error('cipher output not supported');
		                (0, _assert_js_1.abytes)(output);
		            }
		        };
		        // Create wrapped cipher with validation and single-use encryption
		        let called = false;
		        const wrCipher = {
		            encrypt(data, output) {
		                if (called)
		                    throw new Error('cannot encrypt() twice with same key + nonce');
		                called = true;
		                (0, _assert_js_1.abytes)(data);
		                checkOutput(cipher.encrypt.length, output);
		                return cipher.encrypt(data, output);
		            },
		            decrypt(data, output) {
		                (0, _assert_js_1.abytes)(data);
		                if (tagl && data.length < tagl)
		                    throw new Error('invalid ciphertext length: smaller than tagLength=' + tagl);
		                checkOutput(cipher.decrypt.length, output);
		                return cipher.decrypt(data, output);
		            },
		        };
		        return wrCipher;
		    }
		    Object.assign(wrappedCipher, params);
		    return wrappedCipher;
		};
		exports.wrapCipher = wrapCipher;
		function getOutput(expectedLength, out, onlyAligned = true) {
		    if (out === undefined)
		        return new Uint8Array(expectedLength);
		    if (out.length !== expectedLength)
		        throw new Error('invalid output length, expected ' + expectedLength + ', got: ' + out.length);
		    if (onlyAligned && !isAligned32(out))
		        throw new Error('invalid output, must be aligned');
		    return out;
		}
		// Polyfill for Safari 14
		function setBigUint64(view, byteOffset, value, isLE) {
		    if (typeof view.setBigUint64 === 'function')
		        return view.setBigUint64(byteOffset, value, isLE);
		    const _32n = BigInt(32);
		    const _u32_max = BigInt(0xffffffff);
		    const wh = Number((value >> _32n) & _u32_max);
		    const wl = Number(value & _u32_max);
		    const h = isLE ? 4 : 0;
		    const l = isLE ? 0 : 4;
		    view.setUint32(byteOffset + h, wh, isLE);
		    view.setUint32(byteOffset + l, wl, isLE);
		}
		function u64Lengths(ciphertext, AAD) {
		    const num = new Uint8Array(16);
		    const view = (0, exports.createView)(num);
		    setBigUint64(view, 0, BigInt(AAD ? AAD.length : 0), true);
		    setBigUint64(view, 8, BigInt(ciphertext.length), true);
		    return num;
		}
		// Is byte array aligned to 4 byte offset (u32)?
		function isAligned32(bytes) {
		    return bytes.byteOffset % 4 === 0;
		}
		// copy bytes to new u8a (aligned). Because Buffer.slice is broken.
		function copyBytes(bytes) {
		    return Uint8Array.from(bytes);
		}
		function clean(...arrays) {
		    for (let i = 0; i < arrays.length; i++) {
		        arrays[i].fill(0);
		    }
		}
		
	} (utils$3));
	return utils$3;
}

var config = {};

var consts = {};

var hasRequiredConsts;

function requireConsts () {
	if (hasRequiredConsts) return consts;
	hasRequiredConsts = 1;
	Object.defineProperty(consts, "__esModule", { value: true });
	consts.AEAD_TAG_LENGTH = consts.XCHACHA20_NONCE_LENGTH = consts.CURVE25519_PUBLIC_KEY_SIZE = consts.ETH_PUBLIC_KEY_SIZE = consts.UNCOMPRESSED_PUBLIC_KEY_SIZE = consts.COMPRESSED_PUBLIC_KEY_SIZE = consts.SECRET_KEY_LENGTH = void 0;
	// elliptic
	consts.SECRET_KEY_LENGTH = 32;
	consts.COMPRESSED_PUBLIC_KEY_SIZE = 33;
	consts.UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
	consts.ETH_PUBLIC_KEY_SIZE = 64;
	consts.CURVE25519_PUBLIC_KEY_SIZE = 32;
	// symmetric
	consts.XCHACHA20_NONCE_LENGTH = 24;
	consts.AEAD_TAG_LENGTH = 16;
	return consts;
}

var hasRequiredConfig;

function requireConfig () {
	if (hasRequiredConfig) return config;
	hasRequiredConfig = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.ephemeralKeySize = exports.symmetricNonceLength = exports.symmetricAlgorithm = exports.isHkdfKeyCompressed = exports.isEphemeralKeyCompressed = exports.ellipticCurve = exports.ECIES_CONFIG = void 0;
		var consts_1 = requireConsts();
		var Config = /** @class */ (function () {
		    function Config() {
		        this.ellipticCurve = "secp256k1";
		        this.isEphemeralKeyCompressed = false; // secp256k1 only
		        this.isHkdfKeyCompressed = false; // secp256k1 only
		        this.symmetricAlgorithm = "aes-256-gcm";
		        this.symmetricNonceLength = 16; // aes-256-gcm only
		    }
		    return Config;
		}());
		exports.ECIES_CONFIG = new Config();
		var ellipticCurve = function () { return exports.ECIES_CONFIG.ellipticCurve; };
		exports.ellipticCurve = ellipticCurve;
		var isEphemeralKeyCompressed = function () { return exports.ECIES_CONFIG.isEphemeralKeyCompressed; };
		exports.isEphemeralKeyCompressed = isEphemeralKeyCompressed;
		var isHkdfKeyCompressed = function () { return exports.ECIES_CONFIG.isHkdfKeyCompressed; };
		exports.isHkdfKeyCompressed = isHkdfKeyCompressed;
		var symmetricAlgorithm = function () { return exports.ECIES_CONFIG.symmetricAlgorithm; };
		exports.symmetricAlgorithm = symmetricAlgorithm;
		var symmetricNonceLength = function () { return exports.ECIES_CONFIG.symmetricNonceLength; };
		exports.symmetricNonceLength = symmetricNonceLength;
		var ephemeralKeySize = function () {
		    var mapping = {
		        secp256k1: exports.ECIES_CONFIG.isEphemeralKeyCompressed
		            ? consts_1.COMPRESSED_PUBLIC_KEY_SIZE
		            : consts_1.UNCOMPRESSED_PUBLIC_KEY_SIZE,
		        x25519: consts_1.CURVE25519_PUBLIC_KEY_SIZE,
		        ed25519: consts_1.CURVE25519_PUBLIC_KEY_SIZE,
		    };
		    if (exports.ECIES_CONFIG.ellipticCurve in mapping) {
		        return mapping[exports.ECIES_CONFIG.ellipticCurve];
		    } /* v8 ignore next 2 */
		    else {
		        throw new Error("Not implemented");
		    }
		};
		exports.ephemeralKeySize = ephemeralKeySize; 
	} (config));
	return config;
}

var keys = {};

var PrivateKey = {};

var utils$2 = {};

var elliptic = {};

var webcrypto = {};

var crypto$1 = {};

var hasRequiredCrypto$1;

function requireCrypto$1 () {
	if (hasRequiredCrypto$1) return crypto$1;
	hasRequiredCrypto$1 = 1;
	Object.defineProperty(crypto$1, "__esModule", { value: true });
	crypto$1.crypto = void 0;
	crypto$1.crypto = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
	
	return crypto$1;
}

var hasRequiredWebcrypto;

function requireWebcrypto () {
	if (hasRequiredWebcrypto) return webcrypto;
	hasRequiredWebcrypto = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.gcm = exports.ctr = exports.cbc = exports.utils = void 0;
		exports.randomBytes = randomBytes;
		exports.getWebcryptoSubtle = getWebcryptoSubtle;
		exports.managedNonce = managedNonce;
		/**
		 * WebCrypto-based AES gcm/ctr/cbc, `managedNonce` and `randomBytes`.
		 * We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
		 * node.js versions earlier than v19 don't declare it in global scope.
		 * For node.js, package.js on#exports field mapping rewrites import
		 * from `crypto` to `cryptoNode`, which imports native module.
		 * Makes the utils un-importable in browsers without a bundler.
		 * Once node.js 18 is deprecated, we can just drop the import.
		 * @module
		 */
		// Use full path so that Node.js can rewrite it to `cryptoNode.js`.
		const crypto_1 = requireCrypto$1();
		const _assert_js_1 = /*@__PURE__*/ require_assert$1();
		const utils_js_1 = /*@__PURE__*/ requireUtils$3();
		/**
		 * Secure PRNG. Uses `crypto.getRandomValues`, which defers to OS.
		 */
		function randomBytes(bytesLength = 32) {
		    if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === 'function') {
		        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
		    }
		    // Legacy Node.js compatibility
		    if (crypto_1.crypto && typeof crypto_1.crypto.randomBytes === 'function') {
		        return crypto_1.crypto.randomBytes(bytesLength);
		    }
		    throw new Error('crypto.getRandomValues must be defined');
		}
		function getWebcryptoSubtle() {
		    if (crypto_1.crypto && typeof crypto_1.crypto.subtle === 'object' && crypto_1.crypto.subtle != null)
		        return crypto_1.crypto.subtle;
		    throw new Error('crypto.subtle must be defined');
		}
		/**
		 * Uses CSPRG for nonce, nonce injected in ciphertext.
		 * @example
		 * const gcm = managedNonce(aes.gcm);
		 * const ciphr = gcm(key).encrypt(data);
		 * const plain = gcm(key).decrypt(ciph);
		 */
		function managedNonce(fn) {
		    const { nonceLength } = fn;
		    (0, _assert_js_1.anumber)(nonceLength);
		    return ((key, ...args) => ({
		        encrypt(plaintext, ...argsEnc) {
		            const nonce = randomBytes(nonceLength);
		            const ciphertext = fn(key, nonce, ...args).encrypt(plaintext, ...argsEnc);
		            const out = (0, utils_js_1.concatBytes)(nonce, ciphertext);
		            ciphertext.fill(0);
		            return out;
		        },
		        decrypt(ciphertext, ...argsDec) {
		            const nonce = ciphertext.subarray(0, nonceLength);
		            const data = ciphertext.subarray(nonceLength);
		            return fn(key, nonce, ...args).decrypt(data, ...argsDec);
		        },
		    }));
		}
		// Overridable
		// @TODO
		exports.utils = {
		    async encrypt(key, keyParams, cryptParams, plaintext) {
		        const cr = getWebcryptoSubtle();
		        const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
		        const ciphertext = await cr.encrypt(cryptParams, iKey, plaintext);
		        return new Uint8Array(ciphertext);
		    },
		    async decrypt(key, keyParams, cryptParams, ciphertext) {
		        const cr = getWebcryptoSubtle();
		        const iKey = await cr.importKey('raw', key, keyParams, true, ['decrypt']);
		        const plaintext = await cr.decrypt(cryptParams, iKey, ciphertext);
		        return new Uint8Array(plaintext);
		    },
		};
		const mode = {
		    CBC: 'AES-CBC',
		    CTR: 'AES-CTR',
		    GCM: 'AES-GCM',
		};
		function getCryptParams(algo, nonce, AAD) {
		    if (algo === mode.CBC)
		        return { name: mode.CBC, iv: nonce };
		    if (algo === mode.CTR)
		        return { name: mode.CTR, counter: nonce, length: 64 };
		    if (algo === mode.GCM) {
		        if (AAD)
		            return { name: mode.GCM, iv: nonce, additionalData: AAD };
		        else
		            return { name: mode.GCM, iv: nonce };
		    }
		    throw new Error('unknown aes block mode');
		}
		function generate(algo) {
		    return (key, nonce, AAD) => {
		        (0, _assert_js_1.abytes)(key);
		        (0, _assert_js_1.abytes)(nonce);
		        const keyParams = { name: algo, length: key.length * 8 };
		        const cryptParams = getCryptParams(algo, nonce, AAD);
		        let consumed = false;
		        return {
		            // keyLength,
		            encrypt(plaintext) {
		                (0, _assert_js_1.abytes)(plaintext);
		                if (consumed)
		                    throw new Error('Cannot encrypt() twice with same key / nonce');
		                consumed = true;
		                return exports.utils.encrypt(key, keyParams, cryptParams, plaintext);
		            },
		            decrypt(ciphertext) {
		                (0, _assert_js_1.abytes)(ciphertext);
		                return exports.utils.decrypt(key, keyParams, cryptParams, ciphertext);
		            },
		        };
		    };
		}
		/** AES-CBC, native webcrypto version */
		exports.cbc = (() => generate(mode.CBC))();
		/** AES-CTR, native webcrypto version */
		exports.ctr = (() => generate(mode.CTR))();
		/** AES-GCM, native webcrypto version */
		exports.gcm = 
		/* @__PURE__ */ (() => generate(mode.GCM))();
		// // Type tests
		// import { siv, gcm, ctr, ecb, cbc } from '../aes.js';
		// import { xsalsa20poly1305 } from '../salsa.js';
		// import { chacha20poly1305, xchacha20poly1305 } from '../chacha.js';
		// const wsiv = managedNonce(siv);
		// const wgcm = managedNonce(gcm);
		// const wctr = managedNonce(ctr);
		// const wcbc = managedNonce(cbc);
		// const wsalsapoly = managedNonce(xsalsa20poly1305);
		// const wchacha = managedNonce(chacha20poly1305);
		// const wxchacha = managedNonce(xchacha20poly1305);
		// // should fail
		// const wcbc2 = managedNonce(managedNonce(cbc));
		// const wctr = managedNonce(ctr);
		
	} (webcrypto));
	return webcrypto;
}

var ed25519 = {};

var sha512 = {};

var _md = {};

var _assert = {};

var hasRequired_assert;

function require_assert () {
	if (hasRequired_assert) return _assert;
	hasRequired_assert = 1;
	/**
	 * Internal assertion helpers.
	 * @module
	 */
	Object.defineProperty(_assert, "__esModule", { value: true });
	_assert.anumber = anumber;
	_assert.abytes = abytes;
	_assert.ahash = ahash;
	_assert.aexists = aexists;
	_assert.aoutput = aoutput;
	/** Asserts something is positive integer. */
	function anumber(n) {
	    if (!Number.isSafeInteger(n) || n < 0)
	        throw new Error('positive integer expected, got ' + n);
	}
	/** Is number an Uint8Array? Copied from utils for perf. */
	function isBytes(a) {
	    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
	}
	/** Asserts something is Uint8Array. */
	function abytes(b, ...lengths) {
	    if (!isBytes(b))
	        throw new Error('Uint8Array expected');
	    if (lengths.length > 0 && !lengths.includes(b.length))
	        throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
	}
	/** Asserts something is hash */
	function ahash(h) {
	    if (typeof h !== 'function' || typeof h.create !== 'function')
	        throw new Error('Hash should be wrapped by utils.wrapConstructor');
	    anumber(h.outputLen);
	    anumber(h.blockLen);
	}
	/** Asserts a hash instance has not been destroyed / finished */
	function aexists(instance, checkFinished = true) {
	    if (instance.destroyed)
	        throw new Error('Hash instance has been destroyed');
	    if (checkFinished && instance.finished)
	        throw new Error('Hash#digest() has already been called');
	}
	/** Asserts output is properly-sized byte array */
	function aoutput(out, instance) {
	    abytes(out);
	    const min = instance.outputLen;
	    if (out.length < min) {
	        throw new Error('digestInto() expects output buffer of length at least ' + min);
	    }
	}
	
	return _assert;
}

var utils$1 = {};

var crypto = {};

var hasRequiredCrypto;

function requireCrypto () {
	if (hasRequiredCrypto) return crypto;
	hasRequiredCrypto = 1;
	Object.defineProperty(crypto, "__esModule", { value: true });
	crypto.crypto = void 0;
	crypto.crypto = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
	
	return crypto;
}

var hasRequiredUtils$2;

function requireUtils$2 () {
	if (hasRequiredUtils$2) return utils$1;
	hasRequiredUtils$2 = 1;
	(function (exports) {
		/**
		 * Utilities for hex, bytes, CSPRNG.
		 * @module
		 */
		/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.Hash = exports.nextTick = exports.byteSwapIfBE = exports.isLE = void 0;
		exports.isBytes = isBytes;
		exports.u8 = u8;
		exports.u32 = u32;
		exports.createView = createView;
		exports.rotr = rotr;
		exports.rotl = rotl;
		exports.byteSwap = byteSwap;
		exports.byteSwap32 = byteSwap32;
		exports.bytesToHex = bytesToHex;
		exports.hexToBytes = hexToBytes;
		exports.asyncLoop = asyncLoop;
		exports.utf8ToBytes = utf8ToBytes;
		exports.toBytes = toBytes;
		exports.concatBytes = concatBytes;
		exports.checkOpts = checkOpts;
		exports.wrapConstructor = wrapConstructor;
		exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
		exports.wrapXOFConstructorWithOpts = wrapXOFConstructorWithOpts;
		exports.randomBytes = randomBytes;
		// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
		// node.js versions earlier than v19 don't declare it in global scope.
		// For node.js, package.json#exports field mapping rewrites import
		// from `crypto` to `cryptoNode`, which imports native module.
		// Makes the utils un-importable in browsers without a bundler.
		// Once node.js 18 is deprecated (2025-04-30), we can just drop the import.
		const crypto_1 = requireCrypto();
		const _assert_js_1 = /*@__PURE__*/ require_assert();
		// export { isBytes } from './_assert.js';
		// We can't reuse isBytes from _assert, because somehow this causes huge perf issues
		function isBytes(a) {
		    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
		}
		// Cast array to different type
		function u8(arr) {
		    return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
		}
		function u32(arr) {
		    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
		}
		// Cast array to view
		function createView(arr) {
		    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
		}
		/** The rotate right (circular right shift) operation for uint32 */
		function rotr(word, shift) {
		    return (word << (32 - shift)) | (word >>> shift);
		}
		/** The rotate left (circular left shift) operation for uint32 */
		function rotl(word, shift) {
		    return (word << shift) | ((word >>> (32 - shift)) >>> 0);
		}
		/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
		exports.isLE = (() => new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();
		// The byte swap operation for uint32
		function byteSwap(word) {
		    return (((word << 24) & 0xff000000) |
		        ((word << 8) & 0xff0000) |
		        ((word >>> 8) & 0xff00) |
		        ((word >>> 24) & 0xff));
		}
		/** Conditionally byte swap if on a big-endian platform */
		exports.byteSwapIfBE = exports.isLE
		    ? (n) => n
		    : (n) => byteSwap(n);
		/** In place byte swap for Uint32Array */
		function byteSwap32(arr) {
		    for (let i = 0; i < arr.length; i++) {
		        arr[i] = byteSwap(arr[i]);
		    }
		}
		// Array where index 0xf0 (240) is mapped to string 'f0'
		const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
		/**
		 * Convert byte array to hex string.
		 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
		 */
		function bytesToHex(bytes) {
		    (0, _assert_js_1.abytes)(bytes);
		    // pre-caching improves the speed 6x
		    let hex = '';
		    for (let i = 0; i < bytes.length; i++) {
		        hex += hexes[bytes[i]];
		    }
		    return hex;
		}
		// We use optimized technique to convert hex string to byte array
		const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
		function asciiToBase16(ch) {
		    if (ch >= asciis._0 && ch <= asciis._9)
		        return ch - asciis._0; // '2' => 50-48
		    if (ch >= asciis.A && ch <= asciis.F)
		        return ch - (asciis.A - 10); // 'B' => 66-(65-10)
		    if (ch >= asciis.a && ch <= asciis.f)
		        return ch - (asciis.a - 10); // 'b' => 98-(97-10)
		    return;
		}
		/**
		 * Convert hex string to byte array.
		 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
		 */
		function hexToBytes(hex) {
		    if (typeof hex !== 'string')
		        throw new Error('hex string expected, got ' + typeof hex);
		    const hl = hex.length;
		    const al = hl / 2;
		    if (hl % 2)
		        throw new Error('hex string expected, got unpadded hex of length ' + hl);
		    const array = new Uint8Array(al);
		    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
		        const n1 = asciiToBase16(hex.charCodeAt(hi));
		        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
		        if (n1 === undefined || n2 === undefined) {
		            const char = hex[hi] + hex[hi + 1];
		            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
		        }
		        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
		    }
		    return array;
		}
		/**
		 * There is no setImmediate in browser and setTimeout is slow.
		 * Call of async fn will return Promise, which will be fullfiled only on
		 * next scheduler queue processing step and this is exactly what we need.
		 */
		const nextTick = async () => { };
		exports.nextTick = nextTick;
		/** Returns control to thread each 'tick' ms to avoid blocking. */
		async function asyncLoop(iters, tick, cb) {
		    let ts = Date.now();
		    for (let i = 0; i < iters; i++) {
		        cb(i);
		        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
		        const diff = Date.now() - ts;
		        if (diff >= 0 && diff < tick)
		            continue;
		        await (0, exports.nextTick)();
		        ts += diff;
		    }
		}
		/**
		 * Convert JS string to byte array.
		 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
		 */
		function utf8ToBytes(str) {
		    if (typeof str !== 'string')
		        throw new Error('utf8ToBytes expected string, got ' + typeof str);
		    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
		}
		/**
		 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
		 * Warning: when Uint8Array is passed, it would NOT get copied.
		 * Keep in mind for future mutable operations.
		 */
		function toBytes(data) {
		    if (typeof data === 'string')
		        data = utf8ToBytes(data);
		    (0, _assert_js_1.abytes)(data);
		    return data;
		}
		/**
		 * Copies several Uint8Arrays into one.
		 */
		function concatBytes(...arrays) {
		    let sum = 0;
		    for (let i = 0; i < arrays.length; i++) {
		        const a = arrays[i];
		        (0, _assert_js_1.abytes)(a);
		        sum += a.length;
		    }
		    const res = new Uint8Array(sum);
		    for (let i = 0, pad = 0; i < arrays.length; i++) {
		        const a = arrays[i];
		        res.set(a, pad);
		        pad += a.length;
		    }
		    return res;
		}
		/** For runtime check if class implements interface */
		class Hash {
		    // Safe version that clones internal state
		    clone() {
		        return this._cloneInto();
		    }
		}
		exports.Hash = Hash;
		function checkOpts(defaults, opts) {
		    if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
		        throw new Error('Options should be object or undefined');
		    const merged = Object.assign(defaults, opts);
		    return merged;
		}
		/** Wraps hash function, creating an interface on top of it */
		function wrapConstructor(hashCons) {
		    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
		    const tmp = hashCons();
		    hashC.outputLen = tmp.outputLen;
		    hashC.blockLen = tmp.blockLen;
		    hashC.create = () => hashCons();
		    return hashC;
		}
		function wrapConstructorWithOpts(hashCons) {
		    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
		    const tmp = hashCons({});
		    hashC.outputLen = tmp.outputLen;
		    hashC.blockLen = tmp.blockLen;
		    hashC.create = (opts) => hashCons(opts);
		    return hashC;
		}
		function wrapXOFConstructorWithOpts(hashCons) {
		    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
		    const tmp = hashCons({});
		    hashC.outputLen = tmp.outputLen;
		    hashC.blockLen = tmp.blockLen;
		    hashC.create = (opts) => hashCons(opts);
		    return hashC;
		}
		/** Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`. */
		function randomBytes(bytesLength = 32) {
		    if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === 'function') {
		        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
		    }
		    // Legacy Node.js compatibility
		    if (crypto_1.crypto && typeof crypto_1.crypto.randomBytes === 'function') {
		        return crypto_1.crypto.randomBytes(bytesLength);
		    }
		    throw new Error('crypto.getRandomValues must be defined');
		}
		
	} (utils$1));
	return utils$1;
}

var hasRequired_md;

function require_md () {
	if (hasRequired_md) return _md;
	hasRequired_md = 1;
	Object.defineProperty(_md, "__esModule", { value: true });
	_md.HashMD = void 0;
	_md.setBigUint64 = setBigUint64;
	_md.Chi = Chi;
	_md.Maj = Maj;
	/**
	 * Internal Merkle-Damgard hash utils.
	 * @module
	 */
	const _assert_js_1 = /*@__PURE__*/ require_assert();
	const utils_js_1 = /*@__PURE__*/ requireUtils$2();
	/** Polyfill for Safari 14. https://caniuse.com/mdn-javascript_builtins_dataview_setbiguint64 */
	function setBigUint64(view, byteOffset, value, isLE) {
	    if (typeof view.setBigUint64 === 'function')
	        return view.setBigUint64(byteOffset, value, isLE);
	    const _32n = BigInt(32);
	    const _u32_max = BigInt(0xffffffff);
	    const wh = Number((value >> _32n) & _u32_max);
	    const wl = Number(value & _u32_max);
	    const h = isLE ? 4 : 0;
	    const l = isLE ? 0 : 4;
	    view.setUint32(byteOffset + h, wh, isLE);
	    view.setUint32(byteOffset + l, wl, isLE);
	}
	/** Choice: a ? b : c */
	function Chi(a, b, c) {
	    return (a & b) ^ (~a & c);
	}
	/** Majority function, true if any two inputs is true. */
	function Maj(a, b, c) {
	    return (a & b) ^ (a & c) ^ (b & c);
	}
	/**
	 * Merkle-Damgard hash construction base class.
	 * Could be used to create MD5, RIPEMD, SHA1, SHA2.
	 */
	class HashMD extends utils_js_1.Hash {
	    constructor(blockLen, outputLen, padOffset, isLE) {
	        super();
	        this.blockLen = blockLen;
	        this.outputLen = outputLen;
	        this.padOffset = padOffset;
	        this.isLE = isLE;
	        this.finished = false;
	        this.length = 0;
	        this.pos = 0;
	        this.destroyed = false;
	        this.buffer = new Uint8Array(blockLen);
	        this.view = (0, utils_js_1.createView)(this.buffer);
	    }
	    update(data) {
	        (0, _assert_js_1.aexists)(this);
	        const { view, buffer, blockLen } = this;
	        data = (0, utils_js_1.toBytes)(data);
	        const len = data.length;
	        for (let pos = 0; pos < len;) {
	            const take = Math.min(blockLen - this.pos, len - pos);
	            // Fast path: we have at least one block in input, cast it to view and process
	            if (take === blockLen) {
	                const dataView = (0, utils_js_1.createView)(data);
	                for (; blockLen <= len - pos; pos += blockLen)
	                    this.process(dataView, pos);
	                continue;
	            }
	            buffer.set(data.subarray(pos, pos + take), this.pos);
	            this.pos += take;
	            pos += take;
	            if (this.pos === blockLen) {
	                this.process(view, 0);
	                this.pos = 0;
	            }
	        }
	        this.length += data.length;
	        this.roundClean();
	        return this;
	    }
	    digestInto(out) {
	        (0, _assert_js_1.aexists)(this);
	        (0, _assert_js_1.aoutput)(out, this);
	        this.finished = true;
	        // Padding
	        // We can avoid allocation of buffer for padding completely if it
	        // was previously not allocated here. But it won't change performance.
	        const { buffer, view, blockLen, isLE } = this;
	        let { pos } = this;
	        // append the bit '1' to the message
	        buffer[pos++] = 0b10000000;
	        this.buffer.subarray(pos).fill(0);
	        // we have less than padOffset left in buffer, so we cannot put length in
	        // current block, need process it and pad again
	        if (this.padOffset > blockLen - pos) {
	            this.process(view, 0);
	            pos = 0;
	        }
	        // Pad until full block byte with zeros
	        for (let i = pos; i < blockLen; i++)
	            buffer[i] = 0;
	        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
	        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
	        // So we just write lowest 64 bits of that value.
	        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
	        this.process(view, 0);
	        const oview = (0, utils_js_1.createView)(out);
	        const len = this.outputLen;
	        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
	        if (len % 4)
	            throw new Error('_sha2: outputLen should be aligned to 32bit');
	        const outLen = len / 4;
	        const state = this.get();
	        if (outLen > state.length)
	            throw new Error('_sha2: outputLen bigger than state');
	        for (let i = 0; i < outLen; i++)
	            oview.setUint32(4 * i, state[i], isLE);
	    }
	    digest() {
	        const { buffer, outputLen } = this;
	        this.digestInto(buffer);
	        const res = buffer.slice(0, outputLen);
	        this.destroy();
	        return res;
	    }
	    _cloneInto(to) {
	        to || (to = new this.constructor());
	        to.set(...this.get());
	        const { blockLen, buffer, length, finished, destroyed, pos } = this;
	        to.length = length;
	        to.pos = pos;
	        to.finished = finished;
	        to.destroyed = destroyed;
	        if (length % blockLen)
	            to.buffer.set(buffer);
	        return to;
	    }
	}
	_md.HashMD = HashMD;
	
	return _md;
}

var _u64 = {};

var hasRequired_u64;

function require_u64 () {
	if (hasRequired_u64) return _u64;
	hasRequired_u64 = 1;
	Object.defineProperty(_u64, "__esModule", { value: true });
	_u64.add5L = _u64.add5H = _u64.add4H = _u64.add4L = _u64.add3H = _u64.add3L = _u64.rotlBL = _u64.rotlBH = _u64.rotlSL = _u64.rotlSH = _u64.rotr32L = _u64.rotr32H = _u64.rotrBL = _u64.rotrBH = _u64.rotrSL = _u64.rotrSH = _u64.shrSL = _u64.shrSH = _u64.toBig = void 0;
	_u64.fromBig = fromBig;
	_u64.split = split;
	_u64.add = add;
	/**
	 * Internal helpers for u64. BigUint64Array is too slow as per 2025, so we implement it using Uint32Array.
	 * @todo re-check https://issues.chromium.org/issues/42212588
	 * @module
	 */
	const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
	const _32n = /* @__PURE__ */ BigInt(32);
	function fromBig(n, le = false) {
	    if (le)
	        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
	    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
	}
	function split(lst, le = false) {
	    let Ah = new Uint32Array(lst.length);
	    let Al = new Uint32Array(lst.length);
	    for (let i = 0; i < lst.length; i++) {
	        const { h, l } = fromBig(lst[i], le);
	        [Ah[i], Al[i]] = [h, l];
	    }
	    return [Ah, Al];
	}
	const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
	_u64.toBig = toBig;
	// for Shift in [0, 32)
	const shrSH = (h, _l, s) => h >>> s;
	_u64.shrSH = shrSH;
	const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
	_u64.shrSL = shrSL;
	// Right rotate for Shift in [1, 32)
	const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
	_u64.rotrSH = rotrSH;
	const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
	_u64.rotrSL = rotrSL;
	// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
	const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
	_u64.rotrBH = rotrBH;
	const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
	_u64.rotrBL = rotrBL;
	// Right rotate for shift===32 (just swaps l&h)
	const rotr32H = (_h, l) => l;
	_u64.rotr32H = rotr32H;
	const rotr32L = (h, _l) => h;
	_u64.rotr32L = rotr32L;
	// Left rotate for Shift in [1, 32)
	const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
	_u64.rotlSH = rotlSH;
	const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
	_u64.rotlSL = rotlSL;
	// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
	const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
	_u64.rotlBH = rotlBH;
	const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
	_u64.rotlBL = rotlBL;
	// JS uses 32-bit signed integers for bitwise operations which means we cannot
	// simple take carry out of low bit sum by shift, we need to use division.
	function add(Ah, Al, Bh, Bl) {
	    const l = (Al >>> 0) + (Bl >>> 0);
	    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
	}
	// Addition with more than 2 elements
	const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
	_u64.add3L = add3L;
	const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
	_u64.add3H = add3H;
	const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
	_u64.add4L = add4L;
	const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
	_u64.add4H = add4H;
	const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
	_u64.add5L = add5L;
	const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
	_u64.add5H = add5H;
	// prettier-ignore
	const u64 = {
	    fromBig, split, toBig,
	    shrSH, shrSL,
	    rotrSH, rotrSL, rotrBH, rotrBL,
	    rotr32H, rotr32L,
	    rotlSH, rotlSL, rotlBH, rotlBL,
	    add, add3L, add3H, add4L, add4H, add5H, add5L,
	};
	_u64.default = u64;
	
	return _u64;
}

var hasRequiredSha512;

function requireSha512 () {
	if (hasRequiredSha512) return sha512;
	hasRequiredSha512 = 1;
	Object.defineProperty(sha512, "__esModule", { value: true });
	sha512.sha384 = sha512.sha512_256 = sha512.sha512_224 = sha512.sha512 = sha512.SHA384 = sha512.SHA512_256 = sha512.SHA512_224 = sha512.SHA512 = void 0;
	/**
	 * SHA2-512 a.k.a. sha512 and sha384. It is slower than sha256 in js because u64 operations are slow.
	 *
	 * Check out [RFC 4634](https://datatracker.ietf.org/doc/html/rfc4634) and
	 * [the paper on truncated SHA512/256](https://eprint.iacr.org/2010/548.pdf).
	 * @module
	 */
	const _md_js_1 = /*@__PURE__*/ require_md();
	const _u64_js_1 = /*@__PURE__*/ require_u64();
	const utils_js_1 = /*@__PURE__*/ requireUtils$2();
	// Round contants (first 32 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
	// prettier-ignore
	const [SHA512_Kh, SHA512_Kl] = /* @__PURE__ */ (() => _u64_js_1.default.split([
	    '0x428a2f98d728ae22', '0x7137449123ef65cd', '0xb5c0fbcfec4d3b2f', '0xe9b5dba58189dbbc',
	    '0x3956c25bf348b538', '0x59f111f1b605d019', '0x923f82a4af194f9b', '0xab1c5ed5da6d8118',
	    '0xd807aa98a3030242', '0x12835b0145706fbe', '0x243185be4ee4b28c', '0x550c7dc3d5ffb4e2',
	    '0x72be5d74f27b896f', '0x80deb1fe3b1696b1', '0x9bdc06a725c71235', '0xc19bf174cf692694',
	    '0xe49b69c19ef14ad2', '0xefbe4786384f25e3', '0x0fc19dc68b8cd5b5', '0x240ca1cc77ac9c65',
	    '0x2de92c6f592b0275', '0x4a7484aa6ea6e483', '0x5cb0a9dcbd41fbd4', '0x76f988da831153b5',
	    '0x983e5152ee66dfab', '0xa831c66d2db43210', '0xb00327c898fb213f', '0xbf597fc7beef0ee4',
	    '0xc6e00bf33da88fc2', '0xd5a79147930aa725', '0x06ca6351e003826f', '0x142929670a0e6e70',
	    '0x27b70a8546d22ffc', '0x2e1b21385c26c926', '0x4d2c6dfc5ac42aed', '0x53380d139d95b3df',
	    '0x650a73548baf63de', '0x766a0abb3c77b2a8', '0x81c2c92e47edaee6', '0x92722c851482353b',
	    '0xa2bfe8a14cf10364', '0xa81a664bbc423001', '0xc24b8b70d0f89791', '0xc76c51a30654be30',
	    '0xd192e819d6ef5218', '0xd69906245565a910', '0xf40e35855771202a', '0x106aa07032bbd1b8',
	    '0x19a4c116b8d2d0c8', '0x1e376c085141ab53', '0x2748774cdf8eeb99', '0x34b0bcb5e19b48a8',
	    '0x391c0cb3c5c95a63', '0x4ed8aa4ae3418acb', '0x5b9cca4f7763e373', '0x682e6ff3d6b2b8a3',
	    '0x748f82ee5defb2fc', '0x78a5636f43172f60', '0x84c87814a1f0ab72', '0x8cc702081a6439ec',
	    '0x90befffa23631e28', '0xa4506cebde82bde9', '0xbef9a3f7b2c67915', '0xc67178f2e372532b',
	    '0xca273eceea26619c', '0xd186b8c721c0c207', '0xeada7dd6cde0eb1e', '0xf57d4f7fee6ed178',
	    '0x06f067aa72176fba', '0x0a637dc5a2c898a6', '0x113f9804bef90dae', '0x1b710b35131c471b',
	    '0x28db77f523047d84', '0x32caab7b40c72493', '0x3c9ebe0a15c9bebc', '0x431d67c49c100d4c',
	    '0x4cc5d4becb3e42b6', '0x597f299cfc657e2a', '0x5fcb6fab3ad6faec', '0x6c44198c4a475817'
	].map(n => BigInt(n))))();
	// Temporary buffer, not used to store anything between runs
	const SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
	const SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
	class SHA512 extends _md_js_1.HashMD {
	    constructor() {
	        super(128, 64, 16, false);
	        // We cannot use array here since array allows indexing by variable which means optimizer/compiler cannot use registers.
	        // Also looks cleaner and easier to verify with spec.
	        // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
	        // h -- high 32 bits, l -- low 32 bits
	        this.Ah = 0x6a09e667 | 0;
	        this.Al = 0xf3bcc908 | 0;
	        this.Bh = 0xbb67ae85 | 0;
	        this.Bl = 0x84caa73b | 0;
	        this.Ch = 0x3c6ef372 | 0;
	        this.Cl = 0xfe94f82b | 0;
	        this.Dh = 0xa54ff53a | 0;
	        this.Dl = 0x5f1d36f1 | 0;
	        this.Eh = 0x510e527f | 0;
	        this.El = 0xade682d1 | 0;
	        this.Fh = 0x9b05688c | 0;
	        this.Fl = 0x2b3e6c1f | 0;
	        this.Gh = 0x1f83d9ab | 0;
	        this.Gl = 0xfb41bd6b | 0;
	        this.Hh = 0x5be0cd19 | 0;
	        this.Hl = 0x137e2179 | 0;
	    }
	    // prettier-ignore
	    get() {
	        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
	        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
	    }
	    // prettier-ignore
	    set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
	        this.Ah = Ah | 0;
	        this.Al = Al | 0;
	        this.Bh = Bh | 0;
	        this.Bl = Bl | 0;
	        this.Ch = Ch | 0;
	        this.Cl = Cl | 0;
	        this.Dh = Dh | 0;
	        this.Dl = Dl | 0;
	        this.Eh = Eh | 0;
	        this.El = El | 0;
	        this.Fh = Fh | 0;
	        this.Fl = Fl | 0;
	        this.Gh = Gh | 0;
	        this.Gl = Gl | 0;
	        this.Hh = Hh | 0;
	        this.Hl = Hl | 0;
	    }
	    process(view, offset) {
	        // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
	        for (let i = 0; i < 16; i++, offset += 4) {
	            SHA512_W_H[i] = view.getUint32(offset);
	            SHA512_W_L[i] = view.getUint32((offset += 4));
	        }
	        for (let i = 16; i < 80; i++) {
	            // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
	            const W15h = SHA512_W_H[i - 15] | 0;
	            const W15l = SHA512_W_L[i - 15] | 0;
	            const s0h = _u64_js_1.default.rotrSH(W15h, W15l, 1) ^ _u64_js_1.default.rotrSH(W15h, W15l, 8) ^ _u64_js_1.default.shrSH(W15h, W15l, 7);
	            const s0l = _u64_js_1.default.rotrSL(W15h, W15l, 1) ^ _u64_js_1.default.rotrSL(W15h, W15l, 8) ^ _u64_js_1.default.shrSL(W15h, W15l, 7);
	            // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
	            const W2h = SHA512_W_H[i - 2] | 0;
	            const W2l = SHA512_W_L[i - 2] | 0;
	            const s1h = _u64_js_1.default.rotrSH(W2h, W2l, 19) ^ _u64_js_1.default.rotrBH(W2h, W2l, 61) ^ _u64_js_1.default.shrSH(W2h, W2l, 6);
	            const s1l = _u64_js_1.default.rotrSL(W2h, W2l, 19) ^ _u64_js_1.default.rotrBL(W2h, W2l, 61) ^ _u64_js_1.default.shrSL(W2h, W2l, 6);
	            // SHA256_W[i] = s0 + s1 + SHA256_W[i - 7] + SHA256_W[i - 16];
	            const SUMl = _u64_js_1.default.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
	            const SUMh = _u64_js_1.default.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
	            SHA512_W_H[i] = SUMh | 0;
	            SHA512_W_L[i] = SUMl | 0;
	        }
	        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
	        // Compression function main loop, 80 rounds
	        for (let i = 0; i < 80; i++) {
	            // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
	            const sigma1h = _u64_js_1.default.rotrSH(Eh, El, 14) ^ _u64_js_1.default.rotrSH(Eh, El, 18) ^ _u64_js_1.default.rotrBH(Eh, El, 41);
	            const sigma1l = _u64_js_1.default.rotrSL(Eh, El, 14) ^ _u64_js_1.default.rotrSL(Eh, El, 18) ^ _u64_js_1.default.rotrBL(Eh, El, 41);
	            //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
	            const CHIh = (Eh & Fh) ^ (~Eh & Gh);
	            const CHIl = (El & Fl) ^ (~El & Gl);
	            // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
	            // prettier-ignore
	            const T1ll = _u64_js_1.default.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
	            const T1h = _u64_js_1.default.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
	            const T1l = T1ll | 0;
	            // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
	            const sigma0h = _u64_js_1.default.rotrSH(Ah, Al, 28) ^ _u64_js_1.default.rotrBH(Ah, Al, 34) ^ _u64_js_1.default.rotrBH(Ah, Al, 39);
	            const sigma0l = _u64_js_1.default.rotrSL(Ah, Al, 28) ^ _u64_js_1.default.rotrBL(Ah, Al, 34) ^ _u64_js_1.default.rotrBL(Ah, Al, 39);
	            const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
	            const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
	            Hh = Gh | 0;
	            Hl = Gl | 0;
	            Gh = Fh | 0;
	            Gl = Fl | 0;
	            Fh = Eh | 0;
	            Fl = El | 0;
	            ({ h: Eh, l: El } = _u64_js_1.default.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
	            Dh = Ch | 0;
	            Dl = Cl | 0;
	            Ch = Bh | 0;
	            Cl = Bl | 0;
	            Bh = Ah | 0;
	            Bl = Al | 0;
	            const All = _u64_js_1.default.add3L(T1l, sigma0l, MAJl);
	            Ah = _u64_js_1.default.add3H(All, T1h, sigma0h, MAJh);
	            Al = All | 0;
	        }
	        // Add the compressed chunk to the current hash value
	        ({ h: Ah, l: Al } = _u64_js_1.default.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
	        ({ h: Bh, l: Bl } = _u64_js_1.default.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
	        ({ h: Ch, l: Cl } = _u64_js_1.default.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
	        ({ h: Dh, l: Dl } = _u64_js_1.default.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
	        ({ h: Eh, l: El } = _u64_js_1.default.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
	        ({ h: Fh, l: Fl } = _u64_js_1.default.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
	        ({ h: Gh, l: Gl } = _u64_js_1.default.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
	        ({ h: Hh, l: Hl } = _u64_js_1.default.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
	        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
	    }
	    roundClean() {
	        SHA512_W_H.fill(0);
	        SHA512_W_L.fill(0);
	    }
	    destroy() {
	        this.buffer.fill(0);
	        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	    }
	}
	sha512.SHA512 = SHA512;
	class SHA512_224 extends SHA512 {
	    constructor() {
	        super();
	        // h -- high 32 bits, l -- low 32 bits
	        this.Ah = 0x8c3d37c8 | 0;
	        this.Al = 0x19544da2 | 0;
	        this.Bh = 0x73e19966 | 0;
	        this.Bl = 0x89dcd4d6 | 0;
	        this.Ch = 0x1dfab7ae | 0;
	        this.Cl = 0x32ff9c82 | 0;
	        this.Dh = 0x679dd514 | 0;
	        this.Dl = 0x582f9fcf | 0;
	        this.Eh = 0x0f6d2b69 | 0;
	        this.El = 0x7bd44da8 | 0;
	        this.Fh = 0x77e36f73 | 0;
	        this.Fl = 0x04c48942 | 0;
	        this.Gh = 0x3f9d85a8 | 0;
	        this.Gl = 0x6a1d36c8 | 0;
	        this.Hh = 0x1112e6ad | 0;
	        this.Hl = 0x91d692a1 | 0;
	        this.outputLen = 28;
	    }
	}
	sha512.SHA512_224 = SHA512_224;
	class SHA512_256 extends SHA512 {
	    constructor() {
	        super();
	        // h -- high 32 bits, l -- low 32 bits
	        this.Ah = 0x22312194 | 0;
	        this.Al = 0xfc2bf72c | 0;
	        this.Bh = 0x9f555fa3 | 0;
	        this.Bl = 0xc84c64c2 | 0;
	        this.Ch = 0x2393b86b | 0;
	        this.Cl = 0x6f53b151 | 0;
	        this.Dh = 0x96387719 | 0;
	        this.Dl = 0x5940eabd | 0;
	        this.Eh = 0x96283ee2 | 0;
	        this.El = 0xa88effe3 | 0;
	        this.Fh = 0xbe5e1e25 | 0;
	        this.Fl = 0x53863992 | 0;
	        this.Gh = 0x2b0199fc | 0;
	        this.Gl = 0x2c85b8aa | 0;
	        this.Hh = 0x0eb72ddc | 0;
	        this.Hl = 0x81c52ca2 | 0;
	        this.outputLen = 32;
	    }
	}
	sha512.SHA512_256 = SHA512_256;
	class SHA384 extends SHA512 {
	    constructor() {
	        super();
	        // h -- high 32 bits, l -- low 32 bits
	        this.Ah = 0xcbbb9d5d | 0;
	        this.Al = 0xc1059ed8 | 0;
	        this.Bh = 0x629a292a | 0;
	        this.Bl = 0x367cd507 | 0;
	        this.Ch = 0x9159015a | 0;
	        this.Cl = 0x3070dd17 | 0;
	        this.Dh = 0x152fecd8 | 0;
	        this.Dl = 0xf70e5939 | 0;
	        this.Eh = 0x67332667 | 0;
	        this.El = 0xffc00b31 | 0;
	        this.Fh = 0x8eb44a87 | 0;
	        this.Fl = 0x68581511 | 0;
	        this.Gh = 0xdb0c2e0d | 0;
	        this.Gl = 0x64f98fa7 | 0;
	        this.Hh = 0x47b5481d | 0;
	        this.Hl = 0xbefa4fa4 | 0;
	        this.outputLen = 48;
	    }
	}
	sha512.SHA384 = SHA384;
	/** SHA2-512 hash function. */
	sha512.sha512 = (0, utils_js_1.wrapConstructor)(() => new SHA512());
	/** SHA2-512/224 "truncated" hash function, with improved resistance to length extension attacks. */
	sha512.sha512_224 = (0, utils_js_1.wrapConstructor)(() => new SHA512_224());
	/** SHA2-512/256 "truncated" hash function, with improved resistance to length extension attacks. */
	sha512.sha512_256 = (0, utils_js_1.wrapConstructor)(() => new SHA512_256());
	/** SHA2-384 hash function. */
	sha512.sha384 = (0, utils_js_1.wrapConstructor)(() => new SHA384());
	
	return sha512;
}

var curve = {};

var modular = {};

var utils = {};

var hasRequiredUtils$1;

function requireUtils$1 () {
	if (hasRequiredUtils$1) return utils;
	hasRequiredUtils$1 = 1;
	/**
	 * Hex, bytes and number utilities.
	 * @module
	 */
	/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
	Object.defineProperty(utils, "__esModule", { value: true });
	utils.notImplemented = utils.bitMask = void 0;
	utils.isBytes = isBytes;
	utils.abytes = abytes;
	utils.abool = abool;
	utils.bytesToHex = bytesToHex;
	utils.numberToHexUnpadded = numberToHexUnpadded;
	utils.hexToNumber = hexToNumber;
	utils.hexToBytes = hexToBytes;
	utils.bytesToNumberBE = bytesToNumberBE;
	utils.bytesToNumberLE = bytesToNumberLE;
	utils.numberToBytesBE = numberToBytesBE;
	utils.numberToBytesLE = numberToBytesLE;
	utils.numberToVarBytesBE = numberToVarBytesBE;
	utils.ensureBytes = ensureBytes;
	utils.concatBytes = concatBytes;
	utils.equalBytes = equalBytes;
	utils.utf8ToBytes = utf8ToBytes;
	utils.inRange = inRange;
	utils.aInRange = aInRange;
	utils.bitLen = bitLen;
	utils.bitGet = bitGet;
	utils.bitSet = bitSet;
	utils.createHmacDrbg = createHmacDrbg;
	utils.validateObject = validateObject;
	utils.memoized = memoized;
	// 100 lines of code in the file are duplicated from noble-hashes (utils).
	// This is OK: `abstract` directory does not use noble-hashes.
	// User may opt-in into using different hashing library. This way, noble-hashes
	// won't be included into their bundle.
	const _0n = /* @__PURE__ */ BigInt(0);
	const _1n = /* @__PURE__ */ BigInt(1);
	const _2n = /* @__PURE__ */ BigInt(2);
	function isBytes(a) {
	    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
	}
	function abytes(item) {
	    if (!isBytes(item))
	        throw new Error('Uint8Array expected');
	}
	function abool(title, value) {
	    if (typeof value !== 'boolean')
	        throw new Error(title + ' boolean expected, got ' + value);
	}
	// Array where index 0xf0 (240) is mapped to string 'f0'
	const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
	/**
	 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
	 */
	function bytesToHex(bytes) {
	    abytes(bytes);
	    // pre-caching improves the speed 6x
	    let hex = '';
	    for (let i = 0; i < bytes.length; i++) {
	        hex += hexes[bytes[i]];
	    }
	    return hex;
	}
	function numberToHexUnpadded(num) {
	    const hex = num.toString(16);
	    return hex.length & 1 ? '0' + hex : hex;
	}
	function hexToNumber(hex) {
	    if (typeof hex !== 'string')
	        throw new Error('hex string expected, got ' + typeof hex);
	    return hex === '' ? _0n : BigInt('0x' + hex); // Big Endian
	}
	// We use optimized technique to convert hex string to byte array
	const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
	function asciiToBase16(ch) {
	    if (ch >= asciis._0 && ch <= asciis._9)
	        return ch - asciis._0; // '2' => 50-48
	    if (ch >= asciis.A && ch <= asciis.F)
	        return ch - (asciis.A - 10); // 'B' => 66-(65-10)
	    if (ch >= asciis.a && ch <= asciis.f)
	        return ch - (asciis.a - 10); // 'b' => 98-(97-10)
	    return;
	}
	/**
	 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
	 */
	function hexToBytes(hex) {
	    if (typeof hex !== 'string')
	        throw new Error('hex string expected, got ' + typeof hex);
	    const hl = hex.length;
	    const al = hl / 2;
	    if (hl % 2)
	        throw new Error('hex string expected, got unpadded hex of length ' + hl);
	    const array = new Uint8Array(al);
	    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
	        const n1 = asciiToBase16(hex.charCodeAt(hi));
	        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
	        if (n1 === undefined || n2 === undefined) {
	            const char = hex[hi] + hex[hi + 1];
	            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
	        }
	        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
	    }
	    return array;
	}
	// BE: Big Endian, LE: Little Endian
	function bytesToNumberBE(bytes) {
	    return hexToNumber(bytesToHex(bytes));
	}
	function bytesToNumberLE(bytes) {
	    abytes(bytes);
	    return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
	}
	function numberToBytesBE(n, len) {
	    return hexToBytes(n.toString(16).padStart(len * 2, '0'));
	}
	function numberToBytesLE(n, len) {
	    return numberToBytesBE(n, len).reverse();
	}
	// Unpadded, rarely used
	function numberToVarBytesBE(n) {
	    return hexToBytes(numberToHexUnpadded(n));
	}
	/**
	 * Takes hex string or Uint8Array, converts to Uint8Array.
	 * Validates output length.
	 * Will throw error for other types.
	 * @param title descriptive title for an error e.g. 'private key'
	 * @param hex hex string or Uint8Array
	 * @param expectedLength optional, will compare to result array's length
	 * @returns
	 */
	function ensureBytes(title, hex, expectedLength) {
	    let res;
	    if (typeof hex === 'string') {
	        try {
	            res = hexToBytes(hex);
	        }
	        catch (e) {
	            throw new Error(title + ' must be hex string or Uint8Array, cause: ' + e);
	        }
	    }
	    else if (isBytes(hex)) {
	        // Uint8Array.from() instead of hash.slice() because node.js Buffer
	        // is instance of Uint8Array, and its slice() creates **mutable** copy
	        res = Uint8Array.from(hex);
	    }
	    else {
	        throw new Error(title + ' must be hex string or Uint8Array');
	    }
	    const len = res.length;
	    if (typeof expectedLength === 'number' && len !== expectedLength)
	        throw new Error(title + ' of length ' + expectedLength + ' expected, got ' + len);
	    return res;
	}
	/**
	 * Copies several Uint8Arrays into one.
	 */
	function concatBytes(...arrays) {
	    let sum = 0;
	    for (let i = 0; i < arrays.length; i++) {
	        const a = arrays[i];
	        abytes(a);
	        sum += a.length;
	    }
	    const res = new Uint8Array(sum);
	    for (let i = 0, pad = 0; i < arrays.length; i++) {
	        const a = arrays[i];
	        res.set(a, pad);
	        pad += a.length;
	    }
	    return res;
	}
	// Compares 2 u8a-s in kinda constant time
	function equalBytes(a, b) {
	    if (a.length !== b.length)
	        return false;
	    let diff = 0;
	    for (let i = 0; i < a.length; i++)
	        diff |= a[i] ^ b[i];
	    return diff === 0;
	}
	/**
	 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
	 */
	function utf8ToBytes(str) {
	    if (typeof str !== 'string')
	        throw new Error('string expected');
	    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
	}
	// Is positive bigint
	const isPosBig = (n) => typeof n === 'bigint' && _0n <= n;
	function inRange(n, min, max) {
	    return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
	}
	/**
	 * Asserts min <= n < max. NOTE: It's < max and not <= max.
	 * @example
	 * aInRange('x', x, 1n, 256n); // would assume x is in (1n..255n)
	 */
	function aInRange(title, n, min, max) {
	    // Why min <= n < max and not a (min < n < max) OR b (min <= n <= max)?
	    // consider P=256n, min=0n, max=P
	    // - a for min=0 would require -1:          `inRange('x', x, -1n, P)`
	    // - b would commonly require subtraction:  `inRange('x', x, 0n, P - 1n)`
	    // - our way is the cleanest:               `inRange('x', x, 0n, P)
	    if (!inRange(n, min, max))
	        throw new Error('expected valid ' + title + ': ' + min + ' <= n < ' + max + ', got ' + n);
	}
	// Bit operations
	/**
	 * Calculates amount of bits in a bigint.
	 * Same as `n.toString(2).length`
	 */
	function bitLen(n) {
	    let len;
	    for (len = 0; n > _0n; n >>= _1n, len += 1)
	        ;
	    return len;
	}
	/**
	 * Gets single bit at position.
	 * NOTE: first bit position is 0 (same as arrays)
	 * Same as `!!+Array.from(n.toString(2)).reverse()[pos]`
	 */
	function bitGet(n, pos) {
	    return (n >> BigInt(pos)) & _1n;
	}
	/**
	 * Sets single bit at position.
	 */
	function bitSet(n, pos, value) {
	    return n | ((value ? _1n : _0n) << BigInt(pos));
	}
	/**
	 * Calculate mask for N bits. Not using ** operator with bigints because of old engines.
	 * Same as BigInt(`0b${Array(i).fill('1').join('')}`)
	 */
	const bitMask = (n) => (_2n << BigInt(n - 1)) - _1n;
	utils.bitMask = bitMask;
	// DRBG
	const u8n = (data) => new Uint8Array(data); // creates Uint8Array
	const u8fr = (arr) => Uint8Array.from(arr); // another shortcut
	/**
	 * Minimal HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
	 * @returns function that will call DRBG until 2nd arg returns something meaningful
	 * @example
	 *   const drbg = createHmacDRBG<Key>(32, 32, hmac);
	 *   drbg(seed, bytesToKey); // bytesToKey must return Key or undefined
	 */
	function createHmacDrbg(hashLen, qByteLen, hmacFn) {
	    if (typeof hashLen !== 'number' || hashLen < 2)
	        throw new Error('hashLen must be a number');
	    if (typeof qByteLen !== 'number' || qByteLen < 2)
	        throw new Error('qByteLen must be a number');
	    if (typeof hmacFn !== 'function')
	        throw new Error('hmacFn must be a function');
	    // Step B, Step C: set hashLen to 8*ceil(hlen/8)
	    let v = u8n(hashLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
	    let k = u8n(hashLen); // Steps B and C of RFC6979 3.2: set hashLen, in our case always same
	    let i = 0; // Iterations counter, will throw when over 1000
	    const reset = () => {
	        v.fill(1);
	        k.fill(0);
	        i = 0;
	    };
	    const h = (...b) => hmacFn(k, v, ...b); // hmac(k)(v, ...values)
	    const reseed = (seed = u8n()) => {
	        // HMAC-DRBG reseed() function. Steps D-G
	        k = h(u8fr([0x00]), seed); // k = hmac(k || v || 0x00 || seed)
	        v = h(); // v = hmac(k || v)
	        if (seed.length === 0)
	            return;
	        k = h(u8fr([0x01]), seed); // k = hmac(k || v || 0x01 || seed)
	        v = h(); // v = hmac(k || v)
	    };
	    const gen = () => {
	        // HMAC-DRBG generate() function
	        if (i++ >= 1000)
	            throw new Error('drbg: tried 1000 values');
	        let len = 0;
	        const out = [];
	        while (len < qByteLen) {
	            v = h();
	            const sl = v.slice();
	            out.push(sl);
	            len += v.length;
	        }
	        return concatBytes(...out);
	    };
	    const genUntil = (seed, pred) => {
	        reset();
	        reseed(seed); // Steps D-G
	        let res = undefined; // Step H: grind until k is in [1..n-1]
	        while (!(res = pred(gen())))
	            reseed();
	        reset();
	        return res;
	    };
	    return genUntil;
	}
	// Validating curves and fields
	const validatorFns = {
	    bigint: (val) => typeof val === 'bigint',
	    function: (val) => typeof val === 'function',
	    boolean: (val) => typeof val === 'boolean',
	    string: (val) => typeof val === 'string',
	    stringOrUint8Array: (val) => typeof val === 'string' || isBytes(val),
	    isSafeInteger: (val) => Number.isSafeInteger(val),
	    array: (val) => Array.isArray(val),
	    field: (val, object) => object.Fp.isValid(val),
	    hash: (val) => typeof val === 'function' && Number.isSafeInteger(val.outputLen),
	};
	// type Record<K extends string | number | symbol, T> = { [P in K]: T; }
	function validateObject(object, validators, optValidators = {}) {
	    const checkField = (fieldName, type, isOptional) => {
	        const checkVal = validatorFns[type];
	        if (typeof checkVal !== 'function')
	            throw new Error('invalid validator function');
	        const val = object[fieldName];
	        if (isOptional && val === undefined)
	            return;
	        if (!checkVal(val, object)) {
	            throw new Error('param ' + String(fieldName) + ' is invalid. Expected ' + type + ', got ' + val);
	        }
	    };
	    for (const [fieldName, type] of Object.entries(validators))
	        checkField(fieldName, type, false);
	    for (const [fieldName, type] of Object.entries(optValidators))
	        checkField(fieldName, type, true);
	    return object;
	}
	// validate type tests
	// const o: { a: number; b: number; c: number } = { a: 1, b: 5, c: 6 };
	// const z0 = validateObject(o, { a: 'isSafeInteger' }, { c: 'bigint' }); // Ok!
	// // Should fail type-check
	// const z1 = validateObject(o, { a: 'tmp' }, { c: 'zz' });
	// const z2 = validateObject(o, { a: 'isSafeInteger' }, { c: 'zz' });
	// const z3 = validateObject(o, { test: 'boolean', z: 'bug' });
	// const z4 = validateObject(o, { a: 'boolean', z: 'bug' });
	/**
	 * throws not implemented error
	 */
	const notImplemented = () => {
	    throw new Error('not implemented');
	};
	utils.notImplemented = notImplemented;
	/**
	 * Memoizes (caches) computation result.
	 * Uses WeakMap: the value is going auto-cleaned by GC after last reference is removed.
	 */
	function memoized(fn) {
	    const map = new WeakMap();
	    return (arg, ...args) => {
	        const val = map.get(arg);
	        if (val !== undefined)
	            return val;
	        const computed = fn(arg, ...args);
	        map.set(arg, computed);
	        return computed;
	    };
	}
	
	return utils;
}

var hasRequiredModular;

function requireModular () {
	if (hasRequiredModular) return modular;
	hasRequiredModular = 1;
	Object.defineProperty(modular, "__esModule", { value: true });
	modular.isNegativeLE = void 0;
	modular.mod = mod;
	modular.pow = pow;
	modular.pow2 = pow2;
	modular.invert = invert;
	modular.tonelliShanks = tonelliShanks;
	modular.FpSqrt = FpSqrt;
	modular.validateField = validateField;
	modular.FpPow = FpPow;
	modular.FpInvertBatch = FpInvertBatch;
	modular.FpDiv = FpDiv;
	modular.FpLegendre = FpLegendre;
	modular.FpIsSquare = FpIsSquare;
	modular.nLength = nLength;
	modular.Field = Field;
	modular.FpSqrtOdd = FpSqrtOdd;
	modular.FpSqrtEven = FpSqrtEven;
	modular.hashToPrivateScalar = hashToPrivateScalar;
	modular.getFieldBytesLength = getFieldBytesLength;
	modular.getMinHashLength = getMinHashLength;
	modular.mapHashToField = mapHashToField;
	/**
	 * Utils for modular division and finite fields.
	 * A finite field over 11 is integer number operations `mod 11`.
	 * There is no division: it is replaced by modular multiplicative inverse.
	 * @module
	 */
	/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
	const utils_js_1 = /*@__PURE__*/ requireUtils$1();
	// prettier-ignore
	const _0n = BigInt(0), _1n = BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _3n = /* @__PURE__ */ BigInt(3);
	// prettier-ignore
	const _4n = /* @__PURE__ */ BigInt(4), _5n = /* @__PURE__ */ BigInt(5), _8n = /* @__PURE__ */ BigInt(8);
	// Calculates a modulo b
	function mod(a, b) {
	    const result = a % b;
	    return result >= _0n ? result : b + result;
	}
	/**
	 * Efficiently raise num to power and do modular division.
	 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
	 * @todo use field version && remove
	 * @example
	 * pow(2n, 6n, 11n) // 64n % 11n == 9n
	 */
	function pow(num, power, modulo) {
	    if (power < _0n)
	        throw new Error('invalid exponent, negatives unsupported');
	    if (modulo <= _0n)
	        throw new Error('invalid modulus');
	    if (modulo === _1n)
	        return _0n;
	    let res = _1n;
	    while (power > _0n) {
	        if (power & _1n)
	            res = (res * num) % modulo;
	        num = (num * num) % modulo;
	        power >>= _1n;
	    }
	    return res;
	}
	/** Does `x^(2^power)` mod p. `pow2(30, 4)` == `30^(2^4)` */
	function pow2(x, power, modulo) {
	    let res = x;
	    while (power-- > _0n) {
	        res *= res;
	        res %= modulo;
	    }
	    return res;
	}
	/**
	 * Inverses number over modulo.
	 * Implemented using [Euclidean GCD](https://brilliant.org/wiki/extended-euclidean-algorithm/).
	 */
	function invert(number, modulo) {
	    if (number === _0n)
	        throw new Error('invert: expected non-zero number');
	    if (modulo <= _0n)
	        throw new Error('invert: expected positive modulus, got ' + modulo);
	    // Fermat's little theorem "CT-like" version inv(n) = n^(m-2) mod m is 30x slower.
	    let a = mod(number, modulo);
	    let b = modulo;
	    // prettier-ignore
	    let x = _0n, u = _1n;
	    while (a !== _0n) {
	        // JIT applies optimization if those two lines follow each other
	        const q = b / a;
	        const r = b % a;
	        const m = x - u * q;
	        // prettier-ignore
	        b = a, a = r, x = u, u = m;
	    }
	    const gcd = b;
	    if (gcd !== _1n)
	        throw new Error('invert: does not exist');
	    return mod(x, modulo);
	}
	/**
	 * Tonelli-Shanks square root search algorithm.
	 * 1. https://eprint.iacr.org/2012/685.pdf (page 12)
	 * 2. Square Roots from 1; 24, 51, 10 to Dan Shanks
	 * Will start an infinite loop if field order P is not prime.
	 * @param P field order
	 * @returns function that takes field Fp (created from P) and number n
	 */
	function tonelliShanks(P) {
	    // Legendre constant: used to calculate Legendre symbol (a | p),
	    // which denotes the value of a^((p-1)/2) (mod p).
	    // (a | p) ≡ 1    if a is a square (mod p)
	    // (a | p) ≡ -1   if a is not a square (mod p)
	    // (a | p) ≡ 0    if a ≡ 0 (mod p)
	    const legendreC = (P - _1n) / _2n;
	    let Q, S, Z;
	    // Step 1: By factoring out powers of 2 from p - 1,
	    // find q and s such that p - 1 = q*(2^s) with q odd
	    for (Q = P - _1n, S = 0; Q % _2n === _0n; Q /= _2n, S++)
	        ;
	    // Step 2: Select a non-square z such that (z | p) ≡ -1 and set c ≡ zq
	    for (Z = _2n; Z < P && pow(Z, legendreC, P) !== P - _1n; Z++) {
	        // Crash instead of infinity loop, we cannot reasonable count until P.
	        if (Z > 1000)
	            throw new Error('Cannot find square root: likely non-prime P');
	    }
	    // Fast-path
	    if (S === 1) {
	        const p1div4 = (P + _1n) / _4n;
	        return function tonelliFast(Fp, n) {
	            const root = Fp.pow(n, p1div4);
	            if (!Fp.eql(Fp.sqr(root), n))
	                throw new Error('Cannot find square root');
	            return root;
	        };
	    }
	    // Slow-path
	    const Q1div2 = (Q + _1n) / _2n;
	    return function tonelliSlow(Fp, n) {
	        // Step 0: Check that n is indeed a square: (n | p) should not be ≡ -1
	        if (Fp.pow(n, legendreC) === Fp.neg(Fp.ONE))
	            throw new Error('Cannot find square root');
	        let r = S;
	        // TODO: will fail at Fp2/etc
	        let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q); // will update both x and b
	        let x = Fp.pow(n, Q1div2); // first guess at the square root
	        let b = Fp.pow(n, Q); // first guess at the fudge factor
	        while (!Fp.eql(b, Fp.ONE)) {
	            if (Fp.eql(b, Fp.ZERO))
	                return Fp.ZERO; // https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm (4. If t = 0, return r = 0)
	            // Find m such b^(2^m)==1
	            let m = 1;
	            for (let t2 = Fp.sqr(b); m < r; m++) {
	                if (Fp.eql(t2, Fp.ONE))
	                    break;
	                t2 = Fp.sqr(t2); // t2 *= t2
	            }
	            // NOTE: r-m-1 can be bigger than 32, need to convert to bigint before shift, otherwise there will be overflow
	            const ge = Fp.pow(g, _1n << BigInt(r - m - 1)); // ge = 2^(r-m-1)
	            g = Fp.sqr(ge); // g = ge * ge
	            x = Fp.mul(x, ge); // x *= ge
	            b = Fp.mul(b, g); // b *= g
	            r = m;
	        }
	        return x;
	    };
	}
	/**
	 * Square root for a finite field. It will try to check if optimizations are applicable and fall back to 4:
	 *
	 * 1. P ≡ 3 (mod 4)
	 * 2. P ≡ 5 (mod 8)
	 * 3. P ≡ 9 (mod 16)
	 * 4. Tonelli-Shanks algorithm
	 *
	 * Different algorithms can give different roots, it is up to user to decide which one they want.
	 * For example there is FpSqrtOdd/FpSqrtEven to choice root based on oddness (used for hash-to-curve).
	 */
	function FpSqrt(P) {
	    // P ≡ 3 (mod 4)
	    // √n = n^((P+1)/4)
	    if (P % _4n === _3n) {
	        // Not all roots possible!
	        // const ORDER =
	        //   0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
	        // const NUM = 72057594037927816n;
	        const p1div4 = (P + _1n) / _4n;
	        return function sqrt3mod4(Fp, n) {
	            const root = Fp.pow(n, p1div4);
	            // Throw if root**2 != n
	            if (!Fp.eql(Fp.sqr(root), n))
	                throw new Error('Cannot find square root');
	            return root;
	        };
	    }
	    // Atkin algorithm for q ≡ 5 (mod 8), https://eprint.iacr.org/2012/685.pdf (page 10)
	    if (P % _8n === _5n) {
	        const c1 = (P - _5n) / _8n;
	        return function sqrt5mod8(Fp, n) {
	            const n2 = Fp.mul(n, _2n);
	            const v = Fp.pow(n2, c1);
	            const nv = Fp.mul(n, v);
	            const i = Fp.mul(Fp.mul(nv, _2n), v);
	            const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
	            if (!Fp.eql(Fp.sqr(root), n))
	                throw new Error('Cannot find square root');
	            return root;
	        };
	    }
	    // Other cases: Tonelli-Shanks algorithm
	    return tonelliShanks(P);
	}
	// Little-endian check for first LE bit (last BE bit);
	const isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n) === _1n;
	modular.isNegativeLE = isNegativeLE;
	// prettier-ignore
	const FIELD_FIELDS = [
	    'create', 'isValid', 'is0', 'neg', 'inv', 'sqrt', 'sqr',
	    'eql', 'add', 'sub', 'mul', 'pow', 'div',
	    'addN', 'subN', 'mulN', 'sqrN'
	];
	function validateField(field) {
	    const initial = {
	        ORDER: 'bigint',
	        MASK: 'bigint',
	        BYTES: 'isSafeInteger',
	        BITS: 'isSafeInteger',
	    };
	    const opts = FIELD_FIELDS.reduce((map, val) => {
	        map[val] = 'function';
	        return map;
	    }, initial);
	    return (0, utils_js_1.validateObject)(field, opts);
	}
	// Generic field functions
	/**
	 * Same as `pow` but for Fp: non-constant-time.
	 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
	 */
	function FpPow(f, num, power) {
	    // Should have same speed as pow for bigints
	    // TODO: benchmark!
	    if (power < _0n)
	        throw new Error('invalid exponent, negatives unsupported');
	    if (power === _0n)
	        return f.ONE;
	    if (power === _1n)
	        return num;
	    let p = f.ONE;
	    let d = num;
	    while (power > _0n) {
	        if (power & _1n)
	            p = f.mul(p, d);
	        d = f.sqr(d);
	        power >>= _1n;
	    }
	    return p;
	}
	/**
	 * Efficiently invert an array of Field elements.
	 * `inv(0)` will return `undefined` here: make sure to throw an error.
	 */
	function FpInvertBatch(f, nums) {
	    const tmp = new Array(nums.length);
	    // Walk from first to last, multiply them by each other MOD p
	    const lastMultiplied = nums.reduce((acc, num, i) => {
	        if (f.is0(num))
	            return acc;
	        tmp[i] = acc;
	        return f.mul(acc, num);
	    }, f.ONE);
	    // Invert last element
	    const inverted = f.inv(lastMultiplied);
	    // Walk from last to first, multiply them by inverted each other MOD p
	    nums.reduceRight((acc, num, i) => {
	        if (f.is0(num))
	            return acc;
	        tmp[i] = f.mul(acc, tmp[i]);
	        return f.mul(acc, num);
	    }, inverted);
	    return tmp;
	}
	function FpDiv(f, lhs, rhs) {
	    return f.mul(lhs, typeof rhs === 'bigint' ? invert(rhs, f.ORDER) : f.inv(rhs));
	}
	/**
	 * Legendre symbol.
	 * * (a | p) ≡ 1    if a is a square (mod p), quadratic residue
	 * * (a | p) ≡ -1   if a is not a square (mod p), quadratic non residue
	 * * (a | p) ≡ 0    if a ≡ 0 (mod p)
	 */
	function FpLegendre(order) {
	    const legendreConst = (order - _1n) / _2n; // Integer arithmetic
	    return (f, x) => f.pow(x, legendreConst);
	}
	// This function returns True whenever the value x is a square in the field F.
	function FpIsSquare(f) {
	    const legendre = FpLegendre(f.ORDER);
	    return (x) => {
	        const p = legendre(f, x);
	        return f.eql(p, f.ZERO) || f.eql(p, f.ONE);
	    };
	}
	// CURVE.n lengths
	function nLength(n, nBitLength) {
	    // Bit size, byte size of CURVE.n
	    const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
	    const nByteLength = Math.ceil(_nBitLength / 8);
	    return { nBitLength: _nBitLength, nByteLength };
	}
	/**
	 * Initializes a finite field over prime.
	 * Major performance optimizations:
	 * * a) denormalized operations like mulN instead of mul
	 * * b) same object shape: never add or remove keys
	 * * c) Object.freeze
	 * Fragile: always run a benchmark on a change.
	 * Security note: operations don't check 'isValid' for all elements for performance reasons,
	 * it is caller responsibility to check this.
	 * This is low-level code, please make sure you know what you're doing.
	 * @param ORDER prime positive bigint
	 * @param bitLen how many bits the field consumes
	 * @param isLE (def: false) if encoding / decoding should be in little-endian
	 * @param redef optional faster redefinitions of sqrt and other methods
	 */
	function Field(ORDER, bitLen, isLE = false, redef = {}) {
	    if (ORDER <= _0n)
	        throw new Error('invalid field: expected ORDER > 0, got ' + ORDER);
	    const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen);
	    if (BYTES > 2048)
	        throw new Error('invalid field: expected ORDER of <= 2048 bytes');
	    let sqrtP; // cached sqrtP
	    const f = Object.freeze({
	        ORDER,
	        isLE,
	        BITS,
	        BYTES,
	        MASK: (0, utils_js_1.bitMask)(BITS),
	        ZERO: _0n,
	        ONE: _1n,
	        create: (num) => mod(num, ORDER),
	        isValid: (num) => {
	            if (typeof num !== 'bigint')
	                throw new Error('invalid field element: expected bigint, got ' + typeof num);
	            return _0n <= num && num < ORDER; // 0 is valid element, but it's not invertible
	        },
	        is0: (num) => num === _0n,
	        isOdd: (num) => (num & _1n) === _1n,
	        neg: (num) => mod(-num, ORDER),
	        eql: (lhs, rhs) => lhs === rhs,
	        sqr: (num) => mod(num * num, ORDER),
	        add: (lhs, rhs) => mod(lhs + rhs, ORDER),
	        sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
	        mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
	        pow: (num, power) => FpPow(f, num, power),
	        div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
	        // Same as above, but doesn't normalize
	        sqrN: (num) => num * num,
	        addN: (lhs, rhs) => lhs + rhs,
	        subN: (lhs, rhs) => lhs - rhs,
	        mulN: (lhs, rhs) => lhs * rhs,
	        inv: (num) => invert(num, ORDER),
	        sqrt: redef.sqrt ||
	            ((n) => {
	                if (!sqrtP)
	                    sqrtP = FpSqrt(ORDER);
	                return sqrtP(f, n);
	            }),
	        invertBatch: (lst) => FpInvertBatch(f, lst),
	        // TODO: do we really need constant cmov?
	        // We don't have const-time bigints anyway, so probably will be not very useful
	        cmov: (a, b, c) => (c ? b : a),
	        toBytes: (num) => (isLE ? (0, utils_js_1.numberToBytesLE)(num, BYTES) : (0, utils_js_1.numberToBytesBE)(num, BYTES)),
	        fromBytes: (bytes) => {
	            if (bytes.length !== BYTES)
	                throw new Error('Field.fromBytes: expected ' + BYTES + ' bytes, got ' + bytes.length);
	            return isLE ? (0, utils_js_1.bytesToNumberLE)(bytes) : (0, utils_js_1.bytesToNumberBE)(bytes);
	        },
	    });
	    return Object.freeze(f);
	}
	function FpSqrtOdd(Fp, elm) {
	    if (!Fp.isOdd)
	        throw new Error("Field doesn't have isOdd");
	    const root = Fp.sqrt(elm);
	    return Fp.isOdd(root) ? root : Fp.neg(root);
	}
	function FpSqrtEven(Fp, elm) {
	    if (!Fp.isOdd)
	        throw new Error("Field doesn't have isOdd");
	    const root = Fp.sqrt(elm);
	    return Fp.isOdd(root) ? Fp.neg(root) : root;
	}
	/**
	 * "Constant-time" private key generation utility.
	 * Same as mapKeyToField, but accepts less bytes (40 instead of 48 for 32-byte field).
	 * Which makes it slightly more biased, less secure.
	 * @deprecated use `mapKeyToField` instead
	 */
	function hashToPrivateScalar(hash, groupOrder, isLE = false) {
	    hash = (0, utils_js_1.ensureBytes)('privateHash', hash);
	    const hashLen = hash.length;
	    const minLen = nLength(groupOrder).nByteLength + 8;
	    if (minLen < 24 || hashLen < minLen || hashLen > 1024)
	        throw new Error('hashToPrivateScalar: expected ' + minLen + '-1024 bytes of input, got ' + hashLen);
	    const num = isLE ? (0, utils_js_1.bytesToNumberLE)(hash) : (0, utils_js_1.bytesToNumberBE)(hash);
	    return mod(num, groupOrder - _1n) + _1n;
	}
	/**
	 * Returns total number of bytes consumed by the field element.
	 * For example, 32 bytes for usual 256-bit weierstrass curve.
	 * @param fieldOrder number of field elements, usually CURVE.n
	 * @returns byte length of field
	 */
	function getFieldBytesLength(fieldOrder) {
	    if (typeof fieldOrder !== 'bigint')
	        throw new Error('field order must be bigint');
	    const bitLength = fieldOrder.toString(2).length;
	    return Math.ceil(bitLength / 8);
	}
	/**
	 * Returns minimal amount of bytes that can be safely reduced
	 * by field order.
	 * Should be 2^-128 for 128-bit curve such as P256.
	 * @param fieldOrder number of field elements, usually CURVE.n
	 * @returns byte length of target hash
	 */
	function getMinHashLength(fieldOrder) {
	    const length = getFieldBytesLength(fieldOrder);
	    return length + Math.ceil(length / 2);
	}
	/**
	 * "Constant-time" private key generation utility.
	 * Can take (n + n/2) or more bytes of uniform input e.g. from CSPRNG or KDF
	 * and convert them into private scalar, with the modulo bias being negligible.
	 * Needs at least 48 bytes of input for 32-byte private key.
	 * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
	 * FIPS 186-5, A.2 https://csrc.nist.gov/publications/detail/fips/186/5/final
	 * RFC 9380, https://www.rfc-editor.org/rfc/rfc9380#section-5
	 * @param hash hash output from SHA3 or a similar function
	 * @param groupOrder size of subgroup - (e.g. secp256k1.CURVE.n)
	 * @param isLE interpret hash bytes as LE num
	 * @returns valid private scalar
	 */
	function mapHashToField(key, fieldOrder, isLE = false) {
	    const len = key.length;
	    const fieldLen = getFieldBytesLength(fieldOrder);
	    const minLen = getMinHashLength(fieldOrder);
	    // No small numbers: need to understand bias story. No huge numbers: easier to detect JS timings.
	    if (len < 16 || len < minLen || len > 1024)
	        throw new Error('expected ' + minLen + '-1024 bytes of input, got ' + len);
	    const num = isLE ? (0, utils_js_1.bytesToNumberLE)(key) : (0, utils_js_1.bytesToNumberBE)(key);
	    // `mod(x, 11)` can sometimes produce 0. `mod(x, 10) + 1` is the same, but no 0
	    const reduced = mod(num, fieldOrder - _1n) + _1n;
	    return isLE ? (0, utils_js_1.numberToBytesLE)(reduced, fieldLen) : (0, utils_js_1.numberToBytesBE)(reduced, fieldLen);
	}
	
	return modular;
}

var hasRequiredCurve;

function requireCurve () {
	if (hasRequiredCurve) return curve;
	hasRequiredCurve = 1;
	Object.defineProperty(curve, "__esModule", { value: true });
	curve.wNAF = wNAF;
	curve.pippenger = pippenger;
	curve.precomputeMSMUnsafe = precomputeMSMUnsafe;
	curve.validateBasic = validateBasic;
	/**
	 * Methods for elliptic curve multiplication by scalars.
	 * Contains wNAF, pippenger
	 * @module
	 */
	/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
	const modular_js_1 = /*@__PURE__*/ requireModular();
	const utils_js_1 = /*@__PURE__*/ requireUtils$1();
	const _0n = BigInt(0);
	const _1n = BigInt(1);
	function constTimeNegate(condition, item) {
	    const neg = item.negate();
	    return condition ? neg : item;
	}
	function validateW(W, bits) {
	    if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
	        throw new Error('invalid window size, expected [1..' + bits + '], got W=' + W);
	}
	function calcWOpts(W, bits) {
	    validateW(W, bits);
	    const windows = Math.ceil(bits / W) + 1; // +1, because
	    const windowSize = 2 ** (W - 1); // -1 because we skip zero
	    return { windows, windowSize };
	}
	function validateMSMPoints(points, c) {
	    if (!Array.isArray(points))
	        throw new Error('array expected');
	    points.forEach((p, i) => {
	        if (!(p instanceof c))
	            throw new Error('invalid point at index ' + i);
	    });
	}
	function validateMSMScalars(scalars, field) {
	    if (!Array.isArray(scalars))
	        throw new Error('array of scalars expected');
	    scalars.forEach((s, i) => {
	        if (!field.isValid(s))
	            throw new Error('invalid scalar at index ' + i);
	    });
	}
	// Since points in different groups cannot be equal (different object constructor),
	// we can have single place to store precomputes
	const pointPrecomputes = new WeakMap();
	const pointWindowSizes = new WeakMap(); // This allows use make points immutable (nothing changes inside)
	function getW(P) {
	    return pointWindowSizes.get(P) || 1;
	}
	/**
	 * Elliptic curve multiplication of Point by scalar. Fragile.
	 * Scalars should always be less than curve order: this should be checked inside of a curve itself.
	 * Creates precomputation tables for fast multiplication:
	 * - private scalar is split by fixed size windows of W bits
	 * - every window point is collected from window's table & added to accumulator
	 * - since windows are different, same point inside tables won't be accessed more than once per calc
	 * - each multiplication is 'Math.ceil(CURVE_ORDER / 𝑊) + 1' point additions (fixed for any scalar)
	 * - +1 window is neccessary for wNAF
	 * - wNAF reduces table size: 2x less memory + 2x faster generation, but 10% slower multiplication
	 *
	 * @todo Research returning 2d JS array of windows, instead of a single window.
	 * This would allow windows to be in different memory locations
	 */
	function wNAF(c, bits) {
	    return {
	        constTimeNegate,
	        hasPrecomputes(elm) {
	            return getW(elm) !== 1;
	        },
	        // non-const time multiplication ladder
	        unsafeLadder(elm, n, p = c.ZERO) {
	            let d = elm;
	            while (n > _0n) {
	                if (n & _1n)
	                    p = p.add(d);
	                d = d.double();
	                n >>= _1n;
	            }
	            return p;
	        },
	        /**
	         * Creates a wNAF precomputation window. Used for caching.
	         * Default window size is set by `utils.precompute()` and is equal to 8.
	         * Number of precomputed points depends on the curve size:
	         * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
	         * - 𝑊 is the window size
	         * - 𝑛 is the bitlength of the curve order.
	         * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
	         * @param elm Point instance
	         * @param W window size
	         * @returns precomputed point tables flattened to a single array
	         */
	        precomputeWindow(elm, W) {
	            const { windows, windowSize } = calcWOpts(W, bits);
	            const points = [];
	            let p = elm;
	            let base = p;
	            for (let window = 0; window < windows; window++) {
	                base = p;
	                points.push(base);
	                // =1, because we skip zero
	                for (let i = 1; i < windowSize; i++) {
	                    base = base.add(p);
	                    points.push(base);
	                }
	                p = base.double();
	            }
	            return points;
	        },
	        /**
	         * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
	         * @param W window size
	         * @param precomputes precomputed tables
	         * @param n scalar (we don't check here, but should be less than curve order)
	         * @returns real and fake (for const-time) points
	         */
	        wNAF(W, precomputes, n) {
	            // TODO: maybe check that scalar is less than group order? wNAF behavious is undefined otherwise
	            // But need to carefully remove other checks before wNAF. ORDER == bits here
	            const { windows, windowSize } = calcWOpts(W, bits);
	            let p = c.ZERO;
	            let f = c.BASE;
	            const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b1111 for W=4 etc.
	            const maxNumber = 2 ** W;
	            const shiftBy = BigInt(W);
	            for (let window = 0; window < windows; window++) {
	                const offset = window * windowSize;
	                // Extract W bits.
	                let wbits = Number(n & mask);
	                // Shift number by W bits.
	                n >>= shiftBy;
	                // If the bits are bigger than max size, we'll split those.
	                // +224 => 256 - 32
	                if (wbits > windowSize) {
	                    wbits -= maxNumber;
	                    n += _1n;
	                }
	                // This code was first written with assumption that 'f' and 'p' will never be infinity point:
	                // since each addition is multiplied by 2 ** W, it cannot cancel each other. However,
	                // there is negate now: it is possible that negated element from low value
	                // would be the same as high element, which will create carry into next window.
	                // It's not obvious how this can fail, but still worth investigating later.
	                // Check if we're onto Zero point.
	                // Add random point inside current window to f.
	                const offset1 = offset;
	                const offset2 = offset + Math.abs(wbits) - 1; // -1 because we skip zero
	                const cond1 = window % 2 !== 0;
	                const cond2 = wbits < 0;
	                if (wbits === 0) {
	                    // The most important part for const-time getPublicKey
	                    f = f.add(constTimeNegate(cond1, precomputes[offset1]));
	                }
	                else {
	                    p = p.add(constTimeNegate(cond2, precomputes[offset2]));
	                }
	            }
	            // JIT-compiler should not eliminate f here, since it will later be used in normalizeZ()
	            // Even if the variable is still unused, there are some checks which will
	            // throw an exception, so compiler needs to prove they won't happen, which is hard.
	            // At this point there is a way to F be infinity-point even if p is not,
	            // which makes it less const-time: around 1 bigint multiply.
	            return { p, f };
	        },
	        /**
	         * Implements ec unsafe (non const-time) multiplication using precomputed tables and w-ary non-adjacent form.
	         * @param W window size
	         * @param precomputes precomputed tables
	         * @param n scalar (we don't check here, but should be less than curve order)
	         * @param acc accumulator point to add result of multiplication
	         * @returns point
	         */
	        wNAFUnsafe(W, precomputes, n, acc = c.ZERO) {
	            const { windows, windowSize } = calcWOpts(W, bits);
	            const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b1111 for W=4 etc.
	            const maxNumber = 2 ** W;
	            const shiftBy = BigInt(W);
	            for (let window = 0; window < windows; window++) {
	                const offset = window * windowSize;
	                if (n === _0n)
	                    break; // No need to go over empty scalar
	                // Extract W bits.
	                let wbits = Number(n & mask);
	                // Shift number by W bits.
	                n >>= shiftBy;
	                // If the bits are bigger than max size, we'll split those.
	                // +224 => 256 - 32
	                if (wbits > windowSize) {
	                    wbits -= maxNumber;
	                    n += _1n;
	                }
	                if (wbits === 0)
	                    continue;
	                let curr = precomputes[offset + Math.abs(wbits) - 1]; // -1 because we skip zero
	                if (wbits < 0)
	                    curr = curr.negate();
	                // NOTE: by re-using acc, we can save a lot of additions in case of MSM
	                acc = acc.add(curr);
	            }
	            return acc;
	        },
	        getPrecomputes(W, P, transform) {
	            // Calculate precomputes on a first run, reuse them after
	            let comp = pointPrecomputes.get(P);
	            if (!comp) {
	                comp = this.precomputeWindow(P, W);
	                if (W !== 1)
	                    pointPrecomputes.set(P, transform(comp));
	            }
	            return comp;
	        },
	        wNAFCached(P, n, transform) {
	            const W = getW(P);
	            return this.wNAF(W, this.getPrecomputes(W, P, transform), n);
	        },
	        wNAFCachedUnsafe(P, n, transform, prev) {
	            const W = getW(P);
	            if (W === 1)
	                return this.unsafeLadder(P, n, prev); // For W=1 ladder is ~x2 faster
	            return this.wNAFUnsafe(W, this.getPrecomputes(W, P, transform), n, prev);
	        },
	        // We calculate precomputes for elliptic curve point multiplication
	        // using windowed method. This specifies window size and
	        // stores precomputed values. Usually only base point would be precomputed.
	        setWindowSize(P, W) {
	            validateW(W, bits);
	            pointWindowSizes.set(P, W);
	            pointPrecomputes.delete(P);
	        },
	    };
	}
	/**
	 * Pippenger algorithm for multi-scalar multiplication (MSM, Pa + Qb + Rc + ...).
	 * 30x faster vs naive addition on L=4096, 10x faster with precomputes.
	 * For N=254bit, L=1, it does: 1024 ADD + 254 DBL. For L=5: 1536 ADD + 254 DBL.
	 * Algorithmically constant-time (for same L), even when 1 point + scalar, or when scalar = 0.
	 * @param c Curve Point constructor
	 * @param fieldN field over CURVE.N - important that it's not over CURVE.P
	 * @param points array of L curve points
	 * @param scalars array of L scalars (aka private keys / bigints)
	 */
	function pippenger(c, fieldN, points, scalars) {
	    // If we split scalars by some window (let's say 8 bits), every chunk will only
	    // take 256 buckets even if there are 4096 scalars, also re-uses double.
	    // TODO:
	    // - https://eprint.iacr.org/2024/750.pdf
	    // - https://tches.iacr.org/index.php/TCHES/article/view/10287
	    // 0 is accepted in scalars
	    validateMSMPoints(points, c);
	    validateMSMScalars(scalars, fieldN);
	    if (points.length !== scalars.length)
	        throw new Error('arrays of points and scalars must have equal length');
	    const zero = c.ZERO;
	    const wbits = (0, utils_js_1.bitLen)(BigInt(points.length));
	    const windowSize = wbits > 12 ? wbits - 3 : wbits > 4 ? wbits - 2 : wbits ? 2 : 1; // in bits
	    const MASK = (1 << windowSize) - 1;
	    const buckets = new Array(MASK + 1).fill(zero); // +1 for zero array
	    const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
	    let sum = zero;
	    for (let i = lastBits; i >= 0; i -= windowSize) {
	        buckets.fill(zero);
	        for (let j = 0; j < scalars.length; j++) {
	            const scalar = scalars[j];
	            const wbits = Number((scalar >> BigInt(i)) & BigInt(MASK));
	            buckets[wbits] = buckets[wbits].add(points[j]);
	        }
	        let resI = zero; // not using this will do small speed-up, but will lose ct
	        // Skip first bucket, because it is zero
	        for (let j = buckets.length - 1, sumI = zero; j > 0; j--) {
	            sumI = sumI.add(buckets[j]);
	            resI = resI.add(sumI);
	        }
	        sum = sum.add(resI);
	        if (i !== 0)
	            for (let j = 0; j < windowSize; j++)
	                sum = sum.double();
	    }
	    return sum;
	}
	/**
	 * Precomputed multi-scalar multiplication (MSM, Pa + Qb + Rc + ...).
	 * @param c Curve Point constructor
	 * @param fieldN field over CURVE.N - important that it's not over CURVE.P
	 * @param points array of L curve points
	 * @returns function which multiplies points with scaars
	 */
	function precomputeMSMUnsafe(c, fieldN, points, windowSize) {
	    /**
	     * Performance Analysis of Window-based Precomputation
	     *
	     * Base Case (256-bit scalar, 8-bit window):
	     * - Standard precomputation requires:
	     *   - 31 additions per scalar × 256 scalars = 7,936 ops
	     *   - Plus 255 summary additions = 8,191 total ops
	     *   Note: Summary additions can be optimized via accumulator
	     *
	     * Chunked Precomputation Analysis:
	     * - Using 32 chunks requires:
	     *   - 255 additions per chunk
	     *   - 256 doublings
	     *   - Total: (255 × 32) + 256 = 8,416 ops
	     *
	     * Memory Usage Comparison:
	     * Window Size | Standard Points | Chunked Points
	     * ------------|-----------------|---------------
	     *     4-bit   |     520         |      15
	     *     8-bit   |    4,224        |     255
	     *    10-bit   |   13,824        |   1,023
	     *    16-bit   |  557,056        |  65,535
	     *
	     * Key Advantages:
	     * 1. Enables larger window sizes due to reduced memory overhead
	     * 2. More efficient for smaller scalar counts:
	     *    - 16 chunks: (16 × 255) + 256 = 4,336 ops
	     *    - ~2x faster than standard 8,191 ops
	     *
	     * Limitations:
	     * - Not suitable for plain precomputes (requires 256 constant doublings)
	     * - Performance degrades with larger scalar counts:
	     *   - Optimal for ~256 scalars
	     *   - Less efficient for 4096+ scalars (Pippenger preferred)
	     */
	    validateW(windowSize, fieldN.BITS);
	    validateMSMPoints(points, c);
	    const zero = c.ZERO;
	    const tableSize = 2 ** windowSize - 1; // table size (without zero)
	    const chunks = Math.ceil(fieldN.BITS / windowSize); // chunks of item
	    const MASK = BigInt((1 << windowSize) - 1);
	    const tables = points.map((p) => {
	        const res = [];
	        for (let i = 0, acc = p; i < tableSize; i++) {
	            res.push(acc);
	            acc = acc.add(p);
	        }
	        return res;
	    });
	    return (scalars) => {
	        validateMSMScalars(scalars, fieldN);
	        if (scalars.length > points.length)
	            throw new Error('array of scalars must be smaller than array of points');
	        let res = zero;
	        for (let i = 0; i < chunks; i++) {
	            // No need to double if accumulator is still zero.
	            if (res !== zero)
	                for (let j = 0; j < windowSize; j++)
	                    res = res.double();
	            const shiftBy = BigInt(chunks * windowSize - (i + 1) * windowSize);
	            for (let j = 0; j < scalars.length; j++) {
	                const n = scalars[j];
	                const curr = Number((n >> shiftBy) & MASK);
	                if (!curr)
	                    continue; // skip zero scalars chunks
	                res = res.add(tables[j][curr - 1]);
	            }
	        }
	        return res;
	    };
	}
	function validateBasic(curve) {
	    (0, modular_js_1.validateField)(curve.Fp);
	    (0, utils_js_1.validateObject)(curve, {
	        n: 'bigint',
	        h: 'bigint',
	        Gx: 'field',
	        Gy: 'field',
	    }, {
	        nBitLength: 'isSafeInteger',
	        nByteLength: 'isSafeInteger',
	    });
	    // Set defaults
	    return Object.freeze({
	        ...(0, modular_js_1.nLength)(curve.n, curve.nBitLength),
	        ...curve,
	        ...{ p: curve.Fp.ORDER },
	    });
	}
	
	return curve;
}

var edwards = {};

var hasRequiredEdwards;

function requireEdwards () {
	if (hasRequiredEdwards) return edwards;
	hasRequiredEdwards = 1;
	Object.defineProperty(edwards, "__esModule", { value: true });
	edwards.twistedEdwards = twistedEdwards;
	/**
	 * Twisted Edwards curve. The formula is: ax² + y² = 1 + dx²y².
	 * For design rationale of types / exports, see weierstrass module documentation.
	 * @module
	 */
	/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
	const curve_js_1 = /*@__PURE__*/ requireCurve();
	const modular_js_1 = /*@__PURE__*/ requireModular();
	const ut = /*@__PURE__*/ requireUtils$1();
	const utils_js_1 = /*@__PURE__*/ requireUtils$1();
	// Be friendly to bad ECMAScript parsers by not using bigint literals
	// prettier-ignore
	const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _8n = BigInt(8);
	// verification rule is either zip215 or rfc8032 / nist186-5. Consult fromHex:
	const VERIFY_DEFAULT = { zip215: true };
	function validateOpts(curve) {
	    const opts = (0, curve_js_1.validateBasic)(curve);
	    ut.validateObject(curve, {
	        hash: 'function',
	        a: 'bigint',
	        d: 'bigint',
	        randomBytes: 'function',
	    }, {
	        adjustScalarBytes: 'function',
	        domain: 'function',
	        uvRatio: 'function',
	        mapToCurve: 'function',
	    });
	    // Set defaults
	    return Object.freeze({ ...opts });
	}
	/**
	 * Creates Twisted Edwards curve with EdDSA signatures.
	 * @example
	 * import { Field } from '@noble/curves/abstract/modular';
	 * // Before that, define BigInt-s: a, d, p, n, Gx, Gy, h
	 * const curve = twistedEdwards({ a, d, Fp: Field(p), n, Gx, Gy, h })
	 */
	function twistedEdwards(curveDef) {
	    const CURVE = validateOpts(curveDef);
	    const { Fp, n: CURVE_ORDER, prehash: prehash, hash: cHash, randomBytes, nByteLength, h: cofactor, } = CURVE;
	    // Important:
	    // There are some places where Fp.BYTES is used instead of nByteLength.
	    // So far, everything has been tested with curves of Fp.BYTES == nByteLength.
	    // TODO: test and find curves which behave otherwise.
	    const MASK = _2n << (BigInt(nByteLength * 8) - _1n);
	    const modP = Fp.create; // Function overrides
	    const Fn = (0, modular_js_1.Field)(CURVE.n, CURVE.nBitLength);
	    // sqrt(u/v)
	    const uvRatio = CURVE.uvRatio ||
	        ((u, v) => {
	            try {
	                return { isValid: true, value: Fp.sqrt(u * Fp.inv(v)) };
	            }
	            catch (e) {
	                return { isValid: false, value: _0n };
	            }
	        });
	    const adjustScalarBytes = CURVE.adjustScalarBytes || ((bytes) => bytes); // NOOP
	    const domain = CURVE.domain ||
	        ((data, ctx, phflag) => {
	            (0, utils_js_1.abool)('phflag', phflag);
	            if (ctx.length || phflag)
	                throw new Error('Contexts/pre-hash are not supported');
	            return data;
	        }); // NOOP
	    // 0 <= n < MASK
	    // Coordinates larger than Fp.ORDER are allowed for zip215
	    function aCoordinate(title, n) {
	        ut.aInRange('coordinate ' + title, n, _0n, MASK);
	    }
	    function assertPoint(other) {
	        if (!(other instanceof Point))
	            throw new Error('ExtendedPoint expected');
	    }
	    // Converts Extended point to default (x, y) coordinates.
	    // Can accept precomputed Z^-1 - for example, from invertBatch.
	    const toAffineMemo = (0, utils_js_1.memoized)((p, iz) => {
	        const { ex: x, ey: y, ez: z } = p;
	        const is0 = p.is0();
	        if (iz == null)
	            iz = is0 ? _8n : Fp.inv(z); // 8 was chosen arbitrarily
	        const ax = modP(x * iz);
	        const ay = modP(y * iz);
	        const zz = modP(z * iz);
	        if (is0)
	            return { x: _0n, y: _1n };
	        if (zz !== _1n)
	            throw new Error('invZ was invalid');
	        return { x: ax, y: ay };
	    });
	    const assertValidMemo = (0, utils_js_1.memoized)((p) => {
	        const { a, d } = CURVE;
	        if (p.is0())
	            throw new Error('bad point: ZERO'); // TODO: optimize, with vars below?
	        // Equation in affine coordinates: ax² + y² = 1 + dx²y²
	        // Equation in projective coordinates (X/Z, Y/Z, Z):  (aX² + Y²)Z² = Z⁴ + dX²Y²
	        const { ex: X, ey: Y, ez: Z, et: T } = p;
	        const X2 = modP(X * X); // X²
	        const Y2 = modP(Y * Y); // Y²
	        const Z2 = modP(Z * Z); // Z²
	        const Z4 = modP(Z2 * Z2); // Z⁴
	        const aX2 = modP(X2 * a); // aX²
	        const left = modP(Z2 * modP(aX2 + Y2)); // (aX² + Y²)Z²
	        const right = modP(Z4 + modP(d * modP(X2 * Y2))); // Z⁴ + dX²Y²
	        if (left !== right)
	            throw new Error('bad point: equation left != right (1)');
	        // In Extended coordinates we also have T, which is x*y=T/Z: check X*Y == Z*T
	        const XY = modP(X * Y);
	        const ZT = modP(Z * T);
	        if (XY !== ZT)
	            throw new Error('bad point: equation left != right (2)');
	        return true;
	    });
	    // Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy).
	    // https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
	    class Point {
	        constructor(ex, ey, ez, et) {
	            this.ex = ex;
	            this.ey = ey;
	            this.ez = ez;
	            this.et = et;
	            aCoordinate('x', ex);
	            aCoordinate('y', ey);
	            aCoordinate('z', ez);
	            aCoordinate('t', et);
	            Object.freeze(this);
	        }
	        get x() {
	            return this.toAffine().x;
	        }
	        get y() {
	            return this.toAffine().y;
	        }
	        static fromAffine(p) {
	            if (p instanceof Point)
	                throw new Error('extended point not allowed');
	            const { x, y } = p || {};
	            aCoordinate('x', x);
	            aCoordinate('y', y);
	            return new Point(x, y, _1n, modP(x * y));
	        }
	        static normalizeZ(points) {
	            const toInv = Fp.invertBatch(points.map((p) => p.ez));
	            return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
	        }
	        // Multiscalar Multiplication
	        static msm(points, scalars) {
	            return (0, curve_js_1.pippenger)(Point, Fn, points, scalars);
	        }
	        // "Private method", don't use it directly
	        _setWindowSize(windowSize) {
	            wnaf.setWindowSize(this, windowSize);
	        }
	        // Not required for fromHex(), which always creates valid points.
	        // Could be useful for fromAffine().
	        assertValidity() {
	            assertValidMemo(this);
	        }
	        // Compare one point to another.
	        equals(other) {
	            assertPoint(other);
	            const { ex: X1, ey: Y1, ez: Z1 } = this;
	            const { ex: X2, ey: Y2, ez: Z2 } = other;
	            const X1Z2 = modP(X1 * Z2);
	            const X2Z1 = modP(X2 * Z1);
	            const Y1Z2 = modP(Y1 * Z2);
	            const Y2Z1 = modP(Y2 * Z1);
	            return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
	        }
	        is0() {
	            return this.equals(Point.ZERO);
	        }
	        negate() {
	            // Flips point sign to a negative one (-x, y in affine coords)
	            return new Point(modP(-this.ex), this.ey, this.ez, modP(-this.et));
	        }
	        // Fast algo for doubling Extended Point.
	        // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
	        // Cost: 4M + 4S + 1*a + 6add + 1*2.
	        double() {
	            const { a } = CURVE;
	            const { ex: X1, ey: Y1, ez: Z1 } = this;
	            const A = modP(X1 * X1); // A = X12
	            const B = modP(Y1 * Y1); // B = Y12
	            const C = modP(_2n * modP(Z1 * Z1)); // C = 2*Z12
	            const D = modP(a * A); // D = a*A
	            const x1y1 = X1 + Y1;
	            const E = modP(modP(x1y1 * x1y1) - A - B); // E = (X1+Y1)2-A-B
	            const G = D + B; // G = D+B
	            const F = G - C; // F = G-C
	            const H = D - B; // H = D-B
	            const X3 = modP(E * F); // X3 = E*F
	            const Y3 = modP(G * H); // Y3 = G*H
	            const T3 = modP(E * H); // T3 = E*H
	            const Z3 = modP(F * G); // Z3 = F*G
	            return new Point(X3, Y3, Z3, T3);
	        }
	        // Fast algo for adding 2 Extended Points.
	        // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
	        // Cost: 9M + 1*a + 1*d + 7add.
	        add(other) {
	            assertPoint(other);
	            const { a, d } = CURVE;
	            const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this;
	            const { ex: X2, ey: Y2, ez: Z2, et: T2 } = other;
	            // Faster algo for adding 2 Extended Points when curve's a=-1.
	            // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-4
	            // Cost: 8M + 8add + 2*2.
	            // Note: It does not check whether the `other` point is valid.
	            if (a === BigInt(-1)) {
	                const A = modP((Y1 - X1) * (Y2 + X2));
	                const B = modP((Y1 + X1) * (Y2 - X2));
	                const F = modP(B - A);
	                if (F === _0n)
	                    return this.double(); // Same point. Tests say it doesn't affect timing
	                const C = modP(Z1 * _2n * T2);
	                const D = modP(T1 * _2n * Z2);
	                const E = D + C;
	                const G = B + A;
	                const H = D - C;
	                const X3 = modP(E * F);
	                const Y3 = modP(G * H);
	                const T3 = modP(E * H);
	                const Z3 = modP(F * G);
	                return new Point(X3, Y3, Z3, T3);
	            }
	            const A = modP(X1 * X2); // A = X1*X2
	            const B = modP(Y1 * Y2); // B = Y1*Y2
	            const C = modP(T1 * d * T2); // C = T1*d*T2
	            const D = modP(Z1 * Z2); // D = Z1*Z2
	            const E = modP((X1 + Y1) * (X2 + Y2) - A - B); // E = (X1+Y1)*(X2+Y2)-A-B
	            const F = D - C; // F = D-C
	            const G = D + C; // G = D+C
	            const H = modP(B - a * A); // H = B-a*A
	            const X3 = modP(E * F); // X3 = E*F
	            const Y3 = modP(G * H); // Y3 = G*H
	            const T3 = modP(E * H); // T3 = E*H
	            const Z3 = modP(F * G); // Z3 = F*G
	            return new Point(X3, Y3, Z3, T3);
	        }
	        subtract(other) {
	            return this.add(other.negate());
	        }
	        wNAF(n) {
	            return wnaf.wNAFCached(this, n, Point.normalizeZ);
	        }
	        // Constant-time multiplication.
	        multiply(scalar) {
	            const n = scalar;
	            ut.aInRange('scalar', n, _1n, CURVE_ORDER); // 1 <= scalar < L
	            const { p, f } = this.wNAF(n);
	            return Point.normalizeZ([p, f])[0];
	        }
	        // Non-constant-time multiplication. Uses double-and-add algorithm.
	        // It's faster, but should only be used when you don't care about
	        // an exposed private key e.g. sig verification.
	        // Does NOT allow scalars higher than CURVE.n.
	        // Accepts optional accumulator to merge with multiply (important for sparse scalars)
	        multiplyUnsafe(scalar, acc = Point.ZERO) {
	            const n = scalar;
	            ut.aInRange('scalar', n, _0n, CURVE_ORDER); // 0 <= scalar < L
	            if (n === _0n)
	                return I;
	            if (this.is0() || n === _1n)
	                return this;
	            return wnaf.wNAFCachedUnsafe(this, n, Point.normalizeZ, acc);
	        }
	        // Checks if point is of small order.
	        // If you add something to small order point, you will have "dirty"
	        // point with torsion component.
	        // Multiplies point by cofactor and checks if the result is 0.
	        isSmallOrder() {
	            return this.multiplyUnsafe(cofactor).is0();
	        }
	        // Multiplies point by curve order and checks if the result is 0.
	        // Returns `false` is the point is dirty.
	        isTorsionFree() {
	            return wnaf.unsafeLadder(this, CURVE_ORDER).is0();
	        }
	        // Converts Extended point to default (x, y) coordinates.
	        // Can accept precomputed Z^-1 - for example, from invertBatch.
	        toAffine(iz) {
	            return toAffineMemo(this, iz);
	        }
	        clearCofactor() {
	            const { h: cofactor } = CURVE;
	            if (cofactor === _1n)
	                return this;
	            return this.multiplyUnsafe(cofactor);
	        }
	        // Converts hash string or Uint8Array to Point.
	        // Uses algo from RFC8032 5.1.3.
	        static fromHex(hex, zip215 = false) {
	            const { d, a } = CURVE;
	            const len = Fp.BYTES;
	            hex = (0, utils_js_1.ensureBytes)('pointHex', hex, len); // copy hex to a new array
	            (0, utils_js_1.abool)('zip215', zip215);
	            const normed = hex.slice(); // copy again, we'll manipulate it
	            const lastByte = hex[len - 1]; // select last byte
	            normed[len - 1] = lastByte & ~0x80; // clear last bit
	            const y = ut.bytesToNumberLE(normed);
	            // zip215=true is good for consensus-critical apps. =false follows RFC8032 / NIST186-5.
	            // RFC8032 prohibits >= p, but ZIP215 doesn't
	            // zip215=true:  0 <= y < MASK (2^256 for ed25519)
	            // zip215=false: 0 <= y < P (2^255-19 for ed25519)
	            const max = zip215 ? MASK : Fp.ORDER;
	            ut.aInRange('pointHex.y', y, _0n, max);
	            // Ed25519: x² = (y²-1)/(dy²+1) mod p. Ed448: x² = (y²-1)/(dy²-1) mod p. Generic case:
	            // ax²+y²=1+dx²y² => y²-1=dx²y²-ax² => y²-1=x²(dy²-a) => x²=(y²-1)/(dy²-a)
	            const y2 = modP(y * y); // denominator is always non-0 mod p.
	            const u = modP(y2 - _1n); // u = y² - 1
	            const v = modP(d * y2 - a); // v = d y² + 1.
	            let { isValid, value: x } = uvRatio(u, v); // √(u/v)
	            if (!isValid)
	                throw new Error('Point.fromHex: invalid y coordinate');
	            const isXOdd = (x & _1n) === _1n; // There are 2 square roots. Use x_0 bit to select proper
	            const isLastByteOdd = (lastByte & 0x80) !== 0; // x_0, last bit
	            if (!zip215 && x === _0n && isLastByteOdd)
	                // if x=0 and x_0 = 1, fail
	                throw new Error('Point.fromHex: x=0 and x_0=1');
	            if (isLastByteOdd !== isXOdd)
	                x = modP(-x); // if x_0 != x mod 2, set x = p-x
	            return Point.fromAffine({ x, y });
	        }
	        static fromPrivateKey(privKey) {
	            return getExtendedPublicKey(privKey).point;
	        }
	        toRawBytes() {
	            const { x, y } = this.toAffine();
	            const bytes = ut.numberToBytesLE(y, Fp.BYTES); // each y has 2 x values (x, -y)
	            bytes[bytes.length - 1] |= x & _1n ? 0x80 : 0; // when compressing, it's enough to store y
	            return bytes; // and use the last byte to encode sign of x
	        }
	        toHex() {
	            return ut.bytesToHex(this.toRawBytes()); // Same as toRawBytes, but returns string.
	        }
	    }
	    Point.BASE = new Point(CURVE.Gx, CURVE.Gy, _1n, modP(CURVE.Gx * CURVE.Gy));
	    Point.ZERO = new Point(_0n, _1n, _1n, _0n); // 0, 1, 1, 0
	    const { BASE: G, ZERO: I } = Point;
	    const wnaf = (0, curve_js_1.wNAF)(Point, nByteLength * 8);
	    function modN(a) {
	        return (0, modular_js_1.mod)(a, CURVE_ORDER);
	    }
	    // Little-endian SHA512 with modulo n
	    function modN_LE(hash) {
	        return modN(ut.bytesToNumberLE(hash));
	    }
	    /** Convenience method that creates public key and other stuff. RFC8032 5.1.5 */
	    function getExtendedPublicKey(key) {
	        const len = Fp.BYTES;
	        key = (0, utils_js_1.ensureBytes)('private key', key, len);
	        // Hash private key with curve's hash function to produce uniformingly random input
	        // Check byte lengths: ensure(64, h(ensure(32, key)))
	        const hashed = (0, utils_js_1.ensureBytes)('hashed private key', cHash(key), 2 * len);
	        const head = adjustScalarBytes(hashed.slice(0, len)); // clear first half bits, produce FE
	        const prefix = hashed.slice(len, 2 * len); // second half is called key prefix (5.1.6)
	        const scalar = modN_LE(head); // The actual private scalar
	        const point = G.multiply(scalar); // Point on Edwards curve aka public key
	        const pointBytes = point.toRawBytes(); // Uint8Array representation
	        return { head, prefix, scalar, point, pointBytes };
	    }
	    // Calculates EdDSA pub key. RFC8032 5.1.5. Privkey is hashed. Use first half with 3 bits cleared
	    function getPublicKey(privKey) {
	        return getExtendedPublicKey(privKey).pointBytes;
	    }
	    // int('LE', SHA512(dom2(F, C) || msgs)) mod N
	    function hashDomainToScalar(context = new Uint8Array(), ...msgs) {
	        const msg = ut.concatBytes(...msgs);
	        return modN_LE(cHash(domain(msg, (0, utils_js_1.ensureBytes)('context', context), !!prehash)));
	    }
	    /** Signs message with privateKey. RFC8032 5.1.6 */
	    function sign(msg, privKey, options = {}) {
	        msg = (0, utils_js_1.ensureBytes)('message', msg);
	        if (prehash)
	            msg = prehash(msg); // for ed25519ph etc.
	        const { prefix, scalar, pointBytes } = getExtendedPublicKey(privKey);
	        const r = hashDomainToScalar(options.context, prefix, msg); // r = dom2(F, C) || prefix || PH(M)
	        const R = G.multiply(r).toRawBytes(); // R = rG
	        const k = hashDomainToScalar(options.context, R, pointBytes, msg); // R || A || PH(M)
	        const s = modN(r + k * scalar); // S = (r + k * s) mod L
	        ut.aInRange('signature.s', s, _0n, CURVE_ORDER); // 0 <= s < l
	        const res = ut.concatBytes(R, ut.numberToBytesLE(s, Fp.BYTES));
	        return (0, utils_js_1.ensureBytes)('result', res, Fp.BYTES * 2); // 64-byte signature
	    }
	    const verifyOpts = VERIFY_DEFAULT;
	    /**
	     * Verifies EdDSA signature against message and public key. RFC8032 5.1.7.
	     * An extended group equation is checked.
	     */
	    function verify(sig, msg, publicKey, options = verifyOpts) {
	        const { context, zip215 } = options;
	        const len = Fp.BYTES; // Verifies EdDSA signature against message and public key. RFC8032 5.1.7.
	        sig = (0, utils_js_1.ensureBytes)('signature', sig, 2 * len); // An extended group equation is checked.
	        msg = (0, utils_js_1.ensureBytes)('message', msg);
	        publicKey = (0, utils_js_1.ensureBytes)('publicKey', publicKey, len);
	        if (zip215 !== undefined)
	            (0, utils_js_1.abool)('zip215', zip215);
	        if (prehash)
	            msg = prehash(msg); // for ed25519ph, etc
	        const s = ut.bytesToNumberLE(sig.slice(len, 2 * len));
	        let A, R, SB;
	        try {
	            // zip215=true is good for consensus-critical apps. =false follows RFC8032 / NIST186-5.
	            // zip215=true:  0 <= y < MASK (2^256 for ed25519)
	            // zip215=false: 0 <= y < P (2^255-19 for ed25519)
	            A = Point.fromHex(publicKey, zip215);
	            R = Point.fromHex(sig.slice(0, len), zip215);
	            SB = G.multiplyUnsafe(s); // 0 <= s < l is done inside
	        }
	        catch (error) {
	            return false;
	        }
	        if (!zip215 && A.isSmallOrder())
	            return false;
	        const k = hashDomainToScalar(context, R.toRawBytes(), A.toRawBytes(), msg);
	        const RkA = R.add(A.multiplyUnsafe(k));
	        // Extended group equation
	        // [8][S]B = [8]R + [8][k]A'
	        return RkA.subtract(SB).clearCofactor().equals(Point.ZERO);
	    }
	    G._setWindowSize(8); // Enable precomputes. Slows down first publicKey computation by 20ms.
	    const utils = {
	        getExtendedPublicKey,
	        // ed25519 private keys are uniform 32b. No need to check for modulo bias, like in secp256k1.
	        randomPrivateKey: () => randomBytes(Fp.BYTES),
	        /**
	         * We're doing scalar multiplication (used in getPublicKey etc) with precomputed BASE_POINT
	         * values. This slows down first getPublicKey() by milliseconds (see Speed section),
	         * but allows to speed-up subsequent getPublicKey() calls up to 20x.
	         * @param windowSize 2, 4, 8, 16
	         */
	        precompute(windowSize = 8, point = Point.BASE) {
	            point._setWindowSize(windowSize);
	            point.multiply(BigInt(3));
	            return point;
	        },
	    };
	    return {
	        CURVE,
	        getPublicKey,
	        sign,
	        verify,
	        ExtendedPoint: Point,
	        utils,
	    };
	}
	
	return edwards;
}

var hashToCurve = {};

var hasRequiredHashToCurve;

function requireHashToCurve () {
	if (hasRequiredHashToCurve) return hashToCurve;
	hasRequiredHashToCurve = 1;
	Object.defineProperty(hashToCurve, "__esModule", { value: true });
	hashToCurve.expand_message_xmd = expand_message_xmd;
	hashToCurve.expand_message_xof = expand_message_xof;
	hashToCurve.hash_to_field = hash_to_field;
	hashToCurve.isogenyMap = isogenyMap;
	hashToCurve.createHasher = createHasher;
	const modular_js_1 = /*@__PURE__*/ requireModular();
	const utils_js_1 = /*@__PURE__*/ requireUtils$1();
	// Octet Stream to Integer. "spec" implementation of os2ip is 2.5x slower vs bytesToNumberBE.
	const os2ip = utils_js_1.bytesToNumberBE;
	// Integer to Octet Stream (numberToBytesBE)
	function i2osp(value, length) {
	    anum(value);
	    anum(length);
	    if (value < 0 || value >= 1 << (8 * length))
	        throw new Error('invalid I2OSP input: ' + value);
	    const res = Array.from({ length }).fill(0);
	    for (let i = length - 1; i >= 0; i--) {
	        res[i] = value & 0xff;
	        value >>>= 8;
	    }
	    return new Uint8Array(res);
	}
	function strxor(a, b) {
	    const arr = new Uint8Array(a.length);
	    for (let i = 0; i < a.length; i++) {
	        arr[i] = a[i] ^ b[i];
	    }
	    return arr;
	}
	function anum(item) {
	    if (!Number.isSafeInteger(item))
	        throw new Error('number expected');
	}
	/**
	 * Produces a uniformly random byte string using a cryptographic hash function H that outputs b bits.
	 * [RFC 9380 5.3.1](https://www.rfc-editor.org/rfc/rfc9380#section-5.3.1).
	 */
	function expand_message_xmd(msg, DST, lenInBytes, H) {
	    (0, utils_js_1.abytes)(msg);
	    (0, utils_js_1.abytes)(DST);
	    anum(lenInBytes);
	    // https://www.rfc-editor.org/rfc/rfc9380#section-5.3.3
	    if (DST.length > 255)
	        DST = H((0, utils_js_1.concatBytes)((0, utils_js_1.utf8ToBytes)('H2C-OVERSIZE-DST-'), DST));
	    const { outputLen: b_in_bytes, blockLen: r_in_bytes } = H;
	    const ell = Math.ceil(lenInBytes / b_in_bytes);
	    if (lenInBytes > 65535 || ell > 255)
	        throw new Error('expand_message_xmd: invalid lenInBytes');
	    const DST_prime = (0, utils_js_1.concatBytes)(DST, i2osp(DST.length, 1));
	    const Z_pad = i2osp(0, r_in_bytes);
	    const l_i_b_str = i2osp(lenInBytes, 2); // len_in_bytes_str
	    const b = new Array(ell);
	    const b_0 = H((0, utils_js_1.concatBytes)(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
	    b[0] = H((0, utils_js_1.concatBytes)(b_0, i2osp(1, 1), DST_prime));
	    for (let i = 1; i <= ell; i++) {
	        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
	        b[i] = H((0, utils_js_1.concatBytes)(...args));
	    }
	    const pseudo_random_bytes = (0, utils_js_1.concatBytes)(...b);
	    return pseudo_random_bytes.slice(0, lenInBytes);
	}
	/**
	 * Produces a uniformly random byte string using an extendable-output function (XOF) H.
	 * 1. The collision resistance of H MUST be at least k bits.
	 * 2. H MUST be an XOF that has been proved indifferentiable from
	 *    a random oracle under a reasonable cryptographic assumption.
	 * [RFC 9380 5.3.2](https://www.rfc-editor.org/rfc/rfc9380#section-5.3.2).
	 */
	function expand_message_xof(msg, DST, lenInBytes, k, H) {
	    (0, utils_js_1.abytes)(msg);
	    (0, utils_js_1.abytes)(DST);
	    anum(lenInBytes);
	    // https://www.rfc-editor.org/rfc/rfc9380#section-5.3.3
	    // DST = H('H2C-OVERSIZE-DST-' || a_very_long_DST, Math.ceil((lenInBytes * k) / 8));
	    if (DST.length > 255) {
	        const dkLen = Math.ceil((2 * k) / 8);
	        DST = H.create({ dkLen }).update((0, utils_js_1.utf8ToBytes)('H2C-OVERSIZE-DST-')).update(DST).digest();
	    }
	    if (lenInBytes > 65535 || DST.length > 255)
	        throw new Error('expand_message_xof: invalid lenInBytes');
	    return (H.create({ dkLen: lenInBytes })
	        .update(msg)
	        .update(i2osp(lenInBytes, 2))
	        // 2. DST_prime = DST || I2OSP(len(DST), 1)
	        .update(DST)
	        .update(i2osp(DST.length, 1))
	        .digest());
	}
	/**
	 * Hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
	 * [RFC 9380 5.2](https://www.rfc-editor.org/rfc/rfc9380#section-5.2).
	 * @param msg a byte string containing the message to hash
	 * @param count the number of elements of F to output
	 * @param options `{DST: string, p: bigint, m: number, k: number, expand: 'xmd' | 'xof', hash: H}`, see above
	 * @returns [u_0, ..., u_(count - 1)], a list of field elements.
	 */
	function hash_to_field(msg, count, options) {
	    (0, utils_js_1.validateObject)(options, {
	        DST: 'stringOrUint8Array',
	        p: 'bigint',
	        m: 'isSafeInteger',
	        k: 'isSafeInteger',
	        hash: 'hash',
	    });
	    const { p, k, m, hash, expand, DST: _DST } = options;
	    (0, utils_js_1.abytes)(msg);
	    anum(count);
	    const DST = typeof _DST === 'string' ? (0, utils_js_1.utf8ToBytes)(_DST) : _DST;
	    const log2p = p.toString(2).length;
	    const L = Math.ceil((log2p + k) / 8); // section 5.1 of ietf draft link above
	    const len_in_bytes = count * m * L;
	    let prb; // pseudo_random_bytes
	    if (expand === 'xmd') {
	        prb = expand_message_xmd(msg, DST, len_in_bytes, hash);
	    }
	    else if (expand === 'xof') {
	        prb = expand_message_xof(msg, DST, len_in_bytes, k, hash);
	    }
	    else if (expand === '_internal_pass') {
	        // for internal tests only
	        prb = msg;
	    }
	    else {
	        throw new Error('expand must be "xmd" or "xof"');
	    }
	    const u = new Array(count);
	    for (let i = 0; i < count; i++) {
	        const e = new Array(m);
	        for (let j = 0; j < m; j++) {
	            const elm_offset = L * (j + i * m);
	            const tv = prb.subarray(elm_offset, elm_offset + L);
	            e[j] = (0, modular_js_1.mod)(os2ip(tv), p);
	        }
	        u[i] = e;
	    }
	    return u;
	}
	function isogenyMap(field, map) {
	    // Make same order as in spec
	    const COEFF = map.map((i) => Array.from(i).reverse());
	    return (x, y) => {
	        const [xNum, xDen, yNum, yDen] = COEFF.map((val) => val.reduce((acc, i) => field.add(field.mul(acc, x), i)));
	        x = field.div(xNum, xDen); // xNum / xDen
	        y = field.mul(y, field.div(yNum, yDen)); // y * (yNum / yDev)
	        return { x: x, y: y };
	    };
	}
	/** Creates hash-to-curve methods from EC Point and mapToCurve function. */
	function createHasher(Point, mapToCurve, def) {
	    if (typeof mapToCurve !== 'function')
	        throw new Error('mapToCurve() must be defined');
	    return {
	        // Encodes byte string to elliptic curve.
	        // hash_to_curve from https://www.rfc-editor.org/rfc/rfc9380#section-3
	        hashToCurve(msg, options) {
	            const u = hash_to_field(msg, 2, { ...def, DST: def.DST, ...options });
	            const u0 = Point.fromAffine(mapToCurve(u[0]));
	            const u1 = Point.fromAffine(mapToCurve(u[1]));
	            const P = u0.add(u1).clearCofactor();
	            P.assertValidity();
	            return P;
	        },
	        // Encodes byte string to elliptic curve.
	        // encode_to_curve from https://www.rfc-editor.org/rfc/rfc9380#section-3
	        encodeToCurve(msg, options) {
	            const u = hash_to_field(msg, 1, { ...def, DST: def.encodeDST, ...options });
	            const P = Point.fromAffine(mapToCurve(u[0])).clearCofactor();
	            P.assertValidity();
	            return P;
	        },
	        // Same as encodeToCurve, but without hash
	        mapToCurve(scalars) {
	            if (!Array.isArray(scalars))
	                throw new Error('mapToCurve: expected array of bigints');
	            for (const i of scalars)
	                if (typeof i !== 'bigint')
	                    throw new Error('mapToCurve: expected array of bigints');
	            const P = Point.fromAffine(mapToCurve(scalars)).clearCofactor();
	            P.assertValidity();
	            return P;
	        },
	    };
	}
	
	return hashToCurve;
}

var montgomery = {};

var hasRequiredMontgomery;

function requireMontgomery () {
	if (hasRequiredMontgomery) return montgomery;
	hasRequiredMontgomery = 1;
	Object.defineProperty(montgomery, "__esModule", { value: true });
	montgomery.montgomery = montgomery$1;
	/**
	 * Montgomery curve methods. It's not really whole montgomery curve,
	 * just bunch of very specific methods for X25519 / X448 from
	 * [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
	 * @module
	 */
	/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
	const modular_js_1 = /*@__PURE__*/ requireModular();
	const utils_js_1 = /*@__PURE__*/ requireUtils$1();
	const _0n = BigInt(0);
	const _1n = BigInt(1);
	function validateOpts(curve) {
	    (0, utils_js_1.validateObject)(curve, {
	        a: 'bigint',
	    }, {
	        montgomeryBits: 'isSafeInteger',
	        nByteLength: 'isSafeInteger',
	        adjustScalarBytes: 'function',
	        domain: 'function',
	        powPminus2: 'function',
	        Gu: 'bigint',
	    });
	    // Set defaults
	    return Object.freeze({ ...curve });
	}
	// Uses only one coordinate instead of two
	function montgomery$1(curveDef) {
	    const CURVE = validateOpts(curveDef);
	    const { P } = CURVE;
	    const modP = (n) => (0, modular_js_1.mod)(n, P);
	    const montgomeryBits = CURVE.montgomeryBits;
	    const montgomeryBytes = Math.ceil(montgomeryBits / 8);
	    const fieldLen = CURVE.nByteLength;
	    const adjustScalarBytes = CURVE.adjustScalarBytes || ((bytes) => bytes);
	    const powPminus2 = CURVE.powPminus2 || ((x) => (0, modular_js_1.pow)(x, P - BigInt(2), P));
	    // cswap from RFC7748. But it is not from RFC7748!
	    /*
	      cswap(swap, x_2, x_3):
	           dummy = mask(swap) AND (x_2 XOR x_3)
	           x_2 = x_2 XOR dummy
	           x_3 = x_3 XOR dummy
	           Return (x_2, x_3)
	    Where mask(swap) is the all-1 or all-0 word of the same length as x_2
	     and x_3, computed, e.g., as mask(swap) = 0 - swap.
	    */
	    function cswap(swap, x_2, x_3) {
	        const dummy = modP(swap * (x_2 - x_3));
	        x_2 = modP(x_2 - dummy);
	        x_3 = modP(x_3 + dummy);
	        return [x_2, x_3];
	    }
	    // x25519 from 4
	    // The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
	    const a24 = (CURVE.a - BigInt(2)) / BigInt(4);
	    /**
	     *
	     * @param pointU u coordinate (x) on Montgomery Curve 25519
	     * @param scalar by which the point would be multiplied
	     * @returns new Point on Montgomery curve
	     */
	    function montgomeryLadder(u, scalar) {
	        (0, utils_js_1.aInRange)('u', u, _0n, P);
	        (0, utils_js_1.aInRange)('scalar', scalar, _0n, P);
	        // Section 5: Implementations MUST accept non-canonical values and process them as
	        // if they had been reduced modulo the field prime.
	        const k = scalar;
	        const x_1 = u;
	        let x_2 = _1n;
	        let z_2 = _0n;
	        let x_3 = u;
	        let z_3 = _1n;
	        let swap = _0n;
	        let sw;
	        for (let t = BigInt(montgomeryBits - 1); t >= _0n; t--) {
	            const k_t = (k >> t) & _1n;
	            swap ^= k_t;
	            sw = cswap(swap, x_2, x_3);
	            x_2 = sw[0];
	            x_3 = sw[1];
	            sw = cswap(swap, z_2, z_3);
	            z_2 = sw[0];
	            z_3 = sw[1];
	            swap = k_t;
	            const A = x_2 + z_2;
	            const AA = modP(A * A);
	            const B = x_2 - z_2;
	            const BB = modP(B * B);
	            const E = AA - BB;
	            const C = x_3 + z_3;
	            const D = x_3 - z_3;
	            const DA = modP(D * A);
	            const CB = modP(C * B);
	            const dacb = DA + CB;
	            const da_cb = DA - CB;
	            x_3 = modP(dacb * dacb);
	            z_3 = modP(x_1 * modP(da_cb * da_cb));
	            x_2 = modP(AA * BB);
	            z_2 = modP(E * (AA + modP(a24 * E)));
	        }
	        // (x_2, x_3) = cswap(swap, x_2, x_3)
	        sw = cswap(swap, x_2, x_3);
	        x_2 = sw[0];
	        x_3 = sw[1];
	        // (z_2, z_3) = cswap(swap, z_2, z_3)
	        sw = cswap(swap, z_2, z_3);
	        z_2 = sw[0];
	        z_3 = sw[1];
	        // z_2^(p - 2)
	        const z2 = powPminus2(z_2);
	        // Return x_2 * (z_2^(p - 2))
	        return modP(x_2 * z2);
	    }
	    function encodeUCoordinate(u) {
	        return (0, utils_js_1.numberToBytesLE)(modP(u), montgomeryBytes);
	    }
	    function decodeUCoordinate(uEnc) {
	        // Section 5: When receiving such an array, implementations of X25519
	        // MUST mask the most significant bit in the final byte.
	        const u = (0, utils_js_1.ensureBytes)('u coordinate', uEnc, montgomeryBytes);
	        if (fieldLen === 32)
	            u[31] &= 127; // 0b0111_1111
	        return (0, utils_js_1.bytesToNumberLE)(u);
	    }
	    function decodeScalar(n) {
	        const bytes = (0, utils_js_1.ensureBytes)('scalar', n);
	        const len = bytes.length;
	        if (len !== montgomeryBytes && len !== fieldLen) {
	            let valid = '' + montgomeryBytes + ' or ' + fieldLen;
	            throw new Error('invalid scalar, expected ' + valid + ' bytes, got ' + len);
	        }
	        return (0, utils_js_1.bytesToNumberLE)(adjustScalarBytes(bytes));
	    }
	    function scalarMult(scalar, u) {
	        const pointU = decodeUCoordinate(u);
	        const _scalar = decodeScalar(scalar);
	        const pu = montgomeryLadder(pointU, _scalar);
	        // The result was not contributory
	        // https://cr.yp.to/ecdh.html#validate
	        if (pu === _0n)
	            throw new Error('invalid private or public key received');
	        return encodeUCoordinate(pu);
	    }
	    // Computes public key from private. By doing scalar multiplication of base point.
	    const GuBytes = encodeUCoordinate(CURVE.Gu);
	    function scalarMultBase(scalar) {
	        return scalarMult(scalar, GuBytes);
	    }
	    return {
	        scalarMult,
	        scalarMultBase,
	        getSharedSecret: (privateKey, publicKey) => scalarMult(privateKey, publicKey),
	        getPublicKey: (privateKey) => scalarMultBase(privateKey),
	        utils: { randomPrivateKey: () => CURVE.randomBytes(CURVE.nByteLength) },
	        GuBytes: GuBytes,
	    };
	}
	
	return montgomery;
}

var hasRequiredEd25519;

function requireEd25519 () {
	if (hasRequiredEd25519) return ed25519;
	hasRequiredEd25519 = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.hash_to_ristretto255 = exports.hashToRistretto255 = exports.RistrettoPoint = exports.encodeToCurve = exports.hashToCurve = exports.edwardsToMontgomery = exports.x25519 = exports.ed25519ph = exports.ed25519ctx = exports.ed25519 = exports.ED25519_TORSION_SUBGROUP = void 0;
		exports.edwardsToMontgomeryPub = edwardsToMontgomeryPub;
		exports.edwardsToMontgomeryPriv = edwardsToMontgomeryPriv;
		/**
		 * ed25519 Twisted Edwards curve with following addons:
		 * - X25519 ECDH
		 * - Ristretto cofactor elimination
		 * - Elligator hash-to-group / point indistinguishability
		 * @module
		 */
		/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
		const sha512_1 = /*@__PURE__*/ requireSha512();
		const utils_1 = /*@__PURE__*/ requireUtils$2();
		const curve_js_1 = /*@__PURE__*/ requireCurve();
		const edwards_js_1 = /*@__PURE__*/ requireEdwards();
		const hash_to_curve_js_1 = /*@__PURE__*/ requireHashToCurve();
		const modular_js_1 = /*@__PURE__*/ requireModular();
		const montgomery_js_1 = /*@__PURE__*/ requireMontgomery();
		const utils_js_1 = /*@__PURE__*/ requireUtils$1();
		const ED25519_P = BigInt('57896044618658097711785492504343953926634992332820282019728792003956564819949');
		// √(-1) aka √(a) aka 2^((p-1)/4)
		const ED25519_SQRT_M1 = /* @__PURE__ */ BigInt('19681161376707505956807079304988542015446066515923890162744021073123829784752');
		// prettier-ignore
		const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3);
		// prettier-ignore
		const _5n = BigInt(5), _8n = BigInt(8);
		function ed25519_pow_2_252_3(x) {
		    // prettier-ignore
		    const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
		    const P = ED25519_P;
		    const x2 = (x * x) % P;
		    const b2 = (x2 * x) % P; // x^3, 11
		    const b4 = ((0, modular_js_1.pow2)(b2, _2n, P) * b2) % P; // x^15, 1111
		    const b5 = ((0, modular_js_1.pow2)(b4, _1n, P) * x) % P; // x^31
		    const b10 = ((0, modular_js_1.pow2)(b5, _5n, P) * b5) % P;
		    const b20 = ((0, modular_js_1.pow2)(b10, _10n, P) * b10) % P;
		    const b40 = ((0, modular_js_1.pow2)(b20, _20n, P) * b20) % P;
		    const b80 = ((0, modular_js_1.pow2)(b40, _40n, P) * b40) % P;
		    const b160 = ((0, modular_js_1.pow2)(b80, _80n, P) * b80) % P;
		    const b240 = ((0, modular_js_1.pow2)(b160, _80n, P) * b80) % P;
		    const b250 = ((0, modular_js_1.pow2)(b240, _10n, P) * b10) % P;
		    const pow_p_5_8 = ((0, modular_js_1.pow2)(b250, _2n, P) * x) % P;
		    // ^ To pow to (p+3)/8, multiply it by x.
		    return { pow_p_5_8, b2 };
		}
		function adjustScalarBytes(bytes) {
		    // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
		    // set the three least significant bits of the first byte
		    bytes[0] &= 248; // 0b1111_1000
		    // and the most significant bit of the last to zero,
		    bytes[31] &= 127; // 0b0111_1111
		    // set the second most significant bit of the last byte to 1
		    bytes[31] |= 64; // 0b0100_0000
		    return bytes;
		}
		// sqrt(u/v)
		function uvRatio(u, v) {
		    const P = ED25519_P;
		    const v3 = (0, modular_js_1.mod)(v * v * v, P); // v³
		    const v7 = (0, modular_js_1.mod)(v3 * v3 * v, P); // v⁷
		    // (p+3)/8 and (p-5)/8
		    const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
		    let x = (0, modular_js_1.mod)(u * v3 * pow, P); // (uv³)(uv⁷)^(p-5)/8
		    const vx2 = (0, modular_js_1.mod)(v * x * x, P); // vx²
		    const root1 = x; // First root candidate
		    const root2 = (0, modular_js_1.mod)(x * ED25519_SQRT_M1, P); // Second root candidate
		    const useRoot1 = vx2 === u; // If vx² = u (mod p), x is a square root
		    const useRoot2 = vx2 === (0, modular_js_1.mod)(-u, P); // If vx² = -u, set x <-- x * 2^((p-1)/4)
		    const noRoot = vx2 === (0, modular_js_1.mod)(-u * ED25519_SQRT_M1, P); // There is no valid root, vx² = -u√(-1)
		    if (useRoot1)
		        x = root1;
		    if (useRoot2 || noRoot)
		        x = root2; // We return root2 anyway, for const-time
		    if ((0, modular_js_1.isNegativeLE)(x, P))
		        x = (0, modular_js_1.mod)(-x, P);
		    return { isValid: useRoot1 || useRoot2, value: x };
		}
		// Just in case
		exports.ED25519_TORSION_SUBGROUP = [
		    '0100000000000000000000000000000000000000000000000000000000000000',
		    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
		    '0000000000000000000000000000000000000000000000000000000000000080',
		    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
		    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
		    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
		    '0000000000000000000000000000000000000000000000000000000000000000',
		    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
		];
		const Fp = /* @__PURE__ */ (() => (0, modular_js_1.Field)(ED25519_P, undefined, true))();
		const ed25519Defaults = /* @__PURE__ */ (() => ({
		    // Param: a
		    a: BigInt(-1), // Fp.create(-1) is proper; our way still works and is faster
		    // d is equal to -121665/121666 over finite field.
		    // Negative number is P - number, and division is invert(number, P)
		    d: BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'),
		    // Finite field 𝔽p over which we'll do calculations; 2n**255n - 19n
		    Fp,
		    // Subgroup order: how many points curve has
		    // 2n**252n + 27742317777372353535851937790883648493n;
		    n: BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989'),
		    // Cofactor
		    h: _8n,
		    // Base point (x, y) aka generator point
		    Gx: BigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
		    Gy: BigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
		    hash: sha512_1.sha512,
		    randomBytes: utils_1.randomBytes,
		    adjustScalarBytes,
		    // dom2
		    // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
		    // Constant-time, u/√v
		    uvRatio,
		}))();
		/**
		 * ed25519 curve with EdDSA signatures.
		 * @example
		 * import { ed25519 } from '@noble/curves/ed25519';
		 * const priv = ed25519.utils.randomPrivateKey();
		 * const pub = ed25519.getPublicKey(priv);
		 * const msg = new TextEncoder().encode('hello');
		 * const sig = ed25519.sign(msg, priv);
		 * ed25519.verify(sig, msg, pub); // Default mode: follows ZIP215
		 * ed25519.verify(sig, msg, pub, { zip215: false }); // RFC8032 / FIPS 186-5
		 */
		exports.ed25519 = (() => (0, edwards_js_1.twistedEdwards)(ed25519Defaults))();
		function ed25519_domain(data, ctx, phflag) {
		    if (ctx.length > 255)
		        throw new Error('Context is too big');
		    return (0, utils_1.concatBytes)((0, utils_1.utf8ToBytes)('SigEd25519 no Ed25519 collisions'), new Uint8Array([phflag ? 1 : 0, ctx.length]), ctx, data);
		}
		exports.ed25519ctx = (() => (0, edwards_js_1.twistedEdwards)({
		    ...ed25519Defaults,
		    domain: ed25519_domain,
		}))();
		exports.ed25519ph = (() => (0, edwards_js_1.twistedEdwards)(Object.assign({}, ed25519Defaults, {
		    domain: ed25519_domain,
		    prehash: sha512_1.sha512,
		})))();
		/**
		 * ECDH using curve25519 aka x25519.
		 * @example
		 * import { x25519 } from '@noble/curves/ed25519';
		 * const priv = 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4';
		 * const pub = 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c';
		 * x25519.getSharedSecret(priv, pub) === x25519.scalarMult(priv, pub); // aliases
		 * x25519.getPublicKey(priv) === x25519.scalarMultBase(priv);
		 * x25519.getPublicKey(x25519.utils.randomPrivateKey());
		 */
		exports.x25519 = (() => (0, montgomery_js_1.montgomery)({
		    P: ED25519_P,
		    a: BigInt(486662),
		    montgomeryBits: 255, // n is 253 bits
		    nByteLength: 32,
		    Gu: BigInt(9),
		    powPminus2: (x) => {
		        const P = ED25519_P;
		        // x^(p-2) aka x^(2^255-21)
		        const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
		        return (0, modular_js_1.mod)((0, modular_js_1.pow2)(pow_p_5_8, _3n, P) * b2, P);
		    },
		    adjustScalarBytes,
		    randomBytes: utils_1.randomBytes,
		}))();
		/**
		 * Converts ed25519 public key to x25519 public key. Uses formula:
		 * * `(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)`
		 * * `(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))`
		 * @example
		 *   const someonesPub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
		 *   const aPriv = x25519.utils.randomPrivateKey();
		 *   x25519.getSharedSecret(aPriv, edwardsToMontgomeryPub(someonesPub))
		 */
		function edwardsToMontgomeryPub(edwardsPub) {
		    const { y } = exports.ed25519.ExtendedPoint.fromHex(edwardsPub);
		    const _1n = BigInt(1);
		    return Fp.toBytes(Fp.create((_1n + y) * Fp.inv(_1n - y)));
		}
		exports.edwardsToMontgomery = edwardsToMontgomeryPub; // deprecated
		/**
		 * Converts ed25519 secret key to x25519 secret key.
		 * @example
		 *   const someonesPub = x25519.getPublicKey(x25519.utils.randomPrivateKey());
		 *   const aPriv = ed25519.utils.randomPrivateKey();
		 *   x25519.getSharedSecret(edwardsToMontgomeryPriv(aPriv), someonesPub)
		 */
		function edwardsToMontgomeryPriv(edwardsPriv) {
		    const hashed = ed25519Defaults.hash(edwardsPriv.subarray(0, 32));
		    return ed25519Defaults.adjustScalarBytes(hashed).subarray(0, 32);
		}
		// Hash To Curve Elligator2 Map (NOTE: different from ristretto255 elligator)
		// NOTE: very important part is usage of FpSqrtEven for ELL2_C1_EDWARDS, since
		// SageMath returns different root first and everything falls apart
		const ELL2_C1 = /* @__PURE__ */ (() => (Fp.ORDER + _3n) / _8n)(); // 1. c1 = (q + 3) / 8       # Integer arithmetic
		const ELL2_C2 = /* @__PURE__ */ (() => Fp.pow(_2n, ELL2_C1))(); // 2. c2 = 2^c1
		const ELL2_C3 = /* @__PURE__ */ (() => Fp.sqrt(Fp.neg(Fp.ONE)))(); // 3. c3 = sqrt(-1)
		// prettier-ignore
		function map_to_curve_elligator2_curve25519(u) {
		    const ELL2_C4 = (Fp.ORDER - _5n) / _8n; // 4. c4 = (q - 5) / 8       # Integer arithmetic
		    const ELL2_J = BigInt(486662);
		    let tv1 = Fp.sqr(u); //  1.  tv1 = u^2
		    tv1 = Fp.mul(tv1, _2n); //  2.  tv1 = 2 * tv1
		    let xd = Fp.add(tv1, Fp.ONE); //  3.   xd = tv1 + 1         # Nonzero: -1 is square (mod p), tv1 is not
		    let x1n = Fp.neg(ELL2_J); //  4.  x1n = -J              # x1 = x1n / xd = -J / (1 + 2 * u^2)
		    let tv2 = Fp.sqr(xd); //  5.  tv2 = xd^2
		    let gxd = Fp.mul(tv2, xd); //  6.  gxd = tv2 * xd        # gxd = xd^3
		    let gx1 = Fp.mul(tv1, ELL2_J); //  7.  gx1 = J * tv1         # x1n + J * xd
		    gx1 = Fp.mul(gx1, x1n); //  8.  gx1 = gx1 * x1n       # x1n^2 + J * x1n * xd
		    gx1 = Fp.add(gx1, tv2); //  9.  gx1 = gx1 + tv2       # x1n^2 + J * x1n * xd + xd^2
		    gx1 = Fp.mul(gx1, x1n); //  10. gx1 = gx1 * x1n       # x1n^3 + J * x1n^2 * xd + x1n * xd^2
		    let tv3 = Fp.sqr(gxd); //  11. tv3 = gxd^2
		    tv2 = Fp.sqr(tv3); //  12. tv2 = tv3^2           # gxd^4
		    tv3 = Fp.mul(tv3, gxd); //  13. tv3 = tv3 * gxd       # gxd^3
		    tv3 = Fp.mul(tv3, gx1); //  14. tv3 = tv3 * gx1       # gx1 * gxd^3
		    tv2 = Fp.mul(tv2, tv3); //  15. tv2 = tv2 * tv3       # gx1 * gxd^7
		    let y11 = Fp.pow(tv2, ELL2_C4); //  16. y11 = tv2^c4        # (gx1 * gxd^7)^((p - 5) / 8)
		    y11 = Fp.mul(y11, tv3); //  17. y11 = y11 * tv3       # gx1*gxd^3*(gx1*gxd^7)^((p-5)/8)
		    let y12 = Fp.mul(y11, ELL2_C3); //  18. y12 = y11 * c3
		    tv2 = Fp.sqr(y11); //  19. tv2 = y11^2
		    tv2 = Fp.mul(tv2, gxd); //  20. tv2 = tv2 * gxd
		    let e1 = Fp.eql(tv2, gx1); //  21.  e1 = tv2 == gx1
		    let y1 = Fp.cmov(y12, y11, e1); //  22.  y1 = CMOV(y12, y11, e1)  # If g(x1) is square, this is its sqrt
		    let x2n = Fp.mul(x1n, tv1); //  23. x2n = x1n * tv1       # x2 = x2n / xd = 2 * u^2 * x1n / xd
		    let y21 = Fp.mul(y11, u); //  24. y21 = y11 * u
		    y21 = Fp.mul(y21, ELL2_C2); //  25. y21 = y21 * c2
		    let y22 = Fp.mul(y21, ELL2_C3); //  26. y22 = y21 * c3
		    let gx2 = Fp.mul(gx1, tv1); //  27. gx2 = gx1 * tv1       # g(x2) = gx2 / gxd = 2 * u^2 * g(x1)
		    tv2 = Fp.sqr(y21); //  28. tv2 = y21^2
		    tv2 = Fp.mul(tv2, gxd); //  29. tv2 = tv2 * gxd
		    let e2 = Fp.eql(tv2, gx2); //  30.  e2 = tv2 == gx2
		    let y2 = Fp.cmov(y22, y21, e2); //  31.  y2 = CMOV(y22, y21, e2)  # If g(x2) is square, this is its sqrt
		    tv2 = Fp.sqr(y1); //  32. tv2 = y1^2
		    tv2 = Fp.mul(tv2, gxd); //  33. tv2 = tv2 * gxd
		    let e3 = Fp.eql(tv2, gx1); //  34.  e3 = tv2 == gx1
		    let xn = Fp.cmov(x2n, x1n, e3); //  35.  xn = CMOV(x2n, x1n, e3)  # If e3, x = x1, else x = x2
		    let y = Fp.cmov(y2, y1, e3); //  36.   y = CMOV(y2, y1, e3)    # If e3, y = y1, else y = y2
		    let e4 = Fp.isOdd(y); //  37.  e4 = sgn0(y) == 1        # Fix sign of y
		    y = Fp.cmov(y, Fp.neg(y), e3 !== e4); //  38.   y = CMOV(y, -y, e3 XOR e4)
		    return { xMn: xn, xMd: xd, yMn: y, yMd: _1n }; //  39. return (xn, xd, y, 1)
		}
		const ELL2_C1_EDWARDS = /* @__PURE__ */ (() => (0, modular_js_1.FpSqrtEven)(Fp, Fp.neg(BigInt(486664))))(); // sgn0(c1) MUST equal 0
		function map_to_curve_elligator2_edwards25519(u) {
		    const { xMn, xMd, yMn, yMd } = map_to_curve_elligator2_curve25519(u); //  1.  (xMn, xMd, yMn, yMd) =
		    // map_to_curve_elligator2_curve25519(u)
		    let xn = Fp.mul(xMn, yMd); //  2.  xn = xMn * yMd
		    xn = Fp.mul(xn, ELL2_C1_EDWARDS); //  3.  xn = xn * c1
		    let xd = Fp.mul(xMd, yMn); //  4.  xd = xMd * yMn    # xn / xd = c1 * xM / yM
		    let yn = Fp.sub(xMn, xMd); //  5.  yn = xMn - xMd
		    let yd = Fp.add(xMn, xMd); //  6.  yd = xMn + xMd    # (n / d - 1) / (n / d + 1) = (n - d) / (n + d)
		    let tv1 = Fp.mul(xd, yd); //  7. tv1 = xd * yd
		    let e = Fp.eql(tv1, Fp.ZERO); //  8.   e = tv1 == 0
		    xn = Fp.cmov(xn, Fp.ZERO, e); //  9.  xn = CMOV(xn, 0, e)
		    xd = Fp.cmov(xd, Fp.ONE, e); //  10. xd = CMOV(xd, 1, e)
		    yn = Fp.cmov(yn, Fp.ONE, e); //  11. yn = CMOV(yn, 1, e)
		    yd = Fp.cmov(yd, Fp.ONE, e); //  12. yd = CMOV(yd, 1, e)
		    const inv = Fp.invertBatch([xd, yd]); // batch division
		    return { x: Fp.mul(xn, inv[0]), y: Fp.mul(yn, inv[1]) }; //  13. return (xn, xd, yn, yd)
		}
		const htf = /* @__PURE__ */ (() => (0, hash_to_curve_js_1.createHasher)(exports.ed25519.ExtendedPoint, (scalars) => map_to_curve_elligator2_edwards25519(scalars[0]), {
		    DST: 'edwards25519_XMD:SHA-512_ELL2_RO_',
		    encodeDST: 'edwards25519_XMD:SHA-512_ELL2_NU_',
		    p: Fp.ORDER,
		    m: 1,
		    k: 128,
		    expand: 'xmd',
		    hash: sha512_1.sha512,
		}))();
		exports.hashToCurve = (() => htf.hashToCurve)();
		exports.encodeToCurve = (() => htf.encodeToCurve)();
		function assertRstPoint(other) {
		    if (!(other instanceof RistPoint))
		        throw new Error('RistrettoPoint expected');
		}
		// √(-1) aka √(a) aka 2^((p-1)/4)
		const SQRT_M1 = ED25519_SQRT_M1;
		// √(ad - 1)
		const SQRT_AD_MINUS_ONE = /* @__PURE__ */ BigInt('25063068953384623474111414158702152701244531502492656460079210482610430750235');
		// 1 / √(a-d)
		const INVSQRT_A_MINUS_D = /* @__PURE__ */ BigInt('54469307008909316920995813868745141605393597292927456921205312896311721017578');
		// 1-d²
		const ONE_MINUS_D_SQ = /* @__PURE__ */ BigInt('1159843021668779879193775521855586647937357759715417654439879720876111806838');
		// (d-1)²
		const D_MINUS_ONE_SQ = /* @__PURE__ */ BigInt('40440834346308536858101042469323190826248399146238708352240133220865137265952');
		// Calculates 1/√(number)
		const invertSqrt = (number) => uvRatio(_1n, number);
		const MAX_255B = /* @__PURE__ */ BigInt('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
		const bytes255ToNumberLE = (bytes) => exports.ed25519.CURVE.Fp.create((0, utils_js_1.bytesToNumberLE)(bytes) & MAX_255B);
		// Computes Elligator map for Ristretto
		// https://ristretto.group/formulas/elligator.html
		function calcElligatorRistrettoMap(r0) {
		    const { d } = exports.ed25519.CURVE;
		    const P = exports.ed25519.CURVE.Fp.ORDER;
		    const mod = exports.ed25519.CURVE.Fp.create;
		    const r = mod(SQRT_M1 * r0 * r0); // 1
		    const Ns = mod((r + _1n) * ONE_MINUS_D_SQ); // 2
		    let c = BigInt(-1); // 3
		    const D = mod((c - d * r) * mod(r + d)); // 4
		    let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D); // 5
		    let s_ = mod(s * r0); // 6
		    if (!(0, modular_js_1.isNegativeLE)(s_, P))
		        s_ = mod(-s_);
		    if (!Ns_D_is_sq)
		        s = s_; // 7
		    if (!Ns_D_is_sq)
		        c = r; // 8
		    const Nt = mod(c * (r - _1n) * D_MINUS_ONE_SQ - D); // 9
		    const s2 = s * s;
		    const W0 = mod((s + s) * D); // 10
		    const W1 = mod(Nt * SQRT_AD_MINUS_ONE); // 11
		    const W2 = mod(_1n - s2); // 12
		    const W3 = mod(_1n + s2); // 13
		    return new exports.ed25519.ExtendedPoint(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
		}
		/**
		 * Each ed25519/ExtendedPoint has 8 different equivalent points. This can be
		 * a source of bugs for protocols like ring signatures. Ristretto was created to solve this.
		 * Ristretto point operates in X:Y:Z:T extended coordinates like ExtendedPoint,
		 * but it should work in its own namespace: do not combine those two.
		 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448
		 */
		class RistPoint {
		    // Private property to discourage combining ExtendedPoint + RistrettoPoint
		    // Always use Ristretto encoding/decoding instead.
		    constructor(ep) {
		        this.ep = ep;
		    }
		    static fromAffine(ap) {
		        return new RistPoint(exports.ed25519.ExtendedPoint.fromAffine(ap));
		    }
		    /**
		     * Takes uniform output of 64-byte hash function like sha512 and converts it to `RistrettoPoint`.
		     * The hash-to-group operation applies Elligator twice and adds the results.
		     * **Note:** this is one-way map, there is no conversion from point to hash.
		     * https://ristretto.group/formulas/elligator.html
		     * @param hex 64-byte output of a hash function
		     */
		    static hashToCurve(hex) {
		        hex = (0, utils_js_1.ensureBytes)('ristrettoHash', hex, 64);
		        const r1 = bytes255ToNumberLE(hex.slice(0, 32));
		        const R1 = calcElligatorRistrettoMap(r1);
		        const r2 = bytes255ToNumberLE(hex.slice(32, 64));
		        const R2 = calcElligatorRistrettoMap(r2);
		        return new RistPoint(R1.add(R2));
		    }
		    /**
		     * Converts ristretto-encoded string to ristretto point.
		     * https://ristretto.group/formulas/decoding.html
		     * @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
		     */
		    static fromHex(hex) {
		        hex = (0, utils_js_1.ensureBytes)('ristrettoHex', hex, 32);
		        const { a, d } = exports.ed25519.CURVE;
		        const P = exports.ed25519.CURVE.Fp.ORDER;
		        const mod = exports.ed25519.CURVE.Fp.create;
		        const emsg = 'RistrettoPoint.fromHex: the hex is not valid encoding of RistrettoPoint';
		        const s = bytes255ToNumberLE(hex);
		        // 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
		        // 3. Check that s is non-negative, or else abort
		        if (!(0, utils_js_1.equalBytes)((0, utils_js_1.numberToBytesLE)(s, 32), hex) || (0, modular_js_1.isNegativeLE)(s, P))
		            throw new Error(emsg);
		        const s2 = mod(s * s);
		        const u1 = mod(_1n + a * s2); // 4 (a is -1)
		        const u2 = mod(_1n - a * s2); // 5
		        const u1_2 = mod(u1 * u1);
		        const u2_2 = mod(u2 * u2);
		        const v = mod(a * d * u1_2 - u2_2); // 6
		        const { isValid, value: I } = invertSqrt(mod(v * u2_2)); // 7
		        const Dx = mod(I * u2); // 8
		        const Dy = mod(I * Dx * v); // 9
		        let x = mod((s + s) * Dx); // 10
		        if ((0, modular_js_1.isNegativeLE)(x, P))
		            x = mod(-x); // 10
		        const y = mod(u1 * Dy); // 11
		        const t = mod(x * y); // 12
		        if (!isValid || (0, modular_js_1.isNegativeLE)(t, P) || y === _0n)
		            throw new Error(emsg);
		        return new RistPoint(new exports.ed25519.ExtendedPoint(x, y, _1n, t));
		    }
		    static msm(points, scalars) {
		        const Fn = (0, modular_js_1.Field)(exports.ed25519.CURVE.n, exports.ed25519.CURVE.nBitLength);
		        return (0, curve_js_1.pippenger)(RistPoint, Fn, points, scalars);
		    }
		    /**
		     * Encodes ristretto point to Uint8Array.
		     * https://ristretto.group/formulas/encoding.html
		     */
		    toRawBytes() {
		        let { ex: x, ey: y, ez: z, et: t } = this.ep;
		        const P = exports.ed25519.CURVE.Fp.ORDER;
		        const mod = exports.ed25519.CURVE.Fp.create;
		        const u1 = mod(mod(z + y) * mod(z - y)); // 1
		        const u2 = mod(x * y); // 2
		        // Square root always exists
		        const u2sq = mod(u2 * u2);
		        const { value: invsqrt } = invertSqrt(mod(u1 * u2sq)); // 3
		        const D1 = mod(invsqrt * u1); // 4
		        const D2 = mod(invsqrt * u2); // 5
		        const zInv = mod(D1 * D2 * t); // 6
		        let D; // 7
		        if ((0, modular_js_1.isNegativeLE)(t * zInv, P)) {
		            let _x = mod(y * SQRT_M1);
		            let _y = mod(x * SQRT_M1);
		            x = _x;
		            y = _y;
		            D = mod(D1 * INVSQRT_A_MINUS_D);
		        }
		        else {
		            D = D2; // 8
		        }
		        if ((0, modular_js_1.isNegativeLE)(x * zInv, P))
		            y = mod(-y); // 9
		        let s = mod((z - y) * D); // 10 (check footer's note, no sqrt(-a))
		        if ((0, modular_js_1.isNegativeLE)(s, P))
		            s = mod(-s);
		        return (0, utils_js_1.numberToBytesLE)(s, 32); // 11
		    }
		    toHex() {
		        return (0, utils_js_1.bytesToHex)(this.toRawBytes());
		    }
		    toString() {
		        return this.toHex();
		    }
		    // Compare one point to another.
		    equals(other) {
		        assertRstPoint(other);
		        const { ex: X1, ey: Y1 } = this.ep;
		        const { ex: X2, ey: Y2 } = other.ep;
		        const mod = exports.ed25519.CURVE.Fp.create;
		        // (x1 * y2 == y1 * x2) | (y1 * y2 == x1 * x2)
		        const one = mod(X1 * Y2) === mod(Y1 * X2);
		        const two = mod(Y1 * Y2) === mod(X1 * X2);
		        return one || two;
		    }
		    add(other) {
		        assertRstPoint(other);
		        return new RistPoint(this.ep.add(other.ep));
		    }
		    subtract(other) {
		        assertRstPoint(other);
		        return new RistPoint(this.ep.subtract(other.ep));
		    }
		    multiply(scalar) {
		        return new RistPoint(this.ep.multiply(scalar));
		    }
		    multiplyUnsafe(scalar) {
		        return new RistPoint(this.ep.multiplyUnsafe(scalar));
		    }
		    double() {
		        return new RistPoint(this.ep.double());
		    }
		    negate() {
		        return new RistPoint(this.ep.negate());
		    }
		}
		exports.RistrettoPoint = (() => {
		    if (!RistPoint.BASE)
		        RistPoint.BASE = new RistPoint(exports.ed25519.ExtendedPoint.BASE);
		    if (!RistPoint.ZERO)
		        RistPoint.ZERO = new RistPoint(exports.ed25519.ExtendedPoint.ZERO);
		    return RistPoint;
		})();
		// Hashing to ristretto255. https://www.rfc-editor.org/rfc/rfc9380#appendix-B
		const hashToRistretto255 = (msg, options) => {
		    const d = options.DST;
		    const DST = typeof d === 'string' ? (0, utils_1.utf8ToBytes)(d) : d;
		    const uniform_bytes = (0, hash_to_curve_js_1.expand_message_xmd)(msg, DST, 64, sha512_1.sha512);
		    const P = RistPoint.hashToCurve(uniform_bytes);
		    return P;
		};
		exports.hashToRistretto255 = hashToRistretto255;
		exports.hash_to_ristretto255 = exports.hashToRistretto255; // legacy
		
	} (ed25519));
	return ed25519;
}

var secp256k1 = {};

var sha256 = {};

var hasRequiredSha256;

function requireSha256 () {
	if (hasRequiredSha256) return sha256;
	hasRequiredSha256 = 1;
	Object.defineProperty(sha256, "__esModule", { value: true });
	sha256.sha224 = sha256.sha256 = sha256.SHA256 = void 0;
	/**
	 * SHA2-256 a.k.a. sha256. In JS, it is the fastest hash, even faster than Blake3.
	 *
	 * To break sha256 using birthday attack, attackers need to try 2^128 hashes.
	 * BTC network is doing 2^70 hashes/sec (2^95 hashes/year) as per 2025.
	 *
	 * Check out [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
	 * @module
	 */
	const _md_js_1 = /*@__PURE__*/ require_md();
	const utils_js_1 = /*@__PURE__*/ requireUtils$2();
	/** Round constants: first 32 bits of fractional parts of the cube roots of the first 64 primes 2..311). */
	// prettier-ignore
	const SHA256_K = /* @__PURE__ */ new Uint32Array([
	    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	]);
	/** Initial state: first 32 bits of fractional parts of the square roots of the first 8 primes 2..19. */
	// prettier-ignore
	const SHA256_IV = /* @__PURE__ */ new Uint32Array([
	    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	]);
	/**
	 * Temporary buffer, not used to store anything between runs.
	 * Named this way because it matches specification.
	 */
	const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
	class SHA256 extends _md_js_1.HashMD {
	    constructor() {
	        super(64, 32, 8, false);
	        // We cannot use array here since array allows indexing by variable
	        // which means optimizer/compiler cannot use registers.
	        this.A = SHA256_IV[0] | 0;
	        this.B = SHA256_IV[1] | 0;
	        this.C = SHA256_IV[2] | 0;
	        this.D = SHA256_IV[3] | 0;
	        this.E = SHA256_IV[4] | 0;
	        this.F = SHA256_IV[5] | 0;
	        this.G = SHA256_IV[6] | 0;
	        this.H = SHA256_IV[7] | 0;
	    }
	    get() {
	        const { A, B, C, D, E, F, G, H } = this;
	        return [A, B, C, D, E, F, G, H];
	    }
	    // prettier-ignore
	    set(A, B, C, D, E, F, G, H) {
	        this.A = A | 0;
	        this.B = B | 0;
	        this.C = C | 0;
	        this.D = D | 0;
	        this.E = E | 0;
	        this.F = F | 0;
	        this.G = G | 0;
	        this.H = H | 0;
	    }
	    process(view, offset) {
	        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
	        for (let i = 0; i < 16; i++, offset += 4)
	            SHA256_W[i] = view.getUint32(offset, false);
	        for (let i = 16; i < 64; i++) {
	            const W15 = SHA256_W[i - 15];
	            const W2 = SHA256_W[i - 2];
	            const s0 = (0, utils_js_1.rotr)(W15, 7) ^ (0, utils_js_1.rotr)(W15, 18) ^ (W15 >>> 3);
	            const s1 = (0, utils_js_1.rotr)(W2, 17) ^ (0, utils_js_1.rotr)(W2, 19) ^ (W2 >>> 10);
	            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
	        }
	        // Compression function main loop, 64 rounds
	        let { A, B, C, D, E, F, G, H } = this;
	        for (let i = 0; i < 64; i++) {
	            const sigma1 = (0, utils_js_1.rotr)(E, 6) ^ (0, utils_js_1.rotr)(E, 11) ^ (0, utils_js_1.rotr)(E, 25);
	            const T1 = (H + sigma1 + (0, _md_js_1.Chi)(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
	            const sigma0 = (0, utils_js_1.rotr)(A, 2) ^ (0, utils_js_1.rotr)(A, 13) ^ (0, utils_js_1.rotr)(A, 22);
	            const T2 = (sigma0 + (0, _md_js_1.Maj)(A, B, C)) | 0;
	            H = G;
	            G = F;
	            F = E;
	            E = (D + T1) | 0;
	            D = C;
	            C = B;
	            B = A;
	            A = (T1 + T2) | 0;
	        }
	        // Add the compressed chunk to the current hash value
	        A = (A + this.A) | 0;
	        B = (B + this.B) | 0;
	        C = (C + this.C) | 0;
	        D = (D + this.D) | 0;
	        E = (E + this.E) | 0;
	        F = (F + this.F) | 0;
	        G = (G + this.G) | 0;
	        H = (H + this.H) | 0;
	        this.set(A, B, C, D, E, F, G, H);
	    }
	    roundClean() {
	        SHA256_W.fill(0);
	    }
	    destroy() {
	        this.set(0, 0, 0, 0, 0, 0, 0, 0);
	        this.buffer.fill(0);
	    }
	}
	sha256.SHA256 = SHA256;
	/**
	 * Constants taken from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf.
	 */
	class SHA224 extends SHA256 {
	    constructor() {
	        super();
	        this.A = 0xc1059ed8 | 0;
	        this.B = 0x367cd507 | 0;
	        this.C = 0x3070dd17 | 0;
	        this.D = 0xf70e5939 | 0;
	        this.E = 0xffc00b31 | 0;
	        this.F = 0x68581511 | 0;
	        this.G = 0x64f98fa7 | 0;
	        this.H = 0xbefa4fa4 | 0;
	        this.outputLen = 28;
	    }
	}
	/** SHA2-256 hash function */
	sha256.sha256 = (0, utils_js_1.wrapConstructor)(() => new SHA256());
	/** SHA2-224 hash function */
	sha256.sha224 = (0, utils_js_1.wrapConstructor)(() => new SHA224());
	
	return sha256;
}

var _shortw_utils = {};

var hmac = {};

var hasRequiredHmac;

function requireHmac () {
	if (hasRequiredHmac) return hmac;
	hasRequiredHmac = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.hmac = exports.HMAC = void 0;
		/**
		 * HMAC: RFC2104 message authentication code.
		 * @module
		 */
		const _assert_js_1 = /*@__PURE__*/ require_assert();
		const utils_js_1 = /*@__PURE__*/ requireUtils$2();
		class HMAC extends utils_js_1.Hash {
		    constructor(hash, _key) {
		        super();
		        this.finished = false;
		        this.destroyed = false;
		        (0, _assert_js_1.ahash)(hash);
		        const key = (0, utils_js_1.toBytes)(_key);
		        this.iHash = hash.create();
		        if (typeof this.iHash.update !== 'function')
		            throw new Error('Expected instance of class which extends utils.Hash');
		        this.blockLen = this.iHash.blockLen;
		        this.outputLen = this.iHash.outputLen;
		        const blockLen = this.blockLen;
		        const pad = new Uint8Array(blockLen);
		        // blockLen can be bigger than outputLen
		        pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
		        for (let i = 0; i < pad.length; i++)
		            pad[i] ^= 0x36;
		        this.iHash.update(pad);
		        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
		        this.oHash = hash.create();
		        // Undo internal XOR && apply outer XOR
		        for (let i = 0; i < pad.length; i++)
		            pad[i] ^= 0x36 ^ 0x5c;
		        this.oHash.update(pad);
		        pad.fill(0);
		    }
		    update(buf) {
		        (0, _assert_js_1.aexists)(this);
		        this.iHash.update(buf);
		        return this;
		    }
		    digestInto(out) {
		        (0, _assert_js_1.aexists)(this);
		        (0, _assert_js_1.abytes)(out, this.outputLen);
		        this.finished = true;
		        this.iHash.digestInto(out);
		        this.oHash.update(out);
		        this.oHash.digestInto(out);
		        this.destroy();
		    }
		    digest() {
		        const out = new Uint8Array(this.oHash.outputLen);
		        this.digestInto(out);
		        return out;
		    }
		    _cloneInto(to) {
		        // Create new instance without calling constructor since key already in state and we don't know it.
		        to || (to = Object.create(Object.getPrototypeOf(this), {}));
		        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
		        to = to;
		        to.finished = finished;
		        to.destroyed = destroyed;
		        to.blockLen = blockLen;
		        to.outputLen = outputLen;
		        to.oHash = oHash._cloneInto(to.oHash);
		        to.iHash = iHash._cloneInto(to.iHash);
		        return to;
		    }
		    destroy() {
		        this.destroyed = true;
		        this.oHash.destroy();
		        this.iHash.destroy();
		    }
		}
		exports.HMAC = HMAC;
		/**
		 * HMAC: RFC2104 message authentication code.
		 * @param hash - function that would be used e.g. sha256
		 * @param key - message key
		 * @param message - message data
		 * @example
		 * import { hmac } from '@noble/hashes/hmac';
		 * import { sha256 } from '@noble/hashes/sha2';
		 * const mac1 = hmac(sha256, 'key', 'message');
		 */
		const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
		exports.hmac = hmac;
		exports.hmac.create = (hash, key) => new HMAC(hash, key);
		
	} (hmac));
	return hmac;
}

var weierstrass = {};

var hasRequiredWeierstrass;

function requireWeierstrass () {
	if (hasRequiredWeierstrass) return weierstrass;
	hasRequiredWeierstrass = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.DER = exports.DERErr = void 0;
		exports.weierstrassPoints = weierstrassPoints;
		exports.weierstrass = weierstrass;
		exports.SWUFpSqrtRatio = SWUFpSqrtRatio;
		exports.mapToCurveSimpleSWU = mapToCurveSimpleSWU;
		/**
		 * Short Weierstrass curve methods. The formula is: y² = x³ + ax + b.
		 *
		 * ### Design rationale for types
		 *
		 * * Interaction between classes from different curves should fail:
		 *   `k256.Point.BASE.add(p256.Point.BASE)`
		 * * For this purpose we want to use `instanceof` operator, which is fast and works during runtime
		 * * Different calls of `curve()` would return different classes -
		 *   `curve(params) !== curve(params)`: if somebody decided to monkey-patch their curve,
		 *   it won't affect others
		 *
		 * TypeScript can't infer types for classes created inside a function. Classes is one instance
		 * of nominative types in TypeScript and interfaces only check for shape, so it's hard to create
		 * unique type for every function call.
		 *
		 * We can use generic types via some param, like curve opts, but that would:
		 *     1. Enable interaction between `curve(params)` and `curve(params)` (curves of same params)
		 *     which is hard to debug.
		 *     2. Params can be generic and we can't enforce them to be constant value:
		 *     if somebody creates curve from non-constant params,
		 *     it would be allowed to interact with other curves with non-constant params
		 *
		 * @todo https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-7.html#unique-symbol
		 * @module
		 */
		/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
		const curve_js_1 = /*@__PURE__*/ requireCurve();
		const modular_js_1 = /*@__PURE__*/ requireModular();
		const ut = /*@__PURE__*/ requireUtils$1();
		const utils_js_1 = /*@__PURE__*/ requireUtils$1();
		function validateSigVerOpts(opts) {
		    if (opts.lowS !== undefined)
		        (0, utils_js_1.abool)('lowS', opts.lowS);
		    if (opts.prehash !== undefined)
		        (0, utils_js_1.abool)('prehash', opts.prehash);
		}
		function validatePointOpts(curve) {
		    const opts = (0, curve_js_1.validateBasic)(curve);
		    ut.validateObject(opts, {
		        a: 'field',
		        b: 'field',
		    }, {
		        allowedPrivateKeyLengths: 'array',
		        wrapPrivateKey: 'boolean',
		        isTorsionFree: 'function',
		        clearCofactor: 'function',
		        allowInfinityPoint: 'boolean',
		        fromBytes: 'function',
		        toBytes: 'function',
		    });
		    const { endo, Fp, a } = opts;
		    if (endo) {
		        if (!Fp.eql(a, Fp.ZERO)) {
		            throw new Error('invalid endomorphism, can only be defined for Koblitz curves that have a=0');
		        }
		        if (typeof endo !== 'object' ||
		            typeof endo.beta !== 'bigint' ||
		            typeof endo.splitScalar !== 'function') {
		            throw new Error('invalid endomorphism, expected beta: bigint and splitScalar: function');
		        }
		    }
		    return Object.freeze({ ...opts });
		}
		const { bytesToNumberBE: b2n, hexToBytes: h2b } = ut;
		class DERErr extends Error {
		    constructor(m = '') {
		        super(m);
		    }
		}
		exports.DERErr = DERErr;
		/**
		 * ASN.1 DER encoding utilities. ASN is very complex & fragile. Format:
		 *
		 *     [0x30 (SEQUENCE), bytelength, 0x02 (INTEGER), intLength, R, 0x02 (INTEGER), intLength, S]
		 *
		 * Docs: https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/, https://luca.ntop.org/Teaching/Appunti/asn1.html
		 */
		exports.DER = {
		    // asn.1 DER encoding utils
		    Err: DERErr,
		    // Basic building block is TLV (Tag-Length-Value)
		    _tlv: {
		        encode: (tag, data) => {
		            const { Err: E } = exports.DER;
		            if (tag < 0 || tag > 256)
		                throw new E('tlv.encode: wrong tag');
		            if (data.length & 1)
		                throw new E('tlv.encode: unpadded data');
		            const dataLen = data.length / 2;
		            const len = ut.numberToHexUnpadded(dataLen);
		            if ((len.length / 2) & 128)
		                throw new E('tlv.encode: long form length too big');
		            // length of length with long form flag
		            const lenLen = dataLen > 127 ? ut.numberToHexUnpadded((len.length / 2) | 128) : '';
		            const t = ut.numberToHexUnpadded(tag);
		            return t + lenLen + len + data;
		        },
		        // v - value, l - left bytes (unparsed)
		        decode(tag, data) {
		            const { Err: E } = exports.DER;
		            let pos = 0;
		            if (tag < 0 || tag > 256)
		                throw new E('tlv.encode: wrong tag');
		            if (data.length < 2 || data[pos++] !== tag)
		                throw new E('tlv.decode: wrong tlv');
		            const first = data[pos++];
		            const isLong = !!(first & 128); // First bit of first length byte is flag for short/long form
		            let length = 0;
		            if (!isLong)
		                length = first;
		            else {
		                // Long form: [longFlag(1bit), lengthLength(7bit), length (BE)]
		                const lenLen = first & 127;
		                if (!lenLen)
		                    throw new E('tlv.decode(long): indefinite length not supported');
		                if (lenLen > 4)
		                    throw new E('tlv.decode(long): byte length is too big'); // this will overflow u32 in js
		                const lengthBytes = data.subarray(pos, pos + lenLen);
		                if (lengthBytes.length !== lenLen)
		                    throw new E('tlv.decode: length bytes not complete');
		                if (lengthBytes[0] === 0)
		                    throw new E('tlv.decode(long): zero leftmost byte');
		                for (const b of lengthBytes)
		                    length = (length << 8) | b;
		                pos += lenLen;
		                if (length < 128)
		                    throw new E('tlv.decode(long): not minimal encoding');
		            }
		            const v = data.subarray(pos, pos + length);
		            if (v.length !== length)
		                throw new E('tlv.decode: wrong value length');
		            return { v, l: data.subarray(pos + length) };
		        },
		    },
		    // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
		    // since we always use positive integers here. It must always be empty:
		    // - add zero byte if exists
		    // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
		    _int: {
		        encode(num) {
		            const { Err: E } = exports.DER;
		            if (num < _0n)
		                throw new E('integer: negative integers are not allowed');
		            let hex = ut.numberToHexUnpadded(num);
		            // Pad with zero byte if negative flag is present
		            if (Number.parseInt(hex[0], 16) & 0b1000)
		                hex = '00' + hex;
		            if (hex.length & 1)
		                throw new E('unexpected DER parsing assertion: unpadded hex');
		            return hex;
		        },
		        decode(data) {
		            const { Err: E } = exports.DER;
		            if (data[0] & 128)
		                throw new E('invalid signature integer: negative');
		            if (data[0] === 0x00 && !(data[1] & 128))
		                throw new E('invalid signature integer: unnecessary leading zero');
		            return b2n(data);
		        },
		    },
		    toSig(hex) {
		        // parse DER signature
		        const { Err: E, _int: int, _tlv: tlv } = exports.DER;
		        const data = typeof hex === 'string' ? h2b(hex) : hex;
		        ut.abytes(data);
		        const { v: seqBytes, l: seqLeftBytes } = tlv.decode(0x30, data);
		        if (seqLeftBytes.length)
		            throw new E('invalid signature: left bytes after parsing');
		        const { v: rBytes, l: rLeftBytes } = tlv.decode(0x02, seqBytes);
		        const { v: sBytes, l: sLeftBytes } = tlv.decode(0x02, rLeftBytes);
		        if (sLeftBytes.length)
		            throw new E('invalid signature: left bytes after parsing');
		        return { r: int.decode(rBytes), s: int.decode(sBytes) };
		    },
		    hexFromSig(sig) {
		        const { _tlv: tlv, _int: int } = exports.DER;
		        const rs = tlv.encode(0x02, int.encode(sig.r));
		        const ss = tlv.encode(0x02, int.encode(sig.s));
		        const seq = rs + ss;
		        return tlv.encode(0x30, seq);
		    },
		};
		// Be friendly to bad ECMAScript parsers by not using bigint literals
		// prettier-ignore
		const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3), _4n = BigInt(4);
		function weierstrassPoints(opts) {
		    const CURVE = validatePointOpts(opts);
		    const { Fp } = CURVE; // All curves has same field / group length as for now, but they can differ
		    const Fn = (0, modular_js_1.Field)(CURVE.n, CURVE.nBitLength);
		    const toBytes = CURVE.toBytes ||
		        ((_c, point, _isCompressed) => {
		            const a = point.toAffine();
		            return ut.concatBytes(Uint8Array.from([0x04]), Fp.toBytes(a.x), Fp.toBytes(a.y));
		        });
		    const fromBytes = CURVE.fromBytes ||
		        ((bytes) => {
		            // const head = bytes[0];
		            const tail = bytes.subarray(1);
		            // if (head !== 0x04) throw new Error('Only non-compressed encoding is supported');
		            const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
		            const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
		            return { x, y };
		        });
		    /**
		     * y² = x³ + ax + b: Short weierstrass curve formula
		     * @returns y²
		     */
		    function weierstrassEquation(x) {
		        const { a, b } = CURVE;
		        const x2 = Fp.sqr(x); // x * x
		        const x3 = Fp.mul(x2, x); // x2 * x
		        return Fp.add(Fp.add(x3, Fp.mul(x, a)), b); // x3 + a * x + b
		    }
		    // Validate whether the passed curve params are valid.
		    // We check if curve equation works for generator point.
		    // `assertValidity()` won't work: `isTorsionFree()` is not available at this point in bls12-381.
		    // ProjectivePoint class has not been initialized yet.
		    if (!Fp.eql(Fp.sqr(CURVE.Gy), weierstrassEquation(CURVE.Gx)))
		        throw new Error('bad generator point: equation left != right');
		    // Valid group elements reside in range 1..n-1
		    function isWithinCurveOrder(num) {
		        return ut.inRange(num, _1n, CURVE.n);
		    }
		    // Validates if priv key is valid and converts it to bigint.
		    // Supports options allowedPrivateKeyLengths and wrapPrivateKey.
		    function normPrivateKeyToScalar(key) {
		        const { allowedPrivateKeyLengths: lengths, nByteLength, wrapPrivateKey, n: N } = CURVE;
		        if (lengths && typeof key !== 'bigint') {
		            if (ut.isBytes(key))
		                key = ut.bytesToHex(key);
		            // Normalize to hex string, pad. E.g. P521 would norm 130-132 char hex to 132-char bytes
		            if (typeof key !== 'string' || !lengths.includes(key.length))
		                throw new Error('invalid private key');
		            key = key.padStart(nByteLength * 2, '0');
		        }
		        let num;
		        try {
		            num =
		                typeof key === 'bigint'
		                    ? key
		                    : ut.bytesToNumberBE((0, utils_js_1.ensureBytes)('private key', key, nByteLength));
		        }
		        catch (error) {
		            throw new Error('invalid private key, expected hex or ' + nByteLength + ' bytes, got ' + typeof key);
		        }
		        if (wrapPrivateKey)
		            num = (0, modular_js_1.mod)(num, N); // disabled by default, enabled for BLS
		        ut.aInRange('private key', num, _1n, N); // num in range [1..N-1]
		        return num;
		    }
		    function assertPrjPoint(other) {
		        if (!(other instanceof Point))
		            throw new Error('ProjectivePoint expected');
		    }
		    // Memoized toAffine / validity check. They are heavy. Points are immutable.
		    // Converts Projective point to affine (x, y) coordinates.
		    // Can accept precomputed Z^-1 - for example, from invertBatch.
		    // (x, y, z) ∋ (x=x/z, y=y/z)
		    const toAffineMemo = (0, utils_js_1.memoized)((p, iz) => {
		        const { px: x, py: y, pz: z } = p;
		        // Fast-path for normalized points
		        if (Fp.eql(z, Fp.ONE))
		            return { x, y };
		        const is0 = p.is0();
		        // If invZ was 0, we return zero point. However we still want to execute
		        // all operations, so we replace invZ with a random number, 1.
		        if (iz == null)
		            iz = is0 ? Fp.ONE : Fp.inv(z);
		        const ax = Fp.mul(x, iz);
		        const ay = Fp.mul(y, iz);
		        const zz = Fp.mul(z, iz);
		        if (is0)
		            return { x: Fp.ZERO, y: Fp.ZERO };
		        if (!Fp.eql(zz, Fp.ONE))
		            throw new Error('invZ was invalid');
		        return { x: ax, y: ay };
		    });
		    // NOTE: on exception this will crash 'cached' and no value will be set.
		    // Otherwise true will be return
		    const assertValidMemo = (0, utils_js_1.memoized)((p) => {
		        if (p.is0()) {
		            // (0, 1, 0) aka ZERO is invalid in most contexts.
		            // In BLS, ZERO can be serialized, so we allow it.
		            // (0, 0, 0) is invalid representation of ZERO.
		            if (CURVE.allowInfinityPoint && !Fp.is0(p.py))
		                return;
		            throw new Error('bad point: ZERO');
		        }
		        // Some 3rd-party test vectors require different wording between here & `fromCompressedHex`
		        const { x, y } = p.toAffine();
		        // Check if x, y are valid field elements
		        if (!Fp.isValid(x) || !Fp.isValid(y))
		            throw new Error('bad point: x or y not FE');
		        const left = Fp.sqr(y); // y²
		        const right = weierstrassEquation(x); // x³ + ax + b
		        if (!Fp.eql(left, right))
		            throw new Error('bad point: equation left != right');
		        if (!p.isTorsionFree())
		            throw new Error('bad point: not in prime-order subgroup');
		        return true;
		    });
		    /**
		     * Projective Point works in 3d / projective (homogeneous) coordinates: (x, y, z) ∋ (x=x/z, y=y/z)
		     * Default Point works in 2d / affine coordinates: (x, y)
		     * We're doing calculations in projective, because its operations don't require costly inversion.
		     */
		    class Point {
		        constructor(px, py, pz) {
		            this.px = px;
		            this.py = py;
		            this.pz = pz;
		            if (px == null || !Fp.isValid(px))
		                throw new Error('x required');
		            if (py == null || !Fp.isValid(py))
		                throw new Error('y required');
		            if (pz == null || !Fp.isValid(pz))
		                throw new Error('z required');
		            Object.freeze(this);
		        }
		        // Does not validate if the point is on-curve.
		        // Use fromHex instead, or call assertValidity() later.
		        static fromAffine(p) {
		            const { x, y } = p || {};
		            if (!p || !Fp.isValid(x) || !Fp.isValid(y))
		                throw new Error('invalid affine point');
		            if (p instanceof Point)
		                throw new Error('projective point not allowed');
		            const is0 = (i) => Fp.eql(i, Fp.ZERO);
		            // fromAffine(x:0, y:0) would produce (x:0, y:0, z:1), but we need (x:0, y:1, z:0)
		            if (is0(x) && is0(y))
		                return Point.ZERO;
		            return new Point(x, y, Fp.ONE);
		        }
		        get x() {
		            return this.toAffine().x;
		        }
		        get y() {
		            return this.toAffine().y;
		        }
		        /**
		         * Takes a bunch of Projective Points but executes only one
		         * inversion on all of them. Inversion is very slow operation,
		         * so this improves performance massively.
		         * Optimization: converts a list of projective points to a list of identical points with Z=1.
		         */
		        static normalizeZ(points) {
		            const toInv = Fp.invertBatch(points.map((p) => p.pz));
		            return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
		        }
		        /**
		         * Converts hash string or Uint8Array to Point.
		         * @param hex short/long ECDSA hex
		         */
		        static fromHex(hex) {
		            const P = Point.fromAffine(fromBytes((0, utils_js_1.ensureBytes)('pointHex', hex)));
		            P.assertValidity();
		            return P;
		        }
		        // Multiplies generator point by privateKey.
		        static fromPrivateKey(privateKey) {
		            return Point.BASE.multiply(normPrivateKeyToScalar(privateKey));
		        }
		        // Multiscalar Multiplication
		        static msm(points, scalars) {
		            return (0, curve_js_1.pippenger)(Point, Fn, points, scalars);
		        }
		        // "Private method", don't use it directly
		        _setWindowSize(windowSize) {
		            wnaf.setWindowSize(this, windowSize);
		        }
		        // A point on curve is valid if it conforms to equation.
		        assertValidity() {
		            assertValidMemo(this);
		        }
		        hasEvenY() {
		            const { y } = this.toAffine();
		            if (Fp.isOdd)
		                return !Fp.isOdd(y);
		            throw new Error("Field doesn't support isOdd");
		        }
		        /**
		         * Compare one point to another.
		         */
		        equals(other) {
		            assertPrjPoint(other);
		            const { px: X1, py: Y1, pz: Z1 } = this;
		            const { px: X2, py: Y2, pz: Z2 } = other;
		            const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
		            const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
		            return U1 && U2;
		        }
		        /**
		         * Flips point to one corresponding to (x, -y) in Affine coordinates.
		         */
		        negate() {
		            return new Point(this.px, Fp.neg(this.py), this.pz);
		        }
		        // Renes-Costello-Batina exception-free doubling formula.
		        // There is 30% faster Jacobian formula, but it is not complete.
		        // https://eprint.iacr.org/2015/1060, algorithm 3
		        // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
		        double() {
		            const { a, b } = CURVE;
		            const b3 = Fp.mul(b, _3n);
		            const { px: X1, py: Y1, pz: Z1 } = this;
		            let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
		            let t0 = Fp.mul(X1, X1); // step 1
		            let t1 = Fp.mul(Y1, Y1);
		            let t2 = Fp.mul(Z1, Z1);
		            let t3 = Fp.mul(X1, Y1);
		            t3 = Fp.add(t3, t3); // step 5
		            Z3 = Fp.mul(X1, Z1);
		            Z3 = Fp.add(Z3, Z3);
		            X3 = Fp.mul(a, Z3);
		            Y3 = Fp.mul(b3, t2);
		            Y3 = Fp.add(X3, Y3); // step 10
		            X3 = Fp.sub(t1, Y3);
		            Y3 = Fp.add(t1, Y3);
		            Y3 = Fp.mul(X3, Y3);
		            X3 = Fp.mul(t3, X3);
		            Z3 = Fp.mul(b3, Z3); // step 15
		            t2 = Fp.mul(a, t2);
		            t3 = Fp.sub(t0, t2);
		            t3 = Fp.mul(a, t3);
		            t3 = Fp.add(t3, Z3);
		            Z3 = Fp.add(t0, t0); // step 20
		            t0 = Fp.add(Z3, t0);
		            t0 = Fp.add(t0, t2);
		            t0 = Fp.mul(t0, t3);
		            Y3 = Fp.add(Y3, t0);
		            t2 = Fp.mul(Y1, Z1); // step 25
		            t2 = Fp.add(t2, t2);
		            t0 = Fp.mul(t2, t3);
		            X3 = Fp.sub(X3, t0);
		            Z3 = Fp.mul(t2, t1);
		            Z3 = Fp.add(Z3, Z3); // step 30
		            Z3 = Fp.add(Z3, Z3);
		            return new Point(X3, Y3, Z3);
		        }
		        // Renes-Costello-Batina exception-free addition formula.
		        // There is 30% faster Jacobian formula, but it is not complete.
		        // https://eprint.iacr.org/2015/1060, algorithm 1
		        // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
		        add(other) {
		            assertPrjPoint(other);
		            const { px: X1, py: Y1, pz: Z1 } = this;
		            const { px: X2, py: Y2, pz: Z2 } = other;
		            let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
		            const a = CURVE.a;
		            const b3 = Fp.mul(CURVE.b, _3n);
		            let t0 = Fp.mul(X1, X2); // step 1
		            let t1 = Fp.mul(Y1, Y2);
		            let t2 = Fp.mul(Z1, Z2);
		            let t3 = Fp.add(X1, Y1);
		            let t4 = Fp.add(X2, Y2); // step 5
		            t3 = Fp.mul(t3, t4);
		            t4 = Fp.add(t0, t1);
		            t3 = Fp.sub(t3, t4);
		            t4 = Fp.add(X1, Z1);
		            let t5 = Fp.add(X2, Z2); // step 10
		            t4 = Fp.mul(t4, t5);
		            t5 = Fp.add(t0, t2);
		            t4 = Fp.sub(t4, t5);
		            t5 = Fp.add(Y1, Z1);
		            X3 = Fp.add(Y2, Z2); // step 15
		            t5 = Fp.mul(t5, X3);
		            X3 = Fp.add(t1, t2);
		            t5 = Fp.sub(t5, X3);
		            Z3 = Fp.mul(a, t4);
		            X3 = Fp.mul(b3, t2); // step 20
		            Z3 = Fp.add(X3, Z3);
		            X3 = Fp.sub(t1, Z3);
		            Z3 = Fp.add(t1, Z3);
		            Y3 = Fp.mul(X3, Z3);
		            t1 = Fp.add(t0, t0); // step 25
		            t1 = Fp.add(t1, t0);
		            t2 = Fp.mul(a, t2);
		            t4 = Fp.mul(b3, t4);
		            t1 = Fp.add(t1, t2);
		            t2 = Fp.sub(t0, t2); // step 30
		            t2 = Fp.mul(a, t2);
		            t4 = Fp.add(t4, t2);
		            t0 = Fp.mul(t1, t4);
		            Y3 = Fp.add(Y3, t0);
		            t0 = Fp.mul(t5, t4); // step 35
		            X3 = Fp.mul(t3, X3);
		            X3 = Fp.sub(X3, t0);
		            t0 = Fp.mul(t3, t1);
		            Z3 = Fp.mul(t5, Z3);
		            Z3 = Fp.add(Z3, t0); // step 40
		            return new Point(X3, Y3, Z3);
		        }
		        subtract(other) {
		            return this.add(other.negate());
		        }
		        is0() {
		            return this.equals(Point.ZERO);
		        }
		        wNAF(n) {
		            return wnaf.wNAFCached(this, n, Point.normalizeZ);
		        }
		        /**
		         * Non-constant-time multiplication. Uses double-and-add algorithm.
		         * It's faster, but should only be used when you don't care about
		         * an exposed private key e.g. sig verification, which works over *public* keys.
		         */
		        multiplyUnsafe(sc) {
		            const { endo, n: N } = CURVE;
		            ut.aInRange('scalar', sc, _0n, N);
		            const I = Point.ZERO;
		            if (sc === _0n)
		                return I;
		            if (this.is0() || sc === _1n)
		                return this;
		            // Case a: no endomorphism. Case b: has precomputes.
		            if (!endo || wnaf.hasPrecomputes(this))
		                return wnaf.wNAFCachedUnsafe(this, sc, Point.normalizeZ);
		            // Case c: endomorphism
		            let { k1neg, k1, k2neg, k2 } = endo.splitScalar(sc);
		            let k1p = I;
		            let k2p = I;
		            let d = this;
		            while (k1 > _0n || k2 > _0n) {
		                if (k1 & _1n)
		                    k1p = k1p.add(d);
		                if (k2 & _1n)
		                    k2p = k2p.add(d);
		                d = d.double();
		                k1 >>= _1n;
		                k2 >>= _1n;
		            }
		            if (k1neg)
		                k1p = k1p.negate();
		            if (k2neg)
		                k2p = k2p.negate();
		            k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
		            return k1p.add(k2p);
		        }
		        /**
		         * Constant time multiplication.
		         * Uses wNAF method. Windowed method may be 10% faster,
		         * but takes 2x longer to generate and consumes 2x memory.
		         * Uses precomputes when available.
		         * Uses endomorphism for Koblitz curves.
		         * @param scalar by which the point would be multiplied
		         * @returns New point
		         */
		        multiply(scalar) {
		            const { endo, n: N } = CURVE;
		            ut.aInRange('scalar', scalar, _1n, N);
		            let point, fake; // Fake point is used to const-time mult
		            if (endo) {
		                const { k1neg, k1, k2neg, k2 } = endo.splitScalar(scalar);
		                let { p: k1p, f: f1p } = this.wNAF(k1);
		                let { p: k2p, f: f2p } = this.wNAF(k2);
		                k1p = wnaf.constTimeNegate(k1neg, k1p);
		                k2p = wnaf.constTimeNegate(k2neg, k2p);
		                k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
		                point = k1p.add(k2p);
		                fake = f1p.add(f2p);
		            }
		            else {
		                const { p, f } = this.wNAF(scalar);
		                point = p;
		                fake = f;
		            }
		            // Normalize `z` for both points, but return only real one
		            return Point.normalizeZ([point, fake])[0];
		        }
		        /**
		         * Efficiently calculate `aP + bQ`. Unsafe, can expose private key, if used incorrectly.
		         * Not using Strauss-Shamir trick: precomputation tables are faster.
		         * The trick could be useful if both P and Q are not G (not in our case).
		         * @returns non-zero affine point
		         */
		        multiplyAndAddUnsafe(Q, a, b) {
		            const G = Point.BASE; // No Strauss-Shamir trick: we have 10% faster G precomputes
		            const mul = (P, a // Select faster multiply() method
		            ) => (a === _0n || a === _1n || !P.equals(G) ? P.multiplyUnsafe(a) : P.multiply(a));
		            const sum = mul(this, a).add(mul(Q, b));
		            return sum.is0() ? undefined : sum;
		        }
		        // Converts Projective point to affine (x, y) coordinates.
		        // Can accept precomputed Z^-1 - for example, from invertBatch.
		        // (x, y, z) ∋ (x=x/z, y=y/z)
		        toAffine(iz) {
		            return toAffineMemo(this, iz);
		        }
		        isTorsionFree() {
		            const { h: cofactor, isTorsionFree } = CURVE;
		            if (cofactor === _1n)
		                return true; // No subgroups, always torsion-free
		            if (isTorsionFree)
		                return isTorsionFree(Point, this);
		            throw new Error('isTorsionFree() has not been declared for the elliptic curve');
		        }
		        clearCofactor() {
		            const { h: cofactor, clearCofactor } = CURVE;
		            if (cofactor === _1n)
		                return this; // Fast-path
		            if (clearCofactor)
		                return clearCofactor(Point, this);
		            return this.multiplyUnsafe(CURVE.h);
		        }
		        toRawBytes(isCompressed = true) {
		            (0, utils_js_1.abool)('isCompressed', isCompressed);
		            this.assertValidity();
		            return toBytes(Point, this, isCompressed);
		        }
		        toHex(isCompressed = true) {
		            (0, utils_js_1.abool)('isCompressed', isCompressed);
		            return ut.bytesToHex(this.toRawBytes(isCompressed));
		        }
		    }
		    Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
		    Point.ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
		    const _bits = CURVE.nBitLength;
		    const wnaf = (0, curve_js_1.wNAF)(Point, CURVE.endo ? Math.ceil(_bits / 2) : _bits);
		    // Validate if generator point is on curve
		    return {
		        CURVE,
		        ProjectivePoint: Point,
		        normPrivateKeyToScalar,
		        weierstrassEquation,
		        isWithinCurveOrder,
		    };
		}
		function validateOpts(curve) {
		    const opts = (0, curve_js_1.validateBasic)(curve);
		    ut.validateObject(opts, {
		        hash: 'hash',
		        hmac: 'function',
		        randomBytes: 'function',
		    }, {
		        bits2int: 'function',
		        bits2int_modN: 'function',
		        lowS: 'boolean',
		    });
		    return Object.freeze({ lowS: true, ...opts });
		}
		/**
		 * Creates short weierstrass curve and ECDSA signature methods for it.
		 * @example
		 * import { Field } from '@noble/curves/abstract/modular';
		 * // Before that, define BigInt-s: a, b, p, n, Gx, Gy
		 * const curve = weierstrass({ a, b, Fp: Field(p), n, Gx, Gy, h: 1n })
		 */
		function weierstrass(curveDef) {
		    const CURVE = validateOpts(curveDef);
		    const { Fp, n: CURVE_ORDER } = CURVE;
		    const compressedLen = Fp.BYTES + 1; // e.g. 33 for 32
		    const uncompressedLen = 2 * Fp.BYTES + 1; // e.g. 65 for 32
		    function modN(a) {
		        return (0, modular_js_1.mod)(a, CURVE_ORDER);
		    }
		    function invN(a) {
		        return (0, modular_js_1.invert)(a, CURVE_ORDER);
		    }
		    const { ProjectivePoint: Point, normPrivateKeyToScalar, weierstrassEquation, isWithinCurveOrder, } = weierstrassPoints({
		        ...CURVE,
		        toBytes(_c, point, isCompressed) {
		            const a = point.toAffine();
		            const x = Fp.toBytes(a.x);
		            const cat = ut.concatBytes;
		            (0, utils_js_1.abool)('isCompressed', isCompressed);
		            if (isCompressed) {
		                return cat(Uint8Array.from([point.hasEvenY() ? 0x02 : 0x03]), x);
		            }
		            else {
		                return cat(Uint8Array.from([0x04]), x, Fp.toBytes(a.y));
		            }
		        },
		        fromBytes(bytes) {
		            const len = bytes.length;
		            const head = bytes[0];
		            const tail = bytes.subarray(1);
		            // this.assertValidity() is done inside of fromHex
		            if (len === compressedLen && (head === 0x02 || head === 0x03)) {
		                const x = ut.bytesToNumberBE(tail);
		                if (!ut.inRange(x, _1n, Fp.ORDER))
		                    throw new Error('Point is not on curve');
		                const y2 = weierstrassEquation(x); // y² = x³ + ax + b
		                let y;
		                try {
		                    y = Fp.sqrt(y2); // y = y² ^ (p+1)/4
		                }
		                catch (sqrtError) {
		                    const suffix = sqrtError instanceof Error ? ': ' + sqrtError.message : '';
		                    throw new Error('Point is not on curve' + suffix);
		                }
		                const isYOdd = (y & _1n) === _1n;
		                // ECDSA
		                const isHeadOdd = (head & 1) === 1;
		                if (isHeadOdd !== isYOdd)
		                    y = Fp.neg(y);
		                return { x, y };
		            }
		            else if (len === uncompressedLen && head === 0x04) {
		                const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
		                const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
		                return { x, y };
		            }
		            else {
		                const cl = compressedLen;
		                const ul = uncompressedLen;
		                throw new Error('invalid Point, expected length of ' + cl + ', or uncompressed ' + ul + ', got ' + len);
		            }
		        },
		    });
		    const numToNByteStr = (num) => ut.bytesToHex(ut.numberToBytesBE(num, CURVE.nByteLength));
		    function isBiggerThanHalfOrder(number) {
		        const HALF = CURVE_ORDER >> _1n;
		        return number > HALF;
		    }
		    function normalizeS(s) {
		        return isBiggerThanHalfOrder(s) ? modN(-s) : s;
		    }
		    // slice bytes num
		    const slcNum = (b, from, to) => ut.bytesToNumberBE(b.slice(from, to));
		    /**
		     * ECDSA signature with its (r, s) properties. Supports DER & compact representations.
		     */
		    class Signature {
		        constructor(r, s, recovery) {
		            this.r = r;
		            this.s = s;
		            this.recovery = recovery;
		            this.assertValidity();
		        }
		        // pair (bytes of r, bytes of s)
		        static fromCompact(hex) {
		            const l = CURVE.nByteLength;
		            hex = (0, utils_js_1.ensureBytes)('compactSignature', hex, l * 2);
		            return new Signature(slcNum(hex, 0, l), slcNum(hex, l, 2 * l));
		        }
		        // DER encoded ECDSA signature
		        // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
		        static fromDER(hex) {
		            const { r, s } = exports.DER.toSig((0, utils_js_1.ensureBytes)('DER', hex));
		            return new Signature(r, s);
		        }
		        assertValidity() {
		            ut.aInRange('r', this.r, _1n, CURVE_ORDER); // r in [1..N]
		            ut.aInRange('s', this.s, _1n, CURVE_ORDER); // s in [1..N]
		        }
		        addRecoveryBit(recovery) {
		            return new Signature(this.r, this.s, recovery);
		        }
		        recoverPublicKey(msgHash) {
		            const { r, s, recovery: rec } = this;
		            const h = bits2int_modN((0, utils_js_1.ensureBytes)('msgHash', msgHash)); // Truncate hash
		            if (rec == null || ![0, 1, 2, 3].includes(rec))
		                throw new Error('recovery id invalid');
		            const radj = rec === 2 || rec === 3 ? r + CURVE.n : r;
		            if (radj >= Fp.ORDER)
		                throw new Error('recovery id 2 or 3 invalid');
		            const prefix = (rec & 1) === 0 ? '02' : '03';
		            const R = Point.fromHex(prefix + numToNByteStr(radj));
		            const ir = invN(radj); // r^-1
		            const u1 = modN(-h * ir); // -hr^-1
		            const u2 = modN(s * ir); // sr^-1
		            const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
		            if (!Q)
		                throw new Error('point at infinify'); // unsafe is fine: no priv data leaked
		            Q.assertValidity();
		            return Q;
		        }
		        // Signatures should be low-s, to prevent malleability.
		        hasHighS() {
		            return isBiggerThanHalfOrder(this.s);
		        }
		        normalizeS() {
		            return this.hasHighS() ? new Signature(this.r, modN(-this.s), this.recovery) : this;
		        }
		        // DER-encoded
		        toDERRawBytes() {
		            return ut.hexToBytes(this.toDERHex());
		        }
		        toDERHex() {
		            return exports.DER.hexFromSig({ r: this.r, s: this.s });
		        }
		        // padded bytes of r, then padded bytes of s
		        toCompactRawBytes() {
		            return ut.hexToBytes(this.toCompactHex());
		        }
		        toCompactHex() {
		            return numToNByteStr(this.r) + numToNByteStr(this.s);
		        }
		    }
		    const utils = {
		        isValidPrivateKey(privateKey) {
		            try {
		                normPrivateKeyToScalar(privateKey);
		                return true;
		            }
		            catch (error) {
		                return false;
		            }
		        },
		        normPrivateKeyToScalar: normPrivateKeyToScalar,
		        /**
		         * Produces cryptographically secure private key from random of size
		         * (groupLen + ceil(groupLen / 2)) with modulo bias being negligible.
		         */
		        randomPrivateKey: () => {
		            const length = (0, modular_js_1.getMinHashLength)(CURVE.n);
		            return (0, modular_js_1.mapHashToField)(CURVE.randomBytes(length), CURVE.n);
		        },
		        /**
		         * Creates precompute table for an arbitrary EC point. Makes point "cached".
		         * Allows to massively speed-up `point.multiply(scalar)`.
		         * @returns cached point
		         * @example
		         * const fast = utils.precompute(8, ProjectivePoint.fromHex(someonesPubKey));
		         * fast.multiply(privKey); // much faster ECDH now
		         */
		        precompute(windowSize = 8, point = Point.BASE) {
		            point._setWindowSize(windowSize);
		            point.multiply(BigInt(3)); // 3 is arbitrary, just need any number here
		            return point;
		        },
		    };
		    /**
		     * Computes public key for a private key. Checks for validity of the private key.
		     * @param privateKey private key
		     * @param isCompressed whether to return compact (default), or full key
		     * @returns Public key, full when isCompressed=false; short when isCompressed=true
		     */
		    function getPublicKey(privateKey, isCompressed = true) {
		        return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
		    }
		    /**
		     * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
		     */
		    function isProbPub(item) {
		        const arr = ut.isBytes(item);
		        const str = typeof item === 'string';
		        const len = (arr || str) && item.length;
		        if (arr)
		            return len === compressedLen || len === uncompressedLen;
		        if (str)
		            return len === 2 * compressedLen || len === 2 * uncompressedLen;
		        if (item instanceof Point)
		            return true;
		        return false;
		    }
		    /**
		     * ECDH (Elliptic Curve Diffie Hellman).
		     * Computes shared public key from private key and public key.
		     * Checks: 1) private key validity 2) shared key is on-curve.
		     * Does NOT hash the result.
		     * @param privateA private key
		     * @param publicB different public key
		     * @param isCompressed whether to return compact (default), or full key
		     * @returns shared public key
		     */
		    function getSharedSecret(privateA, publicB, isCompressed = true) {
		        if (isProbPub(privateA))
		            throw new Error('first arg must be private key');
		        if (!isProbPub(publicB))
		            throw new Error('second arg must be public key');
		        const b = Point.fromHex(publicB); // check for being on-curve
		        return b.multiply(normPrivateKeyToScalar(privateA)).toRawBytes(isCompressed);
		    }
		    // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
		    // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
		    // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
		    // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
		    const bits2int = CURVE.bits2int ||
		        function (bytes) {
		            // Our custom check "just in case"
		            if (bytes.length > 8192)
		                throw new Error('input is too large');
		            // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
		            // for some cases, since bytes.length * 8 is not actual bitLength.
		            const num = ut.bytesToNumberBE(bytes); // check for == u8 done here
		            const delta = bytes.length * 8 - CURVE.nBitLength; // truncate to nBitLength leftmost bits
		            return delta > 0 ? num >> BigInt(delta) : num;
		        };
		    const bits2int_modN = CURVE.bits2int_modN ||
		        function (bytes) {
		            return modN(bits2int(bytes)); // can't use bytesToNumberBE here
		        };
		    // NOTE: pads output with zero as per spec
		    const ORDER_MASK = ut.bitMask(CURVE.nBitLength);
		    /**
		     * Converts to bytes. Checks if num in `[0..ORDER_MASK-1]` e.g.: `[0..2^256-1]`.
		     */
		    function int2octets(num) {
		        ut.aInRange('num < 2^' + CURVE.nBitLength, num, _0n, ORDER_MASK);
		        // works with order, can have different size than numToField!
		        return ut.numberToBytesBE(num, CURVE.nByteLength);
		    }
		    // Steps A, D of RFC6979 3.2
		    // Creates RFC6979 seed; converts msg/privKey to numbers.
		    // Used only in sign, not in verify.
		    // NOTE: we cannot assume here that msgHash has same amount of bytes as curve order,
		    // this will be invalid at least for P521. Also it can be bigger for P224 + SHA256
		    function prepSig(msgHash, privateKey, opts = defaultSigOpts) {
		        if (['recovered', 'canonical'].some((k) => k in opts))
		            throw new Error('sign() legacy options not supported');
		        const { hash, randomBytes } = CURVE;
		        let { lowS, prehash, extraEntropy: ent } = opts; // generates low-s sigs by default
		        if (lowS == null)
		            lowS = true; // RFC6979 3.2: we skip step A, because we already provide hash
		        msgHash = (0, utils_js_1.ensureBytes)('msgHash', msgHash);
		        validateSigVerOpts(opts);
		        if (prehash)
		            msgHash = (0, utils_js_1.ensureBytes)('prehashed msgHash', hash(msgHash));
		        // We can't later call bits2octets, since nested bits2int is broken for curves
		        // with nBitLength % 8 !== 0. Because of that, we unwrap it here as int2octets call.
		        // const bits2octets = (bits) => int2octets(bits2int_modN(bits))
		        const h1int = bits2int_modN(msgHash);
		        const d = normPrivateKeyToScalar(privateKey); // validate private key, convert to bigint
		        const seedArgs = [int2octets(d), int2octets(h1int)];
		        // extraEntropy. RFC6979 3.6: additional k' (optional).
		        if (ent != null && ent !== false) {
		            // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
		            const e = ent === true ? randomBytes(Fp.BYTES) : ent; // generate random bytes OR pass as-is
		            seedArgs.push((0, utils_js_1.ensureBytes)('extraEntropy', e)); // check for being bytes
		        }
		        const seed = ut.concatBytes(...seedArgs); // Step D of RFC6979 3.2
		        const m = h1int; // NOTE: no need to call bits2int second time here, it is inside truncateHash!
		        // Converts signature params into point w r/s, checks result for validity.
		        function k2sig(kBytes) {
		            // RFC 6979 Section 3.2, step 3: k = bits2int(T)
		            const k = bits2int(kBytes); // Cannot use fields methods, since it is group element
		            if (!isWithinCurveOrder(k))
		                return; // Important: all mod() calls here must be done over N
		            const ik = invN(k); // k^-1 mod n
		            const q = Point.BASE.multiply(k).toAffine(); // q = Gk
		            const r = modN(q.x); // r = q.x mod n
		            if (r === _0n)
		                return;
		            // Can use scalar blinding b^-1(bm + bdr) where b ∈ [1,q−1] according to
		            // https://tches.iacr.org/index.php/TCHES/article/view/7337/6509. We've decided against it:
		            // a) dependency on CSPRNG b) 15% slowdown c) doesn't really help since bigints are not CT
		            const s = modN(ik * modN(m + r * d)); // Not using blinding here
		            if (s === _0n)
		                return;
		            let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n); // recovery bit (2 or 3, when q.x > n)
		            let normS = s;
		            if (lowS && isBiggerThanHalfOrder(s)) {
		                normS = normalizeS(s); // if lowS was passed, ensure s is always
		                recovery ^= 1; // // in the bottom half of N
		            }
		            return new Signature(r, normS, recovery); // use normS, not s
		        }
		        return { seed, k2sig };
		    }
		    const defaultSigOpts = { lowS: CURVE.lowS, prehash: false };
		    const defaultVerOpts = { lowS: CURVE.lowS, prehash: false };
		    /**
		     * Signs message hash with a private key.
		     * ```
		     * sign(m, d, k) where
		     *   (x, y) = G × k
		     *   r = x mod n
		     *   s = (m + dr)/k mod n
		     * ```
		     * @param msgHash NOT message. msg needs to be hashed to `msgHash`, or use `prehash`.
		     * @param privKey private key
		     * @param opts lowS for non-malleable sigs. extraEntropy for mixing randomness into k. prehash will hash first arg.
		     * @returns signature with recovery param
		     */
		    function sign(msgHash, privKey, opts = defaultSigOpts) {
		        const { seed, k2sig } = prepSig(msgHash, privKey, opts); // Steps A, D of RFC6979 3.2.
		        const C = CURVE;
		        const drbg = ut.createHmacDrbg(C.hash.outputLen, C.nByteLength, C.hmac);
		        return drbg(seed, k2sig); // Steps B, C, D, E, F, G
		    }
		    // Enable precomputes. Slows down first publicKey computation by 20ms.
		    Point.BASE._setWindowSize(8);
		    // utils.precompute(8, ProjectivePoint.BASE)
		    /**
		     * Verifies a signature against message hash and public key.
		     * Rejects lowS signatures by default: to override,
		     * specify option `{lowS: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
		     *
		     * ```
		     * verify(r, s, h, P) where
		     *   U1 = hs^-1 mod n
		     *   U2 = rs^-1 mod n
		     *   R = U1⋅G - U2⋅P
		     *   mod(R.x, n) == r
		     * ```
		     */
		    function verify(signature, msgHash, publicKey, opts = defaultVerOpts) {
		        const sg = signature;
		        msgHash = (0, utils_js_1.ensureBytes)('msgHash', msgHash);
		        publicKey = (0, utils_js_1.ensureBytes)('publicKey', publicKey);
		        const { lowS, prehash, format } = opts;
		        // Verify opts, deduce signature format
		        validateSigVerOpts(opts);
		        if ('strict' in opts)
		            throw new Error('options.strict was renamed to lowS');
		        if (format !== undefined && format !== 'compact' && format !== 'der')
		            throw new Error('format must be compact or der');
		        const isHex = typeof sg === 'string' || ut.isBytes(sg);
		        const isObj = !isHex &&
		            !format &&
		            typeof sg === 'object' &&
		            sg !== null &&
		            typeof sg.r === 'bigint' &&
		            typeof sg.s === 'bigint';
		        if (!isHex && !isObj)
		            throw new Error('invalid signature, expected Uint8Array, hex string or Signature instance');
		        let _sig = undefined;
		        let P;
		        try {
		            if (isObj)
		                _sig = new Signature(sg.r, sg.s);
		            if (isHex) {
		                // Signature can be represented in 2 ways: compact (2*nByteLength) & DER (variable-length).
		                // Since DER can also be 2*nByteLength bytes, we check for it first.
		                try {
		                    if (format !== 'compact')
		                        _sig = Signature.fromDER(sg);
		                }
		                catch (derError) {
		                    if (!(derError instanceof exports.DER.Err))
		                        throw derError;
		                }
		                if (!_sig && format !== 'der')
		                    _sig = Signature.fromCompact(sg);
		            }
		            P = Point.fromHex(publicKey);
		        }
		        catch (error) {
		            return false;
		        }
		        if (!_sig)
		            return false;
		        if (lowS && _sig.hasHighS())
		            return false;
		        if (prehash)
		            msgHash = CURVE.hash(msgHash);
		        const { r, s } = _sig;
		        const h = bits2int_modN(msgHash); // Cannot use fields methods, since it is group element
		        const is = invN(s); // s^-1
		        const u1 = modN(h * is); // u1 = hs^-1 mod n
		        const u2 = modN(r * is); // u2 = rs^-1 mod n
		        const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2)?.toAffine(); // R = u1⋅G + u2⋅P
		        if (!R)
		            return false;
		        const v = modN(R.x);
		        return v === r;
		    }
		    return {
		        CURVE,
		        getPublicKey,
		        getSharedSecret,
		        sign,
		        verify,
		        ProjectivePoint: Point,
		        Signature,
		        utils,
		    };
		}
		/**
		 * Implementation of the Shallue and van de Woestijne method for any weierstrass curve.
		 * TODO: check if there is a way to merge this with uvRatio in Edwards; move to modular.
		 * b = True and y = sqrt(u / v) if (u / v) is square in F, and
		 * b = False and y = sqrt(Z * (u / v)) otherwise.
		 * @param Fp
		 * @param Z
		 * @returns
		 */
		function SWUFpSqrtRatio(Fp, Z) {
		    // Generic implementation
		    const q = Fp.ORDER;
		    let l = _0n;
		    for (let o = q - _1n; o % _2n === _0n; o /= _2n)
		        l += _1n;
		    const c1 = l; // 1. c1, the largest integer such that 2^c1 divides q - 1.
		    // We need 2n ** c1 and 2n ** (c1-1). We can't use **; but we can use <<.
		    // 2n ** c1 == 2n << (c1-1)
		    const _2n_pow_c1_1 = _2n << (c1 - _1n - _1n);
		    const _2n_pow_c1 = _2n_pow_c1_1 * _2n;
		    const c2 = (q - _1n) / _2n_pow_c1; // 2. c2 = (q - 1) / (2^c1)  # Integer arithmetic
		    const c3 = (c2 - _1n) / _2n; // 3. c3 = (c2 - 1) / 2            # Integer arithmetic
		    const c4 = _2n_pow_c1 - _1n; // 4. c4 = 2^c1 - 1                # Integer arithmetic
		    const c5 = _2n_pow_c1_1; // 5. c5 = 2^(c1 - 1)                  # Integer arithmetic
		    const c6 = Fp.pow(Z, c2); // 6. c6 = Z^c2
		    const c7 = Fp.pow(Z, (c2 + _1n) / _2n); // 7. c7 = Z^((c2 + 1) / 2)
		    let sqrtRatio = (u, v) => {
		        let tv1 = c6; // 1. tv1 = c6
		        let tv2 = Fp.pow(v, c4); // 2. tv2 = v^c4
		        let tv3 = Fp.sqr(tv2); // 3. tv3 = tv2^2
		        tv3 = Fp.mul(tv3, v); // 4. tv3 = tv3 * v
		        let tv5 = Fp.mul(u, tv3); // 5. tv5 = u * tv3
		        tv5 = Fp.pow(tv5, c3); // 6. tv5 = tv5^c3
		        tv5 = Fp.mul(tv5, tv2); // 7. tv5 = tv5 * tv2
		        tv2 = Fp.mul(tv5, v); // 8. tv2 = tv5 * v
		        tv3 = Fp.mul(tv5, u); // 9. tv3 = tv5 * u
		        let tv4 = Fp.mul(tv3, tv2); // 10. tv4 = tv3 * tv2
		        tv5 = Fp.pow(tv4, c5); // 11. tv5 = tv4^c5
		        let isQR = Fp.eql(tv5, Fp.ONE); // 12. isQR = tv5 == 1
		        tv2 = Fp.mul(tv3, c7); // 13. tv2 = tv3 * c7
		        tv5 = Fp.mul(tv4, tv1); // 14. tv5 = tv4 * tv1
		        tv3 = Fp.cmov(tv2, tv3, isQR); // 15. tv3 = CMOV(tv2, tv3, isQR)
		        tv4 = Fp.cmov(tv5, tv4, isQR); // 16. tv4 = CMOV(tv5, tv4, isQR)
		        // 17. for i in (c1, c1 - 1, ..., 2):
		        for (let i = c1; i > _1n; i--) {
		            let tv5 = i - _2n; // 18.    tv5 = i - 2
		            tv5 = _2n << (tv5 - _1n); // 19.    tv5 = 2^tv5
		            let tvv5 = Fp.pow(tv4, tv5); // 20.    tv5 = tv4^tv5
		            const e1 = Fp.eql(tvv5, Fp.ONE); // 21.    e1 = tv5 == 1
		            tv2 = Fp.mul(tv3, tv1); // 22.    tv2 = tv3 * tv1
		            tv1 = Fp.mul(tv1, tv1); // 23.    tv1 = tv1 * tv1
		            tvv5 = Fp.mul(tv4, tv1); // 24.    tv5 = tv4 * tv1
		            tv3 = Fp.cmov(tv2, tv3, e1); // 25.    tv3 = CMOV(tv2, tv3, e1)
		            tv4 = Fp.cmov(tvv5, tv4, e1); // 26.    tv4 = CMOV(tv5, tv4, e1)
		        }
		        return { isValid: isQR, value: tv3 };
		    };
		    if (Fp.ORDER % _4n === _3n) {
		        // sqrt_ratio_3mod4(u, v)
		        const c1 = (Fp.ORDER - _3n) / _4n; // 1. c1 = (q - 3) / 4     # Integer arithmetic
		        const c2 = Fp.sqrt(Fp.neg(Z)); // 2. c2 = sqrt(-Z)
		        sqrtRatio = (u, v) => {
		            let tv1 = Fp.sqr(v); // 1. tv1 = v^2
		            const tv2 = Fp.mul(u, v); // 2. tv2 = u * v
		            tv1 = Fp.mul(tv1, tv2); // 3. tv1 = tv1 * tv2
		            let y1 = Fp.pow(tv1, c1); // 4. y1 = tv1^c1
		            y1 = Fp.mul(y1, tv2); // 5. y1 = y1 * tv2
		            const y2 = Fp.mul(y1, c2); // 6. y2 = y1 * c2
		            const tv3 = Fp.mul(Fp.sqr(y1), v); // 7. tv3 = y1^2; 8. tv3 = tv3 * v
		            const isQR = Fp.eql(tv3, u); // 9. isQR = tv3 == u
		            let y = Fp.cmov(y2, y1, isQR); // 10. y = CMOV(y2, y1, isQR)
		            return { isValid: isQR, value: y }; // 11. return (isQR, y) isQR ? y : y*c2
		        };
		    }
		    // No curves uses that
		    // if (Fp.ORDER % _8n === _5n) // sqrt_ratio_5mod8
		    return sqrtRatio;
		}
		/**
		 * Simplified Shallue-van de Woestijne-Ulas Method
		 * https://www.rfc-editor.org/rfc/rfc9380#section-6.6.2
		 */
		function mapToCurveSimpleSWU(Fp, opts) {
		    (0, modular_js_1.validateField)(Fp);
		    if (!Fp.isValid(opts.A) || !Fp.isValid(opts.B) || !Fp.isValid(opts.Z))
		        throw new Error('mapToCurveSimpleSWU: invalid opts');
		    const sqrtRatio = SWUFpSqrtRatio(Fp, opts.Z);
		    if (!Fp.isOdd)
		        throw new Error('Fp.isOdd is not implemented!');
		    // Input: u, an element of F.
		    // Output: (x, y), a point on E.
		    return (u) => {
		        // prettier-ignore
		        let tv1, tv2, tv3, tv4, tv5, tv6, x, y;
		        tv1 = Fp.sqr(u); // 1.  tv1 = u^2
		        tv1 = Fp.mul(tv1, opts.Z); // 2.  tv1 = Z * tv1
		        tv2 = Fp.sqr(tv1); // 3.  tv2 = tv1^2
		        tv2 = Fp.add(tv2, tv1); // 4.  tv2 = tv2 + tv1
		        tv3 = Fp.add(tv2, Fp.ONE); // 5.  tv3 = tv2 + 1
		        tv3 = Fp.mul(tv3, opts.B); // 6.  tv3 = B * tv3
		        tv4 = Fp.cmov(opts.Z, Fp.neg(tv2), !Fp.eql(tv2, Fp.ZERO)); // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
		        tv4 = Fp.mul(tv4, opts.A); // 8.  tv4 = A * tv4
		        tv2 = Fp.sqr(tv3); // 9.  tv2 = tv3^2
		        tv6 = Fp.sqr(tv4); // 10. tv6 = tv4^2
		        tv5 = Fp.mul(tv6, opts.A); // 11. tv5 = A * tv6
		        tv2 = Fp.add(tv2, tv5); // 12. tv2 = tv2 + tv5
		        tv2 = Fp.mul(tv2, tv3); // 13. tv2 = tv2 * tv3
		        tv6 = Fp.mul(tv6, tv4); // 14. tv6 = tv6 * tv4
		        tv5 = Fp.mul(tv6, opts.B); // 15. tv5 = B * tv6
		        tv2 = Fp.add(tv2, tv5); // 16. tv2 = tv2 + tv5
		        x = Fp.mul(tv1, tv3); // 17.   x = tv1 * tv3
		        const { isValid, value } = sqrtRatio(tv2, tv6); // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
		        y = Fp.mul(tv1, u); // 19.   y = tv1 * u  -> Z * u^3 * y1
		        y = Fp.mul(y, value); // 20.   y = y * y1
		        x = Fp.cmov(x, tv3, isValid); // 21.   x = CMOV(x, tv3, is_gx1_square)
		        y = Fp.cmov(y, value, isValid); // 22.   y = CMOV(y, y1, is_gx1_square)
		        const e1 = Fp.isOdd(u) === Fp.isOdd(y); // 23.  e1 = sgn0(u) == sgn0(y)
		        y = Fp.cmov(Fp.neg(y), y, e1); // 24.   y = CMOV(-y, y, e1)
		        x = Fp.div(x, tv4); // 25.   x = x / tv4
		        return { x, y };
		    };
		}
		
	} (weierstrass));
	return weierstrass;
}

var hasRequired_shortw_utils;

function require_shortw_utils () {
	if (hasRequired_shortw_utils) return _shortw_utils;
	hasRequired_shortw_utils = 1;
	Object.defineProperty(_shortw_utils, "__esModule", { value: true });
	_shortw_utils.getHash = getHash;
	_shortw_utils.createCurve = createCurve;
	/**
	 * Utilities for short weierstrass curves, combined with noble-hashes.
	 * @module
	 */
	/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
	const hmac_1 = /*@__PURE__*/ requireHmac();
	const utils_1 = /*@__PURE__*/ requireUtils$2();
	const weierstrass_js_1 = /*@__PURE__*/ requireWeierstrass();
	/** connects noble-curves to noble-hashes */
	function getHash(hash) {
	    return {
	        hash,
	        hmac: (key, ...msgs) => (0, hmac_1.hmac)(hash, key, (0, utils_1.concatBytes)(...msgs)),
	        randomBytes: utils_1.randomBytes,
	    };
	}
	function createCurve(curveDef, defHash) {
	    const create = (hash) => (0, weierstrass_js_1.weierstrass)({ ...curveDef, ...getHash(hash) });
	    return { ...create(defHash), create };
	}
	
	return _shortw_utils;
}

var hasRequiredSecp256k1;

function requireSecp256k1 () {
	if (hasRequiredSecp256k1) return secp256k1;
	hasRequiredSecp256k1 = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.encodeToCurve = exports.hashToCurve = exports.schnorr = exports.secp256k1 = void 0;
		/**
		 * NIST secp256k1. See [pdf](https://www.secg.org/sec2-v2.pdf).
		 *
		 * Seems to be rigid (not backdoored)
		 * [as per discussion](https://bitcointalk.org/index.php?topic=289795.msg3183975#msg3183975).
		 *
		 * secp256k1 belongs to Koblitz curves: it has efficiently computable endomorphism.
		 * Endomorphism uses 2x less RAM, speeds up precomputation by 2x and ECDH / key recovery by 20%.
		 * For precomputed wNAF it trades off 1/2 init time & 1/3 ram for 20% perf hit.
		 * [See explanation](https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066).
		 * @module
		 */
		/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
		const sha256_1 = /*@__PURE__*/ requireSha256();
		const utils_1 = /*@__PURE__*/ requireUtils$2();
		const _shortw_utils_js_1 = /*@__PURE__*/ require_shortw_utils();
		const hash_to_curve_js_1 = /*@__PURE__*/ requireHashToCurve();
		const modular_js_1 = /*@__PURE__*/ requireModular();
		const utils_js_1 = /*@__PURE__*/ requireUtils$1();
		const weierstrass_js_1 = /*@__PURE__*/ requireWeierstrass();
		const secp256k1P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
		const secp256k1N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
		const _1n = BigInt(1);
		const _2n = BigInt(2);
		const divNearest = (a, b) => (a + b / _2n) / b;
		/**
		 * √n = n^((p+1)/4) for fields p = 3 mod 4. We unwrap the loop and multiply bit-by-bit.
		 * (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
		 */
		function sqrtMod(y) {
		    const P = secp256k1P;
		    // prettier-ignore
		    const _3n = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
		    // prettier-ignore
		    const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
		    const b2 = (y * y * y) % P; // x^3, 11
		    const b3 = (b2 * b2 * y) % P; // x^7
		    const b6 = ((0, modular_js_1.pow2)(b3, _3n, P) * b3) % P;
		    const b9 = ((0, modular_js_1.pow2)(b6, _3n, P) * b3) % P;
		    const b11 = ((0, modular_js_1.pow2)(b9, _2n, P) * b2) % P;
		    const b22 = ((0, modular_js_1.pow2)(b11, _11n, P) * b11) % P;
		    const b44 = ((0, modular_js_1.pow2)(b22, _22n, P) * b22) % P;
		    const b88 = ((0, modular_js_1.pow2)(b44, _44n, P) * b44) % P;
		    const b176 = ((0, modular_js_1.pow2)(b88, _88n, P) * b88) % P;
		    const b220 = ((0, modular_js_1.pow2)(b176, _44n, P) * b44) % P;
		    const b223 = ((0, modular_js_1.pow2)(b220, _3n, P) * b3) % P;
		    const t1 = ((0, modular_js_1.pow2)(b223, _23n, P) * b22) % P;
		    const t2 = ((0, modular_js_1.pow2)(t1, _6n, P) * b2) % P;
		    const root = (0, modular_js_1.pow2)(t2, _2n, P);
		    if (!Fpk1.eql(Fpk1.sqr(root), y))
		        throw new Error('Cannot find square root');
		    return root;
		}
		const Fpk1 = (0, modular_js_1.Field)(secp256k1P, undefined, undefined, { sqrt: sqrtMod });
		/**
		 * secp256k1 short weierstrass curve and ECDSA signatures over it.
		 *
		 * @example
		 * import { secp256k1 } from '@noble/curves/secp256k1';
		 *
		 * const priv = secp256k1.utils.randomPrivateKey();
		 * const pub = secp256k1.getPublicKey(priv);
		 * const msg = new Uint8Array(32).fill(1); // message hash (not message) in ecdsa
		 * const sig = secp256k1.sign(msg, priv); // `{prehash: true}` option is available
		 * const isValid = secp256k1.verify(sig, msg, pub) === true;
		 */
		exports.secp256k1 = (0, _shortw_utils_js_1.createCurve)({
		    a: BigInt(0), // equation params: a, b
		    b: BigInt(7),
		    Fp: Fpk1, // Field's prime: 2n**256n - 2n**32n - 2n**9n - 2n**8n - 2n**7n - 2n**6n - 2n**4n - 1n
		    n: secp256k1N, // Curve order, total count of valid points in the field
		    // Base point (x, y) aka generator point
		    Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
		    Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
		    h: BigInt(1), // Cofactor
		    lowS: true, // Allow only low-S signatures by default in sign() and verify()
		    endo: {
		        // Endomorphism, see above
		        beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
		        splitScalar: (k) => {
		            const n = secp256k1N;
		            const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
		            const b1 = -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
		            const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
		            const b2 = a1;
		            const POW_2_128 = BigInt('0x100000000000000000000000000000000'); // (2n**128n).toString(16)
		            const c1 = divNearest(b2 * k, n);
		            const c2 = divNearest(-b1 * k, n);
		            let k1 = (0, modular_js_1.mod)(k - c1 * a1 - c2 * a2, n);
		            let k2 = (0, modular_js_1.mod)(-c1 * b1 - c2 * b2, n);
		            const k1neg = k1 > POW_2_128;
		            const k2neg = k2 > POW_2_128;
		            if (k1neg)
		                k1 = n - k1;
		            if (k2neg)
		                k2 = n - k2;
		            if (k1 > POW_2_128 || k2 > POW_2_128) {
		                throw new Error('splitScalar: Endomorphism failed, k=' + k);
		            }
		            return { k1neg, k1, k2neg, k2 };
		        },
		    },
		}, sha256_1.sha256);
		// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
		// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
		const _0n = BigInt(0);
		/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
		const TAGGED_HASH_PREFIXES = {};
		function taggedHash(tag, ...messages) {
		    let tagP = TAGGED_HASH_PREFIXES[tag];
		    if (tagP === undefined) {
		        const tagH = (0, sha256_1.sha256)(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
		        tagP = (0, utils_js_1.concatBytes)(tagH, tagH);
		        TAGGED_HASH_PREFIXES[tag] = tagP;
		    }
		    return (0, sha256_1.sha256)((0, utils_js_1.concatBytes)(tagP, ...messages));
		}
		// ECDSA compact points are 33-byte. Schnorr is 32: we strip first byte 0x02 or 0x03
		const pointToBytes = (point) => point.toRawBytes(true).slice(1);
		const numTo32b = (n) => (0, utils_js_1.numberToBytesBE)(n, 32);
		const modP = (x) => (0, modular_js_1.mod)(x, secp256k1P);
		const modN = (x) => (0, modular_js_1.mod)(x, secp256k1N);
		const Point = exports.secp256k1.ProjectivePoint;
		const GmulAdd = (Q, a, b) => Point.BASE.multiplyAndAddUnsafe(Q, a, b);
		// Calculate point, scalar and bytes
		function schnorrGetExtPubKey(priv) {
		    let d_ = exports.secp256k1.utils.normPrivateKeyToScalar(priv); // same method executed in fromPrivateKey
		    let p = Point.fromPrivateKey(d_); // P = d'⋅G; 0 < d' < n check is done inside
		    const scalar = p.hasEvenY() ? d_ : modN(-d_);
		    return { scalar: scalar, bytes: pointToBytes(p) };
		}
		/**
		 * lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
		 * @returns valid point checked for being on-curve
		 */
		function lift_x(x) {
		    (0, utils_js_1.aInRange)('x', x, _1n, secp256k1P); // Fail if x ≥ p.
		    const xx = modP(x * x);
		    const c = modP(xx * x + BigInt(7)); // Let c = x³ + 7 mod p.
		    let y = sqrtMod(c); // Let y = c^(p+1)/4 mod p.
		    if (y % _2n !== _0n)
		        y = modP(-y); // Return the unique point P such that x(P) = x and
		    const p = new Point(x, y, _1n); // y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
		    p.assertValidity();
		    return p;
		}
		const num = utils_js_1.bytesToNumberBE;
		/**
		 * Create tagged hash, convert it to bigint, reduce modulo-n.
		 */
		function challenge(...args) {
		    return modN(num(taggedHash('BIP0340/challenge', ...args)));
		}
		/**
		 * Schnorr public key is just `x` coordinate of Point as per BIP340.
		 */
		function schnorrGetPublicKey(privateKey) {
		    return schnorrGetExtPubKey(privateKey).bytes; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
		}
		/**
		 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
		 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
		 */
		function schnorrSign(message, privateKey, auxRand = (0, utils_1.randomBytes)(32)) {
		    const m = (0, utils_js_1.ensureBytes)('message', message);
		    const { bytes: px, scalar: d } = schnorrGetExtPubKey(privateKey); // checks for isWithinCurveOrder
		    const a = (0, utils_js_1.ensureBytes)('auxRand', auxRand, 32); // Auxiliary random data a: a 32-byte array
		    const t = numTo32b(d ^ num(taggedHash('BIP0340/aux', a))); // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
		    const rand = taggedHash('BIP0340/nonce', t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)
		    const k_ = modN(num(rand)); // Let k' = int(rand) mod n
		    if (k_ === _0n)
		        throw new Error('sign failed: k is zero'); // Fail if k' = 0.
		    const { bytes: rx, scalar: k } = schnorrGetExtPubKey(k_); // Let R = k'⋅G.
		    const e = challenge(rx, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
		    const sig = new Uint8Array(64); // Let sig = bytes(R) || bytes((k + ed) mod n).
		    sig.set(rx, 0);
		    sig.set(numTo32b(modN(k + e * d)), 32);
		    // If Verify(bytes(P), m, sig) (see below) returns failure, abort
		    if (!schnorrVerify(sig, m, px))
		        throw new Error('sign: Invalid signature produced');
		    return sig;
		}
		/**
		 * Verifies Schnorr signature.
		 * Will swallow errors & return false except for initial type validation of arguments.
		 */
		function schnorrVerify(signature, message, publicKey) {
		    const sig = (0, utils_js_1.ensureBytes)('signature', signature, 64);
		    const m = (0, utils_js_1.ensureBytes)('message', message);
		    const pub = (0, utils_js_1.ensureBytes)('publicKey', publicKey, 32);
		    try {
		        const P = lift_x(num(pub)); // P = lift_x(int(pk)); fail if that fails
		        const r = num(sig.subarray(0, 32)); // Let r = int(sig[0:32]); fail if r ≥ p.
		        if (!(0, utils_js_1.inRange)(r, _1n, secp256k1P))
		            return false;
		        const s = num(sig.subarray(32, 64)); // Let s = int(sig[32:64]); fail if s ≥ n.
		        if (!(0, utils_js_1.inRange)(s, _1n, secp256k1N))
		            return false;
		        const e = challenge(numTo32b(r), pointToBytes(P), m); // int(challenge(bytes(r)||bytes(P)||m))%n
		        const R = GmulAdd(P, s, modN(-e)); // R = s⋅G - e⋅P
		        if (!R || !R.hasEvenY() || R.toAffine().x !== r)
		            return false; // -eP == (n-e)P
		        return true; // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
		    }
		    catch (error) {
		        return false;
		    }
		}
		/**
		 * Schnorr signatures over secp256k1.
		 * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
		 * @example
		 * import { schnorr } from '@noble/curves/secp256k1';
		 * const priv = schnorr.utils.randomPrivateKey();
		 * const pub = schnorr.getPublicKey(priv);
		 * const msg = new TextEncoder().encode('hello');
		 * const sig = schnorr.sign(msg, priv);
		 * const isValid = schnorr.verify(sig, msg, pub);
		 */
		exports.schnorr = (() => ({
		    getPublicKey: schnorrGetPublicKey,
		    sign: schnorrSign,
		    verify: schnorrVerify,
		    utils: {
		        randomPrivateKey: exports.secp256k1.utils.randomPrivateKey,
		        lift_x,
		        pointToBytes,
		        numberToBytesBE: utils_js_1.numberToBytesBE,
		        bytesToNumberBE: utils_js_1.bytesToNumberBE,
		        taggedHash,
		        mod: modular_js_1.mod,
		    },
		}))();
		const isoMap = /* @__PURE__ */ (() => (0, hash_to_curve_js_1.isogenyMap)(Fpk1, [
		    // xNum
		    [
		        '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7',
		        '0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581',
		        '0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262',
		        '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c',
		    ],
		    // xDen
		    [
		        '0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b',
		        '0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14',
		        '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
		    ],
		    // yNum
		    [
		        '0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c',
		        '0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3',
		        '0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931',
		        '0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84',
		    ],
		    // yDen
		    [
		        '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b',
		        '0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573',
		        '0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f',
		        '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
		    ],
		].map((i) => i.map((j) => BigInt(j)))))();
		const mapSWU = /* @__PURE__ */ (() => (0, weierstrass_js_1.mapToCurveSimpleSWU)(Fpk1, {
		    A: BigInt('0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533'),
		    B: BigInt('1771'),
		    Z: Fpk1.create(BigInt('-11')),
		}))();
		const htf = /* @__PURE__ */ (() => (0, hash_to_curve_js_1.createHasher)(exports.secp256k1.ProjectivePoint, (scalars) => {
		    const { x, y } = mapSWU(Fpk1.create(scalars[0]));
		    return isoMap(x, y);
		}, {
		    DST: 'secp256k1_XMD:SHA-256_SSWU_RO_',
		    encodeDST: 'secp256k1_XMD:SHA-256_SSWU_NU_',
		    p: Fpk1.ORDER,
		    m: 1,
		    k: 128,
		    expand: 'xmd',
		    hash: sha256_1.sha256,
		}))();
		/** secp256k1 hash-to-curve from [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380). */
		exports.hashToCurve = (() => htf.hashToCurve)();
		/** secp256k1 encode-to-curve from [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380). */
		exports.encodeToCurve = (() => htf.encodeToCurve)();
		
	} (secp256k1));
	return secp256k1;
}

var hex = {};

var hasRequiredHex;

function requireHex () {
	if (hasRequiredHex) return hex;
	hasRequiredHex = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.decodeHex = exports.remove0x = void 0;
		var utils_1 = /*@__PURE__*/ requireUtils$3();
		var remove0x = function (hex) {
		    return hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
		};
		exports.remove0x = remove0x;
		var decodeHex = function (hex) { return (0, utils_1.hexToBytes)((0, exports.remove0x)(hex)); };
		exports.decodeHex = decodeHex; 
	} (hex));
	return hex;
}

var hasRequiredElliptic;

function requireElliptic () {
	if (hasRequiredElliptic) return elliptic;
	hasRequiredElliptic = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.hexToPublicKey = exports.convertPublicKeyFormat = exports.getSharedPoint = exports.getPublicKey = exports.isValidPrivateKey = exports.getValidSecret = void 0;
		var webcrypto_1 = /*@__PURE__*/ requireWebcrypto();
		var ed25519_1 = /*@__PURE__*/ requireEd25519();
		var secp256k1_1 = /*@__PURE__*/ requireSecp256k1();
		var config_1 = requireConfig();
		var consts_1 = requireConsts();
		var hex_1 = requireHex();
		var getValidSecret = function () {
		    var key;
		    do {
		        key = (0, webcrypto_1.randomBytes)(consts_1.SECRET_KEY_LENGTH);
		    } while (!(0, exports.isValidPrivateKey)(key));
		    return key;
		};
		exports.getValidSecret = getValidSecret;
		var isValidPrivateKey = function (secret) {
		    // on secp256k1: only key ∈ (0, group order) is valid
		    // on curve25519: any 32-byte key is valid
		    return _exec((0, config_1.ellipticCurve)(), function (curve) { return curve.utils.isValidPrivateKey(secret); }, function () { return true; }, function () { return true; });
		};
		exports.isValidPrivateKey = isValidPrivateKey;
		var getPublicKey = function (secret) {
		    return _exec((0, config_1.ellipticCurve)(), function (curve) { return curve.getPublicKey(secret); }, function (curve) { return curve.getPublicKey(secret); }, function (curve) { return curve.getPublicKey(secret); });
		};
		exports.getPublicKey = getPublicKey;
		var getSharedPoint = function (sk, pk, compressed) {
		    return _exec((0, config_1.ellipticCurve)(), function (curve) { return curve.getSharedSecret(sk, pk, compressed); }, function (curve) { return curve.getSharedSecret(sk, pk); }, function (curve) { return getSharedPointOnEd25519(curve, sk, pk); });
		};
		exports.getSharedPoint = getSharedPoint;
		var convertPublicKeyFormat = function (pk, compressed) {
		    // only for secp256k1
		    return _exec((0, config_1.ellipticCurve)(), function (curve) { return curve.getSharedSecret(BigInt(1), pk, compressed); }, function () { return pk; }, function () { return pk; });
		};
		exports.convertPublicKeyFormat = convertPublicKeyFormat;
		var hexToPublicKey = function (hex) {
		    var decoded = (0, hex_1.decodeHex)(hex);
		    return _exec((0, config_1.ellipticCurve)(), function () { return compatEthPublicKey(decoded); }, function () { return decoded; }, function () { return decoded; });
		};
		exports.hexToPublicKey = hexToPublicKey;
		function _exec(curve, secp256k1Callback, x25519Callback, ed25519Callback) {
		    if (curve === "secp256k1") {
		        return secp256k1Callback(secp256k1_1.secp256k1);
		    }
		    else if (curve === "x25519") {
		        return x25519Callback(ed25519_1.x25519);
		    }
		    else if (curve === "ed25519") {
		        return ed25519Callback(ed25519_1.ed25519);
		    } /* v8 ignore next 2 */
		    else {
		        throw new Error("Not implemented");
		    }
		}
		var compatEthPublicKey = function (pk) {
		    if (pk.length === consts_1.ETH_PUBLIC_KEY_SIZE) {
		        var fixed = new Uint8Array(1 + pk.length);
		        fixed.set([0x04]);
		        fixed.set(pk, 1);
		        return fixed;
		    }
		    return pk;
		};
		var getSharedPointOnEd25519 = function (curve, sk, pk) {
		    // Note: scalar is hashed from sk
		    var scalar = curve.utils.getExtendedPublicKey(sk).scalar;
		    var point = curve.ExtendedPoint.fromHex(pk).multiply(scalar);
		    return point.toRawBytes();
		}; 
	} (elliptic));
	return elliptic;
}

var hash = {};

var hkdf = {};

var hasRequiredHkdf;

function requireHkdf () {
	if (hasRequiredHkdf) return hkdf;
	hasRequiredHkdf = 1;
	Object.defineProperty(hkdf, "__esModule", { value: true });
	hkdf.hkdf = void 0;
	hkdf.extract = extract;
	hkdf.expand = expand;
	/**
	 * HKDF (RFC 5869): extract + expand in one step.
	 * See https://soatok.blog/2021/11/17/understanding-hkdf/.
	 * @module
	 */
	const _assert_js_1 = /*@__PURE__*/ require_assert();
	const hmac_js_1 = /*@__PURE__*/ requireHmac();
	const utils_js_1 = /*@__PURE__*/ requireUtils$2();
	/**
	 * HKDF-extract from spec. Less important part. `HKDF-Extract(IKM, salt) -> PRK`
	 * Arguments position differs from spec (IKM is first one, since it is not optional)
	 * @param hash - hash function that would be used (e.g. sha256)
	 * @param ikm - input keying material, the initial key
	 * @param salt - optional salt value (a non-secret random value)
	 */
	function extract(hash, ikm, salt) {
	    (0, _assert_js_1.ahash)(hash);
	    // NOTE: some libraries treat zero-length array as 'not provided';
	    // we don't, since we have undefined as 'not provided'
	    // https://github.com/RustCrypto/KDFs/issues/15
	    if (salt === undefined)
	        salt = new Uint8Array(hash.outputLen);
	    return (0, hmac_js_1.hmac)(hash, (0, utils_js_1.toBytes)(salt), (0, utils_js_1.toBytes)(ikm));
	}
	const HKDF_COUNTER = /* @__PURE__ */ new Uint8Array([0]);
	const EMPTY_BUFFER = /* @__PURE__ */ new Uint8Array();
	/**
	 * HKDF-expand from the spec. The most important part. `HKDF-Expand(PRK, info, L) -> OKM`
	 * @param hash - hash function that would be used (e.g. sha256)
	 * @param prk - a pseudorandom key of at least HashLen octets (usually, the output from the extract step)
	 * @param info - optional context and application specific information (can be a zero-length string)
	 * @param length - length of output keying material in bytes
	 */
	function expand(hash, prk, info, length = 32) {
	    (0, _assert_js_1.ahash)(hash);
	    (0, _assert_js_1.anumber)(length);
	    if (length > 255 * hash.outputLen)
	        throw new Error('Length should be <= 255*HashLen');
	    const blocks = Math.ceil(length / hash.outputLen);
	    if (info === undefined)
	        info = EMPTY_BUFFER;
	    // first L(ength) octets of T
	    const okm = new Uint8Array(blocks * hash.outputLen);
	    // Re-use HMAC instance between blocks
	    const HMAC = hmac_js_1.hmac.create(hash, prk);
	    const HMACTmp = HMAC._cloneInto();
	    const T = new Uint8Array(HMAC.outputLen);
	    for (let counter = 0; counter < blocks; counter++) {
	        HKDF_COUNTER[0] = counter + 1;
	        // T(0) = empty string (zero length)
	        // T(N) = HMAC-Hash(PRK, T(N-1) | info | N)
	        HMACTmp.update(counter === 0 ? EMPTY_BUFFER : T)
	            .update(info)
	            .update(HKDF_COUNTER)
	            .digestInto(T);
	        okm.set(T, hash.outputLen * counter);
	        HMAC._cloneInto(HMACTmp);
	    }
	    HMAC.destroy();
	    HMACTmp.destroy();
	    T.fill(0);
	    HKDF_COUNTER.fill(0);
	    return okm.slice(0, length);
	}
	/**
	 * HKDF (RFC 5869): derive keys from an initial input.
	 * Combines hkdf_extract + hkdf_expand in one step
	 * @param hash - hash function that would be used (e.g. sha256)
	 * @param ikm - input keying material, the initial key
	 * @param salt - optional salt value (a non-secret random value)
	 * @param info - optional context and application specific information (can be a zero-length string)
	 * @param length - length of output keying material in bytes
	 * @example
	 * import { hkdf } from '@noble/hashes/hkdf';
	 * import { sha256 } from '@noble/hashes/sha2';
	 * import { randomBytes } from '@noble/hashes/utils';
	 * const inputKey = randomBytes(32);
	 * const salt = randomBytes(32);
	 * const info = 'application-key';
	 * const hk1 = hkdf(sha256, inputKey, salt, info, 32);
	 */
	const hkdf$1 = (hash, ikm, salt, info, length) => expand(hash, extract(hash, ikm, salt), info, length);
	hkdf.hkdf = hkdf$1;
	
	return hkdf;
}

var hasRequiredHash;

function requireHash () {
	if (hasRequiredHash) return hash;
	hasRequiredHash = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.getSharedKey = exports.deriveKey = void 0;
		var utils_1 = /*@__PURE__*/ requireUtils$3();
		var hkdf_1 = /*@__PURE__*/ requireHkdf();
		var sha256_1 = /*@__PURE__*/ requireSha256();
		var deriveKey = function (master, salt, info) {
		    // 32 bytes shared secret for aes256 and xchacha20 derived from HKDF-SHA256
		    return (0, hkdf_1.hkdf)(sha256_1.sha256, master, salt, info, 32);
		};
		exports.deriveKey = deriveKey;
		var getSharedKey = function () {
		    var parts = [];
		    for (var _i = 0; _i < arguments.length; _i++) {
		        parts[_i] = arguments[_i];
		    }
		    return (0, exports.deriveKey)(utils_1.concatBytes.apply(void 0, parts));
		};
		exports.getSharedKey = getSharedKey; 
	} (hash));
	return hash;
}

var symmetric = {};

var node$1 = {};

var compat = {};

var hasRequiredCompat;

function requireCompat () {
	if (hasRequiredCompat) return compat;
	hasRequiredCompat = 1;
	Object.defineProperty(compat, "__esModule", { value: true });
	compat._compat = void 0;
	var utils_1 = /*@__PURE__*/ requireUtils$3();
	var node_crypto_1 = require$$1;
	var AEAD_TAG_LENGTH = 16;
	/**
	 * make `node:crypto`'s ciphers compatible with `@noble/ciphers`.
	 *
	 * `Cipher`'s interface is the same for both `aes-256-gcm` and `chacha20-poly1305`,
	 * albeit the latter is one of `CipherCCMTypes`.
	 * Interestingly, whether to set `plaintextLength` or not, or which value to set, has no actual effect.
	 */
	var _compat = function (algorithm, key, nonce, AAD) {
	    var isAEAD = algorithm === "aes-256-gcm" || algorithm === "chacha20-poly1305";
	    var authTagLength = isAEAD ? AEAD_TAG_LENGTH : 0;
	    // authTagLength is necessary for `chacha20-poly1305` before Node v16.17
	    var options = isAEAD ? { authTagLength: authTagLength } : undefined;
	    var encrypt = function (plainText) {
	        var cipher = (0, node_crypto_1.createCipheriv)(algorithm, key, nonce, options);
	        if (isAEAD && AAD !== undefined) {
	            cipher.setAAD(AAD);
	        }
	        var updated = cipher.update(plainText);
	        var finalized = cipher.final();
	        var tag = isAEAD ? cipher.getAuthTag() : new Uint8Array(0);
	        return (0, utils_1.concatBytes)(updated, finalized, tag);
	    };
	    var decrypt = function (cipherText) {
	        var rawCipherText = cipherText.subarray(0, cipherText.length - authTagLength);
	        var tag = cipherText.subarray(cipherText.length - authTagLength);
	        var decipher = (0, node_crypto_1.createDecipheriv)(algorithm, key, nonce, options);
	        if (isAEAD) {
	            if (AAD !== undefined) {
	                decipher.setAAD(AAD);
	            }
	            decipher.setAuthTag(tag);
	        }
	        var updated = decipher.update(rawCipherText);
	        var finalized = decipher.final();
	        return (0, utils_1.concatBytes)(updated, finalized);
	    };
	    return {
	        encrypt: encrypt,
	        decrypt: decrypt,
	    };
	};
	compat._compat = _compat;
	return compat;
}

var hasRequiredNode$1;

function requireNode$1 () {
	if (hasRequiredNode$1) return node$1;
	hasRequiredNode$1 = 1;
	Object.defineProperty(node$1, "__esModule", { value: true });
	node$1.aes256cbc = node$1.aes256gcm = void 0;
	var compat_1 = requireCompat();
	var aes256gcm = function (key, nonce, AAD) {
	    return (0, compat_1._compat)("aes-256-gcm", key, nonce, AAD);
	};
	node$1.aes256gcm = aes256gcm;
	var aes256cbc = function (key, nonce, AAD) {
	    return (0, compat_1._compat)("aes-256-cbc", key, nonce);
	};
	node$1.aes256cbc = aes256cbc;
	return node$1;
}

var node = {};

var hchacha = {};

var hasRequiredHchacha;

function requireHchacha () {
	if (hasRequiredHchacha) return hchacha;
	hasRequiredHchacha = 1;
	Object.defineProperty(hchacha, "__esModule", { value: true });
	hchacha._hchacha20 = void 0;
	/**
	 * Copied from `@noble/ciphers/chacha`
	 */
	// prettier-ignore
	var _hchacha20 = function (s, k, i, o32) {
	    var x00 = s[0], x01 = s[1], x02 = s[2], x03 = s[3], x04 = k[0], x05 = k[1], x06 = k[2], x07 = k[3], x08 = k[4], x09 = k[5], x10 = k[6], x11 = k[7], x12 = i[0], x13 = i[1], x14 = i[2], x15 = i[3];
	    for (var r = 0; r < 20; r += 2) {
	        x00 = (x00 + x04) | 0;
	        x12 = rotl(x12 ^ x00, 16);
	        x08 = (x08 + x12) | 0;
	        x04 = rotl(x04 ^ x08, 12);
	        x00 = (x00 + x04) | 0;
	        x12 = rotl(x12 ^ x00, 8);
	        x08 = (x08 + x12) | 0;
	        x04 = rotl(x04 ^ x08, 7);
	        x01 = (x01 + x05) | 0;
	        x13 = rotl(x13 ^ x01, 16);
	        x09 = (x09 + x13) | 0;
	        x05 = rotl(x05 ^ x09, 12);
	        x01 = (x01 + x05) | 0;
	        x13 = rotl(x13 ^ x01, 8);
	        x09 = (x09 + x13) | 0;
	        x05 = rotl(x05 ^ x09, 7);
	        x02 = (x02 + x06) | 0;
	        x14 = rotl(x14 ^ x02, 16);
	        x10 = (x10 + x14) | 0;
	        x06 = rotl(x06 ^ x10, 12);
	        x02 = (x02 + x06) | 0;
	        x14 = rotl(x14 ^ x02, 8);
	        x10 = (x10 + x14) | 0;
	        x06 = rotl(x06 ^ x10, 7);
	        x03 = (x03 + x07) | 0;
	        x15 = rotl(x15 ^ x03, 16);
	        x11 = (x11 + x15) | 0;
	        x07 = rotl(x07 ^ x11, 12);
	        x03 = (x03 + x07) | 0;
	        x15 = rotl(x15 ^ x03, 8);
	        x11 = (x11 + x15) | 0;
	        x07 = rotl(x07 ^ x11, 7);
	        x00 = (x00 + x05) | 0;
	        x15 = rotl(x15 ^ x00, 16);
	        x10 = (x10 + x15) | 0;
	        x05 = rotl(x05 ^ x10, 12);
	        x00 = (x00 + x05) | 0;
	        x15 = rotl(x15 ^ x00, 8);
	        x10 = (x10 + x15) | 0;
	        x05 = rotl(x05 ^ x10, 7);
	        x01 = (x01 + x06) | 0;
	        x12 = rotl(x12 ^ x01, 16);
	        x11 = (x11 + x12) | 0;
	        x06 = rotl(x06 ^ x11, 12);
	        x01 = (x01 + x06) | 0;
	        x12 = rotl(x12 ^ x01, 8);
	        x11 = (x11 + x12) | 0;
	        x06 = rotl(x06 ^ x11, 7);
	        x02 = (x02 + x07) | 0;
	        x13 = rotl(x13 ^ x02, 16);
	        x08 = (x08 + x13) | 0;
	        x07 = rotl(x07 ^ x08, 12);
	        x02 = (x02 + x07) | 0;
	        x13 = rotl(x13 ^ x02, 8);
	        x08 = (x08 + x13) | 0;
	        x07 = rotl(x07 ^ x08, 7);
	        x03 = (x03 + x04) | 0;
	        x14 = rotl(x14 ^ x03, 16);
	        x09 = (x09 + x14) | 0;
	        x04 = rotl(x04 ^ x09, 12);
	        x03 = (x03 + x04) | 0;
	        x14 = rotl(x14 ^ x03, 8);
	        x09 = (x09 + x14) | 0;
	        x04 = rotl(x04 ^ x09, 7);
	    }
	    var oi = 0;
	    o32[oi++] = x00;
	    o32[oi++] = x01;
	    o32[oi++] = x02;
	    o32[oi++] = x03;
	    o32[oi++] = x12;
	    o32[oi++] = x13;
	    o32[oi++] = x14;
	    o32[oi++] = x15;
	};
	hchacha._hchacha20 = _hchacha20;
	var rotl = function (a, b) {
	    return (a << b) | (a >>> (32 - b));
	};
	return hchacha;
}

var hasRequiredNode;

function requireNode () {
	if (hasRequiredNode) return node;
	hasRequiredNode = 1;
	Object.defineProperty(node, "__esModule", { value: true });
	node.chacha20 = node.xchacha20 = void 0;
	var utils_1 = /*@__PURE__*/ requireUtils$3();
	var compat_1 = requireCompat();
	var hchacha_1 = requireHchacha();
	var xchacha20 = function (key, nonce, AAD) {
	    if (nonce.length !== 24) {
	        throw new Error("xchacha20's nonce must be 24 bytes");
	    }
	    var constants = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]); // "expand 32-byte k"
	    var subKey = new Uint32Array(8);
	    (0, hchacha_1._hchacha20)(constants, (0, utils_1.u32)(key), (0, utils_1.u32)(nonce.subarray(0, 16)), subKey);
	    var subNonce = new Uint8Array(12);
	    subNonce.set([0, 0, 0, 0]);
	    subNonce.set(nonce.subarray(16), 4);
	    return (0, compat_1._compat)("chacha20-poly1305", (0, utils_1.u8)(subKey), subNonce, AAD);
	};
	node.xchacha20 = xchacha20;
	var chacha20 = function (key, nonce, AAD) {
	    if (nonce.length !== 12) {
	        throw new Error("chacha20's nonce must be 12 bytes");
	    }
	    return (0, compat_1._compat)("chacha20-poly1305", key, nonce, AAD);
	};
	node.chacha20 = chacha20;
	return node;
}

var hasRequiredSymmetric;

function requireSymmetric () {
	if (hasRequiredSymmetric) return symmetric;
	hasRequiredSymmetric = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.aesDecrypt = exports.aesEncrypt = exports.symDecrypt = exports.symEncrypt = void 0;
		var utils_1 = /*@__PURE__*/ requireUtils$3();
		var webcrypto_1 = /*@__PURE__*/ requireWebcrypto();
		var aes_1 = requireNode$1();
		var chacha_1 = requireNode();
		var config_1 = requireConfig();
		var consts_1 = requireConsts();
		var symEncrypt = function (key, plainText, AAD) { return _exec(_encrypt, key, plainText, AAD); };
		exports.symEncrypt = symEncrypt;
		var symDecrypt = function (key, cipherText, AAD) { return _exec(_decrypt, key, cipherText, AAD); };
		exports.symDecrypt = symDecrypt;
		/** @deprecated - use `symEncrypt` instead. */
		exports.aesEncrypt = exports.symEncrypt; // TODO: delete
		/** @deprecated - use `symDecrypt` instead. */
		exports.aesDecrypt = exports.symDecrypt; // TODO: delete
		function _exec(callback, key, data, AAD) {
		    var algorithm = (0, config_1.symmetricAlgorithm)();
		    if (algorithm === "aes-256-gcm") {
		        return callback(aes_1.aes256gcm, key, data, (0, config_1.symmetricNonceLength)(), consts_1.AEAD_TAG_LENGTH, AAD);
		    }
		    else if (algorithm === "xchacha20") {
		        return callback(chacha_1.xchacha20, key, data, consts_1.XCHACHA20_NONCE_LENGTH, consts_1.AEAD_TAG_LENGTH, AAD);
		    }
		    else if (algorithm === "aes-256-cbc") {
		        // NOT RECOMMENDED. There is neither AAD nor AEAD tag in cbc mode
		        // aes-256-cbc always uses 16 bytes iv
		        return callback(aes_1.aes256cbc, key, data, 16, 0);
		    }
		    else {
		        throw new Error("Not implemented");
		    }
		}
		function _encrypt(func, key, data, nonceLength, tagLength, AAD) {
		    var nonce = (0, webcrypto_1.randomBytes)(nonceLength);
		    var cipher = func(key, nonce, AAD);
		    // @noble/ciphers format: cipherText || tag
		    var encrypted = cipher.encrypt(data);
		    if (tagLength === 0) {
		        return (0, utils_1.concatBytes)(nonce, encrypted);
		    }
		    var cipherTextLength = encrypted.length - tagLength;
		    var cipherText = encrypted.subarray(0, cipherTextLength);
		    var tag = encrypted.subarray(cipherTextLength);
		    // ecies payload format: pk || nonce || tag || cipherText
		    return (0, utils_1.concatBytes)(nonce, tag, cipherText);
		}
		function _decrypt(func, key, data, nonceLength, tagLength, AAD) {
		    var nonce = data.subarray(0, nonceLength);
		    var cipher = func(key, Uint8Array.from(nonce), AAD); // to reset byteOffset
		    var encrypted = data.subarray(nonceLength);
		    if (tagLength === 0) {
		        return cipher.decrypt(encrypted);
		    }
		    var tag = encrypted.subarray(0, tagLength);
		    var cipherText = encrypted.subarray(tagLength);
		    return cipher.decrypt((0, utils_1.concatBytes)(cipherText, tag));
		} 
	} (symmetric));
	return symmetric;
}

var hasRequiredUtils;

function requireUtils () {
	if (hasRequiredUtils) return utils$2;
	hasRequiredUtils = 1;
	(function (exports) {
		var __createBinding = (utils$2 && utils$2.__createBinding) || (Object.create ? (function(o, m, k, k2) {
		    if (k2 === undefined) k2 = k;
		    var desc = Object.getOwnPropertyDescriptor(m, k);
		    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
		      desc = { enumerable: true, get: function() { return m[k]; } };
		    }
		    Object.defineProperty(o, k2, desc);
		}) : (function(o, m, k, k2) {
		    if (k2 === undefined) k2 = k;
		    o[k2] = m[k];
		}));
		var __exportStar = (utils$2 && utils$2.__exportStar) || function(m, exports) {
		    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
		};
		Object.defineProperty(exports, "__esModule", { value: true });
		__exportStar(requireElliptic(), exports);
		__exportStar(requireHash(), exports);
		__exportStar(requireHex(), exports);
		__exportStar(requireSymmetric(), exports); 
	} (utils$2));
	return utils$2;
}

var PublicKey = {};

var hasRequiredPublicKey;

function requirePublicKey () {
	if (hasRequiredPublicKey) return PublicKey;
	hasRequiredPublicKey = 1;
	Object.defineProperty(PublicKey, "__esModule", { value: true });
	PublicKey.PublicKey = void 0;
	var utils_1 = /*@__PURE__*/ requireUtils$3();
	var utils_2 = requireUtils();
	var PublicKey$1 = /** @class */ (function () {
	    function PublicKey(data) {
	        // data can be either compressed or uncompressed if secp256k1
	        var compressed = (0, utils_2.convertPublicKeyFormat)(data, true);
	        var uncompressed = (0, utils_2.convertPublicKeyFormat)(data, false);
	        this.data = compressed;
	        this.dataUncompressed =
	            compressed.length !== uncompressed.length ? uncompressed : null;
	    }
	    PublicKey.fromHex = function (hex) {
	        return new PublicKey((0, utils_2.hexToPublicKey)(hex));
	    };
	    Object.defineProperty(PublicKey.prototype, "_uncompressed", {
	        get: function () {
	            return this.dataUncompressed !== null ? this.dataUncompressed : this.data;
	        },
	        enumerable: false,
	        configurable: true
	    });
	    Object.defineProperty(PublicKey.prototype, "uncompressed", {
	        /** @deprecated - use `PublicKey.toBytes(false)` instead. You may also need `Buffer.from`. */
	        get: function () {
	            return Buffer.from(this._uncompressed); // TODO: delete
	        },
	        enumerable: false,
	        configurable: true
	    });
	    Object.defineProperty(PublicKey.prototype, "compressed", {
	        /** @deprecated - use `PublicKey.toBytes()` instead. You may also need `Buffer.from`. */
	        get: function () {
	            return Buffer.from(this.data); // TODO: delete
	        },
	        enumerable: false,
	        configurable: true
	    });
	    PublicKey.prototype.toBytes = function (compressed) {
	        if (compressed === void 0) { compressed = true; }
	        return compressed ? this.data : this._uncompressed;
	    };
	    PublicKey.prototype.toHex = function (compressed) {
	        if (compressed === void 0) { compressed = true; }
	        return (0, utils_1.bytesToHex)(this.toBytes(compressed));
	    };
	    /**
	     * Derives a shared secret from receiver's private key (sk) and ephemeral public key (this).
	     * Opposite of `encapsulate`.
	     * @see PrivateKey.encapsulate
	     *
	     * @param sk - Receiver's private key.
	     * @param compressed - (default: `false`) Whether to use compressed or uncompressed public keys in the key derivation (secp256k1 only).
	     * @returns Shared secret, derived with HKDF-SHA256.
	     */
	    PublicKey.prototype.decapsulate = function (sk, compressed) {
	        if (compressed === void 0) { compressed = false; }
	        var senderPoint = this.toBytes(compressed);
	        var sharedPoint = sk.multiply(this, compressed);
	        return (0, utils_2.getSharedKey)(senderPoint, sharedPoint);
	    };
	    PublicKey.prototype.equals = function (other) {
	        return (0, utils_1.equalBytes)(this.data, other.data);
	    };
	    return PublicKey;
	}());
	PublicKey.PublicKey = PublicKey$1;
	return PublicKey;
}

var hasRequiredPrivateKey;

function requirePrivateKey () {
	if (hasRequiredPrivateKey) return PrivateKey;
	hasRequiredPrivateKey = 1;
	Object.defineProperty(PrivateKey, "__esModule", { value: true });
	PrivateKey.PrivateKey = void 0;
	var utils_1 = /*@__PURE__*/ requireUtils$3();
	var utils_2 = requireUtils();
	var PublicKey_1 = requirePublicKey();
	var PrivateKey$1 = /** @class */ (function () {
	    function PrivateKey(secret) {
	        if (secret === undefined) {
	            this.data = (0, utils_2.getValidSecret)();
	        }
	        else if ((0, utils_2.isValidPrivateKey)(secret)) {
	            this.data = secret;
	        }
	        else {
	            throw new Error("Invalid private key");
	        }
	        this.publicKey = new PublicKey_1.PublicKey((0, utils_2.getPublicKey)(this.data));
	    }
	    PrivateKey.fromHex = function (hex) {
	        return new PrivateKey((0, utils_2.decodeHex)(hex));
	    };
	    Object.defineProperty(PrivateKey.prototype, "secret", {
	        /** @description From version 0.5.0, `Uint8Array` will be returned instead of `Buffer`. */
	        get: function () {
	            // TODO: Uint8Array
	            return Buffer.from(this.data);
	        },
	        enumerable: false,
	        configurable: true
	    });
	    PrivateKey.prototype.toHex = function () {
	        return (0, utils_1.bytesToHex)(this.data);
	    };
	    /**
	     * Derives a shared secret from ephemeral private key (this) and receiver's public key (pk).
	     * @description The shared key is 32 bytes, derived with `HKDF-SHA256(senderPoint || sharedPoint)`. See implementation for details.
	     *
	     * There are some variations in different ECIES implementations:
	     * which key derivation function to use, compressed or uncompressed `senderPoint`/`sharedPoint`, whether to include `senderPoint`, etc.
	     *
	     * Because the entropy of `senderPoint`, `sharedPoint` is enough high[1], we don't need salt to derive keys.
	     *
	     * [1]: Two reasons: the public keys are "random" bytes (albeit secp256k1 public keys are **not uniformly** random), and ephemeral keys are generated in every encryption.
	     *
	     * @param pk - Receiver's public key.
	     * @param compressed - (default: `false`) Whether to use compressed or uncompressed public keys in the key derivation (secp256k1 only).
	     * @returns Shared secret, derived with HKDF-SHA256.
	     */
	    PrivateKey.prototype.encapsulate = function (pk, compressed) {
	        if (compressed === void 0) { compressed = false; }
	        var senderPoint = this.publicKey.toBytes(compressed);
	        var sharedPoint = this.multiply(pk, compressed);
	        return (0, utils_2.getSharedKey)(senderPoint, sharedPoint);
	    };
	    PrivateKey.prototype.multiply = function (pk, compressed) {
	        if (compressed === void 0) { compressed = false; }
	        return (0, utils_2.getSharedPoint)(this.data, pk.toBytes(true), compressed);
	    };
	    PrivateKey.prototype.equals = function (other) {
	        return (0, utils_1.equalBytes)(this.data, other.data);
	    };
	    return PrivateKey;
	}());
	PrivateKey.PrivateKey = PrivateKey$1;
	return PrivateKey;
}

var hasRequiredKeys;

function requireKeys () {
	if (hasRequiredKeys) return keys;
	hasRequiredKeys = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.PublicKey = exports.PrivateKey = void 0;
		// treat Buffer as Uint8array, i.e. no call of Buffer specific functions
		// finally Uint8Array only
		var PrivateKey_1 = requirePrivateKey();
		Object.defineProperty(exports, "PrivateKey", { enumerable: true, get: function () { return PrivateKey_1.PrivateKey; } });
		var PublicKey_1 = requirePublicKey();
		Object.defineProperty(exports, "PublicKey", { enumerable: true, get: function () { return PublicKey_1.PublicKey; } }); 
	} (keys));
	return keys;
}

var hasRequiredDist;

function requireDist () {
	if (hasRequiredDist) return dist;
	hasRequiredDist = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.utils = exports.PublicKey = exports.PrivateKey = exports.ECIES_CONFIG = void 0;
		exports.encrypt = encrypt;
		exports.decrypt = decrypt;
		var utils_1 = /*@__PURE__*/ requireUtils$3();
		var config_1 = requireConfig();
		var keys_1 = requireKeys();
		var utils_2 = requireUtils();
		/**
		 * Encrypts data with a receiver's public key.
		 * @description From version 0.5.0, `Uint8Array` will be returned instead of `Buffer`.
		 * To keep the same behavior, use `Buffer.from(encrypt(...))`.
		 *
		 * @param receiverRawPK - Raw public key of the receiver, either as a hex string or a Uint8Array.
		 * @param data - Data to encrypt.
		 * @returns Encrypted payload, format: `public key || encrypted`.
		 */
		function encrypt(receiverRawPK, data) {
		    return Buffer.from(_encrypt(receiverRawPK, data));
		}
		function _encrypt(receiverRawPK, data) {
		    var ephemeralSK = new keys_1.PrivateKey();
		    var receiverPK = receiverRawPK instanceof Uint8Array
		        ? new keys_1.PublicKey(receiverRawPK)
		        : keys_1.PublicKey.fromHex(receiverRawPK);
		    var sharedKey = ephemeralSK.encapsulate(receiverPK, (0, config_1.isHkdfKeyCompressed)());
		    var ephemeralPK = ephemeralSK.publicKey.toBytes((0, config_1.isEphemeralKeyCompressed)());
		    var encrypted = (0, utils_2.symEncrypt)(sharedKey, data);
		    return (0, utils_1.concatBytes)(ephemeralPK, encrypted);
		}
		/**
		 * Decrypts data with a receiver's private key.
		 * @description From version 0.5.0, `Uint8Array` will be returned instead of `Buffer`.
		 * To keep the same behavior, use `Buffer.from(decrypt(...))`.
		 *
		 * @param receiverRawSK - Raw private key of the receiver, either as a hex string or a Uint8Array.
		 * @param data - Data to decrypt.
		 * @returns Decrypted plain text.
		 */
		function decrypt(receiverRawSK, data) {
		    return Buffer.from(_decrypt(receiverRawSK, data));
		}
		function _decrypt(receiverRawSK, data) {
		    var receiverSK = receiverRawSK instanceof Uint8Array
		        ? new keys_1.PrivateKey(receiverRawSK)
		        : keys_1.PrivateKey.fromHex(receiverRawSK);
		    var keySize = (0, config_1.ephemeralKeySize)();
		    var ephemeralPK = new keys_1.PublicKey(data.subarray(0, keySize));
		    var encrypted = data.subarray(keySize);
		    var sharedKey = ephemeralPK.decapsulate(receiverSK, (0, config_1.isHkdfKeyCompressed)());
		    return (0, utils_2.symDecrypt)(sharedKey, encrypted);
		}
		var config_2 = requireConfig();
		Object.defineProperty(exports, "ECIES_CONFIG", { enumerable: true, get: function () { return config_2.ECIES_CONFIG; } });
		var keys_2 = requireKeys();
		Object.defineProperty(exports, "PrivateKey", { enumerable: true, get: function () { return keys_2.PrivateKey; } });
		Object.defineProperty(exports, "PublicKey", { enumerable: true, get: function () { return keys_2.PublicKey; } });
		/** @deprecated - use `import utils from "eciesjs/utils"` instead. */
		exports.utils = {
		    // TODO: remove these after 0.5.0
		    aesEncrypt: utils_2.aesEncrypt,
		    aesDecrypt: utils_2.aesDecrypt,
		    symEncrypt: utils_2.symEncrypt,
		    symDecrypt: utils_2.symDecrypt,
		    decodeHex: utils_2.decodeHex,
		    getValidSecret: utils_2.getValidSecret,
		    remove0x: utils_2.remove0x,
		}; 
	} (dist));
	return dist;
}

var distExports = requireDist();

const ivLength = 12;
const tagLength = 16;
const sigLength = 65;
const chunkLength = 64 * 1024 * 1024 + tagLength;
// Inference
async function deriveEncryptionKey(signer) {
    const signature = await signer.signMessage(MESSAGE_FOR_ENCRYPTION_KEY);
    const hash = ethers.sha256(ethers.toUtf8Bytes(signature));
    return hash;
}
async function encryptData(signer, data) {
    const key = await deriveEncryptionKey(signer);
    const encrypted = CryptoJS.AES.encrypt(data, key).toString();
    return encrypted;
}
async function decryptData(signer, encryptedData) {
    const key = await deriveEncryptionKey(signer);
    const bytes = CryptoJS.AES.decrypt(encryptedData, key);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    return decrypted;
}
// Fine-tuning
function hexToRoots(hexString) {
    if (hexString.startsWith('0x')) {
        hexString = hexString.slice(2);
    }
    return Buffer.from(hexString, 'hex').toString('utf8');
}
async function signRequest(signer, userAddress, nonce, datasetRootHash, fee) {
    const hash = ethers.solidityPackedKeccak256(['address', 'uint256', 'string', 'uint256'], [userAddress, nonce, datasetRootHash, fee]);
    return await signer.signMessage(ethers.toBeArray(hash));
}
async function eciesDecrypt(signer, encryptedData) {
    encryptedData = encryptedData.startsWith('0x')
        ? encryptedData.slice(2)
        : encryptedData;
    const privateKey = distExports.PrivateKey.fromHex(signer.privateKey);
    const data = Buffer.from(encryptedData, 'hex');
    const decrypted = distExports.decrypt(privateKey.secret, data);
    return decrypted.toString('hex');
}
async function aesGCMDecryptToFile(key, encryptedModelPath, decryptedModelPath, providerSigner) {
    const fd = await promises.open(encryptedModelPath, 'r');
    // read signature and nonce
    const tagSig = Buffer.alloc(sigLength);
    const iv = Buffer.alloc(ivLength);
    let offset = 0;
    let readResult = await fd.read(tagSig, 0, sigLength, offset);
    offset += readResult.bytesRead;
    readResult = await fd.read(iv, 0, ivLength, offset);
    offset += readResult.bytesRead;
    const privateKey = Buffer.from(key, 'hex');
    const buffer = Buffer.alloc(chunkLength);
    let tagsBuffer = Buffer.from([]);
    const writeFd = await promises.open(decryptedModelPath, 'w');
    // read chunks
    while (true) {
        readResult = await fd.read(buffer, 0, chunkLength, offset);
        let chunkSize = readResult.bytesRead;
        if (chunkSize === 0) {
            break;
        }
        const decipher = crypto$2.createDecipheriv('aes-256-gcm', privateKey, iv);
        const tag = buffer.subarray(chunkSize - tagLength, chunkSize);
        decipher.setAuthTag(tag);
        let decrypted = Buffer.concat([
            decipher.update(buffer.subarray(0, chunkSize - tagLength)),
            decipher.final(),
        ]);
        await writeFd.appendFile(decrypted);
        tagsBuffer = Buffer.concat([tagsBuffer, tag]);
        offset += chunkSize;
    }
    await writeFd.close();
    await fd.close();
    const recoveredAddress = ethers.recoverAddress(ethers.keccak256(tagsBuffer), '0x' + tagSig.toString('hex'));
    if (recoveredAddress.toLowerCase() !== providerSigner.toLowerCase()) {
        throw new Error('Invalid tag signature');
    }
}

function strToPrivateKey(str) {
    const parsed = JSON.parse(str);
    if (!Array.isArray(parsed) || parsed.length !== 2) {
        throw new Error('Invalid input string');
    }
    const [first, second] = parsed.map((value) => {
        if (typeof value === 'string' || typeof value === 'number') {
            return BigInt(value);
        }
        throw new Error('Invalid number format');
    });
    return [first, second];
}
function privateKeyToStr(key) {
    try {
        return JSON.stringify(key.map((v) => v.toString()));
    }
    catch (error) {
        throw error;
    }
}

class Metadata {
    nodeStorage = {};
    initialized = false;
    constructor() { }
    async initialize() {
        if (this.initialized) {
            return;
        }
        this.nodeStorage = {};
        this.initialized = true;
    }
    async setItem(key, value) {
        await this.initialize();
        this.nodeStorage[key] = value;
    }
    async getItem(key) {
        await this.initialize();
        return this.nodeStorage[key] ?? null;
    }
    async storeSettleSignerPrivateKey(key, value) {
        const bigIntStringArray = value.map((bi) => bi.toString());
        const bigIntJsonString = JSON.stringify(bigIntStringArray);
        await this.setItem(`${key}_settleSignerPrivateKey`, bigIntJsonString);
    }
    async storeSigningKey(key, value) {
        await this.setItem(`${key}_signingKey`, value);
    }
    async getSettleSignerPrivateKey(key) {
        const value = await this.getItem(`${key}_settleSignerPrivateKey`);
        if (!value) {
            return null;
        }
        const bigIntStringArray = JSON.parse(value);
        return bigIntStringArray.map((str) => BigInt(str));
    }
    async getSigningKey(key) {
        const value = await this.getItem(`${key}_signingKey`);
        return value ?? null;
    }
}

var CacheValueTypeEnum;
(function (CacheValueTypeEnum) {
    CacheValueTypeEnum["Service"] = "service";
    CacheValueTypeEnum["BigInt"] = "bigint";
    CacheValueTypeEnum["Other"] = "other";
})(CacheValueTypeEnum || (CacheValueTypeEnum = {}));
class Cache {
    nodeStorage = {};
    initialized = false;
    constructor() { }
    setLock(key, value, ttl, type) {
        this.initialize();
        if (this.nodeStorage[key]) {
            return false;
        }
        this.setItem(key, value, ttl, type);
        return true;
    }
    removeLock(key) {
        this.initialize();
        delete this.nodeStorage[key];
    }
    setItem(key, value, ttl, type) {
        this.initialize();
        const now = new Date();
        const item = {
            type,
            value: Cache.encodeValue(value),
            expiry: now.getTime() + ttl,
        };
        this.nodeStorage[key] = JSON.stringify(item);
    }
    getItem(key) {
        this.initialize();
        const itemStr = this.nodeStorage[key] ?? null;
        if (!itemStr) {
            return null;
        }
        const item = JSON.parse(itemStr);
        const now = new Date();
        if (now.getTime() > item.expiry) {
            delete this.nodeStorage[key];
            return null;
        }
        return Cache.decodeValue(item.value, item.type);
    }
    initialize() {
        if (this.initialized) {
            return;
        }
        this.nodeStorage = {};
        this.initialized = true;
    }
    static encodeValue(value) {
        return JSON.stringify(value, (_, val) => typeof val === 'bigint' ? `${val.toString()}n` : val);
    }
    static decodeValue(encodedValue, type) {
        let ret = JSON.parse(encodedValue, (_, val) => {
            if (typeof val === 'string' && /^\d+n$/.test(val)) {
                return BigInt(val.slice(0, -1));
            }
            return val;
        });
        if (type === CacheValueTypeEnum.Service) {
            return Cache.createServiceStructOutput(ret);
        }
        return ret;
    }
    static createServiceStructOutput(fields) {
        const tuple = fields;
        const object = {
            provider: fields[0],
            serviceType: fields[1],
            url: fields[2],
            inputPrice: fields[3],
            outputPrice: fields[4],
            updatedAt: fields[5],
            model: fields[6],
            verifiability: fields[7],
        };
        return Object.assign(tuple, object);
    }
}

async function getNonceWithCache(cache) {
    const lockKey = 'nonce_lock';
    const nonceKey = 'nonce';
    while (!(await acquireLock(cache, lockKey))) {
        await delay(10);
    }
    try {
        const now = new Date();
        const lastNonce = cache.getItem(nonceKey) || 0;
        let nonce = now.getTime() * 10000 + 40;
        if (lastNonce >= nonce) {
            nonce = lastNonce + 40;
        }
        cache.setItem(nonceKey, nonce, 10000000 * 60 * 1000, CacheValueTypeEnum.Other);
        return nonce;
    }
    finally {
        await releaseLock(cache, lockKey);
    }
}
function getNonce() {
    const now = new Date();
    return now.getTime() * 10000 + 40;
}
async function acquireLock(cache, key) {
    const lock = await cache.setLock(key, 'true', 1000, CacheValueTypeEnum.Other);
    return lock;
}
async function releaseLock(cache, key) {
    await cache.removeLock(key);
}
function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

let eddsa;
let babyjubjub;
async function initBabyJub() {
    if (!babyjubjub) {
        babyjubjub = await buildBabyjub();
    }
}
async function initEddsa() {
    if (!eddsa) {
        eddsa = await buildEddsa();
    }
}
async function babyJubJubGeneratePrivateKey() {
    await initBabyJub();
    return babyjubjub.F.random();
}
async function babyJubJubGeneratePublicKey(privateKey) {
    await initEddsa();
    return eddsa.prv2pub(privateKey);
}
async function babyJubJubSignature(msg, privateKey) {
    await initEddsa();
    return eddsa.signPedersen(privateKey, msg);
}
async function packSignature(signature) {
    await initEddsa();
    return eddsa.packSignature(signature);
}
async function packPoint(point) {
    await initBabyJub();
    return babyjubjub.packPoint(point);
}

const BYTE_SIZE = 8;
function bigintToBytes(bigint, length) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = Number((bigint >> BigInt(BYTE_SIZE * i)) & BigInt(0xff));
    }
    return bytes;
}
function bytesToBigint(bytes) {
    let bigint = BigInt(0);
    for (let i = 0; i < bytes.length; i++) {
        bigint += BigInt(bytes[i]) << BigInt(BYTE_SIZE * i);
    }
    return bigint;
}

const FIELD_SIZE = 32;
async function signRequests(requests, privateKey) {
    const serializedRequestTrace = requests.map((request) => request.serialize());
    const signatures = [];
    for (let i = 0; i < serializedRequestTrace.length; i++) {
        const signature = await babyJubJubSignature(serializedRequestTrace[i], privateKey);
        signatures.push(await packSignature(signature));
    }
    return signatures;
}

const BIGINT_SIZE = 16;
async function genKeyPair() {
    // generate private key
    const privkey = await babyJubJubGeneratePrivateKey();
    // generate public key
    const pubkey = await babyJubJubGeneratePublicKey(privkey);
    // pack public key to FIELD_SIZE bytes
    const packedPubkey = await packPoint(pubkey);
    // unpack packed pubkey to bigint
    const packedPubkey0 = bytesToBigint(packedPubkey.slice(0, BIGINT_SIZE));
    const packedPubkey1 = bytesToBigint(packedPubkey.slice(BIGINT_SIZE));
    // unpack private key to bigint
    const packPrivkey0 = bytesToBigint(privkey.slice(0, BIGINT_SIZE));
    const packPrivkey1 = bytesToBigint(privkey.slice(BIGINT_SIZE));
    return {
        packedPrivkey: [packPrivkey0, packPrivkey1],
        doublePackedPubkey: [packedPubkey0, packedPubkey1],
    };
}
async function signData(data, packedPrivkey) {
    // unpack private key to bytes
    const packedPrivkey0 = bigintToBytes(packedPrivkey[0], BIGINT_SIZE);
    const packedPrivkey1 = bigintToBytes(packedPrivkey[1], BIGINT_SIZE);
    // combine bytes to Uint8Array
    const privateKey = new Uint8Array(FIELD_SIZE);
    privateKey.set(packedPrivkey0, 0);
    privateKey.set(packedPrivkey1, BIGINT_SIZE);
    // sign data
    const signatures = await signRequests(data, privateKey);
    return signatures;
}

const ADDR_LENGTH = 20;
const NONCE_LENGTH = 8;
const FEE_LENGTH = 16;
class Request {
    nonce;
    fee;
    userAddress;
    providerAddress;
    constructor(nonce, fee, userAddress, // hexstring format with '0x' prefix
    providerAddress // hexstring format with '0x' prefix
    ) {
        this.nonce = BigInt(nonce);
        this.fee = BigInt(fee);
        this.userAddress = BigInt(userAddress);
        this.providerAddress = BigInt(providerAddress);
    }
    serialize() {
        const buffer = new ArrayBuffer(NONCE_LENGTH + ADDR_LENGTH * 2 + FEE_LENGTH);
        let offset = 0;
        // write nonce (u64)
        const nonceBytes = bigintToBytes(this.nonce, NONCE_LENGTH);
        new Uint8Array(buffer, offset, NONCE_LENGTH).set(nonceBytes);
        offset += NONCE_LENGTH;
        // write fee (u128)
        const feeBytes = bigintToBytes(this.fee, FEE_LENGTH);
        new Uint8Array(buffer, offset, FEE_LENGTH).set(feeBytes);
        offset += FEE_LENGTH;
        // write userAddress (u160)
        const userAddressBytes = bigintToBytes(this.userAddress, ADDR_LENGTH);
        new Uint8Array(buffer, offset, ADDR_LENGTH).set(userAddressBytes);
        offset += ADDR_LENGTH;
        // write providerAddress (u160)
        const providerAddressBytes = bigintToBytes(this.providerAddress, ADDR_LENGTH);
        new Uint8Array(buffer, offset, ADDR_LENGTH).set(providerAddressBytes);
        offset += ADDR_LENGTH;
        return new Uint8Array(buffer);
    }
    static deserialize(byteArray) {
        const expectedLength = NONCE_LENGTH + ADDR_LENGTH * 2 + FEE_LENGTH;
        if (byteArray.length !== expectedLength) {
            throw new Error(`Invalid byte array length for deserialization. Expected: ${expectedLength}, but got: ${byteArray.length}`);
        }
        let offset = 0;
        // read nonce (u64)
        const nonce = bytesToBigint(new Uint8Array(byteArray.slice(offset, offset + NONCE_LENGTH)));
        offset += NONCE_LENGTH;
        // read fee (u128)
        const fee = bytesToBigint(new Uint8Array(byteArray.slice(offset, offset + FEE_LENGTH)));
        offset += FEE_LENGTH;
        // read userAddress (u160)
        const userAddress = bytesToBigint(new Uint8Array(byteArray.slice(offset, offset + ADDR_LENGTH)));
        offset += ADDR_LENGTH;
        // read providerAddress (u160)
        const providerAddress = bytesToBigint(new Uint8Array(byteArray.slice(offset, offset + ADDR_LENGTH)));
        offset += ADDR_LENGTH;
        return new Request(nonce.toString(), fee.toString(), '0x' + userAddress.toString(16), '0x' + providerAddress.toString(16));
    }
    // Getters
    getNonce() {
        return this.nonce;
    }
    getFee() {
        return this.fee;
    }
    getUserAddress() {
        return this.userAddress;
    }
    getProviderAddress() {
        return this.providerAddress;
    }
}

class ZGServingUserBrokerBase {
    contract;
    metadata;
    cache;
    checkAccountThreshold = BigInt(1000);
    topUpTriggerThreshold = BigInt(5000);
    topUpTargetThreshold = BigInt(10000);
    ledger;
    constructor(contract, ledger, metadata, cache) {
        this.contract = contract;
        this.ledger = ledger;
        this.metadata = metadata;
        this.cache = cache;
    }
    async getProviderData(providerAddress) {
        const key = `${this.contract.getUserAddress()}_${providerAddress}`;
        const [settleSignerPrivateKey] = await Promise.all([
            this.metadata.getSettleSignerPrivateKey(key),
        ]);
        return { settleSignerPrivateKey };
    }
    async getService(providerAddress, useCache = true) {
        const key = providerAddress;
        const cachedSvc = await this.cache.getItem(key);
        if (cachedSvc && useCache) {
            return cachedSvc;
        }
        try {
            const svc = await this.contract.getService(providerAddress);
            await this.cache.setItem(key, svc, 1 * 60 * 1000, CacheValueTypeEnum.Service);
            return svc;
        }
        catch (error) {
            throw error;
        }
    }
    async getExtractor(providerAddress, useCache = true) {
        try {
            const svc = await this.getService(providerAddress, useCache);
            const extractor = this.createExtractor(svc);
            return extractor;
        }
        catch (error) {
            throw error;
        }
    }
    createExtractor(svc) {
        switch (svc.serviceType) {
            case 'chatbot':
                return new ChatBot(svc);
            default:
                throw new Error('Unknown service type');
        }
    }
    a0giToNeuron(value) {
        const valueStr = value.toFixed(18);
        const parts = valueStr.split('.');
        // Handle integer part
        const integerPart = parts[0];
        let integerPartAsBigInt = BigInt(integerPart) * BigInt(10 ** 18);
        // Handle fractional part if it exists
        if (parts.length > 1) {
            let fractionalPart = parts[1];
            while (fractionalPart.length < 18) {
                fractionalPart += '0';
            }
            if (fractionalPart.length > 18) {
                fractionalPart = fractionalPart.slice(0, 18); // Truncate to avoid overflow
            }
            const fractionalPartAsBigInt = BigInt(fractionalPart);
            integerPartAsBigInt += fractionalPartAsBigInt;
        }
        return integerPartAsBigInt;
    }
    neuronToA0gi(value) {
        const divisor = BigInt(10 ** 18);
        const integerPart = value / divisor;
        const remainder = value % divisor;
        const decimalPart = Number(remainder) / Number(divisor);
        return Number(integerPart) + decimalPart;
    }
    async getHeader(providerAddress, content, outputFee) {
        try {
            const extractor = await this.getExtractor(providerAddress);
            const { settleSignerPrivateKey } = await this.getProviderData(providerAddress);
            const key = `${this.contract.getUserAddress()}_${providerAddress}`;
            let privateKey = settleSignerPrivateKey;
            if (!privateKey) {
                const account = await this.contract.getAccount(providerAddress);
                const privateKeyStr = await decryptData(this.contract.signer, account.additionalInfo);
                privateKey = strToPrivateKey(privateKeyStr);
                this.metadata.storeSettleSignerPrivateKey(key, privateKey);
            }
            const nonce = await getNonceWithCache(this.cache);
            const inputFee = await this.calculateInputFees(extractor, content);
            const fee = inputFee + outputFee;
            const request = new Request(nonce.toString(), fee.toString(), this.contract.getUserAddress(), providerAddress);
            const settleSignature = await signData([request], privateKey);
            const sig = JSON.stringify(Array.from(settleSignature[0]));
            return {
                'X-Phala-Signature-Type': 'StandaloneApi',
                Address: this.contract.getUserAddress(),
                Fee: fee.toString(),
                'Input-Fee': inputFee.toString(),
                Nonce: nonce.toString(),
                'Previous-Output-Fee': outputFee.toString(),
                Signature: sig,
            };
        }
        catch (error) {
            throw error;
        }
    }
    async calculateInputFees(extractor, content) {
        const svc = await extractor.getSvcInfo();
        const inputCount = await extractor.getInputCount(content);
        const inputFee = BigInt(inputCount) * svc.inputPrice;
        return inputFee;
    }
    async updateCachedFee(provider, fee) {
        try {
            const curFee = (await this.cache.getItem(provider + '_cachedFee')) || BigInt(0);
            await this.cache.setItem(provider + '_cachedFee', BigInt(curFee) + fee, 1 * 60 * 1000, CacheValueTypeEnum.BigInt);
        }
        catch (error) {
            throw error;
        }
    }
    async clearCacheFee(provider, fee) {
        try {
            const curFee = (await this.cache.getItem(provider + '_cachedFee')) || BigInt(0);
            await this.cache.setItem(provider, BigInt(curFee) + fee, 1 * 60 * 1000, CacheValueTypeEnum.BigInt);
        }
        catch (error) {
            throw error;
        }
    }
    /**
     * Transfer fund from ledger if fund in the inference account is less than a 5000 * (inputPrice + outputPrice)
     */
    async topUpAccountIfNeeded(provider, content, gasPrice) {
        try {
            const extractor = await this.getExtractor(provider);
            const svc = await extractor.getSvcInfo();
            // Calculate target and trigger thresholds
            const targetThreshold = this.topUpTargetThreshold * (svc.inputPrice + svc.outputPrice);
            const triggerThreshold = this.topUpTriggerThreshold * (svc.inputPrice + svc.outputPrice);
            // Check if it's the first round
            const isFirstRound = (await this.cache.getItem('firstRound')) !== 'false';
            if (isFirstRound) {
                await this.handleFirstRound(provider, triggerThreshold, targetThreshold, gasPrice);
                return;
            }
            // Calculate new fee and update cached fee
            const newFee = await this.calculateInputFees(extractor, content);
            await this.updateCachedFee(provider, newFee);
            // Check if we need to check the account
            if (!(await this.shouldCheckAccount(svc)))
                return;
            // Re-check the account balance
            const acc = await this.contract.getAccount(provider);
            const lockedFund = acc.balance - acc.pendingRefund;
            if (lockedFund < triggerThreshold) {
                await this.ledger.transferFund(provider, 'inference', targetThreshold, gasPrice);
            }
            await this.clearCacheFee(provider, newFee);
        }
        catch (error) {
            throw error;
        }
    }
    async handleFirstRound(provider, triggerThreshold, targetThreshold, gasPrice) {
        try {
            const acc = await this.contract.getAccount(provider);
            // Check if the account balance is below the trigger threshold
            const lockedFund = acc.balance - acc.pendingRefund;
            if (lockedFund < triggerThreshold) {
                await this.ledger.transferFund(provider, 'inference', targetThreshold, gasPrice);
            }
        }
        catch (error) {
            if (error.message.includes('AccountNotExists')) {
                await this.ledger.transferFund(provider, 'inference', targetThreshold, gasPrice);
            }
            else {
                throw error;
            }
        }
        // Mark the first round as complete
        await this.cache.setItem('firstRound', 'false', 10000000 * 60 * 1000, CacheValueTypeEnum.Other);
    }
    /**
     * Check the cache fund for this provider, return true if the fund is above 1000 * (inputPrice + outputPrice)
     * @param provider
     * @param svc
     */
    async shouldCheckAccount(svc) {
        try {
            const key = svc.provider + '_cachedFee';
            const usedFund = (await this.cache.getItem(key)) || BigInt(0);
            return (usedFund >
                this.checkAccountThreshold * (svc.inputPrice + svc.outputPrice));
        }
        catch (error) {
            throw error;
        }
    }
}

/**
 * AccountProcessor contains methods for creating, depositing funds, and retrieving 0G Serving Accounts.
 */
class AccountProcessor extends ZGServingUserBrokerBase {
    async getAccount(provider) {
        try {
            return await this.contract.getAccount(provider);
        }
        catch (error) {
            throw error;
        }
    }
    async listAccount() {
        try {
            return await this.contract.listAccount();
        }
        catch (error) {
            throw error;
        }
    }
}

/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
const _abi$2 = [
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'AccountExists',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'AccountNotExists',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'string',
                name: 'reason',
                type: 'string',
            },
        ],
        name: 'InvalidProofInputs',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'ServiceNotExist',
        type: 'error',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'amount',
                type: 'uint256',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'pendingRefund',
                type: 'uint256',
            },
        ],
        name: 'BalanceUpdated',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'previousOwner',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'address',
                name: 'newOwner',
                type: 'address',
            },
        ],
        name: 'OwnershipTransferred',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'uint256',
                name: 'index',
                type: 'uint256',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'timestamp',
                type: 'uint256',
            },
        ],
        name: 'RefundRequested',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'service',
                type: 'address',
            },
        ],
        name: 'ServiceRemoved',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'service',
                type: 'address',
            },
            {
                indexed: false,
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
            {
                indexed: false,
                internalType: 'string',
                name: 'url',
                type: 'string',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'inputPrice',
                type: 'uint256',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'outputPrice',
                type: 'uint256',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'updatedAt',
                type: 'uint256',
            },
            {
                indexed: false,
                internalType: 'string',
                name: 'model',
                type: 'string',
            },
            {
                indexed: false,
                internalType: 'string',
                name: 'verifiability',
                type: 'string',
            },
        ],
        name: 'ServiceUpdated',
        type: 'event',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'accountExists',
        outputs: [
            {
                internalType: 'bool',
                name: '',
                type: 'bool',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'uint256[2]',
                name: 'signer',
                type: 'uint256[2]',
            },
            {
                internalType: 'string',
                name: 'additionalInfo',
                type: 'string',
            },
        ],
        name: 'addAccount',
        outputs: [],
        stateMutability: 'payable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
            {
                internalType: 'string',
                name: 'url',
                type: 'string',
            },
            {
                internalType: 'string',
                name: 'model',
                type: 'string',
            },
            {
                internalType: 'string',
                name: 'verifiability',
                type: 'string',
            },
            {
                internalType: 'uint256',
                name: 'inputPrice',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'outputPrice',
                type: 'uint256',
            },
        ],
        name: 'addOrUpdateService',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'batchVerifierAddress',
        outputs: [
            {
                internalType: 'address',
                name: '',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'deleteAccount',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'cancelRetrievingAmount',
                type: 'uint256',
            },
        ],
        name: 'depositFund',
        outputs: [],
        stateMutability: 'payable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'getAccount',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'user',
                        type: 'address',
                    },
                    {
                        internalType: 'address',
                        name: 'provider',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nonce',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'balance',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'pendingRefund',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256[2]',
                        name: 'signer',
                        type: 'uint256[2]',
                    },
                    {
                        components: [
                            {
                                internalType: 'uint256',
                                name: 'index',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'amount',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'createdAt',
                                type: 'uint256',
                            },
                            {
                                internalType: 'bool',
                                name: 'processed',
                                type: 'bool',
                            },
                        ],
                        internalType: 'struct Refund[]',
                        name: 'refunds',
                        type: 'tuple[]',
                    },
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
                    },
                ],
                internalType: 'struct Account',
                name: '',
                type: 'tuple',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'getAllAccounts',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'user',
                        type: 'address',
                    },
                    {
                        internalType: 'address',
                        name: 'provider',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nonce',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'balance',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'pendingRefund',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256[2]',
                        name: 'signer',
                        type: 'uint256[2]',
                    },
                    {
                        components: [
                            {
                                internalType: 'uint256',
                                name: 'index',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'amount',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'createdAt',
                                type: 'uint256',
                            },
                            {
                                internalType: 'bool',
                                name: 'processed',
                                type: 'bool',
                            },
                        ],
                        internalType: 'struct Refund[]',
                        name: 'refunds',
                        type: 'tuple[]',
                    },
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
                    },
                ],
                internalType: 'struct Account[]',
                name: '',
                type: 'tuple[]',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'getAllServices',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'provider',
                        type: 'address',
                    },
                    {
                        internalType: 'string',
                        name: 'serviceType',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'url',
                        type: 'string',
                    },
                    {
                        internalType: 'uint256',
                        name: 'inputPrice',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'outputPrice',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'updatedAt',
                        type: 'uint256',
                    },
                    {
                        internalType: 'string',
                        name: 'model',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'verifiability',
                        type: 'string',
                    },
                ],
                internalType: 'struct Service[]',
                name: 'services',
                type: 'tuple[]',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'getPendingRefund',
        outputs: [
            {
                internalType: 'uint256',
                name: '',
                type: 'uint256',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'getService',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'provider',
                        type: 'address',
                    },
                    {
                        internalType: 'string',
                        name: 'serviceType',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'url',
                        type: 'string',
                    },
                    {
                        internalType: 'uint256',
                        name: 'inputPrice',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'outputPrice',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'updatedAt',
                        type: 'uint256',
                    },
                    {
                        internalType: 'string',
                        name: 'model',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'verifiability',
                        type: 'string',
                    },
                ],
                internalType: 'struct Service',
                name: 'service',
                type: 'tuple',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: '_locktime',
                type: 'uint256',
            },
            {
                internalType: 'address',
                name: '_batchVerifierAddress',
                type: 'address',
            },
            {
                internalType: 'address',
                name: '_ledgerAddress',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'owner',
                type: 'address',
            },
        ],
        name: 'initialize',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'initialized',
        outputs: [
            {
                internalType: 'bool',
                name: '',
                type: 'bool',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'ledgerAddress',
        outputs: [
            {
                internalType: 'address',
                name: '',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'lockTime',
        outputs: [
            {
                internalType: 'uint256',
                name: '',
                type: 'uint256',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'owner',
        outputs: [
            {
                internalType: 'address',
                name: '',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'processRefund',
        outputs: [
            {
                internalType: 'uint256',
                name: 'totalAmount',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'balance',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'pendingRefund',
                type: 'uint256',
            },
        ],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'removeService',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'renounceOwnership',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'requestRefundAll',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                components: [
                    {
                        internalType: 'uint256[]',
                        name: 'inProof',
                        type: 'uint256[]',
                    },
                    {
                        internalType: 'uint256[]',
                        name: 'proofInputs',
                        type: 'uint256[]',
                    },
                    {
                        internalType: 'uint256',
                        name: 'numChunks',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256[]',
                        name: 'segmentSize',
                        type: 'uint256[]',
                    },
                ],
                internalType: 'struct VerifierInput',
                name: 'verifierInput',
                type: 'tuple',
            },
        ],
        name: 'settleFees',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'newOwner',
                type: 'address',
            },
        ],
        name: 'transferOwnership',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: '_batchVerifierAddress',
                type: 'address',
            },
        ],
        name: 'updateBatchVerifierAddress',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: '_locktime',
                type: 'uint256',
            },
        ],
        name: 'updateLockTime',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
];
const _bytecode$2 = '0x60806040523480156200001157600080fd5b506200001d3362000023565b62000073565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6133cc80620000836000396000f3fe60806040526004361061014b5760003560e01c8063715018a6116100b6578063972167251161006f57806397216725146103cd578063bbee42d9146103ed578063d1d2005614610402578063f2fde38b14610422578063fbfa4e1114610442578063fd5908471461046257600080fd5b8063715018a614610327578063745e87f71461033c578063746e78d71461034f578063754d1d541461036f57806378c004361461038f5780638da5cb5b146103af57600080fd5b8063264173d611610108578063264173d61461023f578063371c22c51461025f57806340f5dbbd146102975780634bc3aff4146102b95780634e3c4f22146102cc5780636c79158d1461030757600080fd5b806308e93d0a146101505780630d6680871461017b578063147500e31461019f578063158ef93e146101cf57806315a52302146101f057806321fe0f301461021d575b600080fd5b34801561015c57600080fd5b5061016561048f565b6040516101729190612adf565b60405180910390f35b34801561018757600080fd5b5061019160015481565b604051908152602001610172565b3480156101ab57600080fd5b506101bf6101ba366004612b5d565b6104a0565b6040519015158152602001610172565b3480156101db57600080fd5b506000546101bf90600160a01b900460ff1681565b3480156101fc57600080fd5b5061021061020b366004612b90565b6104b7565b6040516101729190612c40565b34801561022957600080fd5b50610232610758565b6040516101729190612c53565b34801561024b57600080fd5b5061019161025a366004612b5d565b610764565b34801561026b57600080fd5b5060025461027f906001600160a01b031681565b6040516001600160a01b039091168152602001610172565b3480156102a357600080fd5b506102b76102b2366004612d94565b610772565b005b6102b76102c7366004612e65565b610884565b3480156102d857600080fd5b506102ec6102e7366004612b5d565b610919565b60408051938452602084019290925290820152606001610172565b34801561031357600080fd5b506102b7610322366004612b5d565b6109f0565b34801561033357600080fd5b506102b7610a2a565b6102b761034a366004612ed9565b610a3e565b34801561035b57600080fd5b506102b761036a366004612b90565b610ac8565b34801561037b57600080fd5b506102b761038a366004612f15565b610afc565b34801561039b57600080fd5b506102b76103aa366004612f62565b610bcc565b3480156103bb57600080fd5b506000546001600160a01b031661027f565b3480156103d957600080fd5b506102b76103e8366004612b5d565b6111e4565b3480156103f957600080fd5b506102b761121a565b34801561040e57600080fd5b5060035461027f906001600160a01b031681565b34801561042e57600080fd5b506102b761043d366004612b90565b611252565b34801561044e57600080fd5b506102b761045d366004612fa4565b6112cb565b34801561046e57600080fd5b5061048261047d366004612b5d565b6112d8565b6040516101729190612fbd565b606061049b6006611485565b905090565b60006104ae600684846116c6565b90505b92915050565b6104bf6127f2565b6104ca6009836116e3565b60408051610100810190915281546001600160a01b031681526001820180549192916020840191906104fb90612fd0565b80601f016020809104026020016040519081016040528092919081815260200182805461052790612fd0565b80156105745780601f1061054957610100808354040283529160200191610574565b820191906000526020600020905b81548152906001019060200180831161055757829003601f168201915b5050505050815260200160028201805461058d90612fd0565b80601f01602080910402602001604051908101604052809291908181526020018280546105b990612fd0565b80156106065780601f106105db57610100808354040283529160200191610606565b820191906000526020600020905b8154815290600101906020018083116105e957829003601f168201915b5050505050815260200160038201548152602001600482015481526020016005820154815260200160068201805461063d90612fd0565b80601f016020809104026020016040519081016040528092919081815260200182805461066990612fd0565b80156106b65780601f1061068b576101008083540402835291602001916106b6565b820191906000526020600020905b81548152906001019060200180831161069957829003601f168201915b505050505081526020016007820180546106cf90612fd0565b80601f01602080910402602001604051908101604052809291908181526020018280546106fb90612fd0565b80156107485780601f1061071d57610100808354040283529160200191610748565b820191906000526020600020905b81548152906001019060200180831161072b57829003601f168201915b5050505050815250509050919050565b606061049b60096116ef565b60006104ae60068484611a1d565b610826338a8a8a8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050604080516020601f8e018190048102820181019092528c815292508c91508b908190840183828082843760009201919091525050604080516020601f8d018190048102820181019092528b815292508b91508a90819084018382808284376000920191909152506009979695949392508a9150899050611a38565b336001600160a01b03167f30ecc203691b2d18e17ee75d47caf34a3fb9f86e855f7e0414d3cec26d0c424b8a8a8a8686428d8d8d8d6040516108719a99989796959493929190613033565b60405180910390a2505050505050505050565b6003546001600160a01b031633146108b75760405162461bcd60e51b81526004016108ae906130a6565b60405180910390fd5b6000806108c960068787873488611b12565b91509150846001600160a01b0316866001600160a01b03166000805160206133778339815191528484604051610909929190918252602082015260400190565b60405180910390a3505050505050565b600354600090819081906001600160a01b0316331461094a5760405162461bcd60e51b81526004016108ae906130a6565b60015461095d9060069087908790611b7d565b91945092509050600083900361097657600092506109e9565b604051339084156108fc029085906000818181858888f193505050501580156109a3573d6000803e3d6000fd5b50836001600160a01b0316856001600160a01b031660008051602061337783398151915284846040516109e0929190918252602082015260400190565b60405180910390a35b9250925092565b6003546001600160a01b03163314610a1a5760405162461bcd60e51b81526004016108ae906130a6565b610a2660068383611cb8565b5050565b610a32611d79565b610a3c6000611dd3565b565b6003546001600160a01b03163314610a685760405162461bcd60e51b81526004016108ae906130a6565b600080610a79600686868634611e23565b91509150836001600160a01b0316856001600160a01b03166000805160206133778339815191528484604051610ab9929190918252602082015260400190565b60405180910390a35050505050565b610ad0611d79565b600280546001600160a01b039092166001600160a01b0319928316811790915560048054909216179055565b600054600160a01b900460ff1615610b615760405162461bcd60e51b815260206004820152602260248201527f496e697469616c697a61626c653a20616c726561647920696e697469616c697a604482015261195960f21b60648201526084016108ae565b6000805460ff60a01b1916600160a01b179055610b7d81611dd3565b50600192909255600280546001600160a01b039283166001600160a01b031991821681179092556003805493909416928116831790935560058054841690921790915560048054909216179055565b6004546000906001600160a01b031663ad12259a610bea84806130e7565b610bf760208701876130e7565b87604001356040518663ffffffff1660e01b8152600401610c1c959493929190613163565b602060405180830381865afa158015610c39573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610c5d919061319d565b905080610cad5760405163885e287960e01b815260206004820152601f60248201527f5a4b20736574746c656d656e742076616c69646174696f6e206661696c65640060448201526064016108ae565b6000610cbc60208401846130e7565b808060200260200160405190810160405280939291908181526020018383602002808284376000920182905250939450339250839150505b610d0160608701876130e7565b905081101561116e576000610d1960608801886130e7565b83818110610d2957610d296131bf565b90506020020135905060008185610d4091906131eb565b9050600080878781518110610d5757610d576131bf565b60200260200101519050600088886002610d7191906131eb565b81518110610d8157610d816131bf565b60200260200101519050600089896003610d9b91906131eb565b81518110610dab57610dab6131bf565b602002602001015190506000610dcd84336006611fd29092919063ffffffff16565b90508a610ddb8b60056131eb565b81518110610deb57610deb6131bf565b602002602001015181600501600060028110610e0957610e096131bf565b0154141580610e5257508a610e1f8b60066131eb565b81518110610e2f57610e2f6131bf565b602002602001015181600501600160028110610e4d57610e4d6131bf565b015414155b15610ea05760405163885e287960e01b815260206004820152601760248201527f7369676e6572206b657920697320696e636f727265637400000000000000000060448201526064016108ae565b8281600201541115610ef55760405163885e287960e01b815260206004820152601a60248201527f696e697469616c206e6f6e636520697320696e636f727265637400000000000060448201526064016108ae565b895b868110156110f75760008c8281518110610f1357610f136131bf565b6020026020010151905060008d836001610f2d91906131eb565b81518110610f3d57610f3d6131bf565b602002602001015190508d836003610f5591906131eb565b81518110610f6557610f656131bf565b6020026020010151945060008e846004610f7f91906131eb565b81518110610f8f57610f8f6131bf565b6020026020010151905060008a856009610fa991906131eb565b10610fb5576000610fda565b8f610fc18660096131eb565b81518110610fd157610fd16131bf565b60200260200101515b90508015801590610feb5750808710155b1561102c5760405163885e287960e01b815260206004820152601060248201526f1b9bdb98d9481bdd995c9b185c1c195960821b60448201526064016108ae565b888414158061103b57508d8314155b156110d357888403611082576040518060400160405280601d81526020017f70726f7669646572206164647265737320697320696e636f72726563740000008152506110b9565b6040518060400160405280601981526020017f75736572206164647265737320697320696e636f7272656374000000000000008152505b60405163885e287960e01b81526004016108ae91906131fe565b6110dd828b6131eb565b9950505050506007816110f091906131eb565b9050610ef7565b5084816003015410156111445760405163885e287960e01b8152602060048201526014602482015273696e73756666696369656e742062616c616e636560601b60448201526064016108ae565b61114e8186611fdf565b60020155509195508392506111669150829050613211565b915050610cf4565b50825182146111dd5760405163885e287960e01b815260206004820152603460248201527f6172726179207365676d656e7453697a652073756d206d69736d617463686573604482015273040e0eac4d8d2c640d2dce0eae840d8cadccee8d60631b60648201526084016108ae565b5050505050565b6003546001600160a01b0316331461120e5760405162461bcd60e51b81526004016108ae906130a6565b610a266006838361224c565b6112256009336122ec565b60405133907f29d546abb6e94f4f04d5bdccb6682316f597d43776078f47e273f000e77b2a9190600090a2565b61125a611d79565b6001600160a01b0381166112bf5760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b60648201526084016108ae565b6112c881611dd3565b50565b6112d3611d79565b600155565b6112e0612840565b6112ec60068484611fd2565b604080516101008101825282546001600160a01b039081168252600184015416602082015260028084015482840152600384015460608301526004840154608083015282518084019384905291939260a085019291600585019182845b815481526020019060010190808311611349575050505050815260200160078201805480602002602001604051908101604052809291908181526020016000905b828210156113e3576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff1615156060830152908352909201910161138a565b5050505081526020016008820180546113fb90612fd0565b80601f016020809104026020016040519081016040528092919081815260200182805461142790612fd0565b80156114745780601f1061144957610100808354040283529160200191611474565b820191906000526020600020905b81548152906001019060200180831161145757829003601f168201915b505050505081525050905092915050565b606060006114928361233b565b90508067ffffffffffffffff8111156114ad576114ad612ca8565b6040519080825280602002602001820160405280156114e657816020015b6114d3612840565b8152602001906001900390816114cb5790505b50915060005b818110156116bf576114fe8482612346565b604080516101008101825282546001600160a01b039081168252600184015416602082015260028084015482840152600384015460608301526004840154608083015282518084019384905291939260a085019291600585019182845b81548152602001906001019080831161155b575050505050815260200160078201805480602002602001604051908101604052809291908181526020016000905b828210156115f5576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff1615156060830152908352909201910161159c565b50505050815260200160088201805461160d90612fd0565b80601f016020809104026020016040519081016040528092919081815260200182805461163990612fd0565b80156116865780601f1061165b57610100808354040283529160200191611686565b820191906000526020600020905b81548152906001019060200180831161166957829003601f168201915b5050505050815250508382815181106116a1576116a16131bf565b602002602001018190525080806116b790613211565b9150506114ec565b5050919050565b60006116db846116d6858561236c565b6123a4565b949350505050565b60006104ae83836123b0565b606060006116fc8361233b565b90508067ffffffffffffffff81111561171757611717612ca8565b60405190808252806020026020018201604052801561175057816020015b61173d6127f2565b8152602001906001900390816117355790505b50915060005b818110156116bf576117688482612346565b60408051610100810190915281546001600160a01b0316815260018201805491929160208401919061179990612fd0565b80601f01602080910402602001604051908101604052809291908181526020018280546117c590612fd0565b80156118125780601f106117e757610100808354040283529160200191611812565b820191906000526020600020905b8154815290600101906020018083116117f557829003601f168201915b5050505050815260200160028201805461182b90612fd0565b80601f016020809104026020016040519081016040528092919081815260200182805461185790612fd0565b80156118a45780601f10611879576101008083540402835291602001916118a4565b820191906000526020600020905b81548152906001019060200180831161188757829003601f168201915b505050505081526020016003820154815260200160048201548152602001600582015481526020016006820180546118db90612fd0565b80601f016020809104026020016040519081016040528092919081815260200182805461190790612fd0565b80156119545780601f1061192957610100808354040283529160200191611954565b820191906000526020600020905b81548152906001019060200180831161193757829003601f168201915b5050505050815260200160078201805461196d90612fd0565b80601f016020809104026020016040519081016040528092919081815260200182805461199990612fd0565b80156119e65780601f106119bb576101008083540402835291602001916119e6565b820191906000526020600020905b8154815290600101906020018083116119c957829003601f168201915b505050505081525050838281518110611a0157611a016131bf565b602002602001018190525080611a1690613211565b9050611756565b600080611a2b858585612401565b6004015495945050505050565b6000611a4388612464565b9050611a4f89826123a4565b611aa757611aa089826040518061010001604052808c6001600160a01b031681526020018b81526020018a815260200187815260200186815260200142815260200189815260200188815250612498565b5050611b08565b6000611ab38a8a6123b0565b905060018101611ac38982613270565b50600381018490556004810183905560028101611ae08882613270565b5042600582015560068101611af58782613270565b5060078101611b048682613270565b5050505b5050505050505050565b6000806000611b21888861236c565b9050611b2d89826123a4565b15611b5e57604051632cf0675960e21b81526001600160a01b03808a166004830152881660248201526044016108ae565b611b6d89828a8a8a8a8a612548565b5092976000975095505050505050565b600080600080611b8e888888612401565b90506000935060005b6007820154811015611c9e576000826007018281548110611bba57611bba6131bf565b60009182526020909120600490910201600381015490915060ff1615611be05750611c8c565b868160020154611bf091906131eb565b421015611bfd5750611c8c565b8060010154836003016000828254611c159190613330565b90915550506001810154600484018054600090611c33908490613330565b90915550506001810154611c4790876131eb565b9550826007018281548110611c5e57611c5e6131bf565b600091825260208220600490910201818155600181018290556002810191909155600301805460ff19169055505b80611c9681613211565b915050611b97565b508060030154925080600401549150509450945094915050565b6000611cc5848484612401565b9050600081600401548260030154611cdd9190613330565b905080600003611cee575050505050565b6040805160808101825260078401805480835260208084018681524295850195865260006060860181815260018086018755958252928120955160049485029096019586559051938501939093559351600284015592516003909201805460ff1916921515929092179091559083018054839290611d6d9084906131eb565b90915550505050505050565b6000546001600160a01b03163314610a3c5760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657260448201526064016108ae565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6000806000611e32878761236c565b9050611e3e88826123a4565b611e6e5760405163023280eb60e21b81526001600160a01b038089166004830152871660248201526044016108ae565b6000611e7b898989612401565b905060005b6007820154811015611f9e576000826007018281548110611ea357611ea36131bf565b60009182526020909120600490910201600381015490915060ff1615611ec95750611f8c565b8060010154836004016000828254611ee19190613330565b909155505060018101548811611f3857826007018281548110611f0657611f066131bf565b600091825260208220600490910201818155600181018290556002810191909155600301805460ff1916905550611f9e565b6001810154611f479089613330565b9750826007018281548110611f5e57611f5e6131bf565b600091825260208220600490910201818155600181018290556002810191909155600301805460ff19169055505b80611f9681613211565b915050611e80565b5084816003016000828254611fb391906131eb565b9091555050600381015460049091015490999098509650505050505050565b60006116db848484612401565b81600401548260030154611ff39190613330565b811115612158576000826004015483600301546120109190613330565b61201a9083613330565b9050808360040154101561207f5760405163885e287960e01b815260206004820152602560248201527f696e73756666696369656e742062616c616e636520696e2070656e64696e675260448201526419599d5b9960da1b60648201526084016108ae565b808360040160008282546120939190613330565b909155505060078301546000906120ac90600190613330565b90505b600081126121555760008460070182815481106120ce576120ce6131bf565b60009182526020909120600490910201600381015490915060ff16156120f45750612143565b8281600101541161211557600181015461210e9084613330565b9250612133565b828160010160008282546121299190613330565b9091555060009350505b826000036121415750612155565b505b8061214d81613343565b9150506120af565b50505b8082600301600082825461216c9190613330565b90915550506005548254604051631bb1482360e31b81526001600160a01b0391821660048201526024810184905291169063dd8a411890604401600060405180830381600087803b1580156121c057600080fd5b505af11580156121d4573d6000803e3d6000fd5b50508354600385015460048601546040805192835260208301919091523394506001600160a01b039092169250600080516020613377833981519152910160405180910390a3604051339082156108fc029083906000818181858888f19350505050158015612247573d6000803e3d6000fd5b505050565b6000612258838361236c565b905061226484826123a4565b61226e5750505050565b61227884826125c3565b50600081815260028086016020526040822080546001600160a01b03199081168255600182018054909116905590810182905560038101829055600481018290556005810182905560068101829055906122d660078301600061289d565b6122e46008830160006128be565b505050505050565b60006122f782612464565b905061230383826123a4565b61232b576040516304c76d3f60e11b81526001600160a01b03831660048201526024016108ae565b61233583826125cf565b50505050565b60006104b18261264c565b6000806123538484612656565b6000908152600285016020526040902091505092915050565b604080516001600160a01b03938416602080830191909152929093168382015280518084038201815260609093019052815191012090565b60006104ae8383612662565b6000806123bc83612464565b600081815260028601602052604090209091506123d985836123a4565b6116db576040516304c76d3f60e11b81526001600160a01b03851660048201526024016108ae565b60008061240e848461236c565b6000818152600287016020526040902090915061242b86836123a4565b61245b5760405163023280eb60e21b81526001600160a01b038087166004830152851660248201526044016108ae565b95945050505050565b604080516001600160a01b038316602082015260009101604051602081830303815290604052805190602001209050919050565b600082815260028401602090815260408220835181546001600160a01b0319166001600160a01b039091161781559083015183919060018201906124dc9082613270565b50604082015160028201906124f19082613270565b50606082015160038201556080820151600482015560a0820151600582015560c082015160068201906125249082613270565b5060e082015160078201906125399082613270565b506116db91508590508461267a565b6000868152600280890160205260409091206003810184905580546001600160a01b038089166001600160a01b0319928316178355600183018054918916919092161790559061259e90600583019086906128f8565b50600881016125ad8382613270565b506125b8888861267a565b505050505050505050565b60006104ae8383612686565b6000818152600283016020526040812080546001600160a01b0319168155816125fb60018301826128be565b6126096002830160006128be565b60038201600090556004820160009055600582016000905560068201600061263191906128be565b61263f6007830160006128be565b506104ae905083836125c3565b60006104b1825490565b60006104ae8383612779565b600081815260018301602052604081205415156104ae565b60006104ae83836127a3565b6000818152600183016020526040812054801561276f5760006126aa600183613330565b85549091506000906126be90600190613330565b90508181146127235760008660000182815481106126de576126de6131bf565b9060005260206000200154905080876000018481548110612701576127016131bf565b6000918252602080832090910192909255918252600188019052604090208390555b855486908061273457612734613360565b6001900381819060005260206000200160009055905585600101600086815260200190815260200160002060009055600193505050506104b1565b60009150506104b1565b6000826000018281548110612790576127906131bf565b9060005260206000200154905092915050565b60008181526001830160205260408120546127ea575081546001818101845560008481526020808220909301849055845484825282860190935260409020919091556104b1565b5060006104b1565b60405180610100016040528060006001600160a01b03168152602001606081526020016060815260200160008152602001600081526020016000815260200160608152602001606081525090565b60405180610100016040528060006001600160a01b0316815260200160006001600160a01b03168152602001600081526020016000815260200160008152602001612889612936565b815260200160608152602001606081525090565b50805460008255600402906000526020600020908101906112c89190612954565b5080546128ca90612fd0565b6000825580601f106128da575050565b601f0160209004906000526020600020908101906112c89190612982565b8260028101928215612926579160200282015b8281111561292657823582559160200191906001019061290b565b50612932929150612982565b5090565b60405180604001604052806002906020820280368337509192915050565b5b8082111561293257600080825560018201819055600282015560038101805460ff19169055600401612955565b5b808211156129325760008155600101612983565b8060005b600281101561233557815184526020938401939091019060010161299b565b600081518084526020808501945080840160005b83811015612a0c57815180518852838101518489015260408082015190890152606090810151151590880152608090960195908201906001016129ce565b509495945050505050565b6000815180845260005b81811015612a3d57602081850181015186830182015201612a21565b506000602082860101526020601f19601f83011685010191505092915050565b600061012060018060a01b038084511685528060208501511660208601525060408301516040850152606083015160608501526080830151608085015260a0830151612aac60a0860182612997565b5060c08301518160e0860152612ac4828601826129ba565b91505060e083015184820361010086015261245b8282612a17565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b82811015612b3457603f19888603018452612b22858351612a5d565b94509285019290850190600101612b06565b5092979650505050505050565b80356001600160a01b0381168114612b5857600080fd5b919050565b60008060408385031215612b7057600080fd5b612b7983612b41565b9150612b8760208401612b41565b90509250929050565b600060208284031215612ba257600080fd5b6104ae82612b41565b80516001600160a01b0316825260006101006020830151816020860152612bd482860182612a17565b91505060408301518482036040860152612bee8282612a17565b915050606083015160608501526080830151608085015260a083015160a085015260c083015184820360c0860152612c268282612a17565b91505060e083015184820360e086015261245b8282612a17565b6020815260006104ae6020830184612bab565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b82811015612b3457603f19888603018452612c96858351612bab565b94509285019290850190600101612c7a565b634e487b7160e01b600052604160045260246000fd5b600082601f830112612ccf57600080fd5b813567ffffffffffffffff80821115612cea57612cea612ca8565b604051601f8301601f19908116603f01168101908282118183101715612d1257612d12612ca8565b81604052838152866020858801011115612d2b57600080fd5b836020870160208301376000602085830101528094505050505092915050565b60008083601f840112612d5d57600080fd5b50813567ffffffffffffffff811115612d7557600080fd5b602083019150836020828501011115612d8d57600080fd5b9250929050565b600080600080600080600080600060c08a8c031215612db257600080fd5b893567ffffffffffffffff80821115612dca57600080fd5b612dd68d838e01612cbe565b9a5060208c0135915080821115612dec57600080fd5b612df88d838e01612d4b565b909a50985060408c0135915080821115612e1157600080fd5b612e1d8d838e01612d4b565b909850965060608c0135915080821115612e3657600080fd5b50612e438c828d01612d4b565b9a9d999c50979a96999598959660808101359660a09091013595509350505050565b60008060008060a08587031215612e7b57600080fd5b612e8485612b41565b9350612e9260208601612b41565b92506080850186811115612ea557600080fd5b6040860192503567ffffffffffffffff811115612ec157600080fd5b612ecd87828801612cbe565b91505092959194509250565b600080600060608486031215612eee57600080fd5b612ef784612b41565b9250612f0560208501612b41565b9150604084013590509250925092565b60008060008060808587031215612f2b57600080fd5b84359350612f3b60208601612b41565b9250612f4960408601612b41565b9150612f5760608601612b41565b905092959194509250565b600060208284031215612f7457600080fd5b813567ffffffffffffffff811115612f8b57600080fd5b820160808185031215612f9d57600080fd5b9392505050565b600060208284031215612fb657600080fd5b5035919050565b6020815260006104ae6020830184612a5d565b600181811c90821680612fe457607f821691505b60208210810361300457634e487b7160e01b600052602260045260246000fd5b50919050565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b60e08152600061304660e083018d612a17565b8281036020840152613059818c8e61300a565b905089604084015288606084015287608084015282810360a084015261308081878961300a565b905082810360c084015261309581858761300a565b9d9c50505050505050505050505050565b60208082526021908201527f43616c6c6572206973206e6f7420746865206c656467657220636f6e747261636040820152601d60fa1b606082015260800190565b6000808335601e198436030181126130fe57600080fd5b83018035915067ffffffffffffffff82111561311957600080fd5b6020019150600581901b3603821315612d8d57600080fd5b81835260006001600160fb1b0383111561314a57600080fd5b8260051b80836020870137939093016020019392505050565b606081526000613177606083018789613131565b828103602084015261318a818688613131565b9150508260408301529695505050505050565b6000602082840312156131af57600080fd5b81518015158114612f9d57600080fd5b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b808201808211156104b1576104b16131d5565b6020815260006104ae6020830184612a17565b600060018201613223576132236131d5565b5060010190565b601f82111561224757600081815260208120601f850160051c810160208610156132515750805b601f850160051c820191505b818110156122e45782815560010161325d565b815167ffffffffffffffff81111561328a5761328a612ca8565b61329e816132988454612fd0565b8461322a565b602080601f8311600181146132d357600084156132bb5750858301515b600019600386901b1c1916600185901b1785556122e4565b600085815260208120601f198616915b82811015613302578886015182559484019460019091019084016132e3565b50858210156133205787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b818103818111156104b1576104b16131d5565b6000600160ff1b8201613358576133586131d5565b506000190190565b634e487b7160e01b600052603160045260246000fdfe526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c776a2646970667358221220cc9ea8f736f576b0d18f7b980b923566ccb3db13dff381dacb94691f5ff60dcd64736f6c63430008140033';
const isSuperArgs$2 = (xs) => xs.length > 1;
class InferenceServing__factory extends ContractFactory {
    constructor(...args) {
        if (isSuperArgs$2(args)) {
            super(...args);
        }
        else {
            super(_abi$2, _bytecode$2, args[0]);
        }
    }
    getDeployTransaction(overrides) {
        return super.getDeployTransaction(overrides || {});
    }
    deploy(overrides) {
        return super.deploy(overrides || {});
    }
    connect(runner) {
        return super.connect(runner);
    }
    static bytecode = _bytecode$2;
    static abi = _abi$2;
    static createInterface() {
        return new Interface(_abi$2);
    }
    static connect(address, runner) {
        return new Contract(address, _abi$2, runner);
    }
}

class InferenceServingContract {
    serving;
    signer;
    _userAddress;
    constructor(signer, contractAddress, userAddress) {
        this.serving = InferenceServing__factory.connect(contractAddress, signer);
        this.signer = signer;
        this._userAddress = userAddress;
    }
    lockTime() {
        return this.serving.lockTime();
    }
    async listService() {
        try {
            const services = await this.serving.getAllServices();
            return services;
        }
        catch (error) {
            throw error;
        }
    }
    async listAccount() {
        try {
            const accounts = await this.serving.getAllAccounts();
            return accounts;
        }
        catch (error) {
            throw error;
        }
    }
    async getAccount(provider) {
        try {
            const user = this.getUserAddress();
            const account = await this.serving.getAccount(user, provider);
            return account;
        }
        catch (error) {
            throw error;
        }
    }
    async getService(providerAddress) {
        try {
            return this.serving.getService(providerAddress);
        }
        catch (error) {
            throw error;
        }
    }
    getUserAddress() {
        return this._userAddress;
    }
}

/**
 * RequestProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
class RequestProcessor extends ZGServingUserBrokerBase {
    constructor(contract, metadata, cache, ledger) {
        super(contract, ledger, metadata, cache);
    }
    async getServiceMetadata(providerAddress) {
        const service = await this.getService(providerAddress);
        return {
            endpoint: `${service.url}/v1/proxy`,
            model: service.model,
        };
    }
    /*
     * 1. To Ensure No Insufficient Balance Occurs.
     *
     * The provider settles accounts regularly. In addition, we will add a rule to the provider's settlement logic:
     * if the actual balance of the customer's account is less than 5000, settlement will be triggered immediately.
     * The actual balance is defined as the customer's inference account balance minus any unsettled amounts.
     *
     * This way, if the customer checks their account and sees a balance greater than 5000, even if the provider settles
     * immediately, the deduction will leave about 5000, ensuring that no insufficient balance situation occurs.
     *
     * 2. To Avoid Frequent Transfers
     *
     * On the customer's side, if the balance falls below 5000, it should be topped up to 10000. This is to avoid frequent
     * transfers.
     *
     * 3. To Avoid Having to Check the Balance on Every Customer Request
     *
     * Record expenditures in processResponse and maintain a total consumption amount. Every time the total expenditure
     * reaches 1000, recheck the balance and perform a transfer if necessary.
     *
     * ps: The units for 5000 and 1000 can be (service.inputPricePerToken + service.outputPricePerToken).
     */
    async getRequestHeaders(providerAddress, content) {
        try {
            await this.topUpAccountIfNeeded(providerAddress, content);
            return await this.getHeader(providerAddress, content, BigInt(0));
        }
        catch (error) {
            throw error;
        }
    }
}

var VerifiabilityEnum;
(function (VerifiabilityEnum) {
    VerifiabilityEnum["OpML"] = "OpML";
    VerifiabilityEnum["TeeML"] = "TeeML";
    VerifiabilityEnum["ZKML"] = "ZKML";
})(VerifiabilityEnum || (VerifiabilityEnum = {}));
let ModelProcessor$1 = class ModelProcessor extends ZGServingUserBrokerBase {
    async listService() {
        try {
            const services = await this.contract.listService();
            return services;
        }
        catch (error) {
            throw error;
        }
    }
};
function isVerifiability(value) {
    return Object.values(VerifiabilityEnum).includes(value);
}

/**
 * The Verifier class contains methods for verifying service reliability.
 */
class Verifier extends ZGServingUserBrokerBase {
    async verifyService(providerAddress) {
        try {
            const { valid } = await this.getSigningAddress(providerAddress, true);
            return valid;
        }
        catch (error) {
            throw error;
        }
    }
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
    async getSigningAddress(providerAddress, verifyRA = false) {
        const key = `${this.contract.getUserAddress()}_${providerAddress}`;
        let signingKey = await this.metadata.getSigningKey(key);
        if (!verifyRA && signingKey) {
            return {
                valid: null,
                signingAddress: signingKey,
            };
        }
        try {
            const extractor = await this.getExtractor(providerAddress, false);
            const svc = await extractor.getSvcInfo();
            const signerRA = await Verifier.fetSignerRA(svc.url, svc.model);
            if (!signerRA?.signing_address) {
                throw new Error('signing address does not exist');
            }
            signingKey = `${this.contract.getUserAddress()}_${providerAddress}`;
            await this.metadata.storeSigningKey(signingKey, signerRA.signing_address);
            // TODO: use intel_quote to verify signing address
            const valid = await Verifier.verifyRA(signerRA.nvidia_payload);
            return {
                valid,
                signingAddress: signerRA.signing_address,
            };
        }
        catch (error) {
            throw error;
        }
    }
    async getSignerRaDownloadLink(providerAddress) {
        try {
            const svc = await this.getService(providerAddress);
            return `${svc.url}/v1/proxy/attestation/report`;
        }
        catch (error) {
            throw error;
        }
    }
    async getChatSignatureDownloadLink(providerAddress, chatID) {
        try {
            const svc = await this.getService(providerAddress);
            return `${svc.url}/v1/proxy/signature/${chatID}`;
        }
        catch (error) {
            throw error;
        }
    }
    // TODO: add test
    static async verifyRA(nvidia_payload) {
        return fetch('https://nras.attestation.nvidia.com/v3/attest/gpu', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify(nvidia_payload),
        })
            .then((response) => {
            if (response.status === 200) {
                return true;
            }
            if (response.status === 404) {
                throw new Error('verify RA error: 404');
            }
            else {
                return false;
            }
        })
            .catch((error) => {
            if (error instanceof Error) {
                console.error(error.message);
            }
            return false;
        });
    }
    static async fetSignerRA(providerBrokerURL, model) {
        return fetch(`${providerBrokerURL}/v1/proxy/attestation/report?model=${model}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        })
            .then((response) => {
            return response.json();
        })
            .then((data) => {
            if (data.nvidia_payload) {
                try {
                    data.nvidia_payload = JSON.parse(data.nvidia_payload);
                }
                catch (error) {
                    throw Error('parsing nvidia_payload error');
                }
            }
            if (data.intel_quote) {
                try {
                    data.intel_quote =
                        '0x' +
                            Buffer.from(data.intel_quote, 'base64').toString('hex');
                }
                catch (error) {
                    throw Error('parsing intel_quote error');
                }
            }
            return data;
        })
            .catch((error) => {
            throw error;
        });
    }
    static async fetSignatureByChatID(providerBrokerURL, chatID, model) {
        return fetch(`${providerBrokerURL}/v1/proxy/signature/${chatID}?model=${model}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        })
            .then((response) => {
            if (!response.ok) {
                throw new Error('getting signature error');
            }
            return response.json();
        })
            .then((data) => {
            return data;
        })
            .catch((error) => {
            throw error;
        });
    }
    static verifySignature(message, signature, expectedAddress) {
        const messageHash = ethers.hashMessage(message);
        const recoveredAddress = ethers.recoverAddress(messageHash, signature);
        return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
    }
}

/**
 * ResponseProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
class ResponseProcessor extends ZGServingUserBrokerBase {
    verifier;
    constructor(contract, ledger, metadata, cache) {
        super(contract, ledger, metadata, cache);
        this.verifier = new Verifier(contract, ledger, metadata, cache);
    }
    async settleFeeWithA0gi(providerAddress, fee) {
        if (!fee) {
            return;
        }
        await this.topUpAccountIfNeeded(providerAddress, '');
        await this.settleFee(providerAddress, this.a0giToNeuron(fee));
    }
    /**
     * settleFee sends an empty request to the service provider to settle the fee.
     */
    async settleFee(providerAddress, fee) {
        try {
            if (!fee) {
                return;
            }
            const service = await this.contract.getService(providerAddress);
            if (!service) {
                throw new Error('Service is not available');
            }
            const { provider, url } = service;
            const headers = await this.getHeader(provider, '', fee);
            const response = await fetch(`${url}/v1/proxy/settle-fee`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...headers,
                },
            });
            if (response.status !== 202 && response.status !== 200) {
                const errorData = await response.json();
                throw new Error(errorData.error);
            }
        }
        catch (error) {
            throw error;
        }
    }
    async processResponse(providerAddress, content, chatID) {
        try {
            const extractor = await this.getExtractor(providerAddress);
            const outputFee = await this.calculateOutputFees(extractor, content);
            await this.updateCachedFee(providerAddress, outputFee);
            await this.settleFee(providerAddress, outputFee);
            const svc = await extractor.getSvcInfo();
            if (!isVerifiability(svc.verifiability)) {
                return false;
            }
            if (!chatID) {
                throw new Error('Chat ID does not exist');
            }
            let singerRAVerificationResult = await this.verifier.getSigningAddress(providerAddress);
            if (!singerRAVerificationResult.valid) {
                singerRAVerificationResult =
                    await this.verifier.getSigningAddress(providerAddress, true);
            }
            if (!singerRAVerificationResult.valid) {
                throw new Error('Signing address is invalid');
            }
            const ResponseSignature = await Verifier.fetSignatureByChatID(svc.url, chatID, svc.model);
            return Verifier.verifySignature(ResponseSignature.text, ResponseSignature.signature, singerRAVerificationResult.signingAddress);
        }
        catch (error) {
            throw error;
        }
    }
    async calculateOutputFees(extractor, content) {
        const svc = await extractor.getSvcInfo();
        const outputCount = await extractor.getOutputCount(content);
        return BigInt(outputCount) * svc.outputPrice;
    }
}

class InferenceBroker {
    requestProcessor;
    responseProcessor;
    verifier;
    accountProcessor;
    modelProcessor;
    signer;
    contractAddress;
    ledger;
    constructor(signer, contractAddress, ledger) {
        this.signer = signer;
        this.contractAddress = contractAddress;
        this.ledger = ledger;
    }
    async initialize() {
        let userAddress;
        try {
            userAddress = await this.signer.getAddress();
        }
        catch (error) {
            throw error;
        }
        const contract = new InferenceServingContract(this.signer, this.contractAddress, userAddress);
        const metadata = new Metadata();
        const cache = new Cache();
        this.requestProcessor = new RequestProcessor(contract, metadata, cache, this.ledger);
        this.responseProcessor = new ResponseProcessor(contract, this.ledger, metadata, cache);
        this.accountProcessor = new AccountProcessor(contract, this.ledger, metadata, cache);
        this.modelProcessor = new ModelProcessor$1(contract, this.ledger, metadata, cache);
        this.verifier = new Verifier(contract, this.ledger, metadata, cache);
    }
    /**
     * Retrieves a list of services from the contract.
     *
     * @returns {Promise<ServiceStructOutput[]>} A promise that resolves to an array of ServiceStructOutput objects.
     * @throws An error if the service list cannot be retrieved.
     */
    listService = async () => {
        try {
            return await this.modelProcessor.listService();
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * Retrieves the account information for a given provider address.
     *
     * @param {string} providerAddress - The address of the provider identifying the account.
     *
     * @returns A promise that resolves to the account information.
     *
     * @throws Will throw an error if the account retrieval process fails.
     */
    getAccount = async (providerAddress) => {
        try {
            return await this.accountProcessor.getAccount(providerAddress);
        }
        catch (error) {
            throw error;
        }
    };
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
    getServiceMetadata = async (providerAddress) => {
        try {
            return await this.requestProcessor.getServiceMetadata(providerAddress);
        }
        catch (error) {
            throw error;
        }
    };
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
    getRequestHeaders = async (providerAddress, content) => {
        try {
            return await this.requestProcessor.getRequestHeaders(providerAddress, content);
        }
        catch (error) {
            throw error;
        }
    };
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
     *
     * @returns A boolean value. True indicates the returned content is valid, otherwise it is invalid.
     *
     * @throws An error if any issues occur during the processing of the response.
     */
    processResponse = async (providerAddress, content, chatID) => {
        try {
            return await this.responseProcessor.processResponse(providerAddress, content, chatID);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * verifyService is used to verify the reliability of the service.
     *
     * @param {string} providerAddress - The address of the provider.
     *
     * @returns A <boolean | null> value. True indicates the service is reliable, otherwise it is unreliable.
     *
     * @throws An error if errors occur during the verification process.
     */
    verifyService = async (providerAddress) => {
        try {
            return await this.verifier.verifyService(providerAddress);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * getSignerRaDownloadLink returns the download link for the Signer RA.
     *
     * It can be provided to users who wish to manually verify the Signer RA.
     *
     * @param {string} providerAddress - provider address.
     *
     * @returns Download link.
     */
    getSignerRaDownloadLink = async (providerAddress) => {
        try {
            return await this.verifier.getSignerRaDownloadLink(providerAddress);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * getChatSignatureDownloadLink returns the download link for the signature of a single chat.
     *
     * It can be provided to users who wish to manually verify the content of a single chat.
     *
     * @param {string} providerAddress - provider address.
     * @param {string} chatID - ID of the chat.
     *
     * @description To verify the chat signature, use the following code:
     *
     * ```typescript
     * const messageHash = ethers.hashMessage(messageToBeVerified)
     * const recoveredAddress = ethers.recoverAddress(messageHash, signature)
     * const isValid = recoveredAddress.toLowerCase() === signingAddress.toLowerCase()
     * ```
     *
     * @returns Download link.
     */
    getChatSignatureDownloadLink = async (providerAddress, chatID) => {
        try {
            return await this.verifier.getChatSignatureDownloadLink(providerAddress, chatID);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * settleFee is used to settle the fee for the provider service.
     *
     * Normally, the fee for each request will be automatically settled in processResponse.
     * However, if processResponse fails due to network issues or other reasons,
     * you can manually call settleFee to settle the fee.
     *
     * @param {string} providerAddress - The address of the provider.
     * @param {number} fee - The fee to be settled. The unit of the fee is A0GI.
     *
     * @returns A promise that resolves when the fee settlement is successful.
     *
     * @throws An error if any issues occur during the fee settlement process.
     */
    settleFee = async (providerAddress, fee) => {
        try {
            return await this.responseProcessor.settleFeeWithA0gi(providerAddress, fee);
        }
        catch (error) {
            throw error;
        }
    };
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
async function createInferenceBroker(signer, contractAddress, ledger) {
    const broker = new InferenceBroker(signer, contractAddress, ledger);
    try {
        await broker.initialize();
        return broker;
    }
    catch (error) {
        throw error;
    }
}

class BrokerBase {
    contract;
    ledger;
    servingProvider;
    constructor(contract, ledger, servingProvider) {
        this.contract = contract;
        this.ledger = ledger;
        this.servingProvider = servingProvider;
    }
}

/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
const _abi$1 = [
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'AccountExists',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'AccountNotExists',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'string',
                name: 'reason',
                type: 'string',
            },
        ],
        name: 'InvalidVerifierInput',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'ServiceNotExist',
        type: 'error',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'amount',
                type: 'uint256',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'pendingRefund',
                type: 'uint256',
            },
        ],
        name: 'BalanceUpdated',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'previousOwner',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'address',
                name: 'newOwner',
                type: 'address',
            },
        ],
        name: 'OwnershipTransferred',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'uint256',
                name: 'index',
                type: 'uint256',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'timestamp',
                type: 'uint256',
            },
        ],
        name: 'RefundRequested',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
        ],
        name: 'ServiceRemoved',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                indexed: false,
                internalType: 'string',
                name: 'url',
                type: 'string',
            },
            {
                components: [
                    {
                        internalType: 'uint256',
                        name: 'cpuCount',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nodeMemory',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'gpuCount',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nodeStorage',
                        type: 'uint256',
                    },
                    {
                        internalType: 'string',
                        name: 'gpuType',
                        type: 'string',
                    },
                ],
                indexed: false,
                internalType: 'struct Quota',
                name: 'quota',
                type: 'tuple',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'pricePerToken',
                type: 'uint256',
            },
            {
                indexed: false,
                internalType: 'address',
                name: 'providerSigner',
                type: 'address',
            },
            {
                indexed: false,
                internalType: 'bool',
                name: 'occupied',
                type: 'bool',
            },
        ],
        name: 'ServiceUpdated',
        type: 'event',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'accountExists',
        outputs: [
            {
                internalType: 'bool',
                name: '',
                type: 'bool',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'index',
                type: 'uint256',
            },
        ],
        name: 'acknowledgeDeliverable',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'providerSigner',
                type: 'address',
            },
        ],
        name: 'acknowledgeProviderSigner',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'string',
                name: 'additionalInfo',
                type: 'string',
            },
        ],
        name: 'addAccount',
        outputs: [],
        stateMutability: 'payable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'bytes',
                name: 'modelRootHash',
                type: 'bytes',
            },
        ],
        name: 'addDeliverable',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'string',
                name: 'url',
                type: 'string',
            },
            {
                components: [
                    {
                        internalType: 'uint256',
                        name: 'cpuCount',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nodeMemory',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'gpuCount',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nodeStorage',
                        type: 'uint256',
                    },
                    {
                        internalType: 'string',
                        name: 'gpuType',
                        type: 'string',
                    },
                ],
                internalType: 'struct Quota',
                name: 'quota',
                type: 'tuple',
            },
            {
                internalType: 'uint256',
                name: 'pricePerToken',
                type: 'uint256',
            },
            {
                internalType: 'address',
                name: 'providerSigner',
                type: 'address',
            },
            {
                internalType: 'bool',
                name: 'occupied',
                type: 'bool',
            },
        ],
        name: 'addOrUpdateService',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'deleteAccount',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'cancelRetrievingAmount',
                type: 'uint256',
            },
        ],
        name: 'depositFund',
        outputs: [],
        stateMutability: 'payable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'getAccount',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'user',
                        type: 'address',
                    },
                    {
                        internalType: 'address',
                        name: 'provider',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nonce',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'balance',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'pendingRefund',
                        type: 'uint256',
                    },
                    {
                        components: [
                            {
                                internalType: 'uint256',
                                name: 'index',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'amount',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'createdAt',
                                type: 'uint256',
                            },
                            {
                                internalType: 'bool',
                                name: 'processed',
                                type: 'bool',
                            },
                        ],
                        internalType: 'struct Refund[]',
                        name: 'refunds',
                        type: 'tuple[]',
                    },
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
                    },
                    {
                        internalType: 'address',
                        name: 'providerSigner',
                        type: 'address',
                    },
                    {
                        components: [
                            {
                                internalType: 'bytes',
                                name: 'modelRootHash',
                                type: 'bytes',
                            },
                            {
                                internalType: 'bytes',
                                name: 'encryptedSecret',
                                type: 'bytes',
                            },
                            {
                                internalType: 'bool',
                                name: 'acknowledged',
                                type: 'bool',
                            },
                        ],
                        internalType: 'struct Deliverable[]',
                        name: 'deliverables',
                        type: 'tuple[]',
                    },
                ],
                internalType: 'struct Account',
                name: '',
                type: 'tuple',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'getAllAccounts',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'user',
                        type: 'address',
                    },
                    {
                        internalType: 'address',
                        name: 'provider',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nonce',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'balance',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'pendingRefund',
                        type: 'uint256',
                    },
                    {
                        components: [
                            {
                                internalType: 'uint256',
                                name: 'index',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'amount',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'createdAt',
                                type: 'uint256',
                            },
                            {
                                internalType: 'bool',
                                name: 'processed',
                                type: 'bool',
                            },
                        ],
                        internalType: 'struct Refund[]',
                        name: 'refunds',
                        type: 'tuple[]',
                    },
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
                    },
                    {
                        internalType: 'address',
                        name: 'providerSigner',
                        type: 'address',
                    },
                    {
                        components: [
                            {
                                internalType: 'bytes',
                                name: 'modelRootHash',
                                type: 'bytes',
                            },
                            {
                                internalType: 'bytes',
                                name: 'encryptedSecret',
                                type: 'bytes',
                            },
                            {
                                internalType: 'bool',
                                name: 'acknowledged',
                                type: 'bool',
                            },
                        ],
                        internalType: 'struct Deliverable[]',
                        name: 'deliverables',
                        type: 'tuple[]',
                    },
                ],
                internalType: 'struct Account[]',
                name: '',
                type: 'tuple[]',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'getAllServices',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'provider',
                        type: 'address',
                    },
                    {
                        internalType: 'string',
                        name: 'url',
                        type: 'string',
                    },
                    {
                        components: [
                            {
                                internalType: 'uint256',
                                name: 'cpuCount',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'nodeMemory',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'gpuCount',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'nodeStorage',
                                type: 'uint256',
                            },
                            {
                                internalType: 'string',
                                name: 'gpuType',
                                type: 'string',
                            },
                        ],
                        internalType: 'struct Quota',
                        name: 'quota',
                        type: 'tuple',
                    },
                    {
                        internalType: 'uint256',
                        name: 'pricePerToken',
                        type: 'uint256',
                    },
                    {
                        internalType: 'address',
                        name: 'providerSigner',
                        type: 'address',
                    },
                    {
                        internalType: 'bool',
                        name: 'occupied',
                        type: 'bool',
                    },
                ],
                internalType: 'struct Service[]',
                name: 'services',
                type: 'tuple[]',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'index',
                type: 'uint256',
            },
        ],
        name: 'getDeliverable',
        outputs: [
            {
                components: [
                    {
                        internalType: 'bytes',
                        name: 'modelRootHash',
                        type: 'bytes',
                    },
                    {
                        internalType: 'bytes',
                        name: 'encryptedSecret',
                        type: 'bytes',
                    },
                    {
                        internalType: 'bool',
                        name: 'acknowledged',
                        type: 'bool',
                    },
                ],
                internalType: 'struct Deliverable',
                name: '',
                type: 'tuple',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'getPendingRefund',
        outputs: [
            {
                internalType: 'uint256',
                name: '',
                type: 'uint256',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'getService',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'provider',
                        type: 'address',
                    },
                    {
                        internalType: 'string',
                        name: 'url',
                        type: 'string',
                    },
                    {
                        components: [
                            {
                                internalType: 'uint256',
                                name: 'cpuCount',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'nodeMemory',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'gpuCount',
                                type: 'uint256',
                            },
                            {
                                internalType: 'uint256',
                                name: 'nodeStorage',
                                type: 'uint256',
                            },
                            {
                                internalType: 'string',
                                name: 'gpuType',
                                type: 'string',
                            },
                        ],
                        internalType: 'struct Quota',
                        name: 'quota',
                        type: 'tuple',
                    },
                    {
                        internalType: 'uint256',
                        name: 'pricePerToken',
                        type: 'uint256',
                    },
                    {
                        internalType: 'address',
                        name: 'providerSigner',
                        type: 'address',
                    },
                    {
                        internalType: 'bool',
                        name: 'occupied',
                        type: 'bool',
                    },
                ],
                internalType: 'struct Service',
                name: 'service',
                type: 'tuple',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: '_locktime',
                type: 'uint256',
            },
            {
                internalType: 'address',
                name: '_ledgerAddress',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'owner',
                type: 'address',
            },
        ],
        name: 'initialize',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'initialized',
        outputs: [
            {
                internalType: 'bool',
                name: '',
                type: 'bool',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'ledgerAddress',
        outputs: [
            {
                internalType: 'address',
                name: '',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'lockTime',
        outputs: [
            {
                internalType: 'uint256',
                name: '',
                type: 'uint256',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'owner',
        outputs: [
            {
                internalType: 'address',
                name: '',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'processRefund',
        outputs: [
            {
                internalType: 'uint256',
                name: 'totalAmount',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'balance',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'pendingRefund',
                type: 'uint256',
            },
        ],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'removeService',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'renounceOwnership',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
        ],
        name: 'requestRefundAll',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                components: [
                    {
                        internalType: 'uint256',
                        name: 'index',
                        type: 'uint256',
                    },
                    {
                        internalType: 'bytes',
                        name: 'encryptedSecret',
                        type: 'bytes',
                    },
                    {
                        internalType: 'bytes',
                        name: 'modelRootHash',
                        type: 'bytes',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nonce',
                        type: 'uint256',
                    },
                    {
                        internalType: 'address',
                        name: 'providerSigner',
                        type: 'address',
                    },
                    {
                        internalType: 'bytes',
                        name: 'signature',
                        type: 'bytes',
                    },
                    {
                        internalType: 'uint256',
                        name: 'taskFee',
                        type: 'uint256',
                    },
                    {
                        internalType: 'address',
                        name: 'user',
                        type: 'address',
                    },
                ],
                internalType: 'struct VerifierInput',
                name: 'verifierInput',
                type: 'tuple',
            },
        ],
        name: 'settleFees',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'newOwner',
                type: 'address',
            },
        ],
        name: 'transferOwnership',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: '_locktime',
                type: 'uint256',
            },
        ],
        name: 'updateLockTime',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
];
const _bytecode$1 = '0x60806040523480156200001157600080fd5b506200001d3362000023565b62000073565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b613a8880620000836000396000f3fe6080604052600436106101815760003560e01c80637743ae87116100d1578063bbee42d91161008a578063f2c6741a11610064578063f2c6741a14610481578063f2fde38b146104a1578063fbfa4e11146104c1578063fd590847146104e157600080fd5b8063bbee42d914610439578063d1d200561461044e578063e50688f91461046e57600080fd5b80637743ae87146103675780638da5cb5b1461038757806397216725146103b957806397e19403146103d957806398248997146103f9578063b4988fd01461041957600080fd5b8063264173d61161013e5780635f7069db116101185780635f7069db146102fd5780636c79158d1461031f578063715018a61461033f578063745e87f71461035457600080fd5b8063264173d614610275578063290a68df146102955780634e3c4f22146102c257600080fd5b806308e93d0a146101865780630d668087146101b1578063147500e3146101d5578063158ef93e1461020557806315a523021461022657806321fe0f3014610253575b600080fd5b34801561019257600080fd5b5061019b61050e565b6040516101a89190612f34565b60405180910390f35b3480156101bd57600080fd5b506101c760015481565b6040519081526020016101a8565b3480156101e157600080fd5b506101f56101f0366004612fb2565b61051f565b60405190151581526020016101a8565b34801561021157600080fd5b506000546101f590600160a01b900460ff1681565b34801561023257600080fd5b50610246610241366004612fe5565b610536565b6040516101a891906130ae565b34801561025f57600080fd5b506102686106ff565b6040516101a891906130c1565b34801561028157600080fd5b506101c7610290366004612fb2565b61070b565b3480156102a157600080fd5b506102b56102b0366004613116565b610719565b6040516101a89190613152565b3480156102ce57600080fd5b506102e26102dd366004612fb2565b6108ab565b604080519384526020840192909252908201526060016101a8565b34801561030957600080fd5b5061031d610318366004613165565b61099d565b005b34801561032b57600080fd5b5061031d61033a366004612fb2565b6109ae565b34801561034b57600080fd5b5061031d6109e4565b61031d610362366004613116565b6109f8565b34801561037357600080fd5b5061031d6103823660046132f6565b610a94565b34801561039357600080fd5b506000546001600160a01b03165b6040516001600160a01b0390911681526020016101a8565b3480156103c557600080fd5b5061031d6103d4366004612fb2565b610b31565b3480156103e557600080fd5b5061031d6103f43660046133b3565b610b67565b34801561040557600080fd5b5061031d6104143660046133f5565b610e51565b34801561042557600080fd5b5061031d610434366004613442565b610e5e565b34801561044557600080fd5b5061031d610f12565b34801561045a57600080fd5b506002546103a1906001600160a01b031681565b61031d61047c36600461347e565b610f4a565b34801561048d57600080fd5b5061031d61049c366004612fb2565b610f85565b3480156104ad57600080fd5b5061031d6104bc366004612fe5565b610f92565b3480156104cd57600080fd5b5061031d6104dc3660046134db565b61100b565b3480156104ed57600080fd5b506105016104fc366004612fb2565b611018565b6040516101a891906134f4565b606061051a6004611337565b905090565b600061052d600484846116ea565b90505b92915050565b61053e612b5c565b610549600783611707565b6040805160c0810190915281546001600160a01b0316815260018201805491929160208401919061057990613507565b80601f01602080910402602001604051908101604052809291908181526020018280546105a590613507565b80156105f25780601f106105c7576101008083540402835291602001916105f2565b820191906000526020600020905b8154815290600101906020018083116105d557829003601f168201915b50505050508152602001600282016040518060a00160405290816000820154815260200160018201548152602001600282015481526020016003820154815260200160048201805461064390613507565b80601f016020809104026020016040519081016040528092919081815260200182805461066f90613507565b80156106bc5780601f10610691576101008083540402835291602001916106bc565b820191906000526020600020905b81548152906001019060200180831161069f57829003601f168201915b505050919092525050508152600782015460208201526008909101546001600160a01b0381166040830152600160a01b900460ff16151560609091015292915050565b606061051a6007611713565b600061052d6004848461196b565b6040805160608082018352808252602082015260009181019190915261074160048585611986565b600801828154811061075557610755613541565b906000526020600020906003020160405180606001604052908160008201805461077e90613507565b80601f01602080910402602001604051908101604052809291908181526020018280546107aa90613507565b80156107f75780601f106107cc576101008083540402835291602001916107f7565b820191906000526020600020905b8154815290600101906020018083116107da57829003601f168201915b5050505050815260200160018201805461081090613507565b80601f016020809104026020016040519081016040528092919081815260200182805461083c90613507565b80156108895780601f1061085e57610100808354040283529160200191610889565b820191906000526020600020905b81548152906001019060200180831161086c57829003601f168201915b50505091835250506002919091015460ff161515602090910152949350505050565b600254600090819081906001600160a01b031633146108e55760405162461bcd60e51b81526004016108dc90613557565b60405180910390fd5b6001546108f89060049087908790611993565b9194509250905060008390036109115760009250610996565b604051339084156108fc029085906000818181858888f1935050505015801561093e573d6000803e3d6000fd5b50836001600160a01b0316856001600160a01b03167f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c776848460405161098d929190918252602082015260400190565b60405180910390a35b9250925092565b6109aa6004338484611ace565b5050565b6002546001600160a01b031633146109d85760405162461bcd60e51b81526004016108dc90613557565b6109aa60048383611bdd565b6109ec611c9e565b6109f66000611cf8565b565b6002546001600160a01b03163314610a225760405162461bcd60e51b81526004016108dc90613557565b600080610a33600486868634611d48565b91509150836001600160a01b0316856001600160a01b03167f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c7768484604051610a85929190918252602082015260400190565b60405180910390a35050505050565b610ade3387878080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506007949392508991508890508787611ef7565b336001600160a01b03167f9657518f02d23efc8a15c042c006a06464dd791f65394ff87310a287c6949462878787878787604051610b2196959493929190613598565b60405180910390a2505050505050565b6002546001600160a01b03163314610b5b5760405162461bcd60e51b81526004016108dc90613557565b6109aa60048383611ffd565b6000610b86610b7d610100840160e08501612fe5565b60049033611986565b9050610b9860a0830160808401612fe5565b60078201546001600160a01b03908116911614610c0d5760405163de83c54360e01b815260206004820152602c60248201527f70726f7669646572207369676e696e672061646472657373206973206e6f742060448201526b1858dadb9bdddb195919d95960a21b60648201526084016108dc565b8160600135816002015410610c785760405163de83c54360e01b815260206004820152602a60248201527f6e6f6e63652073686f756c64206c6172676572207468616e207468652063757260448201526972656e74206e6f6e636560b01b60648201526084016108dc565b8160c0013581600301541015610cc85760405163de83c54360e01b8152602060048201526014602482015273696e73756666696369656e742062616c616e636560601b60448201526064016108dc565b600081600801836000013581548110610ce357610ce3613541565b90600052602060002090600302019050828060400190610d039190613600565b604051610d1192919061364d565b60405190819003812090610d2690839061365d565b604051809103902014610d7c5760405163de83c54360e01b815260206004820152601860248201527f6d6f64656c20726f6f742068617368206d69736d61746368000000000000000060448201526064016108dc565b6007820154600090610da0906001600160a01b0316610d9a866136d3565b906120ae565b905080610df05760405163de83c54360e01b815260206004820181905260248201527f54454520736574746c656d656e742076616c69646174696f6e206661696c656460448201526064016108dc565b610dfd6020850185613600565b6008850180548735908110610e1457610e14613541565b90600052602060002090600302016001019182610e329291906137eb565b5060608401356002840155610e4b8360c08601356120f4565b50505050565b6109aa6004833384612373565b600054600160a01b900460ff1615610ec35760405162461bcd60e51b815260206004820152602260248201527f496e697469616c697a61626c653a20616c726561647920696e697469616c697a604482015261195960f21b60648201526084016108dc565b6000805460ff60a01b1916600160a01b179055610edf81611cf8565b50600191909155600280546001600160a01b039092166001600160a01b0319928316811790915560038054909216179055565b610f1d60073361244d565b60405133907f29d546abb6e94f4f04d5bdccb6682316f597d43776078f47e273f000e77b2a9190600090a2565b6002546001600160a01b03163314610f745760405162461bcd60e51b81526004016108dc90613557565b600080610a33600486863487612496565b6109aa60043384846124ff565b610f9a611c9e565b6001600160a01b038116610fff5760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b60648201526084016108dc565b61100881611cf8565b50565b611013611c9e565b600155565b611020612bcb565b61102c60048484611986565b604080516101208101825282546001600160a01b039081168252600184015416602080830191909152600284015482840152600384015460608301526004840154608083015260058401805484518184028101840190955280855292949360a0860193909260009084015b828210156110f0576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff16151560608301529083529092019101611097565b50505050815260200160068201805461110890613507565b80601f016020809104026020016040519081016040528092919081815260200182805461113490613507565b80156111815780601f1061115657610100808354040283529160200191611181565b820191906000526020600020905b81548152906001019060200180831161116457829003601f168201915b505050918352505060078201546001600160a01b0316602080830191909152600883018054604080518285028101850182528281529401939260009084015b8282101561132857838290600052602060002090600302016040518060600160405290816000820180546111f390613507565b80601f016020809104026020016040519081016040528092919081815260200182805461121f90613507565b801561126c5780601f106112415761010080835404028352916020019161126c565b820191906000526020600020905b81548152906001019060200180831161124f57829003601f168201915b5050505050815260200160018201805461128590613507565b80601f01602080910402602001604051908101604052809291908181526020018280546112b190613507565b80156112fe5780601f106112d3576101008083540402835291602001916112fe565b820191906000526020600020905b8154815290600101906020018083116112e157829003601f168201915b50505091835250506002919091015460ff16151560209182015290825260019290920191016111c0565b50505091525090949350505050565b6060600061134483612572565b9050806001600160401b0381111561135e5761135e61318f565b60405190808252806020026020018201604052801561139757816020015b611384612bcb565b81526020019060019003908161137c5790505b50915060005b818110156116e3576113af848261257d565b604080516101208101825282546001600160a01b039081168252600184015416602080830191909152600284015482840152600384015460608301526004840154608083015260058401805484518184028101840190955280855292949360a0860193909260009084015b82821015611473576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff1615156060830152908352909201910161141a565b50505050815260200160068201805461148b90613507565b80601f01602080910402602001604051908101604052809291908181526020018280546114b790613507565b80156115045780601f106114d957610100808354040283529160200191611504565b820191906000526020600020905b8154815290600101906020018083116114e757829003601f168201915b505050918352505060078201546001600160a01b0316602080830191909152600883018054604080518285028101850182528281529401939260009084015b828210156116ab578382906000526020600020906003020160405180606001604052908160008201805461157690613507565b80601f01602080910402602001604051908101604052809291908181526020018280546115a290613507565b80156115ef5780601f106115c4576101008083540402835291602001916115ef565b820191906000526020600020905b8154815290600101906020018083116115d257829003601f168201915b5050505050815260200160018201805461160890613507565b80601f016020809104026020016040519081016040528092919081815260200182805461163490613507565b80156116815780601f1061165657610100808354040283529160200191611681565b820191906000526020600020905b81548152906001019060200180831161166457829003601f168201915b50505091835250506002919091015460ff1615156020918201529082526001929092019101611543565b50505050815250508382815181106116c5576116c5613541565b602002602001018190525080806116db906138c1565b91505061139d565b5050919050565b60006116ff846116fa85856125a3565b6125db565b949350505050565b600061052d83836125e7565b6060600061172083612572565b9050806001600160401b0381111561173a5761173a61318f565b60405190808252806020026020018201604052801561177357816020015b611760612b5c565b8152602001906001900390816117585790505b50915060005b818110156116e35761178b848261257d565b6040805160c0810190915281546001600160a01b031681526001820180549192916020840191906117bb90613507565b80601f01602080910402602001604051908101604052809291908181526020018280546117e790613507565b80156118345780601f1061180957610100808354040283529160200191611834565b820191906000526020600020905b81548152906001019060200180831161181757829003601f168201915b50505050508152602001600282016040518060a00160405290816000820154815260200160018201548152602001600282015481526020016003820154815260200160048201805461188590613507565b80601f01602080910402602001604051908101604052809291908181526020018280546118b190613507565b80156118fe5780601f106118d3576101008083540402835291602001916118fe565b820191906000526020600020905b8154815290600101906020018083116118e157829003601f168201915b505050919092525050508152600782015460208201526008909101546001600160a01b0381166040830152600160a01b900460ff161515606090910152835184908390811061194f5761194f613541565b602002602001018190525080611964906138c1565b9050611779565b600080611979858585612638565b6004015495945050505050565b60006116ff848484612638565b6000806000806119a4888888612638565b90506000935060005b6005820154811015611ab45760008260050182815481106119d0576119d0613541565b60009182526020909120600490910201600381015490915060ff16156119f65750611aa2565b868160020154611a0691906138da565b421015611a135750611aa2565b8060010154836003016000828254611a2b91906138ed565b90915550506001810154600484018054600090611a499084906138ed565b90915550506001810154611a5d90876138da565b9550826005018281548110611a7457611a74613541565b600091825260208220600490910201818155600181018290556002810191909155600301805460ff19169055505b80611aac816138c1565b9150506119ad565b508060030154925080600401549150509450945094915050565b611adc846116fa85856125a3565b611b0c5760405163023280eb60e21b81526001600160a01b038085166004830152831660248201526044016108dc565b6000611b19858585612638565b9050806008018281548110611b3057611b30613541565b90600052602060002090600302016000018054611b4c90613507565b9050600003611b9d5760405162461bcd60e51b815260206004820152601b60248201527f64656c6976657261626c6520646f6573206e6f742065786973742e000000000060448201526064016108dc565b6001816008018381548110611bb457611bb4613541565b60009182526020909120600390910201600201805460ff19169115159190911790555050505050565b6000611bea848484612638565b9050600081600401548260030154611c0291906138ed565b905080600003611c13575050505050565b6040805160808101825260058401805480835260208084018681524295850195865260006060860181815260018086018755958252928120955160049485029096019586559051938501939093559351600284015592516003909201805460ff1916921515929092179091559083018054839290611c929084906138da565b90915550505050505050565b6000546001600160a01b031633146109f65760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657260448201526064016108dc565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6000806000611d5787876125a3565b9050611d6388826125db565b611d935760405163023280eb60e21b81526001600160a01b038089166004830152871660248201526044016108dc565b6000611da0898989612638565b905060005b6005820154811015611ec3576000826005018281548110611dc857611dc8613541565b60009182526020909120600490910201600381015490915060ff1615611dee5750611eb1565b8060010154836004016000828254611e0691906138ed565b909155505060018101548811611e5d57826005018281548110611e2b57611e2b613541565b600091825260208220600490910201818155600181018290556002810191909155600301805460ff1916905550611ec3565b6001810154611e6c90896138ed565b9750826005018281548110611e8357611e83613541565b600091825260208220600490910201818155600181018290556002810191909155600301805460ff19169055505b80611ebb816138c1565b915050611da5565b5084816003016000828254611ed891906138da565b9091555050600381015460049091015490999098509650505050505050565b6000611f028761269b565b9050611f0e88826125db565b611f6557611f5e88826040518060c001604052808b6001600160a01b031681526020018a8152602001898152602001888152602001876001600160a01b03168152602001600015158152506126d0565b5050611ff4565b6000611f7189896125e7565b905060018101611f818882613900565b5085516002820190815560208701516003830155604087015160048301556060870151600583015560808701518791906006840190611fc09082613900565b505050600781018590556008018054831515600160a01b026001600160a81b03199091166001600160a01b03861617179055505b50505050505050565b600061200983836125a3565b905061201584826125db565b61201f5750505050565b61202984826127ad565b50600081815260028086016020526040822080546001600160a01b0319908116825560018201805490911690559081018290556003810182905560048101829055906120786005830182612c32565b612086600683016000612c53565b6007820180546001600160a01b03191690556120a6600883016000612c8d565b505050505050565b6000806120ba846127b9565b905060006120c7826127ea565b9050836001600160a01b03166120e1828760a00151612825565b6001600160a01b03161495945050505050565b8160040154826003015461210891906138ed565b81111561226d5760008260040154836003015461212591906138ed565b61212f90836138ed565b905080836004015410156121945760405163de83c54360e01b815260206004820152602560248201527f696e73756666696369656e742062616c616e636520696e2070656e64696e675260448201526419599d5b9960da1b60648201526084016108dc565b808360040160008282546121a891906138ed565b909155505060058301546000906121c1906001906138ed565b90505b6000811261226a5760008460050182815481106121e3576121e3613541565b60009182526020909120600490910201600381015490915060ff16156122095750612258565b8281600101541161222a57600181015461222390846138ed565b9250612248565b8281600101600082825461223e91906138ed565b9091555060009350505b82600003612256575061226a565b505b80612262816139bf565b9150506121c4565b50505b8082600301600082825461228191906138ed565b90915550506003548254604051631bb1482360e31b81526001600160a01b0391821660048201526024810184905291169063dd8a411890604401600060405180830381600087803b1580156122d557600080fd5b505af11580156122e9573d6000803e3d6000fd5b50508354600385015460048601546040805192835260208301919091523394506001600160a01b0390921692507f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c776910160405180910390a3604051339082156108fc029083906000818181858888f1935050505015801561236e573d6000803e3d6000fd5b505050565b612381846116fa85856125a3565b6123b15760405163023280eb60e21b81526001600160a01b038085166004830152831660248201526044016108dc565b60006123be858585612638565b604080516060810182528481528151602081810184526000808352818401929092529282018190526008840180546001810182559082529290208151939450909283926003029091019081906124149082613900565b50602082015160018201906124299082613900565b50604091909101516002909101805460ff1916911515919091179055505050505050565b60006124588261269b565b905061246483826125db565b61248c576040516304c76d3f60e11b81526001600160a01b03831660048201526024016108dc565b610e4b83826128a4565b60008060006124a587876125a3565b90506124b188826125db565b156124e257604051632cf0675960e21b81526001600160a01b038089166004830152871660248201526044016108dc565b6124f0888289898989612921565b50929660009650945050505050565b61250d846116fa85856125a3565b61253d5760405163023280eb60e21b81526001600160a01b038085166004830152831660248201526044016108dc565b600061254a858585612638565b60070180546001600160a01b0319166001600160a01b03939093169290921790915550505050565b600061053082612987565b60008061258a8484612991565b6000908152600285016020526040902091505092915050565b604080516001600160a01b03938416602080830191909152929093168382015280518084038201815260609093019052815191012090565b600061052d838361299d565b6000806125f38361269b565b6000818152600286016020526040902090915061261085836125db565b6116ff576040516304c76d3f60e11b81526001600160a01b03851660048201526024016108dc565b60008061264584846125a3565b6000818152600287016020526040902090915061266286836125db565b6126925760405163023280eb60e21b81526001600160a01b038087166004830152851660248201526044016108dc565b95945050505050565b604080516001600160a01b0383166020820152600091015b604051602081830303815290604052805190602001209050919050565b600082815260028401602090815260408220835181546001600160a01b0319166001600160a01b039091161781559083015183919060018201906127149082613900565b5060408201518160020160008201518160000155602082015181600101556040820151816002015560608201518160030155608082015181600401908161275b9190613900565b5050506060820151600782015560808201516008909101805460a0909301511515600160a01b026001600160a81b03199093166001600160a01b03909216919091179190911790556116ff84846129b5565b600061052d83836129c1565b6020808201516040808401516060850151608086015160c087015160e088015194516000976126b3979691016139dc565b6040517f19457468657265756d205369676e6564204d6573736167653a0a3332000000006020820152603c8101829052600090605c016126b3565b60008060008061283485612ab4565b6040805160008152602081018083528b905260ff8516918101919091526060810183905260808101829052929550909350915060019060a0016020604051602081039080840390855afa15801561288f573d6000803e3d6000fd5b5050604051601f190151979650505050505050565b6000818152600283016020526040812080546001600160a01b0319168155816128d06001830182612c53565b600060028301818155600384018290556004840182905560058401829055906128fc6006850182612c53565b5050600060078301555060080180546001600160a81b031916905561052d83836127ad565b600085815260028701602052604090206003810183905580546001600160a01b038087166001600160a01b031992831617835560018301805491871691909216179055600681016129728382613900565b5061297d87876129b5565b5050505050505050565b6000610530825490565b600061052d8383612ae3565b6000818152600183016020526040812054151561052d565b600061052d8383612b0d565b60008181526001830160205260408120548015612aaa5760006129e56001836138ed565b85549091506000906129f9906001906138ed565b9050818114612a5e576000866000018281548110612a1957612a19613541565b9060005260206000200154905080876000018481548110612a3c57612a3c613541565b6000918252602080832090910192909255918252600188019052604090208390555b8554869080612a6f57612a6f613a3c565b600190038181906000526020600020016000905590558560010160008681526020019081526020016000206000905560019350505050610530565b6000915050610530565b60008060008351604114612ac757600080fd5b5050506020810151604082015160609092015160001a92909190565b6000826000018281548110612afa57612afa613541565b9060005260206000200154905092915050565b6000818152600183016020526040812054612b5457508154600181810184556000848152602080822090930184905584548482528286019093526040902091909155610530565b506000610530565b6040518060c0016040528060006001600160a01b0316815260200160608152602001612bb06040518060a0016040528060008152602001600081526020016000815260200160008152602001606081525090565b81526000602082018190526040820181905260609091015290565b60405180610120016040528060006001600160a01b0316815260200160006001600160a01b03168152602001600081526020016000815260200160008152602001606081526020016060815260200160006001600160a01b03168152602001606081525090565b50805460008255600402906000526020600020908101906110089190612cae565b508054612c5f90613507565b6000825580601f10612c6f575050565b601f0160209004906000526020600020908101906110089190612ce0565b50805460008255600302906000526020600020908101906110089190612cf5565b5b80821115612cdc57600080825560018201819055600282015560038101805460ff19169055600401612caf565b5090565b5b80821115612cdc5760008155600101612ce1565b80821115612cdc576000612d098282612c53565b612d17600183016000612c53565b5060028101805460ff19169055600301612cf5565b600081518084526020808501945080840160005b83811015612d7e5781518051885283810151848901526040808201519089015260609081015115159088015260809096019590820190600101612d40565b509495945050505050565b60005b83811015612da4578181015183820152602001612d8c565b50506000910152565b60008151808452612dc5816020860160208601612d89565b601f01601f19169290920160200192915050565b6000815160608452612dee6060850182612dad565b905060208301518482036020860152612e078282612dad565b9150506040830151151560408501528091505092915050565b600082825180855260208086019550808260051b84010181860160005b84811015612e6b57601f19868403018952612e59838351612dd9565b98840198925090830190600101612e3d565b5090979650505050505050565b80516001600160a01b0316825260006101206020830151612ea460208601826001600160a01b03169052565b5060408301516040850152606083015160608501526080830151608085015260a08301518160a0860152612eda82860182612d2c565b91505060c083015184820360c0860152612ef48282612dad565b91505060e0830151612f1160e08601826001600160a01b03169052565b506101008084015185830382870152612f2a8382612e20565b9695505050505050565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b82811015612f8957603f19888603018452612f77858351612e78565b94509285019290850190600101612f5b565b5092979650505050505050565b80356001600160a01b0381168114612fad57600080fd5b919050565b60008060408385031215612fc557600080fd5b612fce83612f96565b9150612fdc60208401612f96565b90509250929050565b600060208284031215612ff757600080fd5b61052d82612f96565b805182526020810151602083015260408101516040830152606081015160608301526000608082015160a060808501526116ff60a0850182612dad565b600060018060a01b03808351168452602083015160c0602086015261306560c0860182612dad565b90506040840151858203604087015261307e8282613000565b9150506060840151606086015281608085015116608086015260a0840151151560a0860152809250505092915050565b60208152600061052d602083018461303d565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b82811015612f8957603f1988860301845261310485835161303d565b945092850192908501906001016130e8565b60008060006060848603121561312b57600080fd5b61313484612f96565b925061314260208501612f96565b9150604084013590509250925092565b60208152600061052d6020830184612dd9565b6000806040838503121561317857600080fd5b61318183612f96565b946020939093013593505050565b634e487b7160e01b600052604160045260246000fd5b60405161010081016001600160401b03811182821017156131c8576131c861318f565b60405290565b600082601f8301126131df57600080fd5b81356001600160401b03808211156131f9576131f961318f565b604051601f8301601f19908116603f011681019082821181831017156132215761322161318f565b8160405283815286602085880101111561323a57600080fd5b836020870160208301376000602085830101528094505050505092915050565b600060a0828403121561326c57600080fd5b60405160a081016001600160401b03828210818311171561328f5761328f61318f565b816040528293508435835260208501356020840152604085013560408401526060850135606084015260808501359150808211156132cc57600080fd5b506132d9858286016131ce565b6080830152505092915050565b80358015158114612fad57600080fd5b60008060008060008060a0878903121561330f57600080fd5b86356001600160401b038082111561332657600080fd5b818901915089601f83011261333a57600080fd5b81358181111561334957600080fd5b8a602082850101111561335b57600080fd5b60209283019850965090880135908082111561337657600080fd5b5061338389828a0161325a565b9450506040870135925061339960608801612f96565b91506133a7608088016132e6565b90509295509295509295565b6000602082840312156133c557600080fd5b81356001600160401b038111156133db57600080fd5b820161010081850312156133ee57600080fd5b9392505050565b6000806040838503121561340857600080fd5b61341183612f96565b915060208301356001600160401b0381111561342c57600080fd5b613438858286016131ce565b9150509250929050565b60008060006060848603121561345757600080fd5b8335925061346760208501612f96565b915061347560408501612f96565b90509250925092565b60008060006060848603121561349357600080fd5b61349c84612f96565b92506134aa60208501612f96565b915060408401356001600160401b038111156134c557600080fd5b6134d1868287016131ce565b9150509250925092565b6000602082840312156134ed57600080fd5b5035919050565b60208152600061052d6020830184612e78565b600181811c9082168061351b57607f821691505b60208210810361353b57634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052603260045260246000fd5b60208082526021908201527f43616c6c6572206973206e6f7420746865206c656467657220636f6e747261636040820152601d60fa1b606082015260800190565b60a081528560a0820152858760c0830137600060c087830101526000601f19601f880116820160c08382030160208401526135d660c0820188613000565b604084019690965250506001600160a01b0392909216606083015215156080909101529392505050565b6000808335601e1984360301811261361757600080fd5b8301803591506001600160401b0382111561363157600080fd5b60200191503681900382131561364657600080fd5b9250929050565b8183823760009101908152919050565b600080835461366b81613507565b600182811680156136835760018114613698576136c7565b60ff19841687528215158302870194506136c7565b8760005260208060002060005b858110156136be5781548a8201529084019082016136a5565b50505082870194505b50929695505050505050565b600061010082360312156136e657600080fd5b6136ee6131a5565b8235815260208301356001600160401b038082111561370c57600080fd5b613718368387016131ce565b6020840152604085013591508082111561373157600080fd5b61373d368387016131ce565b60408401526060850135606084015261375860808601612f96565b608084015260a085013591508082111561377157600080fd5b5061377e368286016131ce565b60a08301525060c083013560c082015261379a60e08401612f96565b60e082015292915050565b601f82111561236e57600081815260208120601f850160051c810160208610156137cc5750805b601f850160051c820191505b818110156120a6578281556001016137d8565b6001600160401b038311156138025761380261318f565b613816836138108354613507565b836137a5565b6000601f84116001811461384a57600085156138325750838201355b600019600387901b1c1916600186901b1783556138a4565b600083815260209020601f19861690835b8281101561387b578685013582556020948501946001909201910161385b565b50868210156138985760001960f88860031b161c19848701351681555b505060018560011b0183555b5050505050565b634e487b7160e01b600052601160045260246000fd5b6000600182016138d3576138d36138ab565b5060010190565b80820180821115610530576105306138ab565b81810381811115610530576105306138ab565b81516001600160401b038111156139195761391961318f565b61392d816139278454613507565b846137a5565b602080601f831160018114613962576000841561394a5750858301515b600019600386901b1c1916600185901b1785556120a6565b600085815260208120601f198616915b8281101561399157888601518255948401946001909101908401613972565b50858210156139af5787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b6000600160ff1b82016139d4576139d46138ab565b506000190190565b600087516139ee818460208c01612d89565b875190830190613a02818360208c01612d89565b0195865250506bffffffffffffffffffffffff19606093841b81166020860152603485019290925290911b16605482015260680192915050565b634e487b7160e01b600052603160045260246000fdfea2646970667358221220aa0def9cb9f218629a73b683ea16e95cfd3e8206886779c350fd59931ea89def64736f6c63430008140033';
const isSuperArgs$1 = (xs) => xs.length > 1;
class FineTuningServing__factory extends ContractFactory {
    constructor(...args) {
        if (isSuperArgs$1(args)) {
            super(...args);
        }
        else {
            super(_abi$1, _bytecode$1, args[0]);
        }
    }
    getDeployTransaction(overrides) {
        return super.getDeployTransaction(overrides || {});
    }
    deploy(overrides) {
        return super.deploy(overrides || {});
    }
    connect(runner) {
        return super.connect(runner);
    }
    static bytecode = _bytecode$1;
    static abi = _abi$1;
    static createInterface() {
        return new Interface(_abi$1);
    }
    static connect(address, runner) {
        return new Contract(address, _abi$1, runner);
    }
}

class FineTuningServingContract {
    serving;
    signer;
    _userAddress;
    _gasPrice;
    constructor(signer, contractAddress, userAddress, gasPrice) {
        this.serving = FineTuningServing__factory.connect(contractAddress, signer);
        this.signer = signer;
        this._userAddress = userAddress;
        this._gasPrice = gasPrice;
    }
    lockTime() {
        return this.serving.lockTime();
    }
    async listService() {
        try {
            const services = await this.serving.getAllServices();
            return services;
        }
        catch (error) {
            throw error;
        }
    }
    async listAccount() {
        try {
            const accounts = await this.serving.getAllAccounts();
            return accounts;
        }
        catch (error) {
            throw error;
        }
    }
    async getAccount(provider) {
        try {
            const user = this.getUserAddress();
            const account = await this.serving.getAccount(user, provider);
            return account;
        }
        catch (error) {
            throw error;
        }
    }
    async acknowledgeProviderSigner(providerAddress, providerSigner, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            const tx = await this.serving.acknowledgeProviderSigner(providerAddress, providerSigner, txOptions);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throw error;
        }
    }
    async acknowledgeDeliverable(providerAddress, index, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            const tx = await this.serving.acknowledgeDeliverable(providerAddress, index, txOptions);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throw error;
        }
    }
    async getService(providerAddress) {
        try {
            return this.serving.getService(providerAddress);
        }
        catch (error) {
            throw error;
        }
    }
    async getDeliverable(providerAddress, index) {
        try {
            const user = this.getUserAddress();
            return this.serving.getDeliverable(user, providerAddress, index);
        }
        catch (error) {
            throw error;
        }
    }
    getUserAddress() {
        return this._userAddress;
    }
}

/**
 * MESSAGE_FOR_ENCRYPTION_KEY is a fixed message used to derive the encryption key.
 *
 * Background:
 * To ensure a consistent and unique encryption key can be generated from a user's Ethereum wallet,
 * we utilize a fixed message combined with a signing mechanism.
 *
 * Purpose:
 * - This string is provided to the Ethereum signing function to generate a digital signature based on the user's private key.
 * - The produced signature is then hashed (using SHA-256) to create a consistent 256-bit encryption key from the same wallet.
 * - This process offers a way to protect data without storing additional keys.
 *
 * Note:
 * - The uniqueness and stability of this message are crucial; do not change it unless you fully understand the impact
 *   on the key derivation and encryption process.
 * - Because the signature is derived from the wallet's private key, it ensures that different wallets cannot produce the same key.
 */
const ZG_RPC_ENDPOINT_TESTNET = 'https://evmrpc-testnet.0g.ai';
const INDEXER_URL_TURBO = 'https://indexer-storage-testnet-turbo.0g.ai';
const MODEL_HASH_MAP = {
    'distilbert-base-uncased': {
        turbo: '0x7f2244b25cd2219dfd9d14c052982ecce409356e0f08e839b79796e270d110a7',
        standard: '',
        description: 'DistilBERT is a transformers model, smaller and faster than BERT, which was pretrained on the same corpus in a self-supervised fashion, using the BERT base model as a teacher. More details can be found at: https://huggingface.co/distilbert/distilbert-base-uncased',
    },
    mobilenet_v2: {
        turbo: '0x8645816c17a8a70ebf32bcc7e621c659e8d0150b1a6bfca27f48f83010c6d12e',
        standard: '',
        description: 'MobileNet V2 model pre-trained on ImageNet-1k at resolution 224x224. More details can be found at: https://huggingface.co/google/mobilenet_v2_1.0_224',
    },
    'deepseek-r1-distill-qwen-1.5b': {
        turbo: '0x2084fdd904c9a3317dde98147d4e7778a40e076b5b0eb469f7a8f27ae5b13e7f',
        standard: '',
        description: 'DeepSeek-R1-Zero, a model trained via large-scale reinforcement learning (RL) without supervised fine-tuning (SFT) as a preliminary step, demonstrated remarkable performance on reasoning. More details can be found at: https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B',
    },
    'cocktailsgd-opt-1.3b': {
        turbo: '0xe25963fd25fe37d7df5216de1eae533ea42090d3642c3f84edd0f179ffc63a94,0xfccaf17bd0ed26b74e8a3883f5c814bcb5f247015d68fd65a28bf98e1bdb0b7f',
        standard: '',
        description: 'CocktailSGD-opt-1.3B finetunes the Opt-1.3B langauge model with CocktailSGD, which is a novel distributed finetuning framework. More details can be found at: https://github.com/DS3Lab/CocktailSGD',
    },
    // TODO: remove
    'mock-model': {
        turbo: '0xcb42b5ca9e998c82dd239ef2d20d22a4ae16b3dc0ce0a855c93b52c7c2bab6dc',
        standard: '',
        description: '',
    },
};
// AutomataDcapAttestation for quote verification
// https://explorer.ata.network/address/0xE26E11B257856B0bEBc4C759aaBDdea72B64351F/contract/65536_2/readContract#F6
const AUTOMATA_RPC = 'https://1rpc.io/ata';
const AUTOMATA_CONTRACT_ADDRESS = '0xE26E11B257856B0bEBc4C759aaBDdea72B64351F';
const AUTOMATA_ABI = [
    {
        inputs: [
            {
                internalType: 'bytes',
                name: 'rawQuote',
                type: 'bytes',
            },
        ],
        name: 'verifyAndAttestOnChain',
        outputs: [
            {
                internalType: 'bool',
                name: 'success',
                type: 'bool',
            },
            {
                internalType: 'bytes',
                name: 'output',
                type: 'bytes',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
];

async function upload(privateKey, dataPath, gasPrice) {
    try {
        const fileSize = await getFileContentSize(dataPath);
        return new Promise((resolve, reject) => {
            const command = path.join(__dirname, '..', '..', '..', '..', 'binary', '0g-storage-client');
            const args = [
                'upload',
                '--url',
                ZG_RPC_ENDPOINT_TESTNET,
                '--key',
                privateKey,
                '--indexer',
                INDEXER_URL_TURBO,
                '--file',
                dataPath,
            ];
            if (gasPrice) {
                args.push('--gas-price', gasPrice.toString());
            }
            const process = spawn(command, args);
            process.stdout.on('data', (data) => {
                console.log(`${data}`);
            });
            process.stderr.on('data', (data) => {
                console.error(`${data}`);
            });
            process.on('close', (code) => {
                if (code !== 0) {
                    reject(new Error(`Process exited with code ${code}`));
                }
                else {
                    console.log(`File size: ${fileSize} bytes`);
                    resolve();
                }
            });
            process.on('error', (err) => {
                reject(err);
            });
        });
    }
    catch (err) {
        console.error(err);
        throw err;
    }
}
async function download(dataPath, dataRoot) {
    return new Promise((resolve, reject) => {
        const command = path.join(__dirname, '..', '..', '..', '..', 'binary', '0g-storage-client');
        const args = [
            'download',
            '--file',
            dataPath,
            '--indexer',
            INDEXER_URL_TURBO,
            '--roots',
            dataRoot,
        ];
        const process = spawn(command, args);
        let log = '';
        process.stdout.on('data', (data) => {
            const output = data.toString();
            log += output;
            console.log(output);
        });
        process.stderr.on('data', (data) => {
            const errorOutput = data.toString();
            log += errorOutput;
            console.error(errorOutput);
        });
        process.on('close', (code) => {
            if (code !== 0) {
                return reject(new Error(`Process exited with code ${code}`));
            }
            if (!log
                .trim()
                .endsWith('Succeeded to validate the downloaded file')) {
                return reject(new Error('Failed to download the file'));
            }
            resolve();
        });
        process.on('error', (err) => {
            reject(err);
        });
    });
}
async function getFileContentSize(filePath) {
    try {
        const fileHandle = await fs.open(filePath, 'r');
        try {
            const stats = await fileHandle.stat();
            return stats.size;
        }
        finally {
            await fileHandle.close();
        }
    }
    catch (err) {
        throw new Error(`Error processing file: ${err instanceof Error ? err.message : String(err)}`);
    }
}

class ModelProcessor extends BrokerBase {
    listModel() {
        return Object.entries(MODEL_HASH_MAP);
    }
    async uploadDataset(privateKey, dataPath, gasPrice) {
        upload(privateKey, dataPath, gasPrice);
    }
    async downloadDataset(dataPath, dataRoot) {
        download(dataPath, dataRoot);
    }
    async acknowledgeModel(providerAddress, dataPath, gasPrice) {
        try {
            const account = await this.contract.getAccount(providerAddress);
            const latestDeliverable = account.deliverables[account.deliverables.length - 1];
            if (!latestDeliverable) {
                throw new Error('No deliverable found');
            }
            await download(dataPath, hexToRoots(latestDeliverable.modelRootHash));
            await this.contract.acknowledgeDeliverable(providerAddress, account.deliverables.length - 1, gasPrice);
        }
        catch (error) {
            throw error;
        }
    }
    async decryptModel(providerAddress, encryptedModelPath, decryptedModelPath) {
        try {
            const account = await this.contract.getAccount(providerAddress);
            const latestDeliverable = account.deliverables[account.deliverables.length - 1];
            if (!latestDeliverable) {
                throw new Error('No deliverable found');
            }
            const secret = await eciesDecrypt(this.contract.signer, latestDeliverable.encryptedSecret);
            await aesGCMDecryptToFile(secret, encryptedModelPath, decryptedModelPath, account.providerSigner);
        }
        catch (error) {
            throw error;
        }
        return;
    }
}

class Automata {
    provider;
    contract;
    constructor() {
        this.provider = new ethers.JsonRpcProvider(AUTOMATA_RPC);
        this.contract = new ethers.Contract(AUTOMATA_CONTRACT_ADDRESS, AUTOMATA_ABI, this.provider);
    }
    async verifyQuote(rawQuote) {
        try {
            const [success] = await this.contract.verifyAndAttestOnChain(rawQuote);
            return success;
        }
        catch (error) {
            throw error;
        }
    }
}

class ServiceProcessor extends BrokerBase {
    automata;
    constructor(contract, ledger, servingProvider) {
        super(contract, ledger, servingProvider);
        this.automata = new Automata();
    }
    async getLockTime() {
        try {
            const lockTime = await this.contract.lockTime();
            return lockTime;
        }
        catch (error) {
            throw error;
        }
    }
    async getAccount(provider) {
        try {
            const account = await this.contract.getAccount(provider);
            return account;
        }
        catch (error) {
            throw error;
        }
    }
    async getAccountWithDetail(provider) {
        try {
            const account = await this.contract.getAccount(provider);
            const lockTime = await this.getLockTime();
            const now = BigInt(Math.floor(Date.now() / 1000)); // Converts milliseconds to seconds
            const refunds = account.refunds
                .filter((refund) => !refund.processed)
                .map((refund) => ({
                amount: refund.amount,
                remainTime: lockTime - (now - refund.createdAt),
            }));
            return { account, refunds };
        }
        catch (error) {
            throw error;
        }
    }
    async listService() {
        try {
            const services = await this.contract.listService();
            return services;
        }
        catch (error) {
            throw error;
        }
    }
    // 5. acknowledge provider signer
    //     1. [`call provider url/v1/quote`] call provider quote api to download quote (contains provider signer)
    //     2. [`TBD`] verify the quote using third party service (TODO: discuss with Phala)
    //     3. [`call contract`] acknowledge the provider signer in contract
    async acknowledgeProviderSigner(providerAddress, gasPrice) {
        try {
            try {
                await this.contract.getAccount(providerAddress);
            }
            catch (error) {
                if (!error.message.includes('AccountNotExists')) {
                    throw error;
                }
                else {
                    await this.ledger.transferFund(providerAddress, 'fine-tuning', BigInt(0), gasPrice);
                }
            }
            let { quote, provider_signer } = await this.servingProvider.getQuote(providerAddress);
            if (!quote || !provider_signer) {
                throw new Error('Invalid quote');
            }
            if (!quote.startsWith('0x')) {
                quote = '0x' + quote;
            }
            const rpc = process.env.RPC_ENDPOINT;
            // bypass quote verification if testing on localhost
            if (!rpc || !/localhost|127\.0\.0\.1/.test(rpc)) {
                const isVerified = await this.automata.verifyQuote(quote);
                if (!isVerified) {
                    throw new Error('Quote verification failed');
                }
            }
            await this.contract.acknowledgeProviderSigner(providerAddress, provider_signer, gasPrice);
        }
        catch (error) {
            throw error;
        }
    }
    // 7. create task
    //     1. get preTrained model root hash based on the model
    //     2. [`call contract`] calculate fee
    //     3. [`call contract`] transfer fund from ledger to fine-tuning provider
    //     4. [`call provider url/v1/task`]call provider task creation api to create task
    async createTask(providerAddress, preTrainedModelName, dataSize, datasetHash, trainingPath, gasPrice) {
        try {
            const service = await this.contract.getService(providerAddress);
            const fee = service.pricePerToken * BigInt(dataSize);
            await this.ledger.transferFund(providerAddress, 'fine-tuning', fee, gasPrice);
            const trainingParams = await fs.readFile(trainingPath, 'utf-8');
            this.verifyTrainingParams(trainingParams);
            const nonce = getNonce();
            const signature = await signRequest(this.contract.signer, this.contract.getUserAddress(), BigInt(nonce), datasetHash, fee);
            const task = {
                userAddress: this.contract.getUserAddress(),
                datasetHash,
                trainingParams,
                preTrainedModelHash: MODEL_HASH_MAP[preTrainedModelName].turbo,
                fee: fee.toString(),
                nonce: nonce.toString(),
                signature,
            };
            return await this.servingProvider.createTask(providerAddress, task);
        }
        catch (error) {
            throw error;
        }
    }
    async listTask(providerAddress) {
        try {
            return await this.servingProvider.listTask(providerAddress, this.contract.getUserAddress());
        }
        catch (error) {
            throw error;
        }
    }
    async getTask(providerAddress, taskID) {
        try {
            if (!taskID) {
                const tasks = await this.servingProvider.listTask(providerAddress, this.contract.getUserAddress(), true);
                if (tasks.length === 0) {
                    throw new Error('No task found');
                }
                return tasks[0];
            }
            return await this.servingProvider.getTask(providerAddress, this.contract.getUserAddress(), taskID);
        }
        catch (error) {
            throw error;
        }
    }
    // 8. [`call provider`] call provider task progress api to get task progress
    async getLog(providerAddress, taskID) {
        if (!taskID) {
            const tasks = await this.servingProvider.listTask(providerAddress, this.contract.getUserAddress(), true);
            taskID = tasks[0].id;
            if (tasks.length === 0 || !taskID) {
                throw new Error('No task found');
            }
        }
        return this.servingProvider.getLog(providerAddress, this.contract.getUserAddress(), taskID);
    }
    verifyTrainingParams(trainingParams) {
        try {
            JSON.parse(trainingParams);
        }
        catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred';
            throw new Error(`Invalid JSON in trainingPath file: ${errorMessage}`);
        }
    }
}

class Provider {
    contract;
    constructor(contract) {
        this.contract = contract;
    }
    async fetchJSON(endpoint, options) {
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error);
            }
            return response.json();
        }
        catch (error) {
            throw error;
        }
    }
    async fetchText(endpoint, options) {
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            const buffer = await response.arrayBuffer();
            return Buffer.from(buffer).toString('utf-8');
        }
        catch (error) {
            throw error;
        }
    }
    async getProviderUrl(providerAddress) {
        try {
            const service = await this.contract.getService(providerAddress);
            return service.url;
        }
        catch (error) {
            throw error;
        }
    }
    async getQuote(providerAddress) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/quote`;
            const quoteString = await this.fetchText(endpoint, {
                method: 'GET',
            });
            const ret = JSON.parse(quoteString);
            return ret;
        }
        catch (error) {
            throw error;
        }
    }
    async createTask(providerAddress, task) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const userAddress = this.contract.getUserAddress();
            const endpoint = `${url}/v1/user/${userAddress}/task`;
            const response = await this.fetchJSON(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(task),
            });
            return response.id;
        }
        catch (error) {
            if (error instanceof Error) {
                throw new Error(`Failed to create task: ${error.message}`);
            }
            throw new Error('Failed to create task');
        }
    }
    async getTask(providerAddress, userAddress, taskID) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/user/${encodeURIComponent(userAddress)}/task/${taskID}`;
            console.log('url', url);
            console.log('endpoint', endpoint);
            return this.fetchJSON(endpoint, { method: 'GET' });
        }
        catch (error) {
            throw error;
        }
    }
    async listTask(providerAddress, userAddress, latest = false) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            let endpoint = `${url}/v1/user/${encodeURIComponent(userAddress)}/task`;
            if (latest) {
                endpoint += '?latest=true';
            }
            return this.fetchJSON(endpoint, { method: 'GET' });
        }
        catch (error) {
            throw error;
        }
    }
    async getLog(providerAddress, userAddress, taskID) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/user/${userAddress}/task/${taskID}/log`;
            return this.fetchText(endpoint, { method: 'GET' });
        }
        catch (error) {
            throw error;
        }
    }
}

class FineTuningBroker {
    signer;
    fineTuningCA;
    ledger;
    modelProcessor;
    serviceProcessor;
    serviceProvider;
    _gasPrice;
    constructor(signer, fineTuningCA, ledger, gasPrice) {
        this.signer = signer;
        this.fineTuningCA = fineTuningCA;
        this.ledger = ledger;
        this._gasPrice = gasPrice;
    }
    async initialize() {
        let userAddress;
        try {
            userAddress = await this.signer.getAddress();
        }
        catch (error) {
            throw error;
        }
        const contract = new FineTuningServingContract(this.signer, this.fineTuningCA, userAddress, this._gasPrice);
        this.serviceProvider = new Provider(contract);
        this.modelProcessor = new ModelProcessor(contract, this.ledger, this.serviceProvider);
        this.serviceProcessor = new ServiceProcessor(contract, this.ledger, this.serviceProvider);
    }
    listService = async () => {
        try {
            return await this.serviceProcessor.listService();
        }
        catch (error) {
            throw error;
        }
    };
    getLockedTime = async () => {
        try {
            return await this.serviceProcessor.getLockTime();
        }
        catch (error) {
            throw error;
        }
    };
    getAccount = async (providerAddress) => {
        try {
            return await this.serviceProcessor.getAccount(providerAddress);
        }
        catch (error) {
            throw error;
        }
    };
    getAccountWithDetail = async (providerAddress) => {
        try {
            return await this.serviceProcessor.getAccountWithDetail(providerAddress);
        }
        catch (error) {
            throw error;
        }
    };
    acknowledgeProviderSigner = async (providerAddress, gasPrice) => {
        try {
            return await this.serviceProcessor.acknowledgeProviderSigner(providerAddress, gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
    listModel = () => {
        try {
            return this.modelProcessor.listModel();
        }
        catch (error) {
            throw error;
        }
    };
    uploadDataset = async (dataPath, gasPrice) => {
        try {
            await this.modelProcessor.uploadDataset(this.signer.privateKey, dataPath, gasPrice || this._gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
    downloadDataset = async (dataPath, dataRoot) => {
        try {
            await this.modelProcessor.downloadDataset(dataPath, dataRoot);
        }
        catch (error) {
            throw error;
        }
    };
    createTask = async (providerAddress, preTrainedModelName, dataSize, datasetHash, trainingPath, gasPrice) => {
        try {
            return await this.serviceProcessor.createTask(providerAddress, preTrainedModelName, dataSize, datasetHash, trainingPath, gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
    listTask = async (providerAddress) => {
        try {
            return await this.serviceProcessor.listTask(providerAddress);
        }
        catch (error) {
            throw error;
        }
    };
    getTask = async (providerAddress, taskID) => {
        try {
            const task = await this.serviceProcessor.getTask(providerAddress, taskID);
            return task;
        }
        catch (error) {
            throw error;
        }
    };
    getLog = async (providerAddress, taskID) => {
        try {
            return await this.serviceProcessor.getLog(providerAddress, taskID);
        }
        catch (error) {
            throw error;
        }
    };
    acknowledgeModel = async (providerAddress, dataPath, gasPrice) => {
        try {
            return await this.modelProcessor.acknowledgeModel(providerAddress, dataPath, gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
    decryptModel = async (providerAddress, encryptedModelPath, decryptedModelPath) => {
        try {
            return await this.modelProcessor.decryptModel(providerAddress, encryptedModelPath, decryptedModelPath);
        }
        catch (error) {
            throw error;
        }
    };
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
async function createFineTuningBroker(signer, contractAddress, ledger, gasPrice) {
    const broker = new FineTuningBroker(signer, contractAddress, ledger, gasPrice);
    try {
        await broker.initialize();
        return broker;
    }
    catch (error) {
        throw error;
    }
}

/**
 * LedgerProcessor contains methods for creating, depositing funds, and retrieving 0G Compute Network Ledgers.
 */
class LedgerProcessor {
    metadata;
    cache;
    ledgerContract;
    inferenceContract;
    fineTuningContract;
    constructor(metadata, cache, ledgerContract, inferenceContract, fineTuningContract) {
        this.metadata = metadata;
        this.ledgerContract = ledgerContract;
        this.inferenceContract = inferenceContract;
        this.fineTuningContract = fineTuningContract;
        this.cache = cache;
    }
    async getLedger() {
        try {
            const ledger = await this.ledgerContract.getLedger();
            return ledger;
        }
        catch (error) {
            throw error;
        }
    }
    async getLedgerWithDetail() {
        try {
            const ledger = await this.ledgerContract.getLedger();
            const ledgerInfo = [
                ledger.totalBalance,
                ledger.totalBalance - ledger.availableBalance,
            ];
            const infers = await Promise.all(ledger.inferenceProviders.map(async (provider) => {
                const account = await this.inferenceContract.getAccount(provider);
                return [provider, account.balance, account.pendingRefund];
            }));
            if (typeof this.fineTuningContract == 'undefined') {
                return { ledgerInfo, infers, fines: [] };
            }
            const fines = await Promise.all(ledger.fineTuningProviders.map(async (provider) => {
                const account = await this.fineTuningContract?.getAccount(provider);
                return [provider, account.balance, account.pendingRefund];
            }));
            return { ledgerInfo, infers, fines };
        }
        catch (error) {
            throw error;
        }
    }
    async listLedger() {
        try {
            const ledgers = await this.ledgerContract.listLedger();
            return ledgers;
        }
        catch (error) {
            throw error;
        }
    }
    async addLedger(balance, gasPrice) {
        try {
            try {
                const ledger = await this.getLedger();
                if (ledger) {
                    throw new Error('Ledger already exists, with balance: ' +
                        this.neuronToA0gi(ledger.totalBalance) +
                        ' A0GI');
                }
            }
            catch (error) {
                if (!error.message.includes('LedgerNotExists')) {
                    throw error;
                }
            }
            const { settleSignerPublicKey, settleSignerEncryptedPrivateKey } = await this.createSettleSignerKey();
            await this.ledgerContract.addLedger(settleSignerPublicKey, this.a0giToNeuron(balance), settleSignerEncryptedPrivateKey, gasPrice);
        }
        catch (error) {
            throw error;
        }
    }
    async deleteLedger(gasPrice) {
        try {
            await this.ledgerContract.deleteLedger(gasPrice);
        }
        catch (error) {
            throw error;
        }
    }
    async depositFund(balance, gasPrice) {
        try {
            const amount = this.a0giToNeuron(balance).toString();
            await this.ledgerContract.depositFund(amount, gasPrice);
        }
        catch (error) {
            throw error;
        }
    }
    async refund(balance, gasPrice) {
        try {
            const amount = this.a0giToNeuron(balance).toString();
            await this.ledgerContract.refund(amount, gasPrice);
        }
        catch (error) {
            throw error;
        }
    }
    async transferFund(to, serviceTypeStr, balance, gasPrice) {
        try {
            const amount = balance.toString();
            await this.ledgerContract.transferFund(to, serviceTypeStr, amount, gasPrice);
        }
        catch (error) {
            throw error;
        }
    }
    async retrieveFund(serviceTypeStr, gasPrice) {
        try {
            const ledger = await this.getLedgerWithDetail();
            const providers = serviceTypeStr == 'inference' ? ledger.infers : ledger.fines;
            if (!providers) {
                throw new Error('No providers found, please ensure you are using Wallet instance to create the broker');
            }
            const providerAddresses = providers
                .filter((x) => x[1] - x[2] > 0n)
                .map((x) => x[0]);
            await this.ledgerContract.retrieveFund(providerAddresses, serviceTypeStr, gasPrice);
            if (serviceTypeStr == 'inference') {
                await this.cache.setItem('firstRound', 'true', 10000000 * 60 * 1000, CacheValueTypeEnum.Other);
            }
        }
        catch (error) {
            throw error;
        }
    }
    async createSettleSignerKey() {
        try {
            // [pri, pub]
            const keyPair = await genKeyPair();
            const key = `${this.ledgerContract.getUserAddress()}`;
            this.metadata.storeSettleSignerPrivateKey(key, keyPair.packedPrivkey);
            const settleSignerEncryptedPrivateKey = await encryptData(this.ledgerContract.signer, privateKeyToStr(keyPair.packedPrivkey));
            return {
                settleSignerEncryptedPrivateKey,
                settleSignerPublicKey: keyPair.doublePackedPubkey,
            };
        }
        catch (error) {
            throw error;
        }
    }
    a0giToNeuron(value) {
        const valueStr = value.toFixed(18);
        const parts = valueStr.split('.');
        // Handle integer part
        const integerPart = parts[0];
        let integerPartAsBigInt = BigInt(integerPart) * BigInt(10 ** 18);
        // Handle fractional part if it exists
        if (parts.length > 1) {
            let fractionalPart = parts[1];
            while (fractionalPart.length < 18) {
                fractionalPart += '0';
            }
            if (fractionalPart.length > 18) {
                fractionalPart = fractionalPart.slice(0, 18); // Truncate to avoid overflow
            }
            const fractionalPartAsBigInt = BigInt(fractionalPart);
            integerPartAsBigInt += fractionalPartAsBigInt;
        }
        return integerPartAsBigInt;
    }
    neuronToA0gi(value) {
        const divisor = BigInt(10 ** 18);
        const integerPart = value / divisor;
        const remainder = value % divisor;
        const decimalPart = Number(remainder) / Number(divisor);
        return Number(integerPart) + decimalPart;
    }
}

/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
const _abi = [
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
        ],
        name: 'InsufficientBalance',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
        ],
        name: 'LedgerExists',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
        ],
        name: 'LedgerNotExists',
        type: 'error',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'previousOwner',
                type: 'address',
            },
            {
                indexed: true,
                internalType: 'address',
                name: 'newOwner',
                type: 'address',
            },
        ],
        name: 'OwnershipTransferred',
        type: 'event',
    },
    {
        inputs: [
            {
                internalType: 'uint256[2]',
                name: 'inferenceSigner',
                type: 'uint256[2]',
            },
            {
                internalType: 'string',
                name: 'additionalInfo',
                type: 'string',
            },
        ],
        name: 'addLedger',
        outputs: [
            {
                internalType: 'uint256',
                name: '',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: '',
                type: 'uint256',
            },
        ],
        stateMutability: 'payable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'deleteLedger',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'depositFund',
        outputs: [],
        stateMutability: 'payable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'fineTuningAddress',
        outputs: [
            {
                internalType: 'address payable',
                name: '',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'getAllLedgers',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'user',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'availableBalance',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'totalBalance',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256[2]',
                        name: 'inferenceSigner',
                        type: 'uint256[2]',
                    },
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
                    },
                    {
                        internalType: 'address[]',
                        name: 'inferenceProviders',
                        type: 'address[]',
                    },
                    {
                        internalType: 'address[]',
                        name: 'fineTuningProviders',
                        type: 'address[]',
                    },
                ],
                internalType: 'struct Ledger[]',
                name: 'ledgers',
                type: 'tuple[]',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
        ],
        name: 'getLedger',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'user',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'availableBalance',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'totalBalance',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256[2]',
                        name: 'inferenceSigner',
                        type: 'uint256[2]',
                    },
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
                    },
                    {
                        internalType: 'address[]',
                        name: 'inferenceProviders',
                        type: 'address[]',
                    },
                    {
                        internalType: 'address[]',
                        name: 'fineTuningProviders',
                        type: 'address[]',
                    },
                ],
                internalType: 'struct Ledger',
                name: '',
                type: 'tuple',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'inferenceAddress',
        outputs: [
            {
                internalType: 'address payable',
                name: '',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: '_inferenceAddress',
                type: 'address',
            },
            {
                internalType: 'address',
                name: '_fineTuningAddress',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'owner',
                type: 'address',
            },
        ],
        name: 'initialize',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'initialized',
        outputs: [
            {
                internalType: 'bool',
                name: '',
                type: 'bool',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [],
        name: 'owner',
        outputs: [
            {
                internalType: 'address',
                name: '',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: 'amount',
                type: 'uint256',
            },
        ],
        name: 'refund',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [],
        name: 'renounceOwnership',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address[]',
                name: 'providers',
                type: 'address[]',
            },
            {
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
        ],
        name: 'retrieveFund',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'amount',
                type: 'uint256',
            },
        ],
        name: 'spendFund',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'string',
                name: 'serviceTypeStr',
                type: 'string',
            },
            {
                internalType: 'uint256',
                name: 'amount',
                type: 'uint256',
            },
        ],
        name: 'transferFund',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'newOwner',
                type: 'address',
            },
        ],
        name: 'transferOwnership',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        stateMutability: 'payable',
        type: 'receive',
    },
];
const _bytecode = '0x608060405234801561001057600080fd5b5061001a3361001f565b61006f565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6120708061007e6000396000f3fe6080604052600436106100f75760003560e01c806372adc0d91161008a578063dd8a411811610059578063dd8a41181461028d578063e5d9fdab146102ad578063f2fde38b146102cd578063f7cd6af9146102ed57600080fd5b806372adc0d91461021f5780638d0d8cb6146102475780638da5cb5b1461024f578063c0c53b8b1461026d57600080fd5b806331404a19116100c657806331404a191461019d578063382e1112146101bd578063410b3815146101f5578063715018a61461020a57600080fd5b8063158ef93e146101035780631665c79b14610139578063278ecde11461015b5780632ba43b821461017d57600080fd5b366100fe57005b600080fd5b34801561010f57600080fd5b5060005461012490600160a01b900460ff1681565b60405190151581526020015b60405180910390f35b34801561014557600080fd5b5061014e61031a565b6040516101309190611989565b34801561016757600080fd5b5061017b6101763660046119eb565b61057d565b005b34801561018957600080fd5b5061017b610198366004611ad7565b61061c565b3480156101a957600080fd5b5061017b6101b8366004611b2e565b6109be565b3480156101c957600080fd5b506002546101dd906001600160a01b031681565b6040516001600160a01b039091168152602001610130565b34801561020157600080fd5b5061017b610b5d565b34801561021657600080fd5b5061017b610d8c565b61023261022d366004611bfd565b610da0565b60408051928352602083019190915201610130565b61017b610df3565b34801561025b57600080fd5b506000546001600160a01b03166101dd565b34801561027957600080fd5b5061017b610288366004611c46565b610e6d565b34801561029957600080fd5b5061017b6102a8366004611c89565b610f37565b3480156102b957600080fd5b506001546101dd906001600160a01b031681565b3480156102d957600080fd5b5061017b6102e8366004611cb3565b611047565b3480156102f957600080fd5b5061030d610308366004611cb3565b6110c0565b6040516101309190611cce565b6060600061032661128f565b90508067ffffffffffffffff81111561034157610341611a20565b60405190808252806020026020018201604052801561037a57816020015b61036761173a565b81526020019060019003908161035f5790505b50915060005b8181101561057857610391816112a0565b6040805160e08101825282546001600160a01b031681526001830154602082015260028084015482840152825180840193849052919392606085019291600385019182845b8154815260200190600101908083116103d6575050505050815260200160058201805461040290611ce1565b80601f016020809104026020016040519081016040528092919081815260200182805461042e90611ce1565b801561047b5780601f106104505761010080835404028352916020019161047b565b820191906000526020600020905b81548152906001019060200180831161045e57829003601f168201915b50505050508152602001600682018054806020026020016040519081016040528092919081815260200182805480156104dd57602002820191906000526020600020905b81546001600160a01b031681526001909101906020018083116104bf575b505050505081526020016007820180548060200260200160405190810160405280929190818152602001828054801561053f57602002820191906000526020600020905b81546001600160a01b03168152600190910190602001808311610521575b50505050508152505083828151811061055a5761055a611d1b565b6020026020010181905250808061057090611d47565b915050610380565b505090565b6000610588336112c3565b905081816001015410156105b65760405163112fed8b60e31b81523360048201526024015b60405180910390fd5b818160010160008282546105ca9190611d60565b92505081905550818160020160008282546105e59190611d60565b9091555050604051339083156108fc029084906000818181858888f19350505050158015610617573d6000803e3d6000fd5b505050565b6000610627336112c3565b9050600080600061063786611318565b60405163147500e360e01b81523360048201526001600160a01b038b81166024830152939650919450925086916060919085169063147500e390604401602060405180830381865afa158015610691573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906106b59190611d73565b156107a157604051631320b9eb60e11b81523360048201526001600160a01b038a811660248301526000919086169063264173d690604401602060405180830381865afa15801561070a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061072e9190611d95565b9050600061073c8983611419565b90506107488185611d60565b6040513360248201526001600160a01b038d1660448201526064810183905290945060840160408051601f198184030181529190526020810180516001600160e01b031663745e87f760e01b179052925061089e915050565b8260000361082857338987600301886005016040516024016107c69493929190611e2b565b60408051601f19818403018152919052602080820180516001600160e01b03166312f0ebfd60e21b17905260068801805460018101825560009182529190200180546001600160a01b038c166001600160a01b0319909116179055905061089e565b33898760050160405160240161084093929190611e8d565b60408051601f19818403018152919052602080820180516001600160e01b031663e50688f960e01b17905260078801805460018101825560009182529190200180546001600160a01b038c166001600160a01b031990911617905590505b81866001015410156108e95760405162461bcd60e51b8152602060048201526014602482015273496e73756666696369656e742062616c616e636560601b60448201526064016105ad565b818660010160008282546108fd9190611d60565b925050819055506000856001600160a01b0316838360405161091f9190611eb9565b60006040518083038185875af1925050503d806000811461095c576040519150601f19603f3d011682016040523d82523d6000602084013e610961565b606091505b50509050806109b25760405162461bcd60e51b815260206004820152601d60248201527f43616c6c20746f206368696c6420636f6e7472616374206661696c656400000060448201526064016105ad565b50505050505050505050565b60006109c982611318565b5091505060006109d8336112c3565b90506000805b8551811015610b3c576000846001600160a01b0316634e3c4f2233898581518110610a0b57610a0b611d1b565b60200260200101516040518363ffffffff1660e01b8152600401610a459291906001600160a01b0392831681529116602082015260400190565b6060604051808303816000875af1158015610a64573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610a889190611ed5565b505090508083610a989190611f03565b9250846001600160a01b0316636c79158d33898581518110610abc57610abc611d1b565b60200260200101516040518363ffffffff1660e01b8152600401610af69291906001600160a01b0392831681529116602082015260400190565b600060405180830381600087803b158015610b1057600080fd5b505af1158015610b24573d6000803e3d6000fd5b50505050508080610b3490611d47565b9150506109de565b5080826001016000828254610b519190611f03565b90915550505050505050565b6000610b6833611433565b9050610b7381611467565b610b9257604051637d2d536b60e01b81523360048201526024016105ad565b6000610b9d336112c3565b905060005b6006820154811015610c5a576007546006830180546001600160a01b0390921691639721672591339185908110610bdb57610bdb611d1b565b60009182526020909120015460405160e084901b6001600160e01b03191681526001600160a01b03928316600482015291166024820152604401600060405180830381600087803b158015610c2f57600080fd5b505af1158015610c43573d6000803e3d6000fd5b505050508080610c5290611d47565b915050610ba2565b5060005b6007820154811015610d16576006546007830180546001600160a01b0390921691639721672591339185908110610c9757610c97611d1b565b60009182526020909120015460405160e084901b6001600160e01b03191681526001600160a01b03928316600482015291166024820152604401600060405180830381600087803b158015610ceb57600080fd5b505af1158015610cff573d6000803e3d6000fd5b505050508080610d0e90611d47565b915050610c5e565b50610d22600383611474565b50600082815260056020526040812080546001600160a01b03191681556001810182905560028101829055600381018290556004810182905590610d6a600583016000611786565b610d786006830160006117c0565b610d866007830160006117c0565b50505050565b610d94611480565b610d9e60006114da565b565b6000806000610dae33611433565b9050610db981611467565b15610dd95760405163cde58aa160e01b81523360048201526024016105ad565b610de6813387348861152a565b5034946000945092505050565b6000610dfe33611433565b9050610e0981611467565b610e2857604051637d2d536b60e01b81523360048201526024016105ad565b6000610e33336112c3565b905034816001016000828254610e499190611f03565b9250508190555034816002016000828254610e649190611f03565b90915550505050565b600054600160a01b900460ff1615610ed25760405162461bcd60e51b815260206004820152602260248201527f496e697469616c697a61626c653a20616c726561647920696e697469616c697a604482015261195960f21b60648201526084016105ad565b6000805460ff60a01b1916600160a01b179055610eee816114da565b50600180546001600160a01b039384166001600160a01b031991821681179092556002805493909416928116831790935560068054841690921790915560078054909216179055565b6002546001600160a01b0316331480610f5a57506001546001600160a01b031633145b610fc25760405162461bcd60e51b815260206004820152603360248201527f43616c6c6572206973206e6f74207468652066696e652074756e696e67206f72604482015272081a5b99995c995b98d94818dbdb9d1c9858dd606a1b60648201526084016105ad565b6000610fcd836112c3565b90508181600101548260020154610fe49190611d60565b10156110295760405162461bcd60e51b8152602060048201526014602482015273496e73756666696369656e742062616c616e636560601b60448201526064016105ad565b8181600201600082825461103d9190611d60565b9091555050505050565b61104f611480565b6001600160a01b0381166110b45760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b60648201526084016105ad565b6110bd816114da565b50565b6110c861173a565b6110d1826112c3565b6040805160e08101825282546001600160a01b031681526001830154602082015260028084015482840152825180840193849052919392606085019291600385019182845b815481526020019060010190808311611116575050505050815260200160058201805461114290611ce1565b80601f016020809104026020016040519081016040528092919081815260200182805461116e90611ce1565b80156111bb5780601f10611190576101008083540402835291602001916111bb565b820191906000526020600020905b81548152906001019060200180831161119e57829003601f168201915b505050505081526020016006820180548060200260200160405190810160405280929190818152602001828054801561121d57602002820191906000526020600020905b81546001600160a01b031681526001909101906020018083116111ff575b505050505081526020016007820180548060200260200160405190810160405280929190818152602001828054801561127f57602002820191906000526020600020905b81546001600160a01b03168152600190910190602001808311611261575b5050505050815250509050919050565b600061129b6003611594565b905090565b6000806112ae60038461159e565b60009081526005602052604090209392505050565b6000806112cf83611433565b60008181526005602052604090209091506112e982611467565b61131157604051637d2d536b60e01b81526001600160a01b03851660048201526024016105ad565b9392505050565b6000806000808460405160200161132f9190611eb9565b6040516020818303038152906040528051906020012090507f2a52b6261f3850b89541ab4444869004fe552e50532808641800076f8e9ec465810361138d5750506001546007546001600160a01b0391821693501690506000611412565b7f37f0d1f2303720bab95e3c739b15188d8c19fade32eb63f80ef3d06b64daa9d281036113d35750506002546006546001600160a01b0391821693501690506001611412565b60405162461bcd60e51b8152602060048201526014602482015273496e76616c69642073657276696365207479706560601b60448201526064016105ad565b9193909250565b6000818310611428578161142a565b825b90505b92915050565b604080516001600160a01b038316602082015260009101604051602081830303815290604052805190602001209050919050565b600061142d6003836115aa565b600061142a83836115c2565b6000546001600160a01b03163314610d9e5760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657260448201526064016105ad565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b600085815260056020526040902060018101839055600280820184905581546001600160a01b0319166001600160a01b03871617825561157090600383019086906117de565b506005810161157f8382611f64565b5061158b6003876116b5565b50505050505050565b600061142d825490565b600061142a83836116c1565b6000818152600183016020526040812054151561142a565b600081815260018301602052604081205480156116ab5760006115e6600183611d60565b85549091506000906115fa90600190611d60565b905081811461165f57600086600001828154811061161a5761161a611d1b565b906000526020600020015490508087600001848154811061163d5761163d611d1b565b6000918252602080832090910192909255918252600188019052604090208390555b855486908061167057611670612024565b60019003818190600052602060002001600090559055856001016000868152602001908152602001600020600090556001935050505061142d565b600091505061142d565b600061142a83836116eb565b60008260000182815481106116d8576116d8611d1b565b9060005260206000200154905092915050565b60008181526001830160205260408120546117325750815460018181018455600084815260208082209093018490558454848252828601909352604090209190915561142d565b50600061142d565b6040518060e0016040528060006001600160a01b03168152602001600081526020016000815260200161176b61181c565b81526020016060815260200160608152602001606081525090565b50805461179290611ce1565b6000825580601f106117a2575050565b601f0160209004906000526020600020908101906110bd919061183a565b50805460008255906000526020600020908101906110bd919061183a565b826002810192821561180c579160200282015b8281111561180c5782358255916020019190600101906117f1565b5061181892915061183a565b5090565b60405180604001604052806002906020820280368337509192915050565b5b80821115611818576000815560010161183b565b60005b8381101561186a578181015183820152602001611852565b50506000910152565b6000815180845261188b81602086016020860161184f565b601f01601f19169290920160200192915050565b600081518084526020808501945080840160005b838110156118d85781516001600160a01b0316875295820195908201906001016118b3565b509495945050505050565b600061010060018060a01b038351168452602080840151818601526040840151604086015260608401516060860160005b600281101561193157825182529183019190830190600101611914565b5050505060808301518160a086015261194c82860182611873565b91505060a083015184820360c0860152611966828261189f565b91505060c083015184820360e0860152611980828261189f565b95945050505050565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b828110156119de57603f198886030184526119cc8583516118e3565b945092850192908501906001016119b0565b5092979650505050505050565b6000602082840312156119fd57600080fd5b5035919050565b80356001600160a01b0381168114611a1b57600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f1916810167ffffffffffffffff81118282101715611a5f57611a5f611a20565b604052919050565b600082601f830112611a7857600080fd5b813567ffffffffffffffff811115611a9257611a92611a20565b611aa5601f8201601f1916602001611a36565b818152846020838601011115611aba57600080fd5b816020850160208301376000918101602001919091529392505050565b600080600060608486031215611aec57600080fd5b611af584611a04565b9250602084013567ffffffffffffffff811115611b1157600080fd5b611b1d86828701611a67565b925050604084013590509250925092565b60008060408385031215611b4157600080fd5b823567ffffffffffffffff80821115611b5957600080fd5b818501915085601f830112611b6d57600080fd5b8135602082821115611b8157611b81611a20565b8160051b611b90828201611a36565b928352848101820192828101908a851115611baa57600080fd5b958301955b84871015611bcf57611bc087611a04565b82529583019590830190611baf565b9750505086013592505080821115611be657600080fd5b50611bf385828601611a67565b9150509250929050565b60008060608385031215611c1057600080fd5b6040830184811115611c2157600080fd5b8392503567ffffffffffffffff811115611c3a57600080fd5b611bf385828601611a67565b600080600060608486031215611c5b57600080fd5b611c6484611a04565b9250611c7260208501611a04565b9150611c8060408501611a04565b90509250925092565b60008060408385031215611c9c57600080fd5b611ca583611a04565b946020939093013593505050565b600060208284031215611cc557600080fd5b61142a82611a04565b60208152600061142a60208301846118e3565b600181811c90821680611cf557607f821691505b602082108103611d1557634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b600060018201611d5957611d59611d31565b5060010190565b8181038181111561142d5761142d611d31565b600060208284031215611d8557600080fd5b8151801515811461131157600080fd5b600060208284031215611da757600080fd5b5051919050565b60008154611dbb81611ce1565b808552602060018381168015611dd85760018114611df257611e20565b60ff1985168884015283151560051b880183019550611e20565b866000528260002060005b85811015611e185781548a8201860152908301908401611dfd565b890184019650505b505050505092915050565b6001600160a01b0385811682528416602080830191909152600090604083019085835b6002811015611e6b57815484529282019260019182019101611e4e565b5050505060a06080830152611e8360a0830184611dae565b9695505050505050565b6001600160a01b0384811682528316602082015260606040820181905260009061198090830184611dae565b60008251611ecb81846020870161184f565b9190910192915050565b600080600060608486031215611eea57600080fd5b8351925060208401519150604084015190509250925092565b8082018082111561142d5761142d611d31565b601f82111561061757600081815260208120601f850160051c81016020861015611f3d5750805b601f850160051c820191505b81811015611f5c57828155600101611f49565b505050505050565b815167ffffffffffffffff811115611f7e57611f7e611a20565b611f9281611f8c8454611ce1565b84611f16565b602080601f831160018114611fc75760008415611faf5750858301515b600019600386901b1c1916600185901b178555611f5c565b600085815260208120601f198616915b82811015611ff657888601518255948401946001909101908401611fd7565b50858210156120145787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b634e487b7160e01b600052603160045260246000fdfea2646970667358221220c3fbf8cb527de392c00c101a551944befabfff3385d43391c5ff160b5c013d5364736f6c63430008140033';
const isSuperArgs = (xs) => xs.length > 1;
class LedgerManager__factory extends ContractFactory {
    constructor(...args) {
        if (isSuperArgs(args)) {
            super(...args);
        }
        else {
            super(_abi, _bytecode, args[0]);
        }
    }
    getDeployTransaction(overrides) {
        return super.getDeployTransaction(overrides || {});
    }
    deploy(overrides) {
        return super.deploy(overrides || {});
    }
    connect(runner) {
        return super.connect(runner);
    }
    static bytecode = _bytecode;
    static abi = _abi;
    static createInterface() {
        return new Interface(_abi);
    }
    static connect(address, runner) {
        return new Contract(address, _abi, runner);
    }
}

class LedgerManagerContract {
    ledger;
    signer;
    _userAddress;
    _gasPrice;
    constructor(signer, contractAddress, userAddress, gasPrice) {
        this.ledger = LedgerManager__factory.connect(contractAddress, signer);
        this.signer = signer;
        this._userAddress = userAddress;
        this._gasPrice = gasPrice;
    }
    async addLedger(signer, balance, settleSignerEncryptedPrivateKey, gasPrice) {
        try {
            const txOptions = { value: balance };
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            const tx = await this.ledger.addLedger(signer, settleSignerEncryptedPrivateKey, txOptions);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throw error;
        }
    }
    async listLedger() {
        try {
            const ledgers = await this.ledger.getAllLedgers();
            return ledgers;
        }
        catch (error) {
            throw error;
        }
    }
    async getLedger() {
        try {
            const user = this.getUserAddress();
            const ledger = await this.ledger.getLedger(user);
            return ledger;
        }
        catch (error) {
            throw error;
        }
    }
    async depositFund(balance, gasPrice) {
        try {
            const txOptions = { value: balance };
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            const tx = await this.ledger.depositFund(txOptions);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throw error;
        }
    }
    async refund(amount, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            const tx = await this.ledger.refund(amount, txOptions);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throw error;
        }
    }
    async transferFund(provider, serviceTypeStr, amount, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            const tx = await this.ledger.transferFund(provider, serviceTypeStr, amount, txOptions);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throw error;
        }
    }
    async retrieveFund(providers, serviceTypeStr, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            const tx = await this.ledger.retrieveFund(providers, serviceTypeStr, txOptions);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throw error;
        }
    }
    async deleteLedger(gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            const tx = await this.ledger.deleteLedger(txOptions);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throw error;
        }
    }
    getUserAddress() {
        return this._userAddress;
    }
}

class LedgerBroker {
    ledger;
    signer;
    ledgerCA;
    inferenceCA;
    fineTuningCA;
    gasPrice;
    constructor(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice) {
        this.signer = signer;
        this.ledgerCA = ledgerCA;
        this.inferenceCA = inferenceCA;
        this.fineTuningCA = fineTuningCA;
        this.gasPrice = gasPrice;
    }
    async initialize() {
        let userAddress;
        try {
            userAddress = await this.signer.getAddress();
        }
        catch (error) {
            throw error;
        }
        const ledgerContract = new LedgerManagerContract(this.signer, this.ledgerCA, userAddress, this.gasPrice);
        const inferenceContract = new InferenceServingContract(this.signer, this.inferenceCA, userAddress);
        let fineTuningContract;
        if (this.signer instanceof Wallet) {
            fineTuningContract = new FineTuningServingContract(this.signer, this.fineTuningCA, userAddress);
        }
        const metadata = new Metadata();
        const cache = new Cache();
        this.ledger = new LedgerProcessor(metadata, cache, ledgerContract, inferenceContract, fineTuningContract);
    }
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
    addLedger = async (balance, gasPrice) => {
        try {
            return await this.ledger.addLedger(balance, gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * Retrieves the ledger information for current wallet address.
     *
     * @returns A promise that resolves to the ledger information.
     *
     * @throws Will throw an error if the ledger retrieval process fails.
     */
    getLedger = async () => {
        try {
            return await this.ledger.getLedgerWithDetail();
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * Deposits a specified amount of funds into Ledger corresponding to the current wallet address.
     *
     * @param {string} amount - The amount of funds to be deposited. Units are in A0GI.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deposit fails.
     */
    depositFund = async (amount, gasPrice) => {
        try {
            return await this.ledger.depositFund(amount, gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
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
     * @note The amount should be a positive number.
     */
    refund = async (amount, gasPrice) => {
        try {
            return await this.ledger.refund(amount, gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * Transfers a specified amount of funds to a provider for a given service type.
     *
     * @param provider - The address of the provider to whom the funds are being transferred.
     * @param serviceTypeStr - The type of service for which the funds are being transferred.
     *                         It can be either 'inference' or 'fine-tuning'.
     * @param amount - The amount of funds to be transferred. Units are in A0GI.
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                            the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @returns A promise that resolves with the result of the fund transfer operation.
     * @throws Will throw an error if the fund transfer operation fails.
     */
    transferFund = async (provider, serviceTypeStr, amount, gasPrice) => {
        try {
            return await this.ledger.transferFund(provider, serviceTypeStr, amount, gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
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
    retrieveFund = async (serviceTypeStr, gasPrice) => {
        try {
            return await this.ledger.retrieveFund(serviceTypeStr, gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
    /**
     * Deletes the ledger corresponding to the current wallet address.
     *
     * @param {number} gasPrice - The gas price to be used for the transaction. If not provided,
     *                           the default/auto-generated gas price will be used. Units are in neuron.
     *
     * @throws  An error if the deletion fails.
     */
    deleteLedger = async (gasPrice) => {
        try {
            return await this.ledger.deleteLedger(gasPrice);
        }
        catch (error) {
            throw error;
        }
    };
}
/**
 * createLedgerBroker is used to initialize LedgerBroker
 *
 * @param signer - Signer from ethers.js.
 * @param contractAddress - Ledger contract address, use default address if not provided.
 *
 * @returns broker instance.
 *
 * @throws An error if the broker cannot be initialized.
 */
async function createLedgerBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice) {
    const broker = new LedgerBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice);
    try {
        await broker.initialize();
        return broker;
    }
    catch (error) {
        throw error;
    }
}

class ZGComputeNetworkBroker {
    ledger;
    inference;
    fineTuning;
    constructor(ledger, inferenceBroker, fineTuningBroker) {
        this.ledger = ledger;
        this.inference = inferenceBroker;
        this.fineTuning = fineTuningBroker;
    }
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
async function createZGComputeNetworkBroker(signer, ledgerCA = '0x0c0D02e4E849C711B2388A829366B5bf3f9c53e7', inferenceCA = '0x46e8a02d609CaEfC1747197da1F38272d5E46c77', fineTuningCA = '0x35A5d96569867fE6534D823268337888229533dE', gasPrice) {
    try {
        const ledger = await createLedgerBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice);
        const inferenceBroker = await createInferenceBroker(signer, inferenceCA, ledger);
        let fineTuningBroker;
        if (signer instanceof Wallet) {
            fineTuningBroker = await createFineTuningBroker(signer, fineTuningCA, ledger, gasPrice);
        }
        const broker = new ZGComputeNetworkBroker(ledger, inferenceBroker, fineTuningBroker);
        return broker;
    }
    catch (error) {
        throw error;
    }
}

export { FineTuningBroker, AccountProcessor as InferenceAccountProcessor, InferenceBroker, ModelProcessor$1 as InferenceModelProcessor, RequestProcessor as InferenceRequestProcessor, ResponseProcessor as InferenceResponseProcessor, Verifier as InferenceVerifier, LedgerBroker, ZGComputeNetworkBroker, createFineTuningBroker, createInferenceBroker, createLedgerBroker, createZGComputeNetworkBroker };
//# sourceMappingURL=index.mjs.map

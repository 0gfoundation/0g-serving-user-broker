import { ethers, ContractFactory, Interface, Contract, ZeroAddress, keccak256, toUtf8Bytes, Wallet } from 'ethers';
import * as fs$1 from 'fs/promises';
import { spawn as spawn$1 } from 'child_process';
import * as path$1 from 'path';
import path__default from 'path';

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
        const utf8Encoder = new TextEncoder();
        const encoded = utf8Encoder.encode(content);
        return encoded.length;
    }
    async getOutputCount(content) {
        if (!content) {
            return 0;
        }
        const utf8Encoder = new TextEncoder();
        const encoded = utf8Encoder.encode(content);
        return encoded.length;
    }
}

var dist = {};

var utils$5 = {};

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
	if (hasRequiredUtils$3) return utils$5;
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
		
	} (utils$5));
	return utils$5;
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

var utils$4 = {};

var elliptic = {};

var webcrypto = {};

var crypto$2 = {};

var hasRequiredCrypto$1;

function requireCrypto$1 () {
	if (hasRequiredCrypto$1) return crypto$2;
	hasRequiredCrypto$1 = 1;
	Object.defineProperty(crypto$2, "__esModule", { value: true });
	crypto$2.crypto = void 0;
	crypto$2.crypto = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
	
	return crypto$2;
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

var utils$3 = {};

var crypto$1 = {};

var hasRequiredCrypto;

function requireCrypto () {
	if (hasRequiredCrypto) return crypto$1;
	hasRequiredCrypto = 1;
	Object.defineProperty(crypto$1, "__esModule", { value: true });
	crypto$1.crypto = void 0;
	crypto$1.crypto = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
	
	return crypto$1;
}

var hasRequiredUtils$2;

function requireUtils$2 () {
	if (hasRequiredUtils$2) return utils$3;
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
		
	} (utils$3));
	return utils$3;
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

var utils$2 = {};

var hasRequiredUtils$1;

function requireUtils$1 () {
	if (hasRequiredUtils$1) return utils$2;
	hasRequiredUtils$1 = 1;
	/**
	 * Hex, bytes and number utilities.
	 * @module
	 */
	/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
	Object.defineProperty(utils$2, "__esModule", { value: true });
	utils$2.notImplemented = utils$2.bitMask = void 0;
	utils$2.isBytes = isBytes;
	utils$2.abytes = abytes;
	utils$2.abool = abool;
	utils$2.bytesToHex = bytesToHex;
	utils$2.numberToHexUnpadded = numberToHexUnpadded;
	utils$2.hexToNumber = hexToNumber;
	utils$2.hexToBytes = hexToBytes;
	utils$2.bytesToNumberBE = bytesToNumberBE;
	utils$2.bytesToNumberLE = bytesToNumberLE;
	utils$2.numberToBytesBE = numberToBytesBE;
	utils$2.numberToBytesLE = numberToBytesLE;
	utils$2.numberToVarBytesBE = numberToVarBytesBE;
	utils$2.ensureBytes = ensureBytes;
	utils$2.concatBytes = concatBytes;
	utils$2.equalBytes = equalBytes;
	utils$2.utf8ToBytes = utf8ToBytes;
	utils$2.inRange = inRange;
	utils$2.aInRange = aInRange;
	utils$2.bitLen = bitLen;
	utils$2.bitGet = bitGet;
	utils$2.bitSet = bitSet;
	utils$2.createHmacDrbg = createHmacDrbg;
	utils$2.validateObject = validateObject;
	utils$2.memoized = memoized;
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
	utils$2.bitMask = bitMask;
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
	utils$2.notImplemented = notImplemented;
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
	
	return utils$2;
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

var noble$1 = {};

var aes = {};

var _polyval = {};

var hasRequired_polyval;

function require_polyval () {
	if (hasRequired_polyval) return _polyval;
	hasRequired_polyval = 1;
	Object.defineProperty(_polyval, "__esModule", { value: true });
	_polyval.polyval = _polyval.ghash = void 0;
	_polyval._toGHASHKey = _toGHASHKey;
	/**
	 * GHash from AES-GCM and its little-endian "mirror image" Polyval from AES-SIV.
	 *
	 * Implemented in terms of GHash with conversion function for keys
	 * GCM GHASH from
	 * [NIST SP800-38d](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf),
	 * SIV from
	 * [RFC 8452](https://datatracker.ietf.org/doc/html/rfc8452).
	 *
	 * GHASH   modulo: x^128 + x^7   + x^2   + x     + 1
	 * POLYVAL modulo: x^128 + x^127 + x^126 + x^121 + 1
	 *
	 * @module
	 */
	const _assert_js_1 = /*@__PURE__*/ require_assert$1();
	const utils_js_1 = /*@__PURE__*/ requireUtils$3();
	const BLOCK_SIZE = 16;
	// TODO: rewrite
	// temporary padding buffer
	const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
	const ZEROS32 = (0, utils_js_1.u32)(ZEROS16);
	const POLY = 0xe1; // v = 2*v % POLY
	// v = 2*v % POLY
	// NOTE: because x + x = 0 (add/sub is same), mul2(x) != x+x
	// We can multiply any number using montgomery ladder and this function (works as double, add is simple xor)
	const mul2 = (s0, s1, s2, s3) => {
	    const hiBit = s3 & 1;
	    return {
	        s3: (s2 << 31) | (s3 >>> 1),
	        s2: (s1 << 31) | (s2 >>> 1),
	        s1: (s0 << 31) | (s1 >>> 1),
	        s0: (s0 >>> 1) ^ ((POLY << 24) & -(hiBit & 1)), // reduce % poly
	    };
	};
	const swapLE = (n) => (((n >>> 0) & 0xff) << 24) |
	    (((n >>> 8) & 0xff) << 16) |
	    (((n >>> 16) & 0xff) << 8) |
	    ((n >>> 24) & 0xff) |
	    0;
	/**
	 * `mulX_POLYVAL(ByteReverse(H))` from spec
	 * @param k mutated in place
	 */
	function _toGHASHKey(k) {
	    k.reverse();
	    const hiBit = k[15] & 1;
	    // k >>= 1
	    let carry = 0;
	    for (let i = 0; i < k.length; i++) {
	        const t = k[i];
	        k[i] = (t >>> 1) | carry;
	        carry = (t & 1) << 7;
	    }
	    k[0] ^= -hiBit & 0xe1; // if (hiBit) n ^= 0xe1000000000000000000000000000000;
	    return k;
	}
	const estimateWindow = (bytes) => {
	    if (bytes > 64 * 1024)
	        return 8;
	    if (bytes > 1024)
	        return 4;
	    return 2;
	};
	class GHASH {
	    // We select bits per window adaptively based on expectedLength
	    constructor(key, expectedLength) {
	        this.blockLen = BLOCK_SIZE;
	        this.outputLen = BLOCK_SIZE;
	        this.s0 = 0;
	        this.s1 = 0;
	        this.s2 = 0;
	        this.s3 = 0;
	        this.finished = false;
	        key = (0, utils_js_1.toBytes)(key);
	        (0, _assert_js_1.abytes)(key, 16);
	        const kView = (0, utils_js_1.createView)(key);
	        let k0 = kView.getUint32(0, false);
	        let k1 = kView.getUint32(4, false);
	        let k2 = kView.getUint32(8, false);
	        let k3 = kView.getUint32(12, false);
	        // generate table of doubled keys (half of montgomery ladder)
	        const doubles = [];
	        for (let i = 0; i < 128; i++) {
	            doubles.push({ s0: swapLE(k0), s1: swapLE(k1), s2: swapLE(k2), s3: swapLE(k3) });
	            ({ s0: k0, s1: k1, s2: k2, s3: k3 } = mul2(k0, k1, k2, k3));
	        }
	        const W = estimateWindow(expectedLength || 1024);
	        if (![1, 2, 4, 8].includes(W))
	            throw new Error('ghash: invalid window size, expected 2, 4 or 8');
	        this.W = W;
	        const bits = 128; // always 128 bits;
	        const windows = bits / W;
	        const windowSize = (this.windowSize = 2 ** W);
	        const items = [];
	        // Create precompute table for window of W bits
	        for (let w = 0; w < windows; w++) {
	            // truth table: 00, 01, 10, 11
	            for (let byte = 0; byte < windowSize; byte++) {
	                // prettier-ignore
	                let s0 = 0, s1 = 0, s2 = 0, s3 = 0;
	                for (let j = 0; j < W; j++) {
	                    const bit = (byte >>> (W - j - 1)) & 1;
	                    if (!bit)
	                        continue;
	                    const { s0: d0, s1: d1, s2: d2, s3: d3 } = doubles[W * w + j];
	                    (s0 ^= d0), (s1 ^= d1), (s2 ^= d2), (s3 ^= d3);
	                }
	                items.push({ s0, s1, s2, s3 });
	            }
	        }
	        this.t = items;
	    }
	    _updateBlock(s0, s1, s2, s3) {
	        (s0 ^= this.s0), (s1 ^= this.s1), (s2 ^= this.s2), (s3 ^= this.s3);
	        const { W, t, windowSize } = this;
	        // prettier-ignore
	        let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
	        const mask = (1 << W) - 1; // 2**W will kill performance.
	        let w = 0;
	        for (const num of [s0, s1, s2, s3]) {
	            for (let bytePos = 0; bytePos < 4; bytePos++) {
	                const byte = (num >>> (8 * bytePos)) & 0xff;
	                for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
	                    const bit = (byte >>> (W * bitPos)) & mask;
	                    const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit];
	                    (o0 ^= e0), (o1 ^= e1), (o2 ^= e2), (o3 ^= e3);
	                    w += 1;
	                }
	            }
	        }
	        this.s0 = o0;
	        this.s1 = o1;
	        this.s2 = o2;
	        this.s3 = o3;
	    }
	    update(data) {
	        data = (0, utils_js_1.toBytes)(data);
	        (0, _assert_js_1.aexists)(this);
	        const b32 = (0, utils_js_1.u32)(data);
	        const blocks = Math.floor(data.length / BLOCK_SIZE);
	        const left = data.length % BLOCK_SIZE;
	        for (let i = 0; i < blocks; i++) {
	            this._updateBlock(b32[i * 4 + 0], b32[i * 4 + 1], b32[i * 4 + 2], b32[i * 4 + 3]);
	        }
	        if (left) {
	            ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
	            this._updateBlock(ZEROS32[0], ZEROS32[1], ZEROS32[2], ZEROS32[3]);
	            (0, utils_js_1.clean)(ZEROS32); // clean tmp buffer
	        }
	        return this;
	    }
	    destroy() {
	        const { t } = this;
	        // clean precompute table
	        for (const elm of t) {
	            (elm.s0 = 0), (elm.s1 = 0), (elm.s2 = 0), (elm.s3 = 0);
	        }
	    }
	    digestInto(out) {
	        (0, _assert_js_1.aexists)(this);
	        (0, _assert_js_1.aoutput)(out, this);
	        this.finished = true;
	        const { s0, s1, s2, s3 } = this;
	        const o32 = (0, utils_js_1.u32)(out);
	        o32[0] = s0;
	        o32[1] = s1;
	        o32[2] = s2;
	        o32[3] = s3;
	        return out;
	    }
	    digest() {
	        const res = new Uint8Array(BLOCK_SIZE);
	        this.digestInto(res);
	        this.destroy();
	        return res;
	    }
	}
	class Polyval extends GHASH {
	    constructor(key, expectedLength) {
	        key = (0, utils_js_1.toBytes)(key);
	        const ghKey = _toGHASHKey((0, utils_js_1.copyBytes)(key));
	        super(ghKey, expectedLength);
	        (0, utils_js_1.clean)(ghKey);
	    }
	    update(data) {
	        data = (0, utils_js_1.toBytes)(data);
	        (0, _assert_js_1.aexists)(this);
	        const b32 = (0, utils_js_1.u32)(data);
	        const left = data.length % BLOCK_SIZE;
	        const blocks = Math.floor(data.length / BLOCK_SIZE);
	        for (let i = 0; i < blocks; i++) {
	            this._updateBlock(swapLE(b32[i * 4 + 3]), swapLE(b32[i * 4 + 2]), swapLE(b32[i * 4 + 1]), swapLE(b32[i * 4 + 0]));
	        }
	        if (left) {
	            ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
	            this._updateBlock(swapLE(ZEROS32[3]), swapLE(ZEROS32[2]), swapLE(ZEROS32[1]), swapLE(ZEROS32[0]));
	            (0, utils_js_1.clean)(ZEROS32);
	        }
	        return this;
	    }
	    digestInto(out) {
	        (0, _assert_js_1.aexists)(this);
	        (0, _assert_js_1.aoutput)(out, this);
	        this.finished = true;
	        // tmp ugly hack
	        const { s0, s1, s2, s3 } = this;
	        const o32 = (0, utils_js_1.u32)(out);
	        o32[0] = s0;
	        o32[1] = s1;
	        o32[2] = s2;
	        o32[3] = s3;
	        return out.reverse();
	    }
	}
	function wrapConstructorWithKey(hashCons) {
	    const hashC = (msg, key) => hashCons(key, msg.length).update((0, utils_js_1.toBytes)(msg)).digest();
	    const tmp = hashCons(new Uint8Array(16), 0);
	    hashC.outputLen = tmp.outputLen;
	    hashC.blockLen = tmp.blockLen;
	    hashC.create = (key, expectedLength) => hashCons(key, expectedLength);
	    return hashC;
	}
	/** GHash MAC for AES-GCM. */
	_polyval.ghash = wrapConstructorWithKey((key, expectedLength) => new GHASH(key, expectedLength));
	/** Polyval MAC for AES-SIV. */
	_polyval.polyval = wrapConstructorWithKey((key, expectedLength) => new Polyval(key, expectedLength));
	
	return _polyval;
}

var hasRequiredAes;

function requireAes () {
	if (hasRequiredAes) return aes;
	hasRequiredAes = 1;
	Object.defineProperty(aes, "__esModule", { value: true });
	aes.unsafe = aes.aeskwp = aes.aeskw = aes.siv = aes.gcm = aes.cfb = aes.cbc = aes.ecb = aes.ctr = void 0;
	/**
	 * [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
	 * a.k.a. Advanced Encryption Standard
	 * is a variant of Rijndael block cipher, standardized by NIST in 2001.
	 * We provide the fastest available pure JS implementation.
	 *
	 * Data is split into 128-bit blocks. Encrypted in 10/12/14 rounds (128/192/256 bits). In every round:
	 * 1. **S-box**, table substitution
	 * 2. **Shift rows**, cyclic shift left of all rows of data array
	 * 3. **Mix columns**, multiplying every column by fixed polynomial
	 * 4. **Add round key**, round_key xor i-th column of array
	 *
	 * Check out [FIPS-197](https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf)
	 * and [original proposal](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf)
	 * @module
	 */
	const _assert_js_1 = /*@__PURE__*/ require_assert$1();
	const _polyval_js_1 = /*@__PURE__*/ require_polyval();
	const utils_js_1 = /*@__PURE__*/ requireUtils$3();
	const BLOCK_SIZE = 16;
	const BLOCK_SIZE32 = 4;
	const EMPTY_BLOCK = /* @__PURE__ */ new Uint8Array(BLOCK_SIZE);
	const POLY = 0x11b; // 1 + x + x**3 + x**4 + x**8
	// TODO: remove multiplication, binary ops only
	function mul2(n) {
	    return (n << 1) ^ (POLY & -(n >> 7));
	}
	function mul(a, b) {
	    let res = 0;
	    for (; b > 0; b >>= 1) {
	        // Montgomery ladder
	        res ^= a & -(b & 1); // if (b&1) res ^=a (but const-time).
	        a = mul2(a); // a = 2*a
	    }
	    return res;
	}
	// AES S-box is generated using finite field inversion,
	// an affine transform, and xor of a constant 0x63.
	const sbox = /* @__PURE__ */ (() => {
	    const t = new Uint8Array(256);
	    for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x))
	        t[i] = x;
	    const box = new Uint8Array(256);
	    box[0] = 0x63; // first elm
	    for (let i = 0; i < 255; i++) {
	        let x = t[255 - i];
	        x |= x << 8;
	        box[t[i]] = (x ^ (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7) ^ 0x63) & 0xff;
	    }
	    (0, utils_js_1.clean)(t);
	    return box;
	})();
	// Inverted S-box
	const invSbox = /* @__PURE__ */ sbox.map((_, j) => sbox.indexOf(j));
	// Rotate u32 by 8
	const rotr32_8 = (n) => (n << 24) | (n >>> 8);
	const rotl32_8 = (n) => (n << 8) | (n >>> 24);
	// The byte swap operation for uint32 (LE<->BE)
	const byteSwap = (word) => ((word << 24) & 0xff000000) |
	    ((word << 8) & 0xff0000) |
	    ((word >>> 8) & 0xff00) |
	    ((word >>> 24) & 0xff);
	// T-table is optimization suggested in 5.2 of original proposal (missed from FIPS-197). Changes:
	// - LE instead of BE
	// - bigger tables: T0 and T1 are merged into T01 table and T2 & T3 into T23;
	//   so index is u16, instead of u8. This speeds up things, unexpectedly
	function genTtable(sbox, fn) {
	    if (sbox.length !== 256)
	        throw new Error('Wrong sbox length');
	    const T0 = new Uint32Array(256).map((_, j) => fn(sbox[j]));
	    const T1 = T0.map(rotl32_8);
	    const T2 = T1.map(rotl32_8);
	    const T3 = T2.map(rotl32_8);
	    const T01 = new Uint32Array(256 * 256);
	    const T23 = new Uint32Array(256 * 256);
	    const sbox2 = new Uint16Array(256 * 256);
	    for (let i = 0; i < 256; i++) {
	        for (let j = 0; j < 256; j++) {
	            const idx = i * 256 + j;
	            T01[idx] = T0[i] ^ T1[j];
	            T23[idx] = T2[i] ^ T3[j];
	            sbox2[idx] = (sbox[i] << 8) | sbox[j];
	        }
	    }
	    return { sbox, sbox2, T0, T1, T2, T3, T01, T23 };
	}
	const tableEncoding = /* @__PURE__ */ genTtable(sbox, (s) => (mul(s, 3) << 24) | (s << 16) | (s << 8) | mul(s, 2));
	const tableDecoding = /* @__PURE__ */ genTtable(invSbox, (s) => (mul(s, 11) << 24) | (mul(s, 13) << 16) | (mul(s, 9) << 8) | mul(s, 14));
	const xPowers = /* @__PURE__ */ (() => {
	    const p = new Uint8Array(16);
	    for (let i = 0, x = 1; i < 16; i++, x = mul2(x))
	        p[i] = x;
	    return p;
	})();
	/** Key expansion used in CTR. */
	function expandKeyLE(key) {
	    (0, _assert_js_1.abytes)(key);
	    const len = key.length;
	    if (![16, 24, 32].includes(len))
	        throw new Error('aes: invalid key size, should be 16, 24 or 32, got ' + len);
	    const { sbox2 } = tableEncoding;
	    const toClean = [];
	    if (!(0, utils_js_1.isAligned32)(key))
	        toClean.push((key = (0, utils_js_1.copyBytes)(key)));
	    const k32 = (0, utils_js_1.u32)(key);
	    const Nk = k32.length;
	    const subByte = (n) => applySbox(sbox2, n, n, n, n);
	    const xk = new Uint32Array(len + 28); // expanded key
	    xk.set(k32);
	    // 4.3.1 Key expansion
	    for (let i = Nk; i < xk.length; i++) {
	        let t = xk[i - 1];
	        if (i % Nk === 0)
	            t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1];
	        else if (Nk > 6 && i % Nk === 4)
	            t = subByte(t);
	        xk[i] = xk[i - Nk] ^ t;
	    }
	    (0, utils_js_1.clean)(...toClean);
	    return xk;
	}
	function expandKeyDecLE(key) {
	    const encKey = expandKeyLE(key);
	    const xk = encKey.slice();
	    const Nk = encKey.length;
	    const { sbox2 } = tableEncoding;
	    const { T0, T1, T2, T3 } = tableDecoding;
	    // Inverse key by chunks of 4 (rounds)
	    for (let i = 0; i < Nk; i += 4) {
	        for (let j = 0; j < 4; j++)
	            xk[i + j] = encKey[Nk - i - 4 + j];
	    }
	    (0, utils_js_1.clean)(encKey);
	    // apply InvMixColumn except first & last round
	    for (let i = 4; i < Nk - 4; i++) {
	        const x = xk[i];
	        const w = applySbox(sbox2, x, x, x, x);
	        xk[i] = T0[w & 0xff] ^ T1[(w >>> 8) & 0xff] ^ T2[(w >>> 16) & 0xff] ^ T3[w >>> 24];
	    }
	    return xk;
	}
	// Apply tables
	function apply0123(T01, T23, s0, s1, s2, s3) {
	    return (T01[((s0 << 8) & 0xff00) | ((s1 >>> 8) & 0xff)] ^
	        T23[((s2 >>> 8) & 0xff00) | ((s3 >>> 24) & 0xff)]);
	}
	function applySbox(sbox2, s0, s1, s2, s3) {
	    return (sbox2[(s0 & 0xff) | (s1 & 0xff00)] |
	        (sbox2[((s2 >>> 16) & 0xff) | ((s3 >>> 16) & 0xff00)] << 16));
	}
	function encrypt(xk, s0, s1, s2, s3) {
	    const { sbox2, T01, T23 } = tableEncoding;
	    let k = 0;
	    (s0 ^= xk[k++]), (s1 ^= xk[k++]), (s2 ^= xk[k++]), (s3 ^= xk[k++]);
	    const rounds = xk.length / 4 - 2;
	    for (let i = 0; i < rounds; i++) {
	        const t0 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
	        const t1 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
	        const t2 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
	        const t3 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
	        (s0 = t0), (s1 = t1), (s2 = t2), (s3 = t3);
	    }
	    // last round (without mixcolumns, so using SBOX2 table)
	    const t0 = xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3);
	    const t1 = xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0);
	    const t2 = xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1);
	    const t3 = xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2);
	    return { s0: t0, s1: t1, s2: t2, s3: t3 };
	}
	// Can't be merged with encrypt: arg positions for apply0123 / applySbox are different
	function decrypt(xk, s0, s1, s2, s3) {
	    const { sbox2, T01, T23 } = tableDecoding;
	    let k = 0;
	    (s0 ^= xk[k++]), (s1 ^= xk[k++]), (s2 ^= xk[k++]), (s3 ^= xk[k++]);
	    const rounds = xk.length / 4 - 2;
	    for (let i = 0; i < rounds; i++) {
	        const t0 = xk[k++] ^ apply0123(T01, T23, s0, s3, s2, s1);
	        const t1 = xk[k++] ^ apply0123(T01, T23, s1, s0, s3, s2);
	        const t2 = xk[k++] ^ apply0123(T01, T23, s2, s1, s0, s3);
	        const t3 = xk[k++] ^ apply0123(T01, T23, s3, s2, s1, s0);
	        (s0 = t0), (s1 = t1), (s2 = t2), (s3 = t3);
	    }
	    // Last round
	    const t0 = xk[k++] ^ applySbox(sbox2, s0, s3, s2, s1);
	    const t1 = xk[k++] ^ applySbox(sbox2, s1, s0, s3, s2);
	    const t2 = xk[k++] ^ applySbox(sbox2, s2, s1, s0, s3);
	    const t3 = xk[k++] ^ applySbox(sbox2, s3, s2, s1, s0);
	    return { s0: t0, s1: t1, s2: t2, s3: t3 };
	}
	// TODO: investigate merging with ctr32
	function ctrCounter(xk, nonce, src, dst) {
	    (0, _assert_js_1.abytes)(nonce, BLOCK_SIZE);
	    (0, _assert_js_1.abytes)(src);
	    const srcLen = src.length;
	    dst = (0, utils_js_1.getOutput)(srcLen, dst);
	    (0, utils_js_1.complexOverlapBytes)(src, dst);
	    const ctr = nonce;
	    const c32 = (0, utils_js_1.u32)(ctr);
	    // Fill block (empty, ctr=0)
	    let { s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]);
	    const src32 = (0, utils_js_1.u32)(src);
	    const dst32 = (0, utils_js_1.u32)(dst);
	    // process blocks
	    for (let i = 0; i + 4 <= src32.length; i += 4) {
	        dst32[i + 0] = src32[i + 0] ^ s0;
	        dst32[i + 1] = src32[i + 1] ^ s1;
	        dst32[i + 2] = src32[i + 2] ^ s2;
	        dst32[i + 3] = src32[i + 3] ^ s3;
	        // Full 128 bit counter with wrap around
	        let carry = 1;
	        for (let i = ctr.length - 1; i >= 0; i--) {
	            carry = (carry + (ctr[i] & 0xff)) | 0;
	            ctr[i] = carry & 0xff;
	            carry >>>= 8;
	        }
	        ({ s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]));
	    }
	    // leftovers (less than block)
	    // It's possible to handle > u32 fast, but is it worth it?
	    const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
	    if (start < srcLen) {
	        const b32 = new Uint32Array([s0, s1, s2, s3]);
	        const buf = (0, utils_js_1.u8)(b32);
	        for (let i = start, pos = 0; i < srcLen; i++, pos++)
	            dst[i] = src[i] ^ buf[pos];
	        (0, utils_js_1.clean)(b32);
	    }
	    return dst;
	}
	// AES CTR with overflowing 32 bit counter
	// It's possible to do 32le significantly simpler (and probably faster) by using u32.
	// But, we need both, and perf bottleneck is in ghash anyway.
	function ctr32(xk, isLE, nonce, src, dst) {
	    (0, _assert_js_1.abytes)(nonce, BLOCK_SIZE);
	    (0, _assert_js_1.abytes)(src);
	    dst = (0, utils_js_1.getOutput)(src.length, dst);
	    const ctr = nonce; // write new value to nonce, so it can be re-used
	    const c32 = (0, utils_js_1.u32)(ctr);
	    const view = (0, utils_js_1.createView)(ctr);
	    const src32 = (0, utils_js_1.u32)(src);
	    const dst32 = (0, utils_js_1.u32)(dst);
	    const ctrPos = isLE ? 0 : 12;
	    const srcLen = src.length;
	    // Fill block (empty, ctr=0)
	    let ctrNum = view.getUint32(ctrPos, isLE); // read current counter value
	    let { s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]);
	    // process blocks
	    for (let i = 0; i + 4 <= src32.length; i += 4) {
	        dst32[i + 0] = src32[i + 0] ^ s0;
	        dst32[i + 1] = src32[i + 1] ^ s1;
	        dst32[i + 2] = src32[i + 2] ^ s2;
	        dst32[i + 3] = src32[i + 3] ^ s3;
	        ctrNum = (ctrNum + 1) >>> 0; // u32 wrap
	        view.setUint32(ctrPos, ctrNum, isLE);
	        ({ s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]));
	    }
	    // leftovers (less than a block)
	    const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
	    if (start < srcLen) {
	        const b32 = new Uint32Array([s0, s1, s2, s3]);
	        const buf = (0, utils_js_1.u8)(b32);
	        for (let i = start, pos = 0; i < srcLen; i++, pos++)
	            dst[i] = src[i] ^ buf[pos];
	        (0, utils_js_1.clean)(b32);
	    }
	    return dst;
	}
	/**
	 * CTR: counter mode. Creates stream cipher.
	 * Requires good IV. Parallelizable. OK, but no MAC.
	 */
	aes.ctr = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 16 }, function aesctr(key, nonce) {
	    function processCtr(buf, dst) {
	        (0, _assert_js_1.abytes)(buf);
	        if (dst !== undefined) {
	            (0, _assert_js_1.abytes)(dst);
	            if (!(0, utils_js_1.isAligned32)(dst))
	                throw new Error('unaligned destination');
	        }
	        const xk = expandKeyLE(key);
	        const n = (0, utils_js_1.copyBytes)(nonce); // align + avoid changing
	        const toClean = [xk, n];
	        if (!(0, utils_js_1.isAligned32)(buf))
	            toClean.push((buf = (0, utils_js_1.copyBytes)(buf)));
	        const out = ctrCounter(xk, n, buf, dst);
	        (0, utils_js_1.clean)(...toClean);
	        return out;
	    }
	    return {
	        encrypt: (plaintext, dst) => processCtr(plaintext, dst),
	        decrypt: (ciphertext, dst) => processCtr(ciphertext, dst),
	    };
	});
	function validateBlockDecrypt(data) {
	    (0, _assert_js_1.abytes)(data);
	    if (data.length % BLOCK_SIZE !== 0) {
	        throw new Error('aes-(cbc/ecb).decrypt ciphertext should consist of blocks with size ' + BLOCK_SIZE);
	    }
	}
	function validateBlockEncrypt(plaintext, pcks5, dst) {
	    (0, _assert_js_1.abytes)(plaintext);
	    let outLen = plaintext.length;
	    const remaining = outLen % BLOCK_SIZE;
	    if (!pcks5 && remaining !== 0)
	        throw new Error('aec/(cbc-ecb): unpadded plaintext with disabled padding');
	    if (!(0, utils_js_1.isAligned32)(plaintext))
	        plaintext = (0, utils_js_1.copyBytes)(plaintext);
	    const b = (0, utils_js_1.u32)(plaintext);
	    if (pcks5) {
	        let left = BLOCK_SIZE - remaining;
	        if (!left)
	            left = BLOCK_SIZE; // if no bytes left, create empty padding block
	        outLen = outLen + left;
	    }
	    dst = (0, utils_js_1.getOutput)(outLen, dst);
	    (0, utils_js_1.complexOverlapBytes)(plaintext, dst);
	    const o = (0, utils_js_1.u32)(dst);
	    return { b, o, out: dst };
	}
	function validatePCKS(data, pcks5) {
	    if (!pcks5)
	        return data;
	    const len = data.length;
	    if (!len)
	        throw new Error('aes/pcks5: empty ciphertext not allowed');
	    const lastByte = data[len - 1];
	    if (lastByte <= 0 || lastByte > 16)
	        throw new Error('aes/pcks5: wrong padding');
	    const out = data.subarray(0, -lastByte);
	    for (let i = 0; i < lastByte; i++)
	        if (data[len - i - 1] !== lastByte)
	            throw new Error('aes/pcks5: wrong padding');
	    return out;
	}
	function padPCKS(left) {
	    const tmp = new Uint8Array(16);
	    const tmp32 = (0, utils_js_1.u32)(tmp);
	    tmp.set(left);
	    const paddingByte = BLOCK_SIZE - left.length;
	    for (let i = BLOCK_SIZE - paddingByte; i < BLOCK_SIZE; i++)
	        tmp[i] = paddingByte;
	    return tmp32;
	}
	/**
	 * ECB: Electronic CodeBook. Simple deterministic replacement.
	 * Dangerous: always map x to y. See [AES Penguin](https://words.filippo.io/the-ecb-penguin/).
	 */
	aes.ecb = (0, utils_js_1.wrapCipher)({ blockSize: 16 }, function aesecb(key, opts = {}) {
	    const pcks5 = !opts.disablePadding;
	    return {
	        encrypt(plaintext, dst) {
	            const { b, o, out: _out } = validateBlockEncrypt(plaintext, pcks5, dst);
	            const xk = expandKeyLE(key);
	            let i = 0;
	            for (; i + 4 <= b.length;) {
	                const { s0, s1, s2, s3 } = encrypt(xk, b[i + 0], b[i + 1], b[i + 2], b[i + 3]);
	                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
	            }
	            if (pcks5) {
	                const tmp32 = padPCKS(plaintext.subarray(i * 4));
	                const { s0, s1, s2, s3 } = encrypt(xk, tmp32[0], tmp32[1], tmp32[2], tmp32[3]);
	                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
	            }
	            (0, utils_js_1.clean)(xk);
	            return _out;
	        },
	        decrypt(ciphertext, dst) {
	            validateBlockDecrypt(ciphertext);
	            const xk = expandKeyDecLE(key);
	            dst = (0, utils_js_1.getOutput)(ciphertext.length, dst);
	            const toClean = [xk];
	            if (!(0, utils_js_1.isAligned32)(ciphertext))
	                toClean.push((ciphertext = (0, utils_js_1.copyBytes)(ciphertext)));
	            (0, utils_js_1.complexOverlapBytes)(ciphertext, dst);
	            const b = (0, utils_js_1.u32)(ciphertext);
	            const o = (0, utils_js_1.u32)(dst);
	            for (let i = 0; i + 4 <= b.length;) {
	                const { s0, s1, s2, s3 } = decrypt(xk, b[i + 0], b[i + 1], b[i + 2], b[i + 3]);
	                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
	            }
	            (0, utils_js_1.clean)(...toClean);
	            return validatePCKS(dst, pcks5);
	        },
	    };
	});
	/**
	 * CBC: Cipher-Block-Chaining. Key is previous round’s block.
	 * Fragile: needs proper padding. Unauthenticated: needs MAC.
	 */
	aes.cbc = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 16 }, function aescbc(key, iv, opts = {}) {
	    const pcks5 = !opts.disablePadding;
	    return {
	        encrypt(plaintext, dst) {
	            const xk = expandKeyLE(key);
	            const { b, o, out: _out } = validateBlockEncrypt(plaintext, pcks5, dst);
	            let _iv = iv;
	            const toClean = [xk];
	            if (!(0, utils_js_1.isAligned32)(_iv))
	                toClean.push((_iv = (0, utils_js_1.copyBytes)(_iv)));
	            const n32 = (0, utils_js_1.u32)(_iv);
	            // prettier-ignore
	            let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
	            let i = 0;
	            for (; i + 4 <= b.length;) {
	                (s0 ^= b[i + 0]), (s1 ^= b[i + 1]), (s2 ^= b[i + 2]), (s3 ^= b[i + 3]);
	                ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
	                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
	            }
	            if (pcks5) {
	                const tmp32 = padPCKS(plaintext.subarray(i * 4));
	                (s0 ^= tmp32[0]), (s1 ^= tmp32[1]), (s2 ^= tmp32[2]), (s3 ^= tmp32[3]);
	                ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
	                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
	            }
	            (0, utils_js_1.clean)(...toClean);
	            return _out;
	        },
	        decrypt(ciphertext, dst) {
	            validateBlockDecrypt(ciphertext);
	            const xk = expandKeyDecLE(key);
	            let _iv = iv;
	            const toClean = [xk];
	            if (!(0, utils_js_1.isAligned32)(_iv))
	                toClean.push((_iv = (0, utils_js_1.copyBytes)(_iv)));
	            const n32 = (0, utils_js_1.u32)(_iv);
	            dst = (0, utils_js_1.getOutput)(ciphertext.length, dst);
	            if (!(0, utils_js_1.isAligned32)(ciphertext))
	                toClean.push((ciphertext = (0, utils_js_1.copyBytes)(ciphertext)));
	            (0, utils_js_1.complexOverlapBytes)(ciphertext, dst);
	            const b = (0, utils_js_1.u32)(ciphertext);
	            const o = (0, utils_js_1.u32)(dst);
	            // prettier-ignore
	            let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
	            for (let i = 0; i + 4 <= b.length;) {
	                // prettier-ignore
	                const ps0 = s0, ps1 = s1, ps2 = s2, ps3 = s3;
	                (s0 = b[i + 0]), (s1 = b[i + 1]), (s2 = b[i + 2]), (s3 = b[i + 3]);
	                const { s0: o0, s1: o1, s2: o2, s3: o3 } = decrypt(xk, s0, s1, s2, s3);
	                (o[i++] = o0 ^ ps0), (o[i++] = o1 ^ ps1), (o[i++] = o2 ^ ps2), (o[i++] = o3 ^ ps3);
	            }
	            (0, utils_js_1.clean)(...toClean);
	            return validatePCKS(dst, pcks5);
	        },
	    };
	});
	/**
	 * CFB: Cipher Feedback Mode. The input for the block cipher is the previous cipher output.
	 * Unauthenticated: needs MAC.
	 */
	aes.cfb = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 16 }, function aescfb(key, iv) {
	    function processCfb(src, isEncrypt, dst) {
	        (0, _assert_js_1.abytes)(src);
	        const srcLen = src.length;
	        dst = (0, utils_js_1.getOutput)(srcLen, dst);
	        if ((0, utils_js_1.overlapBytes)(src, dst))
	            throw new Error('overlapping src and dst not supported.');
	        const xk = expandKeyLE(key);
	        let _iv = iv;
	        const toClean = [xk];
	        if (!(0, utils_js_1.isAligned32)(_iv))
	            toClean.push((_iv = (0, utils_js_1.copyBytes)(_iv)));
	        if (!(0, utils_js_1.isAligned32)(src))
	            toClean.push((src = (0, utils_js_1.copyBytes)(src)));
	        const src32 = (0, utils_js_1.u32)(src);
	        const dst32 = (0, utils_js_1.u32)(dst);
	        const next32 = isEncrypt ? dst32 : src32;
	        const n32 = (0, utils_js_1.u32)(_iv);
	        // prettier-ignore
	        let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
	        for (let i = 0; i + 4 <= src32.length;) {
	            const { s0: e0, s1: e1, s2: e2, s3: e3 } = encrypt(xk, s0, s1, s2, s3);
	            dst32[i + 0] = src32[i + 0] ^ e0;
	            dst32[i + 1] = src32[i + 1] ^ e1;
	            dst32[i + 2] = src32[i + 2] ^ e2;
	            dst32[i + 3] = src32[i + 3] ^ e3;
	            (s0 = next32[i++]), (s1 = next32[i++]), (s2 = next32[i++]), (s3 = next32[i++]);
	        }
	        // leftovers (less than block)
	        const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
	        if (start < srcLen) {
	            ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
	            const buf = (0, utils_js_1.u8)(new Uint32Array([s0, s1, s2, s3]));
	            for (let i = start, pos = 0; i < srcLen; i++, pos++)
	                dst[i] = src[i] ^ buf[pos];
	            (0, utils_js_1.clean)(buf);
	        }
	        (0, utils_js_1.clean)(...toClean);
	        return dst;
	    }
	    return {
	        encrypt: (plaintext, dst) => processCfb(plaintext, true, dst),
	        decrypt: (ciphertext, dst) => processCfb(ciphertext, false, dst),
	    };
	});
	// TODO: merge with chacha, however gcm has bitLen while chacha has byteLen
	function computeTag(fn, isLE, key, data, AAD) {
	    const aadLength = AAD == null ? 0 : AAD.length;
	    const h = fn.create(key, data.length + aadLength);
	    if (AAD)
	        h.update(AAD);
	    h.update(data);
	    const num = new Uint8Array(16);
	    const view = (0, utils_js_1.createView)(num);
	    if (AAD)
	        (0, utils_js_1.setBigUint64)(view, 0, BigInt(aadLength * 8), isLE);
	    (0, utils_js_1.setBigUint64)(view, 8, BigInt(data.length * 8), isLE);
	    h.update(num);
	    const res = h.digest();
	    (0, utils_js_1.clean)(num);
	    return res;
	}
	/**
	 * GCM: Galois/Counter Mode.
	 * Modern, parallel version of CTR, with MAC.
	 * Be careful: MACs can be forged.
	 * Unsafe to use random nonces under the same key, due to collision chance.
	 * As for nonce size, prefer 12-byte, instead of 8-byte.
	 */
	aes.gcm = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 12, tagLength: 16, varSizeNonce: true }, function aesgcm(key, nonce, AAD) {
	    // NIST 800-38d doesn't enforce minimum nonce length.
	    // We enforce 8 bytes for compat with openssl.
	    // 12 bytes are recommended. More than 12 bytes would be converted into 12.
	    if (nonce.length < 8)
	        throw new Error('aes/gcm: invalid nonce length');
	    const tagLength = 16;
	    function _computeTag(authKey, tagMask, data) {
	        const tag = computeTag(_polyval_js_1.ghash, false, authKey, data, AAD);
	        for (let i = 0; i < tagMask.length; i++)
	            tag[i] ^= tagMask[i];
	        return tag;
	    }
	    function deriveKeys() {
	        const xk = expandKeyLE(key);
	        const authKey = EMPTY_BLOCK.slice();
	        const counter = EMPTY_BLOCK.slice();
	        ctr32(xk, false, counter, counter, authKey);
	        // NIST 800-38d, page 15: different behavior for 96-bit and non-96-bit nonces
	        if (nonce.length === 12) {
	            counter.set(nonce);
	        }
	        else {
	            const nonceLen = EMPTY_BLOCK.slice();
	            const view = (0, utils_js_1.createView)(nonceLen);
	            (0, utils_js_1.setBigUint64)(view, 8, BigInt(nonce.length * 8), false);
	            // ghash(nonce || u64be(0) || u64be(nonceLen*8))
	            const g = _polyval_js_1.ghash.create(authKey).update(nonce).update(nonceLen);
	            g.digestInto(counter); // digestInto doesn't trigger '.destroy'
	            g.destroy();
	        }
	        const tagMask = ctr32(xk, false, counter, EMPTY_BLOCK);
	        return { xk, authKey, counter, tagMask };
	    }
	    return {
	        encrypt(plaintext) {
	            const { xk, authKey, counter, tagMask } = deriveKeys();
	            const out = new Uint8Array(plaintext.length + tagLength);
	            const toClean = [xk, authKey, counter, tagMask];
	            if (!(0, utils_js_1.isAligned32)(plaintext))
	                toClean.push((plaintext = (0, utils_js_1.copyBytes)(plaintext)));
	            ctr32(xk, false, counter, plaintext, out.subarray(0, plaintext.length));
	            const tag = _computeTag(authKey, tagMask, out.subarray(0, out.length - tagLength));
	            toClean.push(tag);
	            out.set(tag, plaintext.length);
	            (0, utils_js_1.clean)(...toClean);
	            return out;
	        },
	        decrypt(ciphertext) {
	            const { xk, authKey, counter, tagMask } = deriveKeys();
	            const toClean = [xk, authKey, tagMask, counter];
	            if (!(0, utils_js_1.isAligned32)(ciphertext))
	                toClean.push((ciphertext = (0, utils_js_1.copyBytes)(ciphertext)));
	            const data = ciphertext.subarray(0, -tagLength);
	            const passedTag = ciphertext.subarray(-tagLength);
	            const tag = _computeTag(authKey, tagMask, data);
	            toClean.push(tag);
	            if (!(0, utils_js_1.equalBytes)(tag, passedTag))
	                throw new Error('aes/gcm: invalid ghash tag');
	            const out = ctr32(xk, false, counter, data);
	            (0, utils_js_1.clean)(...toClean);
	            return out;
	        },
	    };
	});
	const limit = (name, min, max) => (value) => {
	    if (!Number.isSafeInteger(value) || min > value || value > max) {
	        const minmax = '[' + min + '..' + max + ']';
	        throw new Error('' + name + ': expected value in range ' + minmax + ', got ' + value);
	    }
	};
	/**
	 * AES-GCM-SIV: classic AES-GCM with nonce-misuse resistance.
	 * Guarantees that, when a nonce is repeated, the only security loss is that identical
	 * plaintexts will produce identical ciphertexts.
	 * RFC 8452, https://datatracker.ietf.org/doc/html/rfc8452
	 */
	aes.siv = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 12, tagLength: 16, varSizeNonce: true }, function aessiv(key, nonce, AAD) {
	    const tagLength = 16;
	    // From RFC 8452: Section 6
	    const AAD_LIMIT = limit('AAD', 0, 2 ** 36);
	    const PLAIN_LIMIT = limit('plaintext', 0, 2 ** 36);
	    const NONCE_LIMIT = limit('nonce', 12, 12);
	    const CIPHER_LIMIT = limit('ciphertext', 16, 2 ** 36 + 16);
	    (0, _assert_js_1.abytes)(key, 16, 24, 32);
	    NONCE_LIMIT(nonce.length);
	    if (AAD !== undefined)
	        AAD_LIMIT(AAD.length);
	    function deriveKeys() {
	        const xk = expandKeyLE(key);
	        const encKey = new Uint8Array(key.length);
	        const authKey = new Uint8Array(16);
	        const toClean = [xk, encKey];
	        let _nonce = nonce;
	        if (!(0, utils_js_1.isAligned32)(_nonce))
	            toClean.push((_nonce = (0, utils_js_1.copyBytes)(_nonce)));
	        const n32 = (0, utils_js_1.u32)(_nonce);
	        // prettier-ignore
	        let s0 = 0, s1 = n32[0], s2 = n32[1], s3 = n32[2];
	        let counter = 0;
	        for (const derivedKey of [authKey, encKey].map(utils_js_1.u32)) {
	            const d32 = (0, utils_js_1.u32)(derivedKey);
	            for (let i = 0; i < d32.length; i += 2) {
	                // aes(u32le(0) || nonce)[:8] || aes(u32le(1) || nonce)[:8] ...
	                const { s0: o0, s1: o1 } = encrypt(xk, s0, s1, s2, s3);
	                d32[i + 0] = o0;
	                d32[i + 1] = o1;
	                s0 = ++counter; // increment counter inside state
	            }
	        }
	        const res = { authKey, encKey: expandKeyLE(encKey) };
	        // Cleanup
	        (0, utils_js_1.clean)(...toClean);
	        return res;
	    }
	    function _computeTag(encKey, authKey, data) {
	        const tag = computeTag(_polyval_js_1.polyval, true, authKey, data, AAD);
	        // Compute the expected tag by XORing S_s and the nonce, clearing the
	        // most significant bit of the last byte and encrypting with the
	        // message-encryption key.
	        for (let i = 0; i < 12; i++)
	            tag[i] ^= nonce[i];
	        tag[15] &= 0x7f; // Clear the highest bit
	        // encrypt tag as block
	        const t32 = (0, utils_js_1.u32)(tag);
	        // prettier-ignore
	        let s0 = t32[0], s1 = t32[1], s2 = t32[2], s3 = t32[3];
	        ({ s0, s1, s2, s3 } = encrypt(encKey, s0, s1, s2, s3));
	        (t32[0] = s0), (t32[1] = s1), (t32[2] = s2), (t32[3] = s3);
	        return tag;
	    }
	    // actual decrypt/encrypt of message.
	    function processSiv(encKey, tag, input) {
	        let block = (0, utils_js_1.copyBytes)(tag);
	        block[15] |= 0x80; // Force highest bit
	        const res = ctr32(encKey, true, block, input);
	        // Cleanup
	        (0, utils_js_1.clean)(block);
	        return res;
	    }
	    return {
	        encrypt(plaintext) {
	            PLAIN_LIMIT(plaintext.length);
	            const { encKey, authKey } = deriveKeys();
	            const tag = _computeTag(encKey, authKey, plaintext);
	            const toClean = [encKey, authKey, tag];
	            if (!(0, utils_js_1.isAligned32)(plaintext))
	                toClean.push((plaintext = (0, utils_js_1.copyBytes)(plaintext)));
	            const out = new Uint8Array(plaintext.length + tagLength);
	            out.set(tag, plaintext.length);
	            out.set(processSiv(encKey, tag, plaintext));
	            // Cleanup
	            (0, utils_js_1.clean)(...toClean);
	            return out;
	        },
	        decrypt(ciphertext) {
	            CIPHER_LIMIT(ciphertext.length);
	            const tag = ciphertext.subarray(-tagLength);
	            const { encKey, authKey } = deriveKeys();
	            const toClean = [encKey, authKey];
	            if (!(0, utils_js_1.isAligned32)(ciphertext))
	                toClean.push((ciphertext = (0, utils_js_1.copyBytes)(ciphertext)));
	            const plaintext = processSiv(encKey, tag, ciphertext.subarray(0, -tagLength));
	            const expectedTag = _computeTag(encKey, authKey, plaintext);
	            toClean.push(expectedTag);
	            if (!(0, utils_js_1.equalBytes)(tag, expectedTag)) {
	                (0, utils_js_1.clean)(...toClean);
	                throw new Error('invalid polyval tag');
	            }
	            // Cleanup
	            (0, utils_js_1.clean)(...toClean);
	            return plaintext;
	        },
	    };
	});
	function isBytes32(a) {
	    return (a instanceof Uint32Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint32Array'));
	}
	function encryptBlock(xk, block) {
	    (0, _assert_js_1.abytes)(block, 16);
	    if (!isBytes32(xk))
	        throw new Error('_encryptBlock accepts result of expandKeyLE');
	    const b32 = (0, utils_js_1.u32)(block);
	    let { s0, s1, s2, s3 } = encrypt(xk, b32[0], b32[1], b32[2], b32[3]);
	    (b32[0] = s0), (b32[1] = s1), (b32[2] = s2), (b32[3] = s3);
	    return block;
	}
	function decryptBlock(xk, block) {
	    (0, _assert_js_1.abytes)(block, 16);
	    if (!isBytes32(xk))
	        throw new Error('_decryptBlock accepts result of expandKeyLE');
	    const b32 = (0, utils_js_1.u32)(block);
	    let { s0, s1, s2, s3 } = decrypt(xk, b32[0], b32[1], b32[2], b32[3]);
	    (b32[0] = s0), (b32[1] = s1), (b32[2] = s2), (b32[3] = s3);
	    return block;
	}
	/**
	 * AES-W (base for AESKW/AESKWP).
	 * Specs: [SP800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf),
	 * [RFC 3394](https://datatracker.ietf.org/doc/rfc3394/),
	 * [RFC 5649](https://datatracker.ietf.org/doc/rfc5649/).
	 */
	const AESW = {
	    /*
	    High-level pseudocode:
	    ```
	    A: u64 = IV
	    out = []
	    for (let i=0, ctr = 0; i<6; i++) {
	      for (const chunk of chunks(plaintext, 8)) {
	        A ^= swapEndianess(ctr++)
	        [A, res] = chunks(encrypt(A || chunk), 8);
	        out ||= res
	      }
	    }
	    out = A || out
	    ```
	    Decrypt is the same, but reversed.
	    */
	    encrypt(kek, out) {
	        // Size is limited to 4GB, otherwise ctr will overflow and we'll need to switch to bigints.
	        // If you need it larger, open an issue.
	        if (out.length >= 2 ** 32)
	            throw new Error('plaintext should be less than 4gb');
	        const xk = expandKeyLE(kek);
	        if (out.length === 16)
	            encryptBlock(xk, out);
	        else {
	            const o32 = (0, utils_js_1.u32)(out);
	            // prettier-ignore
	            let a0 = o32[0], a1 = o32[1]; // A
	            for (let j = 0, ctr = 1; j < 6; j++) {
	                for (let pos = 2; pos < o32.length; pos += 2, ctr++) {
	                    const { s0, s1, s2, s3 } = encrypt(xk, a0, a1, o32[pos], o32[pos + 1]);
	                    // A = MSB(64, B) ^ t where t = (n*j)+i
	                    (a0 = s0), (a1 = s1 ^ byteSwap(ctr)), (o32[pos] = s2), (o32[pos + 1] = s3);
	                }
	            }
	            (o32[0] = a0), (o32[1] = a1); // out = A || out
	        }
	        xk.fill(0);
	    },
	    decrypt(kek, out) {
	        if (out.length - 8 >= 2 ** 32)
	            throw new Error('ciphertext should be less than 4gb');
	        const xk = expandKeyDecLE(kek);
	        const chunks = out.length / 8 - 1; // first chunk is IV
	        if (chunks === 1)
	            decryptBlock(xk, out);
	        else {
	            const o32 = (0, utils_js_1.u32)(out);
	            // prettier-ignore
	            let a0 = o32[0], a1 = o32[1]; // A
	            for (let j = 0, ctr = chunks * 6; j < 6; j++) {
	                for (let pos = chunks * 2; pos >= 1; pos -= 2, ctr--) {
	                    a1 ^= byteSwap(ctr);
	                    const { s0, s1, s2, s3 } = decrypt(xk, a0, a1, o32[pos], o32[pos + 1]);
	                    (a0 = s0), (a1 = s1), (o32[pos] = s2), (o32[pos + 1] = s3);
	                }
	            }
	            (o32[0] = a0), (o32[1] = a1);
	        }
	        xk.fill(0);
	    },
	};
	const AESKW_IV = /* @__PURE__ */ new Uint8Array(8).fill(0xa6); // A6A6A6A6A6A6A6A6
	/**
	 * AES-KW (key-wrap). Injects static IV into plaintext, adds counter, encrypts 6 times.
	 * Reduces block size from 16 to 8 bytes.
	 * For padded version, use aeskwp.
	 * [RFC 3394](https://datatracker.ietf.org/doc/rfc3394/),
	 * [NIST.SP.800-38F](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf).
	 */
	aes.aeskw = (0, utils_js_1.wrapCipher)({ blockSize: 8 }, (kek) => ({
	    encrypt(plaintext) {
	        if (!plaintext.length || plaintext.length % 8 !== 0)
	            throw new Error('invalid plaintext length');
	        if (plaintext.length === 8)
	            throw new Error('8-byte keys not allowed in AESKW, use AESKWP instead');
	        const out = (0, utils_js_1.concatBytes)(AESKW_IV, plaintext);
	        AESW.encrypt(kek, out);
	        return out;
	    },
	    decrypt(ciphertext) {
	        // ciphertext must be at least 24 bytes and a multiple of 8 bytes
	        // 24 because should have at least two block (1 iv + 2).
	        // Replace with 16 to enable '8-byte keys'
	        if (ciphertext.length % 8 !== 0 || ciphertext.length < 3 * 8)
	            throw new Error('invalid ciphertext length');
	        const out = (0, utils_js_1.copyBytes)(ciphertext);
	        AESW.decrypt(kek, out);
	        if (!(0, utils_js_1.equalBytes)(out.subarray(0, 8), AESKW_IV))
	            throw new Error('integrity check failed');
	        out.subarray(0, 8).fill(0); // ciphertext.subarray(0, 8) === IV, but we clean it anyway
	        return out.subarray(8);
	    },
	}));
	/*
	We don't support 8-byte keys. The rabbit hole:

	- Wycheproof says: "NIST SP 800-38F does not define the wrapping of 8 byte keys.
	  RFC 3394 Section 2  on the other hand specifies that 8 byte keys are wrapped
	  by directly encrypting one block with AES."
	    - https://github.com/C2SP/wycheproof/blob/master/doc/key_wrap.md
	    - "RFC 3394 specifies in Section 2, that the input for the key wrap
	      algorithm must be at least two blocks and otherwise the constant
	      field and key are simply encrypted with ECB as a single block"
	- What RFC 3394 actually says (in Section 2):
	    - "Before being wrapped, the key data is parsed into n blocks of 64 bits.
	      The only restriction the key wrap algorithm places on n is that n be
	      at least two"
	    - "For key data with length less than or equal to 64 bits, the constant
	      field used in this specification and the key data form a single
	      128-bit codebook input making this key wrap unnecessary."
	- Which means "assert(n >= 2)" and "use something else for 8 byte keys"
	- NIST SP800-38F actually prohibits 8-byte in "5.3.1 Mandatory Limits".
	  It states that plaintext for KW should be "2 to 2^54 -1 semiblocks".
	- So, where does "directly encrypt single block with AES" come from?
	    - Not RFC 3394. Pseudocode of key wrap in 2.2 explicitly uses
	      loop of 6 for any code path
	    - There is a weird W3C spec:
	      https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#kw-aes128
	    - This spec is outdated, as admitted by Wycheproof authors
	    - There is RFC 5649 for padded key wrap, which is padding construction on
	      top of AESKW. In '4.1.2' it says: "If the padded plaintext contains exactly
	      eight octets, then prepend the AIV as defined in Section 3 above to P[1] and
	      encrypt the resulting 128-bit block using AES in ECB mode [Modes] with key
	      K (the KEK).  In this case, the output is two 64-bit blocks C[0] and C[1]:"
	    - Browser subtle crypto is actually crashes on wrapping keys less than 16 bytes:
	      `Error: error:1C8000E6:Provider routines::invalid input length] { opensslErrorStack: [ 'error:030000BD:digital envelope routines::update error' ]`

	In the end, seems like a bug in Wycheproof.
	The 8-byte check can be easily disabled inside of AES_W.
	*/
	const AESKWP_IV = 0xa65959a6; // single u32le value
	/**
	 * AES-KW, but with padding and allows random keys.
	 * Second u32 of IV is used as counter for length.
	 * [RFC 5649](https://www.rfc-editor.org/rfc/rfc5649)
	 */
	aes.aeskwp = (0, utils_js_1.wrapCipher)({ blockSize: 8 }, (kek) => ({
	    encrypt(plaintext) {
	        if (!plaintext.length)
	            throw new Error('invalid plaintext length');
	        const padded = Math.ceil(plaintext.length / 8) * 8;
	        const out = new Uint8Array(8 + padded);
	        out.set(plaintext, 8);
	        const out32 = (0, utils_js_1.u32)(out);
	        out32[0] = AESKWP_IV;
	        out32[1] = byteSwap(plaintext.length);
	        AESW.encrypt(kek, out);
	        return out;
	    },
	    decrypt(ciphertext) {
	        // 16 because should have at least one block
	        if (ciphertext.length < 16)
	            throw new Error('invalid ciphertext length');
	        const out = (0, utils_js_1.copyBytes)(ciphertext);
	        const o32 = (0, utils_js_1.u32)(out);
	        AESW.decrypt(kek, out);
	        const len = byteSwap(o32[1]) >>> 0;
	        const padded = Math.ceil(len / 8) * 8;
	        if (o32[0] !== AESKWP_IV || out.length - 8 !== padded)
	            throw new Error('integrity check failed');
	        for (let i = len; i < padded; i++)
	            if (out[8 + i] !== 0)
	                throw new Error('integrity check failed');
	        out.subarray(0, 8).fill(0); // ciphertext.subarray(0, 8) === IV, but we clean it anyway
	        return out.subarray(8, 8 + len);
	    },
	}));
	/** Unsafe low-level internal methods. May change at any time. */
	aes.unsafe = {
	    expandKeyLE,
	    expandKeyDecLE,
	    encrypt,
	    decrypt,
	    encryptBlock,
	    decryptBlock,
	    ctrCounter,
	    ctr32,
	};
	
	return aes;
}

var hasRequiredNoble$1;

function requireNoble$1 () {
	if (hasRequiredNoble$1) return noble$1;
	hasRequiredNoble$1 = 1;
	Object.defineProperty(noble$1, "__esModule", { value: true });
	noble$1.aes256cbc = noble$1.aes256gcm = void 0;
	var aes_1 = /*@__PURE__*/ requireAes();
	var aes256gcm = function (key, nonce, AAD) {
	    return (0, aes_1.gcm)(key, nonce, AAD);
	};
	noble$1.aes256gcm = aes256gcm;
	var aes256cbc = function (key, nonce, AAD) {
	    return (0, aes_1.cbc)(key, nonce);
	};
	noble$1.aes256cbc = aes256cbc;
	return noble$1;
}

var noble = {};

var chacha = {};

var _arx = {};

var hasRequired_arx;

function require_arx () {
	if (hasRequired_arx) return _arx;
	hasRequired_arx = 1;
	Object.defineProperty(_arx, "__esModule", { value: true });
	_arx.rotl = rotl;
	_arx.createCipher = createCipher;
	/**
	 * Basic utils for ARX (add-rotate-xor) salsa and chacha ciphers.

	RFC8439 requires multi-step cipher stream, where
	authKey starts with counter: 0, actual msg with counter: 1.

	For this, we need a way to re-use nonce / counter:

	    const counter = new Uint8Array(4);
	    chacha(..., counter, ...); // counter is now 1
	    chacha(..., counter, ...); // counter is now 2

	This is complicated:

	- 32-bit counters are enough, no need for 64-bit: max ArrayBuffer size in JS is 4GB
	- Original papers don't allow mutating counters
	- Counter overflow is undefined [^1]
	- Idea A: allow providing (nonce | counter) instead of just nonce, re-use it
	- Caveat: Cannot be re-used through all cases:
	- * chacha has (counter | nonce)
	- * xchacha has (nonce16 | counter | nonce16)
	- Idea B: separate nonce / counter and provide separate API for counter re-use
	- Caveat: there are different counter sizes depending on an algorithm.
	- salsa & chacha also differ in structures of key & sigma:
	  salsa20:      s[0] | k(4) | s[1] | nonce(2) | ctr(2) | s[2] | k(4) | s[3]
	  chacha:       s(4) | k(8) | ctr(1) | nonce(3)
	  chacha20orig: s(4) | k(8) | ctr(2) | nonce(2)
	- Idea C: helper method such as `setSalsaState(key, nonce, sigma, data)`
	- Caveat: we can't re-use counter array

	xchacha [^2] uses the subkey and remaining 8 byte nonce with ChaCha20 as normal
	(prefixed by 4 NUL bytes, since [RFC8439] specifies a 12-byte nonce).

	[^1]: https://mailarchive.ietf.org/arch/msg/cfrg/gsOnTJzcbgG6OqD8Sc0GO5aR_tU/
	[^2]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.2

	 * @module
	 */
	const _assert_js_1 = /*@__PURE__*/ require_assert$1();
	const utils_js_1 = /*@__PURE__*/ requireUtils$3();
	// We can't make top-level var depend on utils.utf8ToBytes
	// because it's not present in all envs. Creating a similar fn here
	const _utf8ToBytes = (str) => Uint8Array.from(str.split('').map((c) => c.charCodeAt(0)));
	const sigma16 = _utf8ToBytes('expand 16-byte k');
	const sigma32 = _utf8ToBytes('expand 32-byte k');
	const sigma16_32 = (0, utils_js_1.u32)(sigma16);
	const sigma32_32 = (0, utils_js_1.u32)(sigma32);
	function rotl(a, b) {
	    return (a << b) | (a >>> (32 - b));
	}
	// Is byte array aligned to 4 byte offset (u32)?
	function isAligned32(b) {
	    return b.byteOffset % 4 === 0;
	}
	// Salsa and Chacha block length is always 512-bit
	const BLOCK_LEN = 64;
	const BLOCK_LEN32 = 16;
	// new Uint32Array([2**32])   // => Uint32Array(1) [ 0 ]
	// new Uint32Array([2**32-1]) // => Uint32Array(1) [ 4294967295 ]
	const MAX_COUNTER = 2 ** 32 - 1;
	const U32_EMPTY = new Uint32Array();
	function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
	    const len = data.length;
	    const block = new Uint8Array(BLOCK_LEN);
	    const b32 = (0, utils_js_1.u32)(block);
	    // Make sure that buffers aligned to 4 bytes
	    const isAligned = isAligned32(data) && isAligned32(output);
	    const d32 = isAligned ? (0, utils_js_1.u32)(data) : U32_EMPTY;
	    const o32 = isAligned ? (0, utils_js_1.u32)(output) : U32_EMPTY;
	    for (let pos = 0; pos < len; counter++) {
	        core(sigma, key, nonce, b32, counter, rounds);
	        if (counter >= MAX_COUNTER)
	            throw new Error('arx: counter overflow');
	        const take = Math.min(BLOCK_LEN, len - pos);
	        // aligned to 4 bytes
	        if (isAligned && take === BLOCK_LEN) {
	            const pos32 = pos / 4;
	            if (pos % 4 !== 0)
	                throw new Error('arx: invalid block position');
	            for (let j = 0, posj; j < BLOCK_LEN32; j++) {
	                posj = pos32 + j;
	                o32[posj] = d32[posj] ^ b32[j];
	            }
	            pos += BLOCK_LEN;
	            continue;
	        }
	        for (let j = 0, posj; j < take; j++) {
	            posj = pos + j;
	            output[posj] = data[posj] ^ block[j];
	        }
	        pos += take;
	    }
	}
	/** Creates ARX-like (ChaCha, Salsa) cipher stream from core function. */
	function createCipher(core, opts) {
	    const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = (0, utils_js_1.checkOpts)({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts);
	    if (typeof core !== 'function')
	        throw new Error('core must be a function');
	    (0, _assert_js_1.anumber)(counterLength);
	    (0, _assert_js_1.anumber)(rounds);
	    (0, _assert_js_1.abool)(counterRight);
	    (0, _assert_js_1.abool)(allowShortKeys);
	    return (key, nonce, data, output, counter = 0) => {
	        (0, _assert_js_1.abytes)(key);
	        (0, _assert_js_1.abytes)(nonce);
	        (0, _assert_js_1.abytes)(data);
	        const len = data.length;
	        if (output === undefined)
	            output = new Uint8Array(len);
	        (0, _assert_js_1.abytes)(output);
	        (0, _assert_js_1.anumber)(counter);
	        if (counter < 0 || counter >= MAX_COUNTER)
	            throw new Error('arx: counter overflow');
	        if (output.length < len)
	            throw new Error(`arx: output (${output.length}) is shorter than data (${len})`);
	        const toClean = [];
	        // Key & sigma
	        // key=16 -> sigma16, k=key|key
	        // key=32 -> sigma32, k=key
	        let l = key.length;
	        let k;
	        let sigma;
	        if (l === 32) {
	            toClean.push((k = (0, utils_js_1.copyBytes)(key)));
	            sigma = sigma32_32;
	        }
	        else if (l === 16 && allowShortKeys) {
	            k = new Uint8Array(32);
	            k.set(key);
	            k.set(key, 16);
	            sigma = sigma16_32;
	            toClean.push(k);
	        }
	        else {
	            throw new Error(`arx: invalid 32-byte key, got length=${l}`);
	        }
	        // Nonce
	        // salsa20:      8   (8-byte counter)
	        // chacha20orig: 8   (8-byte counter)
	        // chacha20:     12  (4-byte counter)
	        // xsalsa20:     24  (16 -> hsalsa,  8 -> old nonce)
	        // xchacha20:    24  (16 -> hchacha, 8 -> old nonce)
	        // Align nonce to 4 bytes
	        if (!isAligned32(nonce))
	            toClean.push((nonce = (0, utils_js_1.copyBytes)(nonce)));
	        const k32 = (0, utils_js_1.u32)(k);
	        // hsalsa & hchacha: handle extended nonce
	        if (extendNonceFn) {
	            if (nonce.length !== 24)
	                throw new Error(`arx: extended nonce must be 24 bytes`);
	            extendNonceFn(sigma, k32, (0, utils_js_1.u32)(nonce.subarray(0, 16)), k32);
	            nonce = nonce.subarray(16);
	        }
	        // Handle nonce counter
	        const nonceNcLen = 16 - counterLength;
	        if (nonceNcLen !== nonce.length)
	            throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
	        // Pad counter when nonce is 64 bit
	        if (nonceNcLen !== 12) {
	            const nc = new Uint8Array(12);
	            nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
	            nonce = nc;
	            toClean.push(nonce);
	        }
	        const n32 = (0, utils_js_1.u32)(nonce);
	        runCipher(core, sigma, k32, n32, data, output, counter, rounds);
	        (0, utils_js_1.clean)(...toClean);
	        return output;
	    };
	}
	
	return _arx;
}

var _poly1305 = {};

var hasRequired_poly1305;

function require_poly1305 () {
	if (hasRequired_poly1305) return _poly1305;
	hasRequired_poly1305 = 1;
	Object.defineProperty(_poly1305, "__esModule", { value: true });
	_poly1305.poly1305 = void 0;
	_poly1305.wrapConstructorWithKey = wrapConstructorWithKey;
	/**
	 * Poly1305 ([PDF](https://cr.yp.to/mac/poly1305-20050329.pdf),
	 * [wiki](https://en.wikipedia.org/wiki/Poly1305))
	 * is a fast and parallel secret-key message-authentication code suitable for
	 * a wide variety of applications. It was standardized in
	 * [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) and is now used in TLS 1.3.
	 *
	 * Polynomial MACs are not perfect for every situation:
	 * they lack Random Key Robustness: the MAC can be forged, and can't be used in PAKE schemes.
	 * See [invisible salamanders attack](https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/).
	 * To combat invisible salamanders, `hash(key)` can be included in ciphertext,
	 * however, this would violate ciphertext indistinguishability:
	 * an attacker would know which key was used - so `HKDF(key, i)`
	 * could be used instead.
	 *
	 * Check out [original website](https://cr.yp.to/mac.html).
	 * @module
	 */
	const _assert_js_1 = /*@__PURE__*/ require_assert$1();
	const utils_js_1 = /*@__PURE__*/ requireUtils$3();
	// Based on Public Domain poly1305-donna https://github.com/floodyberry/poly1305-donna
	const u8to16 = (a, i) => (a[i++] & 0xff) | ((a[i++] & 0xff) << 8);
	class Poly1305 {
	    constructor(key) {
	        this.blockLen = 16;
	        this.outputLen = 16;
	        this.buffer = new Uint8Array(16);
	        this.r = new Uint16Array(10);
	        this.h = new Uint16Array(10);
	        this.pad = new Uint16Array(8);
	        this.pos = 0;
	        this.finished = false;
	        key = (0, utils_js_1.toBytes)(key);
	        (0, _assert_js_1.abytes)(key, 32);
	        const t0 = u8to16(key, 0);
	        const t1 = u8to16(key, 2);
	        const t2 = u8to16(key, 4);
	        const t3 = u8to16(key, 6);
	        const t4 = u8to16(key, 8);
	        const t5 = u8to16(key, 10);
	        const t6 = u8to16(key, 12);
	        const t7 = u8to16(key, 14);
	        // https://github.com/floodyberry/poly1305-donna/blob/e6ad6e091d30d7f4ec2d4f978be1fcfcbce72781/poly1305-donna-16.h#L47
	        this.r[0] = t0 & 0x1fff;
	        this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
	        this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
	        this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
	        this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
	        this.r[5] = (t4 >>> 1) & 0x1ffe;
	        this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
	        this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
	        this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
	        this.r[9] = (t7 >>> 5) & 0x007f;
	        for (let i = 0; i < 8; i++)
	            this.pad[i] = u8to16(key, 16 + 2 * i);
	    }
	    process(data, offset, isLast = false) {
	        const hibit = isLast ? 0 : 1 << 11;
	        const { h, r } = this;
	        const r0 = r[0];
	        const r1 = r[1];
	        const r2 = r[2];
	        const r3 = r[3];
	        const r4 = r[4];
	        const r5 = r[5];
	        const r6 = r[6];
	        const r7 = r[7];
	        const r8 = r[8];
	        const r9 = r[9];
	        const t0 = u8to16(data, offset + 0);
	        const t1 = u8to16(data, offset + 2);
	        const t2 = u8to16(data, offset + 4);
	        const t3 = u8to16(data, offset + 6);
	        const t4 = u8to16(data, offset + 8);
	        const t5 = u8to16(data, offset + 10);
	        const t6 = u8to16(data, offset + 12);
	        const t7 = u8to16(data, offset + 14);
	        let h0 = h[0] + (t0 & 0x1fff);
	        let h1 = h[1] + (((t0 >>> 13) | (t1 << 3)) & 0x1fff);
	        let h2 = h[2] + (((t1 >>> 10) | (t2 << 6)) & 0x1fff);
	        let h3 = h[3] + (((t2 >>> 7) | (t3 << 9)) & 0x1fff);
	        let h4 = h[4] + (((t3 >>> 4) | (t4 << 12)) & 0x1fff);
	        let h5 = h[5] + ((t4 >>> 1) & 0x1fff);
	        let h6 = h[6] + (((t4 >>> 14) | (t5 << 2)) & 0x1fff);
	        let h7 = h[7] + (((t5 >>> 11) | (t6 << 5)) & 0x1fff);
	        let h8 = h[8] + (((t6 >>> 8) | (t7 << 8)) & 0x1fff);
	        let h9 = h[9] + ((t7 >>> 5) | hibit);
	        let c = 0;
	        let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
	        c = d0 >>> 13;
	        d0 &= 0x1fff;
	        d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
	        c += d0 >>> 13;
	        d0 &= 0x1fff;
	        let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
	        c = d1 >>> 13;
	        d1 &= 0x1fff;
	        d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
	        c += d1 >>> 13;
	        d1 &= 0x1fff;
	        let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
	        c = d2 >>> 13;
	        d2 &= 0x1fff;
	        d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
	        c += d2 >>> 13;
	        d2 &= 0x1fff;
	        let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9);
	        c = d3 >>> 13;
	        d3 &= 0x1fff;
	        d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
	        c += d3 >>> 13;
	        d3 &= 0x1fff;
	        let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
	        c = d4 >>> 13;
	        d4 &= 0x1fff;
	        d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
	        c += d4 >>> 13;
	        d4 &= 0x1fff;
	        let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
	        c = d5 >>> 13;
	        d5 &= 0x1fff;
	        d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
	        c += d5 >>> 13;
	        d5 &= 0x1fff;
	        let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
	        c = d6 >>> 13;
	        d6 &= 0x1fff;
	        d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
	        c += d6 >>> 13;
	        d6 &= 0x1fff;
	        let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
	        c = d7 >>> 13;
	        d7 &= 0x1fff;
	        d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
	        c += d7 >>> 13;
	        d7 &= 0x1fff;
	        let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
	        c = d8 >>> 13;
	        d8 &= 0x1fff;
	        d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
	        c += d8 >>> 13;
	        d8 &= 0x1fff;
	        let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
	        c = d9 >>> 13;
	        d9 &= 0x1fff;
	        d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
	        c += d9 >>> 13;
	        d9 &= 0x1fff;
	        c = ((c << 2) + c) | 0;
	        c = (c + d0) | 0;
	        d0 = c & 0x1fff;
	        c = c >>> 13;
	        d1 += c;
	        h[0] = d0;
	        h[1] = d1;
	        h[2] = d2;
	        h[3] = d3;
	        h[4] = d4;
	        h[5] = d5;
	        h[6] = d6;
	        h[7] = d7;
	        h[8] = d8;
	        h[9] = d9;
	    }
	    finalize() {
	        const { h, pad } = this;
	        const g = new Uint16Array(10);
	        let c = h[1] >>> 13;
	        h[1] &= 0x1fff;
	        for (let i = 2; i < 10; i++) {
	            h[i] += c;
	            c = h[i] >>> 13;
	            h[i] &= 0x1fff;
	        }
	        h[0] += c * 5;
	        c = h[0] >>> 13;
	        h[0] &= 0x1fff;
	        h[1] += c;
	        c = h[1] >>> 13;
	        h[1] &= 0x1fff;
	        h[2] += c;
	        g[0] = h[0] + 5;
	        c = g[0] >>> 13;
	        g[0] &= 0x1fff;
	        for (let i = 1; i < 10; i++) {
	            g[i] = h[i] + c;
	            c = g[i] >>> 13;
	            g[i] &= 0x1fff;
	        }
	        g[9] -= 1 << 13;
	        let mask = (c ^ 1) - 1;
	        for (let i = 0; i < 10; i++)
	            g[i] &= mask;
	        mask = ~mask;
	        for (let i = 0; i < 10; i++)
	            h[i] = (h[i] & mask) | g[i];
	        h[0] = (h[0] | (h[1] << 13)) & 0xffff;
	        h[1] = ((h[1] >>> 3) | (h[2] << 10)) & 0xffff;
	        h[2] = ((h[2] >>> 6) | (h[3] << 7)) & 0xffff;
	        h[3] = ((h[3] >>> 9) | (h[4] << 4)) & 0xffff;
	        h[4] = ((h[4] >>> 12) | (h[5] << 1) | (h[6] << 14)) & 0xffff;
	        h[5] = ((h[6] >>> 2) | (h[7] << 11)) & 0xffff;
	        h[6] = ((h[7] >>> 5) | (h[8] << 8)) & 0xffff;
	        h[7] = ((h[8] >>> 8) | (h[9] << 5)) & 0xffff;
	        let f = h[0] + pad[0];
	        h[0] = f & 0xffff;
	        for (let i = 1; i < 8; i++) {
	            f = (((h[i] + pad[i]) | 0) + (f >>> 16)) | 0;
	            h[i] = f & 0xffff;
	        }
	        (0, utils_js_1.clean)(g);
	    }
	    update(data) {
	        (0, _assert_js_1.aexists)(this);
	        const { buffer, blockLen } = this;
	        data = (0, utils_js_1.toBytes)(data);
	        const len = data.length;
	        for (let pos = 0; pos < len;) {
	            const take = Math.min(blockLen - this.pos, len - pos);
	            // Fast path: we have at least one block in input
	            if (take === blockLen) {
	                for (; blockLen <= len - pos; pos += blockLen)
	                    this.process(data, pos);
	                continue;
	            }
	            buffer.set(data.subarray(pos, pos + take), this.pos);
	            this.pos += take;
	            pos += take;
	            if (this.pos === blockLen) {
	                this.process(buffer, 0, false);
	                this.pos = 0;
	            }
	        }
	        return this;
	    }
	    destroy() {
	        (0, utils_js_1.clean)(this.h, this.r, this.buffer, this.pad);
	    }
	    digestInto(out) {
	        (0, _assert_js_1.aexists)(this);
	        (0, _assert_js_1.aoutput)(out, this);
	        this.finished = true;
	        const { buffer, h } = this;
	        let { pos } = this;
	        if (pos) {
	            buffer[pos++] = 1;
	            for (; pos < 16; pos++)
	                buffer[pos] = 0;
	            this.process(buffer, 0, true);
	        }
	        this.finalize();
	        let opos = 0;
	        for (let i = 0; i < 8; i++) {
	            out[opos++] = h[i] >>> 0;
	            out[opos++] = h[i] >>> 8;
	        }
	        return out;
	    }
	    digest() {
	        const { buffer, outputLen } = this;
	        this.digestInto(buffer);
	        const res = buffer.slice(0, outputLen);
	        this.destroy();
	        return res;
	    }
	}
	function wrapConstructorWithKey(hashCons) {
	    const hashC = (msg, key) => hashCons(key).update((0, utils_js_1.toBytes)(msg)).digest();
	    const tmp = hashCons(new Uint8Array(32));
	    hashC.outputLen = tmp.outputLen;
	    hashC.blockLen = tmp.blockLen;
	    hashC.create = (key) => hashCons(key);
	    return hashC;
	}
	/** Poly1305 MAC from RFC 8439. */
	_poly1305.poly1305 = wrapConstructorWithKey((key) => new Poly1305(key));
	
	return _poly1305;
}

var hasRequiredChacha;

function requireChacha () {
	if (hasRequiredChacha) return chacha;
	hasRequiredChacha = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.xchacha20poly1305 = exports.chacha20poly1305 = exports._poly1305_aead = exports.chacha12 = exports.chacha8 = exports.xchacha20 = exports.chacha20 = exports.chacha20orig = void 0;
		exports.hchacha = hchacha;
		/**
		 * [ChaCha20](https://cr.yp.to/chacha.html) stream cipher, released
		 * in 2008. Developed after Salsa20, ChaCha aims to increase diffusion per round.
		 * It was standardized in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) and
		 * is now used in TLS 1.3.
		 *
		 * [XChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
		 * extended-nonce variant is also provided. Similar to XSalsa, it's safe to use with
		 * randomly-generated nonces.
		 *
		 * Check out [PDF](http://cr.yp.to/chacha/chacha-20080128.pdf) and
		 * [wiki](https://en.wikipedia.org/wiki/Salsa20).
		 * @module
		 */
		const _arx_js_1 = /*@__PURE__*/ require_arx();
		const _poly1305_js_1 = /*@__PURE__*/ require_poly1305();
		const utils_js_1 = /*@__PURE__*/ requireUtils$3();
		/**
		 * ChaCha core function.
		 */
		// prettier-ignore
		function chachaCore(s, k, n, out, cnt, rounds = 20) {
		    let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], // "expa"   "nd 3"  "2-by"  "te k"
		    y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], // Key      Key     Key     Key
		    y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], // Key      Key     Key     Key
		    y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2]; // Counter  Counter	Nonce   Nonce
		    // Save state to temporary variables
		    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
		    for (let r = 0; r < rounds; r += 2) {
		        x00 = (x00 + x04) | 0;
		        x12 = (0, _arx_js_1.rotl)(x12 ^ x00, 16);
		        x08 = (x08 + x12) | 0;
		        x04 = (0, _arx_js_1.rotl)(x04 ^ x08, 12);
		        x00 = (x00 + x04) | 0;
		        x12 = (0, _arx_js_1.rotl)(x12 ^ x00, 8);
		        x08 = (x08 + x12) | 0;
		        x04 = (0, _arx_js_1.rotl)(x04 ^ x08, 7);
		        x01 = (x01 + x05) | 0;
		        x13 = (0, _arx_js_1.rotl)(x13 ^ x01, 16);
		        x09 = (x09 + x13) | 0;
		        x05 = (0, _arx_js_1.rotl)(x05 ^ x09, 12);
		        x01 = (x01 + x05) | 0;
		        x13 = (0, _arx_js_1.rotl)(x13 ^ x01, 8);
		        x09 = (x09 + x13) | 0;
		        x05 = (0, _arx_js_1.rotl)(x05 ^ x09, 7);
		        x02 = (x02 + x06) | 0;
		        x14 = (0, _arx_js_1.rotl)(x14 ^ x02, 16);
		        x10 = (x10 + x14) | 0;
		        x06 = (0, _arx_js_1.rotl)(x06 ^ x10, 12);
		        x02 = (x02 + x06) | 0;
		        x14 = (0, _arx_js_1.rotl)(x14 ^ x02, 8);
		        x10 = (x10 + x14) | 0;
		        x06 = (0, _arx_js_1.rotl)(x06 ^ x10, 7);
		        x03 = (x03 + x07) | 0;
		        x15 = (0, _arx_js_1.rotl)(x15 ^ x03, 16);
		        x11 = (x11 + x15) | 0;
		        x07 = (0, _arx_js_1.rotl)(x07 ^ x11, 12);
		        x03 = (x03 + x07) | 0;
		        x15 = (0, _arx_js_1.rotl)(x15 ^ x03, 8);
		        x11 = (x11 + x15) | 0;
		        x07 = (0, _arx_js_1.rotl)(x07 ^ x11, 7);
		        x00 = (x00 + x05) | 0;
		        x15 = (0, _arx_js_1.rotl)(x15 ^ x00, 16);
		        x10 = (x10 + x15) | 0;
		        x05 = (0, _arx_js_1.rotl)(x05 ^ x10, 12);
		        x00 = (x00 + x05) | 0;
		        x15 = (0, _arx_js_1.rotl)(x15 ^ x00, 8);
		        x10 = (x10 + x15) | 0;
		        x05 = (0, _arx_js_1.rotl)(x05 ^ x10, 7);
		        x01 = (x01 + x06) | 0;
		        x12 = (0, _arx_js_1.rotl)(x12 ^ x01, 16);
		        x11 = (x11 + x12) | 0;
		        x06 = (0, _arx_js_1.rotl)(x06 ^ x11, 12);
		        x01 = (x01 + x06) | 0;
		        x12 = (0, _arx_js_1.rotl)(x12 ^ x01, 8);
		        x11 = (x11 + x12) | 0;
		        x06 = (0, _arx_js_1.rotl)(x06 ^ x11, 7);
		        x02 = (x02 + x07) | 0;
		        x13 = (0, _arx_js_1.rotl)(x13 ^ x02, 16);
		        x08 = (x08 + x13) | 0;
		        x07 = (0, _arx_js_1.rotl)(x07 ^ x08, 12);
		        x02 = (x02 + x07) | 0;
		        x13 = (0, _arx_js_1.rotl)(x13 ^ x02, 8);
		        x08 = (x08 + x13) | 0;
		        x07 = (0, _arx_js_1.rotl)(x07 ^ x08, 7);
		        x03 = (x03 + x04) | 0;
		        x14 = (0, _arx_js_1.rotl)(x14 ^ x03, 16);
		        x09 = (x09 + x14) | 0;
		        x04 = (0, _arx_js_1.rotl)(x04 ^ x09, 12);
		        x03 = (x03 + x04) | 0;
		        x14 = (0, _arx_js_1.rotl)(x14 ^ x03, 8);
		        x09 = (x09 + x14) | 0;
		        x04 = (0, _arx_js_1.rotl)(x04 ^ x09, 7);
		    }
		    // Write output
		    let oi = 0;
		    out[oi++] = (y00 + x00) | 0;
		    out[oi++] = (y01 + x01) | 0;
		    out[oi++] = (y02 + x02) | 0;
		    out[oi++] = (y03 + x03) | 0;
		    out[oi++] = (y04 + x04) | 0;
		    out[oi++] = (y05 + x05) | 0;
		    out[oi++] = (y06 + x06) | 0;
		    out[oi++] = (y07 + x07) | 0;
		    out[oi++] = (y08 + x08) | 0;
		    out[oi++] = (y09 + x09) | 0;
		    out[oi++] = (y10 + x10) | 0;
		    out[oi++] = (y11 + x11) | 0;
		    out[oi++] = (y12 + x12) | 0;
		    out[oi++] = (y13 + x13) | 0;
		    out[oi++] = (y14 + x14) | 0;
		    out[oi++] = (y15 + x15) | 0;
		}
		/**
		 * hchacha helper method, used primarily in xchacha, to hash
		 * key and nonce into key' and nonce'.
		 * Same as chachaCore, but there doesn't seem to be a way to move the block
		 * out without 25% performance hit.
		 */
		// prettier-ignore
		function hchacha(s, k, i, o32) {
		    let x00 = s[0], x01 = s[1], x02 = s[2], x03 = s[3], x04 = k[0], x05 = k[1], x06 = k[2], x07 = k[3], x08 = k[4], x09 = k[5], x10 = k[6], x11 = k[7], x12 = i[0], x13 = i[1], x14 = i[2], x15 = i[3];
		    for (let r = 0; r < 20; r += 2) {
		        x00 = (x00 + x04) | 0;
		        x12 = (0, _arx_js_1.rotl)(x12 ^ x00, 16);
		        x08 = (x08 + x12) | 0;
		        x04 = (0, _arx_js_1.rotl)(x04 ^ x08, 12);
		        x00 = (x00 + x04) | 0;
		        x12 = (0, _arx_js_1.rotl)(x12 ^ x00, 8);
		        x08 = (x08 + x12) | 0;
		        x04 = (0, _arx_js_1.rotl)(x04 ^ x08, 7);
		        x01 = (x01 + x05) | 0;
		        x13 = (0, _arx_js_1.rotl)(x13 ^ x01, 16);
		        x09 = (x09 + x13) | 0;
		        x05 = (0, _arx_js_1.rotl)(x05 ^ x09, 12);
		        x01 = (x01 + x05) | 0;
		        x13 = (0, _arx_js_1.rotl)(x13 ^ x01, 8);
		        x09 = (x09 + x13) | 0;
		        x05 = (0, _arx_js_1.rotl)(x05 ^ x09, 7);
		        x02 = (x02 + x06) | 0;
		        x14 = (0, _arx_js_1.rotl)(x14 ^ x02, 16);
		        x10 = (x10 + x14) | 0;
		        x06 = (0, _arx_js_1.rotl)(x06 ^ x10, 12);
		        x02 = (x02 + x06) | 0;
		        x14 = (0, _arx_js_1.rotl)(x14 ^ x02, 8);
		        x10 = (x10 + x14) | 0;
		        x06 = (0, _arx_js_1.rotl)(x06 ^ x10, 7);
		        x03 = (x03 + x07) | 0;
		        x15 = (0, _arx_js_1.rotl)(x15 ^ x03, 16);
		        x11 = (x11 + x15) | 0;
		        x07 = (0, _arx_js_1.rotl)(x07 ^ x11, 12);
		        x03 = (x03 + x07) | 0;
		        x15 = (0, _arx_js_1.rotl)(x15 ^ x03, 8);
		        x11 = (x11 + x15) | 0;
		        x07 = (0, _arx_js_1.rotl)(x07 ^ x11, 7);
		        x00 = (x00 + x05) | 0;
		        x15 = (0, _arx_js_1.rotl)(x15 ^ x00, 16);
		        x10 = (x10 + x15) | 0;
		        x05 = (0, _arx_js_1.rotl)(x05 ^ x10, 12);
		        x00 = (x00 + x05) | 0;
		        x15 = (0, _arx_js_1.rotl)(x15 ^ x00, 8);
		        x10 = (x10 + x15) | 0;
		        x05 = (0, _arx_js_1.rotl)(x05 ^ x10, 7);
		        x01 = (x01 + x06) | 0;
		        x12 = (0, _arx_js_1.rotl)(x12 ^ x01, 16);
		        x11 = (x11 + x12) | 0;
		        x06 = (0, _arx_js_1.rotl)(x06 ^ x11, 12);
		        x01 = (x01 + x06) | 0;
		        x12 = (0, _arx_js_1.rotl)(x12 ^ x01, 8);
		        x11 = (x11 + x12) | 0;
		        x06 = (0, _arx_js_1.rotl)(x06 ^ x11, 7);
		        x02 = (x02 + x07) | 0;
		        x13 = (0, _arx_js_1.rotl)(x13 ^ x02, 16);
		        x08 = (x08 + x13) | 0;
		        x07 = (0, _arx_js_1.rotl)(x07 ^ x08, 12);
		        x02 = (x02 + x07) | 0;
		        x13 = (0, _arx_js_1.rotl)(x13 ^ x02, 8);
		        x08 = (x08 + x13) | 0;
		        x07 = (0, _arx_js_1.rotl)(x07 ^ x08, 7);
		        x03 = (x03 + x04) | 0;
		        x14 = (0, _arx_js_1.rotl)(x14 ^ x03, 16);
		        x09 = (x09 + x14) | 0;
		        x04 = (0, _arx_js_1.rotl)(x04 ^ x09, 12);
		        x03 = (x03 + x04) | 0;
		        x14 = (0, _arx_js_1.rotl)(x14 ^ x03, 8);
		        x09 = (x09 + x14) | 0;
		        x04 = (0, _arx_js_1.rotl)(x04 ^ x09, 7);
		    }
		    let oi = 0;
		    o32[oi++] = x00;
		    o32[oi++] = x01;
		    o32[oi++] = x02;
		    o32[oi++] = x03;
		    o32[oi++] = x12;
		    o32[oi++] = x13;
		    o32[oi++] = x14;
		    o32[oi++] = x15;
		}
		/**
		 * Original, non-RFC chacha20 from DJB. 8-byte nonce, 8-byte counter.
		 */
		exports.chacha20orig = (0, _arx_js_1.createCipher)(chachaCore, {
		    counterRight: false,
		    counterLength: 8,
		    allowShortKeys: true,
		});
		/**
		 * ChaCha stream cipher. Conforms to RFC 8439 (IETF, TLS). 12-byte nonce, 4-byte counter.
		 * With 12-byte nonce, it's not safe to use fill it with random (CSPRNG), due to collision chance.
		 */
		exports.chacha20 = (0, _arx_js_1.createCipher)(chachaCore, {
		    counterRight: false,
		    counterLength: 4,
		    allowShortKeys: false,
		});
		/**
		 * XChaCha eXtended-nonce ChaCha. 24-byte nonce.
		 * With 24-byte nonce, it's safe to use fill it with random (CSPRNG).
		 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
		 */
		exports.xchacha20 = (0, _arx_js_1.createCipher)(chachaCore, {
		    counterRight: false,
		    counterLength: 8,
		    extendNonceFn: hchacha,
		    allowShortKeys: false,
		});
		/**
		 * Reduced 8-round chacha, described in original paper.
		 */
		exports.chacha8 = (0, _arx_js_1.createCipher)(chachaCore, {
		    counterRight: false,
		    counterLength: 4,
		    rounds: 8,
		});
		/**
		 * Reduced 12-round chacha, described in original paper.
		 */
		exports.chacha12 = (0, _arx_js_1.createCipher)(chachaCore, {
		    counterRight: false,
		    counterLength: 4,
		    rounds: 12,
		});
		const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
		// Pad to digest size with zeros
		const updatePadded = (h, msg) => {
		    h.update(msg);
		    const left = msg.length % 16;
		    if (left)
		        h.update(ZEROS16.subarray(left));
		};
		const ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
		function computeTag(fn, key, nonce, data, AAD) {
		    const authKey = fn(key, nonce, ZEROS32);
		    const h = _poly1305_js_1.poly1305.create(authKey);
		    if (AAD)
		        updatePadded(h, AAD);
		    updatePadded(h, data);
		    const num = new Uint8Array(16);
		    const view = (0, utils_js_1.createView)(num);
		    (0, utils_js_1.setBigUint64)(view, 0, BigInt(AAD ? AAD.length : 0), true);
		    (0, utils_js_1.setBigUint64)(view, 8, BigInt(data.length), true);
		    h.update(num);
		    const res = h.digest();
		    (0, utils_js_1.clean)(authKey, num);
		    return res;
		}
		/**
		 * AEAD algorithm from RFC 8439.
		 * Salsa20 and chacha (RFC 8439) use poly1305 differently.
		 * We could have composed them similar to:
		 * https://github.com/paulmillr/scure-base/blob/b266c73dde977b1dd7ef40ef7a23cc15aab526b3/index.ts#L250
		 * But it's hard because of authKey:
		 * In salsa20, authKey changes position in salsa stream.
		 * In chacha, authKey can't be computed inside computeTag, it modifies the counter.
		 */
		const _poly1305_aead = (xorStream) => (key, nonce, AAD) => {
		    const tagLength = 16;
		    return {
		        encrypt(plaintext, output) {
		            const plength = plaintext.length;
		            output = (0, utils_js_1.getOutput)(plength + tagLength, output, false);
		            output.set(plaintext);
		            const oPlain = output.subarray(0, -tagLength);
		            xorStream(key, nonce, oPlain, oPlain, 1);
		            const tag = computeTag(xorStream, key, nonce, oPlain, AAD);
		            output.set(tag, plength); // append tag
		            (0, utils_js_1.clean)(tag);
		            return output;
		        },
		        decrypt(ciphertext, output) {
		            output = (0, utils_js_1.getOutput)(ciphertext.length - tagLength, output, false);
		            const data = ciphertext.subarray(0, -tagLength);
		            const passedTag = ciphertext.subarray(-tagLength);
		            const tag = computeTag(xorStream, key, nonce, data, AAD);
		            if (!(0, utils_js_1.equalBytes)(passedTag, tag))
		                throw new Error('invalid tag');
		            output.set(ciphertext.subarray(0, -tagLength));
		            xorStream(key, nonce, output, output, 1); // start stream with i=1
		            (0, utils_js_1.clean)(tag);
		            return output;
		        },
		    };
		};
		exports._poly1305_aead = _poly1305_aead;
		/**
		 * ChaCha20-Poly1305 from RFC 8439.
		 *
		 * Unsafe to use random nonces under the same key, due to collision chance.
		 * Prefer XChaCha instead.
		 */
		exports.chacha20poly1305 = (0, utils_js_1.wrapCipher)({ blockSize: 64, nonceLength: 12, tagLength: 16 }, (0, exports._poly1305_aead)(exports.chacha20));
		/**
		 * XChaCha20-Poly1305 extended-nonce chacha.
		 *
		 * Can be safely used with random nonces (CSPRNG).
		 * See [IRTF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
		 */
		exports.xchacha20poly1305 = (0, utils_js_1.wrapCipher)({ blockSize: 64, nonceLength: 24, tagLength: 16 }, (0, exports._poly1305_aead)(exports.xchacha20));
		
	} (chacha));
	return chacha;
}

var hasRequiredNoble;

function requireNoble () {
	if (hasRequiredNoble) return noble;
	hasRequiredNoble = 1;
	Object.defineProperty(noble, "__esModule", { value: true });
	noble.chacha20 = noble.xchacha20 = void 0;
	var chacha_1 = /*@__PURE__*/ requireChacha();
	var xchacha20 = function (key, nonce, AAD) {
	    return (0, chacha_1.xchacha20poly1305)(key, nonce, AAD);
	};
	noble.xchacha20 = xchacha20;
	var chacha20 = function (key, nonce, AAD) {
	    return (0, chacha_1.chacha20poly1305)(key, nonce, AAD);
	};
	noble.chacha20 = chacha20;
	return noble;
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
		var aes_1 = requireNoble$1();
		var chacha_1 = requireNoble();
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
	if (hasRequiredUtils) return utils$4;
	hasRequiredUtils = 1;
	(function (exports) {
		var __createBinding = (utils$4 && utils$4.__createBinding) || (Object.create ? (function(o, m, k, k2) {
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
		var __exportStar = (utils$4 && utils$4.__exportStar) || function(m, exports) {
		    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
		};
		Object.defineProperty(exports, "__esModule", { value: true });
		__exportStar(requireElliptic(), exports);
		__exportStar(requireHash(), exports);
		__exportStar(requireHex(), exports);
		__exportStar(requireSymmetric(), exports); 
	} (utils$4));
	return utils$4;
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

/**
 * Environment detection utility
 * Helps distinguish between Node.js and browser environments
 */
const isBrowser = () => {
    return (typeof window !== 'undefined' && typeof window.document !== 'undefined');
};
const isNode = () => {
    return (typeof process !== 'undefined' &&
        process.versions &&
        process.versions.node !== undefined);
};
const isWebWorker = () => {
    return (typeof globalThis.importScripts === 'function' &&
        typeof navigator !== 'undefined');
};
const hasWebCrypto = () => {
    return (isBrowser() &&
        typeof window.crypto !== 'undefined' &&
        typeof window.crypto.subtle !== 'undefined');
};

class NodeCryptoAdapter {
    crypto;
    constructor() {
        if (isBrowser()) {
            throw new Error('NodeCryptoAdapter can only be used in Node.js environment');
        }
    }
    async getCrypto() {
        if (!this.crypto) {
            this.crypto = await import('crypto');
        }
        return this.crypto;
    }
    async aesGCMEncrypt(key, data, iv) {
        const crypto = await this.getCrypto();
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return { encrypted, authTag };
    }
    async aesGCMDecrypt(key, encryptedData, iv, authTag) {
        const crypto = await this.getCrypto();
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([
            decipher.update(encryptedData),
            decipher.final(),
        ]);
        return decrypted;
    }
    randomBytes(length) {
        if (this.crypto) {
            return this.crypto.randomBytes(length);
        }
        // For synchronous random bytes in Node.js, we'll need to handle this differently
        // This is a limitation - ideally this should be async
        const array = new Uint8Array(length);
        // Use Node.js crypto if available (simplified fallback)
        // In production, this should ideally be async
        try {
            // Check if we're in Node.js environment by checking for process
            if (typeof process !== 'undefined' && process.versions?.node) {
                // Import crypto-browserify as fallback for browser compatibility
                const cryptoBrowserify = require('crypto-browserify');
                return cryptoBrowserify.randomBytes(length);
            }
        }
        catch {
            // Crypto not available
        }
        // Fallback to Math.random (not cryptographically secure, but functional)
        console.warn('Using Math.random for random bytes - not cryptographically secure');
        for (let i = 0; i < length; i++) {
            array[i] = Math.floor(Math.random() * 256);
        }
        return Buffer.from(array);
    }
}
class BrowserCryptoAdapter {
    constructor() {
        if (!hasWebCrypto()) {
            throw new Error('Web Crypto API is not available in this browser');
        }
    }
    async aesGCMEncrypt(key, data, iv) {
        const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
        const result = await crypto.subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128,
        }, cryptoKey, data);
        const encrypted = new Uint8Array(result.slice(0, -16));
        const authTag = new Uint8Array(result.slice(-16));
        return {
            encrypted: Buffer.from(encrypted),
            authTag: Buffer.from(authTag),
        };
    }
    async aesGCMDecrypt(key, encryptedData, iv, authTag) {
        const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
        const combined = new Uint8Array(encryptedData.length + authTag.length);
        combined.set(encryptedData, 0);
        combined.set(authTag, encryptedData.length);
        const result = await crypto.subtle.decrypt({
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128,
        }, cryptoKey, combined);
        return Buffer.from(result);
    }
    randomBytes(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Buffer.from(array);
    }
}
let cryptoAdapter = null;
function getCryptoAdapter() {
    if (!cryptoAdapter) {
        if (isBrowser()) {
            cryptoAdapter = new BrowserCryptoAdapter();
        }
        else {
            cryptoAdapter = new NodeCryptoAdapter();
        }
    }
    return cryptoAdapter;
}

const ivLength = 12;
const tagLength = 16;
const sigLength = 65;
const chunkLength = 64 * 1024 * 1024 + tagLength;
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
async function signTaskID(signer, taskID) {
    const hash = ethers.solidityPackedKeccak256(['bytes'], ['0x' + taskID.replace(/-/g, '')]);
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
    if (isBrowser()) {
        throw new Error('File operations are not supported in browser environment. Use aesGCMDecrypt with ArrayBuffer instead.');
    }
    // Only import fs when in Node.js environment
    const { promises: fs } = await import('fs');
    const fd = await fs.open(encryptedModelPath, 'r');
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
    const writeFd = await fs.open(decryptedModelPath, 'w');
    const cryptoAdapter = getCryptoAdapter();
    // read chunks
    while (true) {
        readResult = await fd.read(buffer, 0, chunkLength, offset);
        const chunkSize = readResult.bytesRead;
        if (chunkSize === 0) {
            break;
        }
        const tag = buffer.subarray(chunkSize - tagLength, chunkSize);
        const encryptedChunk = buffer.subarray(0, chunkSize - tagLength);
        const decrypted = await cryptoAdapter.aesGCMDecrypt(privateKey, Buffer.from(encryptedChunk), Buffer.from(iv), Buffer.from(tag));
        await writeFd.appendFile(decrypted);
        tagsBuffer = Buffer.concat([tagsBuffer, tag]);
        offset += chunkSize;
        for (let i = iv.length - 1; i >= 0; i--) {
            iv[i]++;
            if (iv[i] !== 0)
                break;
        }
    }
    await writeFd.close();
    await fd.close();
    const recoveredAddress = ethers.recoverAddress(ethers.keccak256(tagsBuffer), '0x' + tagSig.toString('hex'));
    if (recoveredAddress.toLowerCase() !== providerSigner.toLowerCase()) {
        throw new Error('Invalid tag signature');
    }
}

function getNonce() {
    const now = new Date();
    return now.getTime() * 10000 + 40;
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
        ],
        name: 'InsufficientBalance',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'serviceAddress',
                type: 'address',
            },
        ],
        name: 'InvalidServiceAddress',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
        ],
        name: 'InvalidServiceType',
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
        inputs: [
            {
                internalType: 'string',
                name: 'serviceName',
                type: 'string',
            },
        ],
        name: 'ServiceNameExists',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'address',
                name: 'serviceAddress',
                type: 'address',
            },
        ],
        name: 'ServiceNotRegistered',
        type: 'error',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: 'requested',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'maximum',
                type: 'uint256',
            },
        ],
        name: 'TooManyProviders',
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
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
            {
                indexed: false,
                internalType: 'string',
                name: 'version',
                type: 'string',
            },
            {
                indexed: false,
                internalType: 'address',
                name: 'serviceAddress',
                type: 'address',
            },
        ],
        name: 'RecommendedServiceUpdated',
        type: 'event',
    },
    {
        anonymous: false,
        inputs: [
            {
                indexed: true,
                internalType: 'address',
                name: 'serviceAddress',
                type: 'address',
            },
            {
                indexed: false,
                internalType: 'string',
                name: 'serviceName',
                type: 'string',
            },
        ],
        name: 'ServiceRegistered',
        type: 'event',
    },
    {
        inputs: [],
        name: 'MAX_PROVIDERS_PER_BATCH',
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
        name: 'getAllActiveServices',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'serviceAddress',
                        type: 'address',
                    },
                    {
                        internalType: 'contract IServing',
                        name: 'serviceContract',
                        type: 'address',
                    },
                    {
                        internalType: 'string',
                        name: 'serviceType',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'version',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'fullName',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'description',
                        type: 'string',
                    },
                    {
                        internalType: 'bool',
                        name: 'isRecommended',
                        type: 'bool',
                    },
                    {
                        internalType: 'uint256',
                        name: 'registeredAt',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct ServiceInfo[]',
                name: '',
                type: 'tuple[]',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: 'offset',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'limit',
                type: 'uint256',
            },
        ],
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
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
                    },
                ],
                internalType: 'struct Ledger[]',
                name: 'ledgers',
                type: 'tuple[]',
            },
            {
                internalType: 'uint256',
                name: 'total',
                type: 'uint256',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
        ],
        name: 'getAllVersions',
        outputs: [
            {
                internalType: 'string[]',
                name: 'versions',
                type: 'string[]',
            },
            {
                internalType: 'address[]',
                name: 'addresses',
                type: 'address[]',
            },
            {
                internalType: 'bool[]',
                name: 'isRecommendedFlags',
                type: 'bool[]',
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
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
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
        inputs: [
            {
                internalType: 'address',
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'string',
                name: 'serviceName',
                type: 'string',
            },
        ],
        name: 'getLedgerProviders',
        outputs: [
            {
                internalType: 'address[]',
                name: '',
                type: 'address[]',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
        ],
        name: 'getRecommendedService',
        outputs: [
            {
                internalType: 'string',
                name: 'version',
                type: 'string',
            },
            {
                internalType: 'address',
                name: 'serviceAddress',
                type: 'address',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'string',
                name: 'serviceName',
                type: 'string',
            },
        ],
        name: 'getServiceAddressByName',
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
                name: 'serviceAddress',
                type: 'address',
            },
        ],
        name: 'getServiceInfo',
        outputs: [
            {
                components: [
                    {
                        internalType: 'address',
                        name: 'serviceAddress',
                        type: 'address',
                    },
                    {
                        internalType: 'contract IServing',
                        name: 'serviceContract',
                        type: 'address',
                    },
                    {
                        internalType: 'string',
                        name: 'serviceType',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'version',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'fullName',
                        type: 'string',
                    },
                    {
                        internalType: 'string',
                        name: 'description',
                        type: 'string',
                    },
                    {
                        internalType: 'bool',
                        name: 'isRecommended',
                        type: 'bool',
                    },
                    {
                        internalType: 'uint256',
                        name: 'registeredAt',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct ServiceInfo',
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
        inputs: [
            {
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
            {
                internalType: 'string',
                name: 'version',
                type: 'string',
            },
        ],
        name: 'isRecommendedVersion',
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
        inputs: [
            {
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
            {
                internalType: 'string',
                name: 'version',
                type: 'string',
            },
            {
                internalType: 'address',
                name: 'serviceAddress',
                type: 'address',
            },
            {
                internalType: 'string',
                name: 'description',
                type: 'string',
            },
        ],
        name: 'registerService',
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
                internalType: 'string',
                name: 'serviceType',
                type: 'string',
            },
            {
                internalType: 'string',
                name: 'version',
                type: 'string',
            },
        ],
        name: 'setRecommendedService',
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
                name: 'serviceName',
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
const _bytecode$2 = '0x60806040523480156200001157600080fd5b506200001d3362000027565b6001805562000077565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b613c7180620000876000396000f3fe60806040526004361061014f5760003560e01c8063987086f0116100b6578063c5e53f7e1161006f578063c5e53f7e146103c9578063d4dca96d146103f1578063dd8a411814610420578063e032f73214610440578063f2fde38b1461046d578063f7cd6af91461048d57600080fd5b8063987086f0146102ec5780639ade39721461031a578063a26105651461033c578063aef421731461035c578063b8d5e58114610389578063c4d66de8146103a957600080fd5b8063410b381511610108578063410b381514610245578063715018a61461025a5780638158c9e51461026f5780638d0d8cb61461028f5780638da5cb5b146102975780639449fe17146102c957600080fd5b80630e8641741461015b578063158ef93e146101925780631ef4dc44146101c3578063278ecde1146101e55780632ba43b821461020557806331404a191461022557600080fd5b3661015657005b600080fd5b34801561016757600080fd5b5061017b610176366004613197565b6104ba565b604051610189929190613223565b60405180910390f35b34801561019e57600080fd5b506000546101b390600160a01b900460ff1681565b6040519015158152602001610189565b3480156101cf57600080fd5b506101e36101de366004613269565b61067c565b005b3480156101f157600080fd5b506101e3610200366004613301565b610afc565b34801561021157600080fd5b506101e361022036600461331a565b610c02565b34801561023157600080fd5b506101e3610240366004613370565b611058565b34801561025157600080fd5b506101e36112f2565b34801561026657600080fd5b506101e3611658565b34801561027b57600080fd5b506101e361028a36600461343e565b61166a565b6101e3611766565b3480156102a357600080fd5b506000546001600160a01b03165b6040516001600160a01b039091168152602001610189565b3480156102d557600080fd5b506102de601481565b604051908152602001610189565b3480156102f857600080fd5b5061030c61030736600461348a565b611816565b6040516101899291906134e7565b34801561032657600080fd5b5061032f611a09565b604051610189919061360d565b34801561034857600080fd5b506101b361035736600461343e565b611d68565b34801561036857600080fd5b5061037c61037736600461366f565b611df4565b60405161018991906136f6565b34801561039557600080fd5b506102b16103a4366004613197565b611fdd565b3480156103b557600080fd5b506101e36103c4366004613709565b61200e565b6103dc6103d7366004613197565b612092565b60408051928352602083019190915201610189565b3480156103fd57600080fd5b5061041161040c366004613197565b61214e565b60405161018993929190613724565b34801561042c57600080fd5b506101e361043b3660046137d6565b6124a7565b34801561044c57600080fd5b5061046061045b366004613709565b612606565b6040516101899190613800565b34801561047957600080fd5b506101e3610488366004613709565b6128b4565b34801561049957600080fd5b506104ad6104a8366004613709565b61292a565b6040516101899190613813565b60606000806104c96004612a09565b905060005b8181101561061b5760006104e3600483612a13565b6001600160a01b0381166000908152600260209081526040918290209151929350909161051291899101613826565b604051602081830303815290604052805190602001208160020160405160200161053c919061387c565b604051602081830303815290604052805190602001201480156105635750600681015460ff165b1561060657806003018281805461057990613842565b80601f01602080910402602001604051908101604052809291908181526020018280546105a590613842565b80156105f25780601f106105c7576101008083540402835291602001916105f2565b820191906000526020600020905b8154815290600101906020018083116105d557829003601f168201915b505050505091509550955050505050915091565b5050808061061390613908565b9150506104ce565b5060405162461bcd60e51b815260206004820152602a60248201527f4e6f207265636f6d6d656e646564207365727669636520666f756e6420666f726044820152692074686973207479706560b01b60648201526084015b60405180910390fd5b610684612a26565b6001600160a01b0382166106da5760405162461bcd60e51b815260206004820152601760248201527f496e76616c6964207365727669636520616464726573730000000000000000006044820152606401610673565b60008451116107235760405162461bcd60e51b815260206004820152601560248201527414d95c9d9a58d9481d1e5c19481c995c5d5a5c9959605a1b6044820152606401610673565b60008351116107675760405162461bcd60e51b815260206004820152601060248201526f15995c9cda5bdb881c995c5d5a5c995960821b6044820152606401610673565b6001600160a01b0382811660009081526002602052604090205416156107cf5760405162461bcd60e51b815260206004820152601a60248201527f5365727669636520616c726561647920726567697374657265640000000000006044820152606401610673565b600084846040516020016107e4929190613921565b604051602081830303815290604052905060006001600160a01b03166003826040516108109190613826565b908152604051908190036020019020546001600160a01b0316146108765760405162461bcd60e51b815260206004820152601b60248201527f53657276696365206e616d6520616c72656164792065786973747300000000006044820152606401610673565b6108906001600160a01b0384166301ffc9a760e01b612a80565b6108f45760405162461bcd60e51b815260206004820152602f60248201527f53657276696365206d75737420737570706f72742045524331363520696e746560448201526e393330b1b2903232ba32b1ba34b7b760891b6064820152608401610673565b61090e6001600160a01b03841663160841b160e01b612a80565b61096c5760405162461bcd60e51b815260206004820152602960248201527f53657276696365206d75737420696d706c656d656e74204953657276696e6720604482015268696e7465726661636560b81b6064820152608401610673565b60408051610100810182526001600160a01b0380861680835260208084018281528486018b8152606086018b90526080860188905260a08601899052600060c087018190524260e088015293845260029283905295909220845181549085166001600160a01b0319918216178255925160018201805491909516931692909217909255925191929190820190610a0290826139a3565b5060608201516003820190610a1790826139a3565b5060808201516004820190610a2c90826139a3565b5060a08201516005820190610a4190826139a3565b5060c082015160068201805460ff191691151591909117905560e0909101516007909101556040518390600390610a79908490613826565b90815260405190819003602001902080546001600160a01b03929092166001600160a01b0319909216919091179055610ab3600484612a9c565b50826001600160a01b03167f4c76643f3c678c590db6e8ad9fe0bb6e75d36cb853c3bd06c487607ff35e6f7182604051610aed9190613a62565b60405180910390a25050505050565b336000610b0882612ab1565b60008181526009602052604090205490915060ff1615610b3a5760405162461bcd60e51b815260040161067390613a75565b6000818152600960205260408120805460ff19166001179055610b5c33612ae5565b90508381600101541015610b855760405163112fed8b60e31b8152336004820152602401610673565b83816001016000828254610b999190613aac565b9250508190555083816002016000828254610bb49190613aac565b9091555050604051339085156108fc029086906000818181858888f19350505050158015610be6573d6000803e3d6000fd5b50506000908152600960205260409020805460ff191690555050565b336000610c0e82612ab1565b60008181526009602052604090205490915060ff1615610c405760405162461bcd60e51b815260040161067390613a75565b6000818152600960205260408120805460ff19166001179055610c6233612ae5565b90506000600386604051610c769190613826565b908152604051908190036020019020546001600160a01b0316905080610cae5760405162461bcd60e51b815260040161067390613abf565b6001600160a01b038082166000908152600260205260409081902080546001820154925163147500e360e01b81523360048201528b8516602482015291939081169216908890606090839063147500e390604401602060405180830381865afa158015610d1f573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d439190613aea565b15610e4057604051631320b9eb60e11b81523360048201526001600160a01b038d811660248301526000919085169063264173d690604401602060405180830381865afa158015610d98573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610dbc9190613b0c565b90506000610dca8c83612b38565b9050610dd68185613aac565b9350338e82604051602401610e0c939291906001600160a01b039384168152919092166020820152604081019190915260600190565b60408051601f198184030181529190526020810180516001600160e01b031663745e87f760e01b1790529250610f1f915050565b338c88600301604051602401610e5893929190613b25565b60408051601f198184030181529190526020810180516001600160e01b031663e50688f960e01b179052600286018054919250610f1f91339190610e9b90613842565b80601f0160208091040260200160405190810160405280929190818152602001828054610ec790613842565b8015610f145780601f10610ee957610100808354040283529160200191610f14565b820191906000526020600020905b815481529060010190602001808311610ef757829003601f168201915b50505050508e612b4e565b8187600101541015610f6a5760405162461bcd60e51b8152602060048201526014602482015273496e73756666696369656e742062616c616e636560601b6044820152606401610673565b81876001016000828254610f7e9190613aac565b925050819055506000846001600160a01b03168383604051610fa09190613826565b60006040518083038185875af1925050503d8060008114610fdd576040519150601f19603f3d011682016040523d82523d6000602084013e610fe2565b606091505b50509050806110335760405162461bcd60e51b815260206004820152601d60248201527f43616c6c20746f206368696c6420636f6e7472616374206661696c65640000006044820152606401610673565b50505060009586525050600960205250506040909120805460ff191690555050505050565b33600061106482612ab1565b60008181526009602052604090205490915060ff16156110965760405162461bcd60e51b815260040161067390613a75565b6000818152600960205260409020805460ff191660011790558351601410156110df57835160405163414f261960e11b8152600481019190915260146024820152604401610673565b60006003846040516110f19190613826565b908152604051908190036020019020546001600160a01b03169050806111295760405162461bcd60e51b815260040161067390613abf565b6001600160a01b03808216600090815260026020526040812060018101549092169061115433612ae5565b90506000805b89518110156112b8576000846001600160a01b0316634e3c4f22338d858151811061118757611187613bce565b60200260200101516040518363ffffffff1660e01b81526004016111c19291906001600160a01b0392831681529116602082015260400190565b6060604051808303816000875af11580156111e0573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906112049190613be4565b5050905080836112149190613c12565b9250846001600160a01b0316636c79158d338d858151811061123857611238613bce565b60200260200101516040518363ffffffff1660e01b81526004016112729291906001600160a01b0392831681529116602082015260400190565b600060405180830381600087803b15801561128c57600080fd5b505af11580156112a0573d6000803e3d6000fd5b505050505080806112b090613908565b91505061115a565b50808260010160008282546112cd9190613c12565b909155505050600094855250506009602052505060409020805460ff19169055505050565b6112fa612b96565b33600061130682612ab1565b60008181526009602052604090205490915060ff16156113385760405162461bcd60e51b815260040161067390613a75565b6000818152600960205260408120805460ff1916600117905561135a33612ae5565b905080600201546000146113b05760405162461bcd60e51b815260206004820152601d60248201527f4d75737420776974686472617720616c6c2066756e64732066697273740000006044820152606401610673565b60006113bb33612ab1565b905060006113c96004612a09565b905060005b818110156115ec5760006113e3600483612a13565b6001600160a01b0381166000908152600260208181526040808420338552600a90925280842090519495509093909161141f919085019061387c565b90815260200160405180910390209050600061143a82612a09565b6001600160401b03811115611451576114516130e2565b60405190808252806020026020018201604052801561147a578160200160208202803683370190505b50905060005b61148983612a09565b8110156114d65761149a8382612a13565b8282815181106114ac576114ac613bce565b6001600160a01b0390921660209283029190910190910152806114ce81613908565b915050611480565b5060005b81518110156115d457600184015482516001600160a01b0390911690639721672590339085908590811061151057611510613bce565b60200260200101516040518363ffffffff1660e01b815260040161154a9291906001600160a01b0392831681529116602082015260400190565b600060405180830381600087803b15801561156457600080fd5b505af1925050508015611575575060015b6115ab576115a582828151811061158e5761158e613bce565b602002602001015184612bef90919063ffffffff16565b506115c2565b6115c082828151811061158e5761158e613bce565b505b806115cc81613908565b9150506114da565b505050505080806115e490613908565b9150506113ce565b506115f8600683612c04565b50600082815260086020526040812080546001600160a01b03191681556001810182905560028101829055906116316003830182613005565b50505060009283525050600960205260409020805460ff191690555061165660018055565b565b611660612a26565b6116566000612c10565b611672612a26565b60008282604051602001611687929190613921565b604051602081830303815290604052905060006003826040516116aa9190613826565b908152604051908190036020019020546001600160a01b03169050806116e25760405162461bcd60e51b815260040161067390613abf565b6116eb84612c60565b6001600160a01b03811660009081526002602052604090819020600601805460ff191660011790555161171f908590613826565b60405180910390207f22cc4700d5c4d3ff57ddfb4bb70d5a0e1bed5c060482e8eeeb8672d4471ad5e28483604051611758929190613223565b60405180910390a250505050565b33600061177282612ab1565b60008181526009602052604090205490915060ff16156117a45760405162461bcd60e51b815260040161067390613a75565b6000818152600960205260408120805460ff191660011790556117c633612ae5565b9050348160010160008282546117dc9190613c12565b92505081905550348160020160008282546117f79190613c12565b9091555050506000908152600960205260409020805460ff1916905550565b60606000611822612d21565b905080841061186457604080516000808252602082019092529061185c565b61184961303f565b8152602001906001900390816118415790505b509150611a02565b600083156118845761187f6118798587613c12565b83612b38565b611886565b815b905060006118948683613aac565b9050806001600160401b038111156118ae576118ae6130e2565b6040519080825280602002602001820160405280156118e757816020015b6118d461303f565b8152602001906001900390816118cc5790505b50935060005b818110156119fe576119076119028289613c12565b612d32565b6040805160808101825282546001600160a01b031681526001830154602082015260028301549181019190915260038201805491929160608401919061194c90613842565b80601f016020809104026020016040519081016040528092919081815260200182805461197890613842565b80156119c55780601f1061199a576101008083540402835291602001916119c5565b820191906000526020600020905b8154815290600101906020018083116119a857829003601f168201915b5050505050815250508582815181106119e0576119e0613bce565b602002602001018190525080806119f690613908565b9150506118ed565b5050505b9250929050565b60606000611a176004612a09565b90506000816001600160401b03811115611a3357611a336130e2565b604051908082528060200260200182016040528015611a6c57816020015b611a59613070565b815260200190600190039081611a515790505b50905060005b82811015611d61576000611a87600483612a13565b6001600160a01b038082166000908152600260208181526040928390208351610100810185528154861681526001820154909516918501919091529081018054949550929390929184019190611adc90613842565b80601f0160208091040260200160405190810160405280929190818152602001828054611b0890613842565b8015611b555780601f10611b2a57610100808354040283529160200191611b55565b820191906000526020600020905b815481529060010190602001808311611b3857829003601f168201915b50505050508152602001600382018054611b6e90613842565b80601f0160208091040260200160405190810160405280929190818152602001828054611b9a90613842565b8015611be75780601f10611bbc57610100808354040283529160200191611be7565b820191906000526020600020905b815481529060010190602001808311611bca57829003601f168201915b50505050508152602001600482018054611c0090613842565b80601f0160208091040260200160405190810160405280929190818152602001828054611c2c90613842565b8015611c795780601f10611c4e57610100808354040283529160200191611c79565b820191906000526020600020905b815481529060010190602001808311611c5c57829003601f168201915b50505050508152602001600582018054611c9290613842565b80601f0160208091040260200160405190810160405280929190818152602001828054611cbe90613842565b8015611d0b5780601f10611ce057610100808354040283529160200191611d0b565b820191906000526020600020905b815481529060010190602001808311611cee57829003601f168201915b5050509183525050600682015460ff16151560208201526007909101546040909101528351849084908110611d4257611d42613bce565b6020026020010181905250508080611d5990613908565b915050611a72565b5092915050565b6000808383604051602001611d7e929190613921565b60405160208183030381529060405290506000600382604051611da19190613826565b908152604051908190036020019020546001600160a01b0316905080611dcc57600092505050611dee565b6001600160a01b031660009081526002602052604090206006015460ff169150505b92915050565b60606000600383604051611e089190613826565b908152604051908190036020019020546001600160a01b0316905080611e405760405162461bcd60e51b815260040161067390613abf565b6001600160a01b03811660009081526002602081905260408220018054611e6690613842565b80601f0160208091040260200160405190810160405280929190818152602001828054611e9290613842565b8015611edf5780601f10611eb457610100808354040283529160200191611edf565b820191906000526020600020905b815481529060010190602001808311611ec257829003601f168201915b505050505090506000600a6000876001600160a01b03166001600160a01b0316815260200190815260200160002082604051611f1b9190613826565b908152602001604051809103902090506000611f3682612a09565b6001600160401b03811115611f4d57611f4d6130e2565b604051908082528060200260200182016040528015611f76578160200160208202803683370190505b50905060005b611f8583612a09565b811015611fd257611f968382612a13565b828281518110611fa857611fa8613bce565b6001600160a01b039092166020928302919091019091015280611fca81613908565b915050611f7c565b509695505050505050565b6000600382604051611fef9190613826565b908152604051908190036020019020546001600160a01b031692915050565b600054600160a01b900460ff16156120735760405162461bcd60e51b815260206004820152602260248201527f496e697469616c697a61626c653a20616c726561647920696e697469616c697a604482015261195960f21b6064820152608401610673565b6000805460ff60a01b1916600160a01b17905561208f81612c10565b50565b6000803360006120a182612ab1565b60008181526009602052604090205490915060ff16156120d35760405162461bcd60e51b815260040161067390613a75565b6000818152600960205260408120805460ff191660011790556120f533612ab1565b905061210081612d55565b156121205760405163cde58aa160e01b8152336004820152602401610673565b61212c81333489612d62565b506000908152600960205260408120805460ff19169055349590945092505050565b6060806060600061215f6004612a09565b90506000805b8281101561221157600061217a600483612a13565b6001600160a01b038116600090815260026020908152604091829020915192935090916121a9918b9101613826565b60405160208183030381529060405280519060200120816002016040516020016121d3919061387c565b60405160208183030381529060405280519060200120036121fc57836121f881613908565b9450505b5050808061220990613908565b915050612165565b50806001600160401b0381111561222a5761222a6130e2565b60405190808252806020026020018201604052801561225d57816020015b60608152602001906001900390816122485790505b509450806001600160401b03811115612278576122786130e2565b6040519080825280602002602001820160405280156122a1578160200160208202803683370190505b509350806001600160401b038111156122bc576122bc6130e2565b6040519080825280602002602001820160405280156122e5578160200160208202803683370190505b5092506000805b8381101561249c576000612301600483612a13565b6001600160a01b03811660009081526002602090815260409182902091519293509091612330918c9101613826565b604051602081830303815290604052805190602001208160020160405160200161235a919061387c565b60405160208183030381529060405280519060200120036124875780600301805461238490613842565b80601f01602080910402602001604051908101604052809291908181526020018280546123b090613842565b80156123fd5780601f106123d2576101008083540402835291602001916123fd565b820191906000526020600020905b8154815290600101906020018083116123e057829003601f168201915b505050505089858151811061241457612414613bce565b60200260200101819052508188858151811061243257612432613bce565b6001600160a01b03909216602092830291909101909101526006810154875160ff9091169088908690811061246957612469613bce565b911515602092830291909101909101528361248381613908565b9450505b5050808061249490613908565b9150506122ec565b505050509193909250565b336000908152600260205260409020546001600160a01b03166125175760405162461bcd60e51b815260206004820152602260248201527f43616c6c6572206973206e6f7420612072656769737465726564207365727669604482015261636560f01b6064820152608401610673565b600061252283612ab1565b60008181526009602052604090205490915060ff16156125545760405162461bcd60e51b815260040161067390613a75565b6000818152600960205260408120805460ff1916600117905561257684612ae5565b9050828160010154826002015461258d9190613aac565b10156125d25760405162461bcd60e51b8152602060048201526014602482015273496e73756666696369656e742062616c616e636560601b6044820152606401610673565b828160020160008282546125e69190613aac565b9091555050506000908152600960205260409020805460ff191690555050565b61260e613070565b6001600160a01b038083166000908152600260208181526040928390208351610100810185528154861681526001820154909516918501919091529081018054919284019161265c90613842565b80601f016020809104026020016040519081016040528092919081815260200182805461268890613842565b80156126d55780601f106126aa576101008083540402835291602001916126d5565b820191906000526020600020905b8154815290600101906020018083116126b857829003601f168201915b505050505081526020016003820180546126ee90613842565b80601f016020809104026020016040519081016040528092919081815260200182805461271a90613842565b80156127675780601f1061273c57610100808354040283529160200191612767565b820191906000526020600020905b81548152906001019060200180831161274a57829003601f168201915b5050505050815260200160048201805461278090613842565b80601f01602080910402602001604051908101604052809291908181526020018280546127ac90613842565b80156127f95780601f106127ce576101008083540402835291602001916127f9565b820191906000526020600020905b8154815290600101906020018083116127dc57829003601f168201915b5050505050815260200160058201805461281290613842565b80601f016020809104026020016040519081016040528092919081815260200182805461283e90613842565b801561288b5780601f106128605761010080835404028352916020019161288b565b820191906000526020600020905b81548152906001019060200180831161286e57829003601f168201915b5050509183525050600682015460ff161515602082015260079091015460409091015292915050565b6128bc612a26565b6001600160a01b0381166129215760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b6064820152608401610673565b61208f81612c10565b61293261303f565b61293b82612ae5565b6040805160808101825282546001600160a01b031681526001830154602082015260028301549181019190915260038201805491929160608401919061298090613842565b80601f01602080910402602001604051908101604052809291908181526020018280546129ac90613842565b80156129f95780601f106129ce576101008083540402835291602001916129f9565b820191906000526020600020905b8154815290600101906020018083116129dc57829003601f168201915b5050505050815250509050919050565b6000611dee825490565b6000612a1f8383612db9565b9392505050565b6000546001600160a01b031633146116565760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e65726044820152606401610673565b6000612a8b83612de3565b8015612a1f5750612a1f8383612e16565b6000612a1f836001600160a01b038416612e9f565b604080516001600160a01b038316602082015260009101604051602081830303815290604052805190602001209050919050565b600080612af183612ab1565b9050612afc81612d55565b612b2457604051637d2d536b60e01b81526001600160a01b0384166004820152602401610673565b600090815260086020526040902092915050565b6000818310612b475781612a1f565b5090919050565b6001600160a01b0383166000908152600a60205260408082209051612b74908590613826565b9081526040519081900360200190209050612b8f8183612a9c565b5050505050565b600260015403612be85760405162461bcd60e51b815260206004820152601f60248201527f5265656e7472616e637947756172643a207265656e7472616e742063616c6c006044820152606401610673565b6002600155565b6000612a1f836001600160a01b038416612eee565b6000612a1f8383612eee565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6000612c6c6004612a09565b905060005b81811015612d1c576000612c86600483612a13565b6001600160a01b03811660009081526002602090815260409182902091519293509091612cb591879101613826565b6040516020818303038152906040528051906020012081600201604051602001612cdf919061387c565b6040516020818303038152906040528051906020012003612d075760068101805460ff191690555b50508080612d1490613908565b915050612c71565b505050565b6000612d2d6006612a09565b905090565b600080612d40600684612a13565b60009081526008602052604090209392505050565b6000611dee600683612fe1565b6000848152600860205260409020600181018390556002810183905580546001600160a01b0319166001600160a01b03851617815560038101612da583826139a3565b50612db1600686612ff9565b505050505050565b6000826000018281548110612dd057612dd0613bce565b9060005260206000200154905092915050565b6000612df6826301ffc9a760e01b612e16565b8015611dee5750612e0f826001600160e01b0319612e16565b1592915050565b604080516001600160e01b03198316602480830191909152825180830390910181526044909101909152602080820180516001600160e01b03166301ffc9a760e01b178152825160009392849283928392918391908a617530fa92503d91506000519050828015612e88575060208210155b8015612e945750600081115b979650505050505050565b6000818152600183016020526040812054612ee657508154600181810184556000848152602080822090930184905584548482528286019093526040902091909155611dee565b506000611dee565b60008181526001830160205260408120548015612fd7576000612f12600183613aac565b8554909150600090612f2690600190613aac565b9050818114612f8b576000866000018281548110612f4657612f46613bce565b9060005260206000200154905080876000018481548110612f6957612f69613bce565b6000918252602080832090910192909255918252600188019052604090208390555b8554869080612f9c57612f9c613c25565b600190038181906000526020600020016000905590558560010160008681526020019081526020016000206000905560019350505050611dee565b6000915050611dee565b60008181526001830160205260408120541515612a1f565b6000612a1f8383612e9f565b50805461301190613842565b6000825580601f10613021575050565b601f01602090049060005260206000209081019061208f91906130c9565b604051806080016040528060006001600160a01b031681526020016000815260200160008152602001606081525090565b60405180610100016040528060006001600160a01b0316815260200160006001600160a01b0316815260200160608152602001606081526020016060815260200160608152602001600015158152602001600081525090565b5b808211156130de57600081556001016130ca565b5090565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f191681016001600160401b0381118282101715613120576131206130e2565b604052919050565b600082601f83011261313957600080fd5b81356001600160401b03811115613152576131526130e2565b613165601f8201601f19166020016130f8565b81815284602083860101111561317a57600080fd5b816020850160208301376000918101602001919091529392505050565b6000602082840312156131a957600080fd5b81356001600160401b038111156131bf57600080fd5b6131cb84828501613128565b949350505050565b60005b838110156131ee5781810151838201526020016131d6565b50506000910152565b6000815180845261320f8160208601602086016131d3565b601f01601f19169290920160200192915050565b60408152600061323660408301856131f7565b905060018060a01b03831660208301529392505050565b80356001600160a01b038116811461326457600080fd5b919050565b6000806000806080858703121561327f57600080fd5b84356001600160401b038082111561329657600080fd5b6132a288838901613128565b955060208701359150808211156132b857600080fd5b6132c488838901613128565b94506132d26040880161324d565b935060608701359150808211156132e857600080fd5b506132f587828801613128565b91505092959194509250565b60006020828403121561331357600080fd5b5035919050565b60008060006060848603121561332f57600080fd5b6133388461324d565b925060208401356001600160401b0381111561335357600080fd5b61335f86828701613128565b925050604084013590509250925092565b6000806040838503121561338357600080fd5b82356001600160401b038082111561339a57600080fd5b818501915085601f8301126133ae57600080fd5b81356020828211156133c2576133c26130e2565b8160051b6133d18282016130f8565b928352848101820192828101908a8511156133eb57600080fd5b958301955b84871015613410576134018761324d565b825295830195908301906133f0565b975050508601359250508082111561342757600080fd5b5061343485828601613128565b9150509250929050565b6000806040838503121561345157600080fd5b82356001600160401b038082111561346857600080fd5b61347486838701613128565b9350602085013591508082111561342757600080fd5b6000806040838503121561349d57600080fd5b50508035926020909101359150565b60018060a01b038151168252602081015160208301526040810151604083015260006060820151608060608501526131cb60808501826131f7565b6000604082016040835280855180835260608501915060608160051b8601019250602080880160005b8381101561353e57605f1988870301855261352c8683516134ac565b95509382019390820190600101613510565b50509490940194909452949350505050565b80516001600160a01b031682526000610100602083015161357c60208601826001600160a01b03169052565b506040830151816040860152613594828601826131f7565b915050606083015184820360608601526135ae82826131f7565b915050608083015184820360808601526135c882826131f7565b91505060a083015184820360a08601526135e282826131f7565b91505060c08301516135f860c086018215159052565b5060e083015160e08501528091505092915050565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b8281101561366257603f19888603018452613650858351613550565b94509285019290850190600101613634565b5092979650505050505050565b6000806040838503121561368257600080fd5b61368b8361324d565b915060208301356001600160401b038111156136a657600080fd5b61343485828601613128565b600081518084526020808501945080840160005b838110156136eb5781516001600160a01b0316875295820195908201906001016136c6565b509495945050505050565b602081526000612a1f60208301846136b2565b60006020828403121561371b57600080fd5b612a1f8261324d565b6000606082016060835280865180835260808501915060808160051b8601019250602080890160005b8381101561377b57607f198887030185526137698683516131f7565b9550938201939082019060010161374d565b50508584038187015261378e84896136b2565b8681036040880152875180825282890195509082019350915060005b828110156137c85784511515845293810193928101926001016137aa565b509198975050505050505050565b600080604083850312156137e957600080fd5b6137f28361324d565b946020939093013593505050565b602081526000612a1f6020830184613550565b602081526000612a1f60208301846134ac565b600082516138388184602087016131d3565b9190910192915050565b600181811c9082168061385657607f821691505b60208210810361387657634e487b7160e01b600052602260045260246000fd5b50919050565b600080835461388a81613842565b600182811680156138a257600181146138b7576138e6565b60ff19841687528215158302870194506138e6565b8760005260208060002060005b858110156138dd5781548a8201529084019082016138c4565b50505082870194505b50929695505050505050565b634e487b7160e01b600052601160045260246000fd5b60006001820161391a5761391a6138f2565b5060010190565b600083516139338184602088016131d3565b602d60f81b90830190815283516139518160018401602088016131d3565b01600101949350505050565b601f821115612d1c57600081815260208120601f850160051c810160208610156139845750805b601f850160051c820191505b81811015612db157828155600101613990565b81516001600160401b038111156139bc576139bc6130e2565b6139d0816139ca8454613842565b8461395d565b602080601f831160018114613a0557600084156139ed5750858301515b600019600386901b1c1916600185901b178555612db1565b600085815260208120601f198616915b82811015613a3457888601518255948401946001909101908401613a15565b5085821015613a525787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b602081526000612a1f60208301846131f7565b6020808252601b908201527f4c6564676572206c6f636b656420666f72206f7065726174696f6e0000000000604082015260600190565b81810381811115611dee57611dee6138f2565b60208082526011908201527014d95c9d9a58d9481b9bdd08199bdd5b99607a1b604082015260600190565b600060208284031215613afc57600080fd5b81518015158114612a1f57600080fd5b600060208284031215613b1e57600080fd5b5051919050565b6001600160a01b03848116825283166020808301919091526060604083015282546000918291613b5481613842565b8060608701526080600180841660008114613b765760018114613b9057613bbe565b60ff1985168984015283151560051b890183019650613bbe565b896000528560002060005b85811015613bb65781548b8201860152908301908701613b9b565b8a0184019750505b50949a9950505050505050505050565b634e487b7160e01b600052603260045260246000fd5b600080600060608486031215613bf957600080fd5b8351925060208401519150604084015190509250925092565b80820180821115611dee57611dee6138f2565b634e487b7160e01b600052603160045260246000fdfea26469706673582212204dba8a33248f1ed38e5ccc01f5ace07cdd6d193e26e9be8c1d789793c6b0562664736f6c63430008140033';
const isSuperArgs$2 = (xs) => xs.length > 1;
class LedgerManager__factory extends ContractFactory {
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
        name: 'InvalidTEESignature',
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
        name: 'TooManyRefunds',
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
                indexed: false,
                internalType: 'address[]',
                name: 'users',
                type: 'address[]',
            },
            {
                indexed: false,
                internalType: 'uint256[]',
                name: 'balances',
                type: 'uint256[]',
            },
            {
                indexed: false,
                internalType: 'uint256[]',
                name: 'pendingRefunds',
                type: 'uint256[]',
            },
        ],
        name: 'BatchBalanceUpdated',
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
                internalType: 'enum SettlementStatus',
                name: 'status',
                type: 'uint8',
            },
            {
                indexed: false,
                internalType: 'uint256',
                name: 'unsettledAmount',
                type: 'uint256',
            },
        ],
        name: 'TEESettlementResult',
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
                internalType: 'uint256[2]',
                name: 'providerPubKey',
                type: 'uint256[2]',
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
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'address',
                name: 'teeSignerAddress',
                type: 'address',
            },
        ],
        name: 'acknowledgeTEESigner',
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
                components: [
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
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
                        type: 'string',
                    },
                ],
                internalType: 'struct ServiceParams',
                name: 'params',
                type: 'tuple',
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
                        internalType: 'uint256[2]',
                        name: 'providerPubKey',
                        type: 'uint256[2]',
                    },
                    {
                        internalType: 'address',
                        name: 'teeSignerAddress',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
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
        inputs: [
            {
                internalType: 'address',
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'offset',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'limit',
                type: 'uint256',
            },
        ],
        name: 'getAccountsByProvider',
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
                        internalType: 'uint256[2]',
                        name: 'providerPubKey',
                        type: 'uint256[2]',
                    },
                    {
                        internalType: 'address',
                        name: 'teeSignerAddress',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct Account[]',
                name: 'accounts',
                type: 'tuple[]',
            },
            {
                internalType: 'uint256',
                name: 'total',
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
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'offset',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'limit',
                type: 'uint256',
            },
        ],
        name: 'getAccountsByUser',
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
                        internalType: 'uint256[2]',
                        name: 'providerPubKey',
                        type: 'uint256[2]',
                    },
                    {
                        internalType: 'address',
                        name: 'teeSignerAddress',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct Account[]',
                name: 'accounts',
                type: 'tuple[]',
            },
            {
                internalType: 'uint256',
                name: 'total',
                type: 'uint256',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: 'offset',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'limit',
                type: 'uint256',
            },
        ],
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
                        internalType: 'uint256[2]',
                        name: 'providerPubKey',
                        type: 'uint256[2]',
                    },
                    {
                        internalType: 'address',
                        name: 'teeSignerAddress',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct Account[]',
                name: 'accounts',
                type: 'tuple[]',
            },
            {
                internalType: 'uint256',
                name: 'total',
                type: 'uint256',
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
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
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
                internalType: 'address[]',
                name: 'users',
                type: 'address[]',
            },
        ],
        name: 'getBatchAccountsByUsers',
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
                        internalType: 'uint256[2]',
                        name: 'providerPubKey',
                        type: 'uint256[2]',
                    },
                    {
                        internalType: 'address',
                        name: 'teeSignerAddress',
                        type: 'address',
                    },
                    {
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct Account[]',
                name: 'accounts',
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
                    {
                        internalType: 'string',
                        name: 'additionalInfo',
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
                        name: 'totalFee',
                        type: 'uint256',
                    },
                    {
                        internalType: 'bytes32',
                        name: 'requestsHash',
                        type: 'bytes32',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nonce',
                        type: 'uint256',
                    },
                    {
                        internalType: 'bytes',
                        name: 'signature',
                        type: 'bytes',
                    },
                ],
                internalType: 'struct TEESettlementData[]',
                name: 'settlements',
                type: 'tuple[]',
            },
        ],
        name: 'previewSettlementResults',
        outputs: [
            {
                internalType: 'address[]',
                name: 'failedUsers',
                type: 'address[]',
            },
            {
                internalType: 'enum SettlementStatus[]',
                name: 'failureReasons',
                type: 'uint8[]',
            },
            {
                internalType: 'address[]',
                name: 'partialUsers',
                type: 'address[]',
            },
            {
                internalType: 'uint256[]',
                name: 'partialAmounts',
                type: 'uint256[]',
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
                        name: 'totalFee',
                        type: 'uint256',
                    },
                    {
                        internalType: 'bytes32',
                        name: 'requestsHash',
                        type: 'bytes32',
                    },
                    {
                        internalType: 'uint256',
                        name: 'nonce',
                        type: 'uint256',
                    },
                    {
                        internalType: 'bytes',
                        name: 'signature',
                        type: 'bytes',
                    },
                ],
                internalType: 'struct TEESettlementData[]',
                name: 'settlements',
                type: 'tuple[]',
            },
        ],
        name: 'settleFeesWithTEE',
        outputs: [
            {
                internalType: 'address[]',
                name: 'failedUsers',
                type: 'address[]',
            },
            {
                internalType: 'enum SettlementStatus[]',
                name: 'failureReasons',
                type: 'uint8[]',
            },
            {
                internalType: 'address[]',
                name: 'partialUsers',
                type: 'address[]',
            },
            {
                internalType: 'uint256[]',
                name: 'partialAmounts',
                type: 'uint256[]',
            },
        ],
        stateMutability: 'nonpayable',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'bytes4',
                name: 'interfaceId',
                type: 'bytes4',
            },
        ],
        name: 'supportsInterface',
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
const _bytecode$1 = '0x60806040523480156200001157600080fd5b506200001d3362000027565b6001805562000077565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b614e7e80620000876000396000f3fe6080604052600436106101c25760003560e01c8063715018a6116100f7578063ba16a75011610095578063e50688f911610064578063e50688f914610547578063f2fde38b1461055a578063fbfa4e111461057a578063fd5908471461059a57600080fd5b8063ba16a750146104c5578063bbee42d9146104f2578063d1d2005614610507578063d9f4140b1461052757600080fd5b80638da5cb5b116100d15780638da5cb5b1461043357806394842d14146104655780639721672514610485578063b4988fd0146104a557600080fd5b8063715018a6146103eb578063745e87f7146104005780638be741191461041357600080fd5b806321fe0f30116101645780634e3c4f221161013e5780634e3c4f22146103505780634fe63f4d1461038b5780635bd7ace2146103ab5780636c79158d146103cb57600080fd5b806321fe0f30146102de578063264173d61461030057806328b604761461032057600080fd5b8063154d75ef116101a0578063154d75ef14610240578063158ef93e1461026257806315a52302146102835780631d73b9f5146102b057600080fd5b806301ffc9a7146101c75780630d668087146101fc578063147500e314610220575b600080fd5b3480156101d357600080fd5b506101e76101e236600461422f565b6105c7565b60405190151581526020015b60405180910390f35b34801561020857600080fd5b5061021260025481565b6040519081526020016101f3565b34801561022c57600080fd5b506101e761023b366004614275565b6105fe565b34801561024c57600080fd5b5061026061025b366004614275565b610613565b005b34801561026e57600080fd5b506000546101e790600160a01b900460ff1681565b34801561028f57600080fd5b506102a361029e3660046142a8565b610624565b6040516101f391906143c3565b3480156102bc57600080fd5b506102d06102cb3660046143d6565b610957565b6040516101f39291906145a3565b3480156102ea57600080fd5b506102f36109a8565b6040516101f391906145c5565b34801561030c57600080fd5b5061021261031b366004614275565b6109b9565b34801561032c57600080fd5b5061034061033b36600461466b565b6109c7565b6040516101f3949392919061471d565b34801561035c57600080fd5b5061037061036b366004614275565b610c68565b604080519384526020840192909252908201526060016101f3565b34801561039757600080fd5b506102d06103a63660046143d6565b610d45565b3480156103b757600080fd5b506102d06103c63660046147c7565b610d80565b3480156103d757600080fd5b506102606103e6366004614275565b610dc6565b3480156103f757600080fd5b50610260611031565b61026061040e3660046147e9565b611045565b34801561041f57600080fd5b5061034061042e36600461466b565b6110e1565b34801561043f57600080fd5b506000546001600160a01b03165b6040516001600160a01b0390911681526020016101f3565b34801561047157600080fd5b50610260610480366004614825565b6114bc565b34801561049157600080fd5b506102606104a0366004614275565b611548565b3480156104b157600080fd5b506102606104c036600461485f565b61157e565b3480156104d157600080fd5b506104e56104e036600461466b565b611632565b6040516101f3919061489b565b3480156104fe57600080fd5b50610260611641565b34801561051357600080fd5b5060035461044d906001600160a01b031681565b34801561053357600080fd5b506102606105423660046148ae565b611679565b6102606105553660046148fe565b611686565b34801561056657600080fd5b506102606105753660046142a8565b6116c1565b34801561058657600080fd5b506102606105953660046149cf565b61173a565b3480156105a657600080fd5b506105ba6105b5366004614275565b611747565b6040516101f391906149e8565b60006001600160e01b0319821663160841b160e01b14806105f857506301ffc9a760e01b6001600160e01b03198316145b92915050565b600061060c60058484611916565b9392505050565b6106206005338484611933565b5050565b61062c614075565b610637600a83611968565b60408051610120810190915281546001600160a01b03168152600182018054919291602084019190610668906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054610694906149fb565b80156106e15780601f106106b6576101008083540402835291602001916106e1565b820191906000526020600020905b8154815290600101906020018083116106c457829003601f168201915b505050505081526020016002820180546106fa906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054610726906149fb565b80156107735780601f1061074857610100808354040283529160200191610773565b820191906000526020600020905b81548152906001019060200180831161075657829003601f168201915b505050505081526020016003820154815260200160048201548152602001600582015481526020016006820180546107aa906149fb565b80601f01602080910402602001604051908101604052809291908181526020018280546107d6906149fb565b80156108235780601f106107f857610100808354040283529160200191610823565b820191906000526020600020905b81548152906001019060200180831161080657829003601f168201915b5050505050815260200160078201805461083c906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054610868906149fb565b80156108b55780601f1061088a576101008083540402835291602001916108b5565b820191906000526020600020905b81548152906001019060200180831161089857829003601f168201915b505050505081526020016008820180546108ce906149fb565b80601f01602080910402602001604051908101604052809291908181526020018280546108fa906149fb565b80156109475780601f1061091c57610100808354040283529160200191610947565b820191906000526020600020905b81548152906001019060200180831161092a57829003601f168201915b5050505050815250509050919050565b60606000821580610969575060328311155b61098e5760405162461bcd60e51b815260040161098590614a35565b60405180910390fd5b61099b6005868686611974565b915091505b935093915050565b60606109b4600a611c89565b905090565b600061060c6005848461204f565b606080808084610a135760405162461bcd60e51b8152602060048201526017602482015276139bc81cd95d1d1b195b595b9d1cc81c1c9bdd9a591959604a1b6044820152606401610985565b846001600160401b03811115610a2b57610a2b6148e8565b604051908082528060200260200182016040528015610a54578160200160208202803683370190505b509350846001600160401b03811115610a6f57610a6f6148e8565b604051908082528060200260200182016040528015610a98578160200160208202803683370190505b509250846001600160401b03811115610ab357610ab36148e8565b604051908082528060200260200182016040528015610adc578160200160208202803683370190505b509150846001600160401b03811115610af757610af76148e8565b604051908082528060200260200182016040528015610b20578160200160208202803683370190505b50905060008060005b87811015610c535736898983818110610b4457610b44614a5e565b9050602002810190610b569190614a74565b905033610b6960408301602084016142a8565b6001600160a01b031614610ba257610b9c888886610b8681614aaa565b9750610b9560208601866142a8565b600261206a565b50610c41565b600080610bae836120e6565b90925090506000826005811115610bc757610bc76146e5565b03610bd457505050610c41565b6001826005811115610be857610be86146e5565b03610c1957610c11888887610bfc81614aaa565b9850610c0b60208801886142a8565b856121be565b505050610c41565b610c3d8a8a88610c2881614aaa565b9950610c3760208801886142a8565b8661206a565b5050505b80610c4b81614aaa565b915050610b29565b50818652908452808352815292959194509250565b600354600090819081906001600160a01b03163314610c995760405162461bcd60e51b815260040161098590614ac3565b600254610cac9060059087908790612217565b919450925090508215610d3e57604051339084156108fc029085906000818181858888f19350505050158015610ce6573d6000803e3d6000fd5b50836001600160a01b0316856001600160a01b03167f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c7768484604051610d35929190918252602082015260400190565b60405180910390a35b9250925092565b60606000821580610d57575060328311155b610d735760405162461bcd60e51b815260040161098590614a35565b61099b6005868686612477565b60606000821580610d92575060328311155b610dae5760405162461bcd60e51b815260040161098590614a35565b610dba60058585612776565b915091505b9250929050565b6003546001600160a01b03163314610df05760405162461bcd60e51b815260040161098590614ac3565b610dfc60058383612a58565b6000610e0a60058484612c06565b604080516101408101825282546001600160a01b039081168252600184015416602080830191909152600284015482840152600384015460608301526004840154608083015260058401805484518184028101840190955280855292949360a0860193909260009084015b82821015610ece576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff16151560608301529083529092019101610e75565b505050508152602001600682018054610ee6906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054610f12906149fb565b8015610f5f5780601f10610f3457610100808354040283529160200191610f5f565b820191906000526020600020905b815481529060010190602001808311610f4257829003601f168201915b5050509183525050604080518082019182905260209092019190600784019060029082845b815481526020019060010190808311610f8457505050918352505060098201546001600160a01b03166020820152600a9091015460409091015260a0810151519091501561102c5760018160a0015151610fde9190614b04565b826001600160a01b0316846001600160a01b03167f54377dfdebf06f6df53fbda737d2dcd7e141f95bbfb0c1223437e856b9de3ac34260405161102391815260200190565b60405180910390a45b505050565b611039612c13565b6110436000612c6d565b565b6003546001600160a01b0316331461106f5760405162461bcd60e51b815260040161098590614ac3565b600080611080600586868634612cbd565b91509150836001600160a01b0316856001600160a01b03167f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c77684846040516110d2929190918252602082015260400190565b60405180910390a35050505050565b60608080808461112d5760405162461bcd60e51b8152602060048201526017602482015276139bc81cd95d1d1b195b595b9d1cc81c1c9bdd9a591959604a1b6044820152606401610985565b603285111561117e5760405162461bcd60e51b815260206004820152601d60248201527f546f6f206d616e7920736574746c656d656e747320696e2062617463680000006044820152606401610985565b846001600160401b03811115611196576111966148e8565b6040519080825280602002602001820160405280156111bf578160200160208202803683370190505b509350846001600160401b038111156111da576111da6148e8565b604051908082528060200260200182016040528015611203578160200160208202803683370190505b509250846001600160401b0381111561121e5761121e6148e8565b604051908082528060200260200182016040528015611247578160200160208202803683370190505b509150846001600160401b03811115611262576112626148e8565b60405190808252806020026020018201604052801561128b578160200160208202803683370190505b5090506000806000805b8881101561146e57368a8a838181106112b0576112b0614a5e565b90506020028101906112c29190614a74565b9050336112d560408301602084016142a8565b6001600160a01b03161461135b576113018989876112f281614aaa565b9850610b9560208601866142a8565b61130e60208201826142a8565b6001600160a01b03167f1f69e5b87fd0ce34b3760ba6e5d8aa95a36e316c3ba44e1e65a9d0eb9e96d0bf6002836040013560405161134d929190614b17565b60405180910390a25061145c565b600080600061136984612eef565b9194509250905061137a8187614b32565b955061138960208501856142a8565b6001600160a01b03167f1f69e5b87fd0ce34b3760ba6e5d8aa95a36e316c3ba44e1e65a9d0eb9e96d0bf84846040516113c3929190614b17565b60405180910390a260008360058111156113df576113df6146e5565b036113ed575050505061145c565b6001836005811115611401576114016146e5565b036114335761142a8a8a8961141581614aaa565b9a5061142460208901896142a8565b866121be565b5050505061145c565b6114578c8c8a61144281614aaa565b9b5061145160208901896142a8565b8761206a565b505050505b8061146681614aaa565b915050611295565b5082875282865281855281845280156114b057604051339082156108fc029083906000818181858888f193505050501580156114ae573d6000803e3d6000fd5b505b50505092959194509250565b6114c8600a338361300b565b337f30ecc203691b2d18e17ee75d47caf34a3fb9f86e855f7e0414d3cec26d0c424b6114f48380614b45565b6115016020860186614b45565b608087013560a08801354261151960408b018b614b45565b61152660608d018d614b45565b60405161153d9b9a99989796959493929190614bb4565b60405180910390a250565b6003546001600160a01b031633146115725760405162461bcd60e51b815260040161098590614ac3565b61062060058383613296565b600054600160a01b900460ff16156115e35760405162461bcd60e51b815260206004820152602260248201527f496e697469616c697a61626c653a20616c726561647920696e697469616c697a604482015261195960f21b6064820152608401610985565b6000805460ff60a01b1916600160a01b1790556115ff81612c6d565b50600291909155600380546001600160a01b039092166001600160a01b0319928316811790915560048054909216179055565b606061060c6005848433613398565b61164c600a3361368a565b60405133907f29d546abb6e94f4f04d5bdccb6682316f597d43776078f47e273f000e77b2a9190600090a2565b61062060053384846136d9565b6003546001600160a01b031633146116b05760405162461bcd60e51b815260040161098590614ac3565b6000806110806005868634876136f7565b6116c9612c13565b6001600160a01b03811661172e5760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b6064820152608401610985565b61173781612c6d565b50565b611742612c13565b600255565b61174f6140ca565b61175b60058484612c06565b604080516101408101825282546001600160a01b039081168252600184015416602080830191909152600284015482840152600384015460608301526004840154608083015260058401805484518184028101840190955280855292949360a0860193909260009084015b8282101561181f576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff161515606083015290835290920191016117c6565b505050508152602001600682018054611837906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054611863906149fb565b80156118b05780601f10611885576101008083540402835291602001916118b0565b820191906000526020600020905b81548152906001019060200180831161189357829003601f168201915b5050509183525050604080518082019182905260209092019190600784019060029082845b8154815260200190600101908083116118d557505050918352505060098201546001600160a01b03166020820152600a909101546040909101529392505050565b600061192b8461192685856137aa565b6137e2565b949350505050565b60006119408585856137ee565b60090180546001600160a01b0319166001600160a01b03939093169290921790915550505050565b600061060c8383613850565b6001600160a01b038316600090815260038501602052604081206060919061199b816138a1565b91508185106119de5760408051600080825260208201909252906119d5565b6119c26140ca565b8152602001906001900390816119ba5790505b50925050611c80565b600084156119f5576119f08587614b32565b6119f7565b825b905082811115611a045750815b6000611a108783614b04565b9050806001600160401b03811115611a2a57611a2a6148e8565b604051908082528060200260200182016040528015611a6357816020015b611a506140ca565b815260200190600190039081611a485790505b50945060005b81811015611c7b576000611a87611a80838b614b32565b86906138ab565b60008181526002808e016020908152604080842081516101408101835281546001600160a01b03908116825260018301541681850152938101548483015260038101546060850152600481015460808501526005810180548351818602810186019094528084529697509395909460a0870194929384015b82821015611b58576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff16151560608301529083529092019101611aff565b505050508152602001600682018054611b70906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054611b9c906149fb565b8015611be95780601f10611bbe57610100808354040283529160200191611be9565b820191906000526020600020905b815481529060010190602001808311611bcc57829003601f168201915b5050509183525050604080518082019182905260209092019190600784019060029082845b815481526020019060010190808311611c0e57505050918352505060098201546001600160a01b03166020820152600a909101546040909101528751889084908110611c5c57611c5c614a5e565b6020026020010181905250508080611c7390614aaa565b915050611a69565b505050505b94509492505050565b60606000611c96836138b7565b9050806001600160401b03811115611cb057611cb06148e8565b604051908082528060200260200182016040528015611ce957816020015b611cd6614075565b815260200190600190039081611cce5790505b50915060005b8181101561204857611d0184826138c2565b60408051610120810190915281546001600160a01b03168152600182018054919291602084019190611d32906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054611d5e906149fb565b8015611dab5780601f10611d8057610100808354040283529160200191611dab565b820191906000526020600020905b815481529060010190602001808311611d8e57829003601f168201915b50505050508152602001600282018054611dc4906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054611df0906149fb565b8015611e3d5780601f10611e1257610100808354040283529160200191611e3d565b820191906000526020600020905b815481529060010190602001808311611e2057829003601f168201915b50505050508152602001600382015481526020016004820154815260200160058201548152602001600682018054611e74906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054611ea0906149fb565b8015611eed5780601f10611ec257610100808354040283529160200191611eed565b820191906000526020600020905b815481529060010190602001808311611ed057829003601f168201915b50505050508152602001600782018054611f06906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054611f32906149fb565b8015611f7f5780601f10611f5457610100808354040283529160200191611f7f565b820191906000526020600020905b815481529060010190602001808311611f6257829003601f168201915b50505050508152602001600882018054611f98906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054611fc4906149fb565b80156120115780601f10611fe657610100808354040283529160200191612011565b820191906000526020600020905b815481529060010190602001808311611ff457829003601f168201915b50505050508152505083828151811061202c5761202c614a5e565b60200260200101819052508061204190614aaa565b9050611cef565b5050919050565b60008061205d8585856137ee565b6004015495945050505050565b8185848151811061207d5761207d614a5e565b60200260200101906001600160a01b031690816001600160a01b031681525050808484815181106120b0576120b0614a5e565b602002602001019060058111156120c9576120c96146e5565b908160058111156120dc576120dc6146e5565b9052505050505050565b600080806121036120fa60208601866142a8565b60059033612c06565b60098101549091506001600160a01b0316612128575060039360409093013592915050565b8360800135816002015410612147575060049360409093013592915050565b60098101546121609085906001600160a01b03166138e8565b612174575060059360409093013592915050565b600381015460006040860135821061218d57600061219b565b61219b826040880135614b04565b905080156121b0576001969095509350505050565b506000958695509350505050565b818584815181106121d1576121d1614a5e565b60200260200101906001600160a01b031690816001600160a01b0316815250508084848151811061220457612204614a5e565b6020026020010181815250505050505050565b6000806000806122288888886137ee565b600581015490915060000361224f576000816003015482600401549350935093505061246d565b600093508391508142815b600584015481101561239d57600084600501828154811061227d5761227d614a5e565b60009182526020909120600490910201600381015490915060ff16156122a3575061238b565b8881600201546122b39190614b32565b83106122de5760018101546122c89089614b32565b60038201805460ff191660011790559750612389565b60018101546122ed9087614b32565b955083821461237b578085600501858154811061230c5761230c614a5e565b60009182526020909120825460049092020190815560018083015490820155600280830154908201556003918201549101805460ff191660ff90921615159190911790556005850180548591908290811061236957612369614a5e565b60009182526020909120600490910201555b8361238581614aaa565b9450505b505b8061239581614aaa565b91505061225a565b50600a830182905560058301548210156124445760058301546000906123c4908490614b04565b9050600f81106123e7576123d88484613a8f565b6005840154600a850155612442565b825b600585015481101561244057600185600501828154811061240c5761240c614a5e565b60009182526020909120600490910201600301805460ff19169115159190911790558061243881614aaa565b9150506123e9565b505b505b858360030160008282546124589190614b04565b90915550505050600481018290556003015491505b9450945094915050565b6001600160a01b038316600090815260048501602052604081206060919061249e816138a1565b91508185106124e05760408051600080825260208201909252906119d5565b6124c56140ca565b8152602001906001900390816124bd57905050925050611c80565b600084156124f7576124f28587614b32565b6124f9565b825b9050828111156125065750815b60006125128783614b04565b9050806001600160401b0381111561252c5761252c6148e8565b60405190808252806020026020018201604052801561256557816020015b6125526140ca565b81526020019060019003908161254a5790505b50945060005b81811015611c7b576000612582611a80838b614b32565b60008181526002808e016020908152604080842081516101408101835281546001600160a01b03908116825260018301541681850152938101548483015260038101546060850152600481015460808501526005810180548351818602810186019094528084529697509395909460a0870194929384015b82821015612653576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff161515606083015290835290920191016125fa565b50505050815260200160068201805461266b906149fb565b80601f0160208091040260200160405190810160405280929190818152602001828054612697906149fb565b80156126e45780601f106126b9576101008083540402835291602001916126e4565b820191906000526020600020905b8154815290600101906020018083116126c757829003601f168201915b5050509183525050604080518082019182905260209092019190600784019060029082845b81548152602001906001019080831161270957505050918352505060098201546001600160a01b03166020820152600a90910154604090910152875188908490811061275757612757614a5e565b602002602001018190525050808061276e90614aaa565b91505061256b565b60606000612783856138b7565b90508084106127c55760408051600080825260208201909252906127bd565b6127aa6140ca565b8152602001906001900390816127a25790505b5091506109a0565b60006127d18486614b32565b90508315806127df57508181115b156127e75750805b60006127f38683614b04565b9050806001600160401b0381111561280d5761280d6148e8565b60405190808252806020026020018201604052801561284657816020015b6128336140ca565b81526020019060019003908161282b5790505b50935060005b81811015612a4d5761286788612862838a614b32565b6138c2565b604080516101408101825282546001600160a01b039081168252600184015416602080830191909152600284015482840152600384015460608301526004840154608083015260058401805484518184028101840190955280855292949360a0860193909260009084015b8282101561292b576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff161515606083015290835290920191016128d2565b505050508152602001600682018054612943906149fb565b80601f016020809104026020016040519081016040528092919081815260200182805461296f906149fb565b80156129bc5780601f10612991576101008083540402835291602001916129bc565b820191906000526020600020905b81548152906001019060200180831161299f57829003601f168201915b5050509183525050604080518082019182905260209092019190600784019060029082845b8154815260200190600101908083116129e157505050918352505060098201546001600160a01b03166020820152600a909101546040909101528551869083908110612a2f57612a2f614a5e565b60200260200101819052508080612a4590614aaa565b91505061284c565b505050935093915050565b6000612a658484846137ee565b9050600081600401548260030154612a7d9190614b04565b905080600003612a8e575050505050565b601e82600a015410612ac657604051639edd285f60e01b81526001600160a01b03808616600483015284166024820152604401610985565b6005820154600a8301546000911115612b625782600a01549050604051806080016040528082815260200183815260200142815260200160001515815250836005018281548110612b1957612b19614a5e565b6000918252602091829020835160049290920201908155908201516001820155604082015160028201556060909101516003909101805460ff1916911515919091179055612bce565b50600582018054604080516080810182528281526020808201868152429383019384526000606084018181526001808801895597825292902092516004860290930192835551948201949094559051600282015591516003909201805460ff1916921515929092179091555b600a83018054906000612be083614aaa565b919050555081836004016000828254612bf99190614b32565b9091555050505050505050565b600061192b8484846137ee565b6000546001600160a01b031633146110435760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e65726044820152606401610985565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6000806000612ccd8888886137ee565b9050600085118015612ce25750600581015415155b15612ebd57600481015485906000805b6005850154811015612e8c576000856005018281548110612d1557612d15614a5e565b60009182526020909120600490910201600381015490915060ff1615612d3b5750612e7a565b80600101548510612d7d576001810154612d559086614b04565b9450806001015484612d679190614b04565b60038201805460ff191660011790559350612dae565b8415612dae5784816001016000828254612d979190614b04565b90915550612da790508585614b04565b9350600094505b600381015460ff16158015612dc35750828214155b15612e5e5780866005018481548110612dde57612dde614a5e565b60009182526020909120825460049092020190815560018083015490820155600280830154908201556003918201549101805460ff191660ff909216151591909117905560058601805484919082908110612e3b57612e3b614a5e565b600091825260209091206004909102015582612e5681614aaa565b935050612e78565b600381015460ff16612e785782612e7481614aaa565b9350505b505b80612e8481614aaa565b915050612cf2565b50600a84018190556005840154811015612eb557612eaa8482613a8f565b6005840154600a8501555b506004830155505b83816003016000828254612ed19190614b32565b90915550506003810154600490910154909890975095505050505050565b6000808080612f046120fa60208701876142a8565b60098101549091506001600160a01b0316612f2c575060039250505060408201356000613004565b8460800135816002015410612f4e575060049250505060408201356000613004565b6009810154612f679086906001600160a01b03166138e8565b612f7e575060059250505060408201356000613004565b608085013560028201556003810154600060408701358210612fa4578660400135612fa6565b815b9050600082886040013511612fbc576000612fca565b612fca8360408a0135614b04565b90508115612fdc57612fdc8483613af7565b8015612ff2576001965094509250613004915050565b50600095508594509250613004915050565b9193909250565b600061301683613ce7565b905061302284826137e2565b6131d4576131cd8482604051806101200160405280876001600160a01b031681526020018680600001906130569190614b45565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050509082525060209081019061309f90880188614b45565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250505090825250608080880135602083015260a088013560408084019190915242606084015291019061310490880188614b45565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050509082525060200161314b6060880188614b45565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050509082525060200161319260c0880188614b45565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152505050915250613d1b565b5050505050565b60006131e08585613850565b90506131ec8380614b45565b60018301916131fc919083614c6f565b506080830135600382015560a0830135600482015561321e6020840184614b45565b600283019161322e919083614c6f565b504260058201556132426040840184614b45565b6006830191613252919083614c6f565b506132606060840184614b45565b6007830191613270919083614c6f565b5061327e60c0840184614b45565b600883019161328e919083614c6f565b505050505050565b60006132a283836137aa565b90506132ae84826137e2565b6132b85750505050565b6001600160a01b038216600090815260038501602052604090206132dc9082613de1565b506001600160a01b038316600090815260048501602052604090206133019082613de1565b5061330c8482613de1565b50600081815260028086016020526040822080546001600160a01b03199081168255600182018054909116905590810182905560038101829055600481018290559061335b6005830182614135565b613369600683016000614156565b6000600783018190556008830155506009810180546001600160a01b03191690556000600a9091015550505050565b60606101f48311156133ec5760405162461bcd60e51b815260206004820152601e60248201527f42617463682073697a6520746f6f206c6172676520286d6178203530302900006044820152606401610985565b826001600160401b03811115613404576134046148e8565b60405190808252806020026020018201604052801561343d57816020015b61342a6140ca565b8152602001906001900390816134225790505b50905060005b8381101561368157600061347d86868481811061346257613462614a5e565b905060200201602081019061347791906142a8565b856137aa565b905061348987826137e2565b1561366e57600081815260028089016020908152604080842081516101408101835281546001600160a01b03908116825260018301541681850152938101548483015260038101546060850152600481015460808501526005810180548351818602810186019094528084529495919460a08701949192909184015b8282101561355e576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff16151560608301529083529092019101613505565b505050508152602001600682018054613576906149fb565b80601f01602080910402602001604051908101604052809291908181526020018280546135a2906149fb565b80156135ef5780601f106135c4576101008083540402835291602001916135ef565b820191906000526020600020905b8154815290600101906020018083116135d257829003601f168201915b5050509183525050604080518082019182905260209092019190600784019060029082845b81548152602001906001019080831161361457505050918352505060098201546001600160a01b03166020820152600a90910154604090910152835184908490811061366257613662614a5e565b60200260200101819052505b508061367981614aaa565b915050613443565b50949350505050565b600061369582613ce7565b90506136a183826137e2565b6136c9576040516304c76d3f60e11b81526001600160a01b0383166004820152602401610985565b6136d38382613ded565b50505050565b60006136e68585856137ee565b905061328e60078201836002614190565b600080600061370687876137aa565b905061371288826137e2565b1561374357604051632cf0675960e21b81526001600160a01b03808916600483015287166024820152604401610985565b613751888289898989613e78565b6001600160a01b038616600090815260038901602052604090206137759082613ee5565b506001600160a01b0387166000908152600489016020526040902061379a9082613ee5565b5093976000975095505050505050565b604080516001600160a01b03938416602080830191909152929093168382015280518084038201815260609093019052815191012090565b600061060c8383613ef1565b6000806137fb84846137aa565b905061380785826137e2565b6138375760405163023280eb60e21b81526001600160a01b03808616600483015284166024820152604401610985565b6000908152600285016020526040902090509392505050565b60008061385c83613ce7565b6000818152600286016020526040902090915061387985836137e2565b61192b576040516304c76d3f60e11b81526001600160a01b0385166004820152602401610985565b60006105f8825490565b600061060c8383613f09565b60006105f8826138a1565b6000806138cf84846138ab565b6000908152600285016020526040902091505092915050565b600036816138f960a0860186614b45565b909250905060418114613911576000925050506105f8565b60006060860135608087013561392d6040890160208a016142a8565b61393a60208a018a6142a8565b604080516020810195909552848101939093526bffffffffffffffffffffffff19606092831b811683860152911b166074830152870135608882015260a8016040516020818303038152906040528051906020012090506000816040516020016139d091907f19457468657265756d205369676e6564204d6573736167653a0a3332000000008152601c810191909152603c0190565b60408051601f19818403018152918152815160209283012092508535918601359086013560001a601b811015613a0e57613a0b601b82614d2e565b90505b60408051600081526020810180835286905260ff83169181019190915260608101849052608081018390526001600160a01b038a169060019060a0016020604051602081039080840390855afa158015613a6c573d6000803e3d6000fd5b505050602060405103516001600160a01b03161497505050505050505092915050565b6005820154805b828111156136d35783600501805480613ab157613ab1614d47565b600082815260208120600460001990930192830201818155600181018290556002810191909155600301805460ff19169055905580613aef81614d5d565b915050613a96565b81600401548260030154613b0b9190614b04565b811115613c0d57600082600401548360030154613b289190614b04565b613b329083614b04565b905080836004016000828254613b489190614b04565b90915550506005830154600090613b6190600190614b04565b90505b60008112613c0a576000846005018281548110613b8357613b83614a5e565b60009182526020909120600490910201600381015490915060ff1615613ba95750613bf8565b82816001015411613bca576001810154613bc39084614b04565b9250613be8565b82816001016000828254613bde9190614b04565b9091555060009350505b82600003613bf65750613c0a565b505b80613c0281614d74565b915050613b64565b50505b80826003016000828254613c219190614b04565b9091555050600480548354604051631bb1482360e31b81526001600160a01b039182169381019390935260248301849052169063dd8a411890604401600060405180830381600087803b158015613c7757600080fd5b505af1158015613c8b573d6000803e3d6000fd5b50508354600385015460048601546040805192835260208301919091523394506001600160a01b0390921692507f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c776910160405180910390a35050565b604080516001600160a01b038316602082015260009101604051602081830303815290604052805190602001209050919050565b600082815260028401602090815260408220835181546001600160a01b0319166001600160a01b03909116178155908301518391906001820190613d5f9082614d89565b5060408201516002820190613d749082614d89565b50606082015160038201556080820151600482015560a0820151600582015560c08201516006820190613da79082614d89565b5060e08201516007820190613dbc9082614d89565b506101008201516008820190613dd29082614d89565b5061192b915085905084613ee5565b600061060c8383613f33565b6000818152600283016020526040812080546001600160a01b031916815581613e196001830182614156565b613e27600283016000614156565b600382016000905560048201600090556005820160009055600682016000613e4f9190614156565b613e5d600783016000614156565b613e6b600883016000614156565b5061060c90508383613de1565b600085815260028701602052604090206003810183905580546001600160a01b038087166001600160a01b03199283161783556001830180549187169190921617905560068101613ec98382614d89565b506000600a820155613edb8787613ee5565b5050505050505050565b600061060c8383614026565b6000818152600183016020526040812054151561060c565b6000826000018281548110613f2057613f20614a5e565b9060005260206000200154905092915050565b6000818152600183016020526040812054801561401c576000613f57600183614b04565b8554909150600090613f6b90600190614b04565b9050818114613fd0576000866000018281548110613f8b57613f8b614a5e565b9060005260206000200154905080876000018481548110613fae57613fae614a5e565b6000918252602080832090910192909255918252600188019052604090208390555b8554869080613fe157613fe1614d47565b6001900381819060005260206000200160009055905585600101600086815260200190815260200160002060009055600193505050506105f8565b60009150506105f8565b600081815260018301602052604081205461406d575081546001818101845560008481526020808220909301849055845484825282860190935260409020919091556105f8565b5060006105f8565b60405180610120016040528060006001600160a01b0316815260200160608152602001606081526020016000815260200160008152602001600081526020016060815260200160608152602001606081525090565b60405180610140016040528060006001600160a01b0316815260200160006001600160a01b0316815260200160008152602001600081526020016000815260200160608152602001606081526020016141216141ce565b815260006020820181905260409091015290565b508054600082556004029060005260206000209081019061173791906141ec565b508054614162906149fb565b6000825580601f10614172575050565b601f016020900490600052602060002090810190611737919061421a565b82600281019282156141be579160200282015b828111156141be5782358255916020019190600101906141a3565b506141ca92915061421a565b5090565b60405180604001604052806002906020820280368337509192915050565b5b808211156141ca57600080825560018201819055600282015560038101805460ff191690556004016141ed565b5b808211156141ca576000815560010161421b565b60006020828403121561424157600080fd5b81356001600160e01b03198116811461060c57600080fd5b80356001600160a01b038116811461427057600080fd5b919050565b6000806040838503121561428857600080fd5b61429183614259565b915061429f60208401614259565b90509250929050565b6000602082840312156142ba57600080fd5b61060c82614259565b6000815180845260005b818110156142e9576020818501810151868301820152016142cd565b506000602082860101526020601f19601f83011685010191505092915050565b80516001600160a01b0316825260006101206020830151816020860152614332828601826142c3565b9150506040830151848203604086015261434c82826142c3565b915050606083015160608501526080830151608085015260a083015160a085015260c083015184820360c086015261438482826142c3565b91505060e083015184820360e086015261439e82826142c3565b91505061010080840151858303828701526143b983826142c3565b9695505050505050565b60208152600061060c6020830184614309565b6000806000606084860312156143eb57600080fd5b6143f484614259565b95602085013595506040909401359392505050565b600081518084526020808501945080840160005b8381101561445b578151805188528381015184890152604080820151908901526060908101511515908801526080909601959082019060010161441d565b509495945050505050565b8060005b60028110156136d357815184526020938401939091019060010161446a565b80516001600160a01b03168252600061016060208301516144b560208601826001600160a01b03169052565b5060408301516040850152606083015160608501526080830151608085015260a08301518160a08601526144eb82860182614409565b91505060c083015184820360c086015261450582826142c3565b91505060e083015161451a60e0860182614466565b50610100830151610120614538818701836001600160a01b03169052565b8085015161014087015250508091505092915050565b600081518084526020808501808196508360051b8101915082860160005b85811015614596578284038952614584848351614489565b9885019893509084019060010161456c565b5091979650505050505050565b6040815260006145b6604083018561454e565b90508260208301529392505050565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b8281101561461a57603f19888603018452614608858351614309565b945092850192908501906001016145ec565b5092979650505050505050565b60008083601f84011261463957600080fd5b5081356001600160401b0381111561465057600080fd5b6020830191508360208260051b8501011115610dbf57600080fd5b6000806020838503121561467e57600080fd5b82356001600160401b0381111561469457600080fd5b6146a085828601614627565b90969095509350505050565b600081518084526020808501945080840160005b8381101561445b5781516001600160a01b0316875295820195908201906001016146c0565b634e487b7160e01b600052602160045260246000fd5b6006811061471957634e487b7160e01b600052602160045260246000fd5b9052565b60808152600061473060808301876146ac565b82810360208481019190915286518083528782019282019060005b8181101561476e5761475e8386516146fb565b938301939183019160010161474b565b5050848103604086015261478281886146ac565b858103606087015286518082528388019450908301915060005b818110156147b85784518352938301939183019160010161479c565b50909998505050505050505050565b600080604083850312156147da57600080fd5b50508035926020909101359150565b6000806000606084860312156147fe57600080fd5b61480784614259565b925061481560208501614259565b9150604084013590509250925092565b60006020828403121561483757600080fd5b81356001600160401b0381111561484d57600080fd5b820160e0818503121561060c57600080fd5b60008060006060848603121561487457600080fd5b8335925061488460208501614259565b915061489260408501614259565b90509250925092565b60208152600061060c602083018461454e565b600080606083850312156148c157600080fd5b6148ca83614259565b9150836060840111156148dc57600080fd5b50926020919091019150565b634e487b7160e01b600052604160045260246000fd5b60008060006060848603121561491357600080fd5b61491c84614259565b925061492a60208501614259565b915060408401356001600160401b038082111561494657600080fd5b818601915086601f83011261495a57600080fd5b81358181111561496c5761496c6148e8565b604051601f8201601f19908116603f01168101908382118183101715614994576149946148e8565b816040528281528960208487010111156149ad57600080fd5b8260208601602083013760006020848301015280955050505050509250925092565b6000602082840312156149e157600080fd5b5035919050565b60208152600061060c6020830184614489565b600181811c90821680614a0f57607f821691505b602082108103614a2f57634e487b7160e01b600052602260045260246000fd5b50919050565b6020808252600f908201526e4c696d697420746f6f206c6172676560881b604082015260600190565b634e487b7160e01b600052603260045260246000fd5b6000823560be19833603018112614a8a57600080fd5b9190910192915050565b634e487b7160e01b600052601160045260246000fd5b600060018201614abc57614abc614a94565b5060010190565b60208082526021908201527f43616c6c6572206973206e6f7420746865206c656467657220636f6e747261636040820152601d60fa1b606082015260800190565b818103818111156105f8576105f8614a94565b60408101614b2582856146fb565b8260208301529392505050565b808201808211156105f8576105f8614a94565b6000808335601e19843603018112614b5c57600080fd5b8301803591506001600160401b03821115614b7657600080fd5b602001915036819003821315610dbf57600080fd5b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b60e081526000614bc860e083018d8f614b8b565b8281036020840152614bdb818c8e614b8b565b905089604084015288606084015287608084015282810360a0840152614c02818789614b8b565b905082810360c0840152614c17818587614b8b565b9e9d5050505050505050505050505050565b601f82111561102c57600081815260208120601f850160051c81016020861015614c505750805b601f850160051c820191505b8181101561328e57828155600101614c5c565b6001600160401b03831115614c8657614c866148e8565b614c9a83614c9483546149fb565b83614c29565b6000601f841160018114614cce5760008515614cb65750838201355b600019600387901b1c1916600186901b1783556131cd565b600083815260209020601f19861690835b82811015614cff5786850135825560209485019460019092019101614cdf565b5086821015614d1c5760001960f88860031b161c19848701351681555b505060018560011b0183555050505050565b60ff81811683821601908111156105f8576105f8614a94565b634e487b7160e01b600052603160045260246000fd5b600081614d6c57614d6c614a94565b506000190190565b6000600160ff1b8201614d6c57614d6c614a94565b81516001600160401b03811115614da257614da26148e8565b614db681614db084546149fb565b84614c29565b602080601f831160018114614deb5760008415614dd35750858301515b600019600386901b1c1916600185901b17855561328e565b600085815260208120601f198616915b82811015614e1a57888601518255948401946001909101908401614dfb565b5085821015614e385787850151600019600388901b60f8161c191681555b5050505050600190811b0190555056fea2646970667358221220ecb877a91cdf5b241189f2f82f71da21e6ca1f68756f1e30b043725875a4cd6c64736f6c63430008140033';
const isSuperArgs$1 = (xs) => xs.length > 1;
class InferenceServing__factory extends ContractFactory {
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
        name: 'TooManyRefunds',
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
                internalType: 'string',
                name: 'id',
                type: 'string',
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
                internalType: 'string',
                name: 'id',
                type: 'string',
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
            {
                internalType: 'string[]',
                name: 'models',
                type: 'string[]',
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
                                internalType: 'string',
                                name: 'id',
                                type: 'string',
                            },
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
                            {
                                internalType: 'uint256',
                                name: 'timestamp',
                                type: 'uint256',
                            },
                        ],
                        internalType: 'struct Deliverable[]',
                        name: 'deliverables',
                        type: 'tuple[]',
                    },
                    {
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'deliverablesHead',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'deliverablesCount',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct AccountDetails',
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
                name: 'provider',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'offset',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'limit',
                type: 'uint256',
            },
        ],
        name: 'getAccountsByProvider',
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
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'deliverablesCount',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct AccountSummary[]',
                name: 'accounts',
                type: 'tuple[]',
            },
            {
                internalType: 'uint256',
                name: 'total',
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
                name: 'user',
                type: 'address',
            },
            {
                internalType: 'uint256',
                name: 'offset',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'limit',
                type: 'uint256',
            },
        ],
        name: 'getAccountsByUser',
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
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'deliverablesCount',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct AccountSummary[]',
                name: 'accounts',
                type: 'tuple[]',
            },
            {
                internalType: 'uint256',
                name: 'total',
                type: 'uint256',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            {
                internalType: 'uint256',
                name: 'offset',
                type: 'uint256',
            },
            {
                internalType: 'uint256',
                name: 'limit',
                type: 'uint256',
            },
        ],
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
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'deliverablesCount',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct AccountSummary[]',
                name: 'accounts',
                type: 'tuple[]',
            },
            {
                internalType: 'uint256',
                name: 'total',
                type: 'uint256',
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
                    {
                        internalType: 'string[]',
                        name: 'models',
                        type: 'string[]',
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
                internalType: 'address[]',
                name: 'users',
                type: 'address[]',
            },
        ],
        name: 'getBatchAccountsByUsers',
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
                        internalType: 'uint256',
                        name: 'validRefundsLength',
                        type: 'uint256',
                    },
                    {
                        internalType: 'uint256',
                        name: 'deliverablesCount',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct AccountSummary[]',
                name: 'accounts',
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
                internalType: 'string',
                name: 'id',
                type: 'string',
            },
        ],
        name: 'getDeliverable',
        outputs: [
            {
                components: [
                    {
                        internalType: 'string',
                        name: 'id',
                        type: 'string',
                    },
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
                    {
                        internalType: 'uint256',
                        name: 'timestamp',
                        type: 'uint256',
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
        name: 'getDeliverables',
        outputs: [
            {
                components: [
                    {
                        internalType: 'string',
                        name: 'id',
                        type: 'string',
                    },
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
                    {
                        internalType: 'uint256',
                        name: 'timestamp',
                        type: 'uint256',
                    },
                ],
                internalType: 'struct Deliverable[]',
                name: '',
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
                    {
                        internalType: 'string[]',
                        name: 'models',
                        type: 'string[]',
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
            {
                internalType: 'uint256',
                name: '_penaltyPercentage',
                type: 'uint256',
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
        inputs: [],
        name: 'penaltyPercentage',
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
                        internalType: 'string',
                        name: 'id',
                        type: 'string',
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
                internalType: 'bytes4',
                name: 'interfaceId',
                type: 'bytes4',
            },
        ],
        name: 'supportsInterface',
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
    {
        inputs: [
            {
                internalType: 'uint256',
                name: '_penaltyPercentage',
                type: 'uint256',
            },
        ],
        name: 'updatePenaltyPercentage',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
    },
];
const _bytecode = '0x60806040523480156200001157600080fd5b506200001d3362000027565b6001805562000077565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b61571680620000876000396000f3fe6080604052600436106101ee5760003560e01c8063745e87f71161010d578063bbee42d9116100a0578063eb9616931161006f578063eb961693146105c6578063f2c6741a146105e6578063f2fde38b14610606578063fbfa4e1114610626578063fd5908471461064657600080fd5b8063bbee42d91461055e578063d1d2005614610573578063e37259e914610593578063e50688f9146105b357600080fd5b806397216725116100dc57806397216725146104c4578063a134f9e1146104e4578063a296bf4f14610511578063ba16a7501461053157600080fd5b8063745e87f7146104325780638da5cb5b1461044557806395e21362146104775780639622e9341461049757600080fd5b8063264173d6116101855780635bd7ace2116101545780635bd7ace2146103bd5780636c79158d146103dd5780636dc7513d146103fd578063715018a61461041d57600080fd5b8063264173d614610320578063389f68ee146103405780634e3c4f22146103625780634fe63f4d1461039d57600080fd5b806315908d51116101c157806315908d511461028d57806315a52302146102a35780631d73b9f5146102d057806321fe0f30146102fe57600080fd5b806301ffc9a7146101f35780630d66808714610228578063147500e31461024c578063158ef93e1461026c575b600080fd5b3480156101ff57600080fd5b5061021361020e3660046144ec565b610673565b60405190151581526020015b60405180910390f35b34801561023457600080fd5b5061023e60025481565b60405190815260200161021f565b34801561025857600080fd5b50610213610267366004614532565b6106aa565b34801561027857600080fd5b5060005461021390600160a01b900460ff1681565b34801561029957600080fd5b5061023e600d5481565b3480156102af57600080fd5b506102c36102be366004614565565b6106bf565b60405161021f91906146d8565b3480156102dc57600080fd5b506102f06102eb3660046146eb565b610969565b60405161021f9291906147f7565b34801561030a57600080fd5b506103136109ba565b60405161021f9190614819565b34801561032c57600080fd5b5061023e61033b366004614532565b6109cb565b34801561034c57600080fd5b5061036061035b366004614a6a565b6109d9565b005b34801561036e57600080fd5b5061038261037d366004614532565b610a78565b6040805193845260208401929092529082015260600161021f565b3480156103a957600080fd5b506102f06103b83660046146eb565b610b61565b3480156103c957600080fd5b506102f06103d8366004614b78565b610b9c565b3480156103e957600080fd5b506103606103f8366004614532565b610be2565b34801561040957600080fd5b50610360610418366004614b9a565b610c1c565b34801561042957600080fd5b50610360610c31565b610360610440366004614c13565b610c45565b34801561045157600080fd5b506000546001600160a01b03165b6040516001600160a01b03909116815260200161021f565b34801561048357600080fd5b50610360610492366004614c4f565b610ce1565b3480156104a357600080fd5b506104b76104b2366004614532565b6110e9565b60405161021f9190614d3d565b3480156104d057600080fd5b506103606104df366004614532565b6110f7565b3480156104f057600080fd5b506105046104ff366004614d50565b61112d565b60405161021f9190614db0565b34801561051d57600080fd5b5061036061052c366004614dc3565b611178565b34801561053d57600080fd5b5061055161054c366004614e15565b61118b565b60405161021f9190614e89565b34801561056a57600080fd5b5061036061119a565b34801561057f57600080fd5b5060035461045f906001600160a01b031681565b34801561059f57600080fd5b506103606105ae366004614e9c565b6111d2565b6103606105c1366004614ee0565b611289565b3480156105d257600080fd5b506103606105e1366004614f3d565b6112c4565b3480156105f257600080fd5b50610360610601366004614532565b6112d1565b34801561061257600080fd5b50610360610621366004614565565b6112de565b34801561063257600080fd5b50610360610641366004614f3d565b611357565b34801561065257600080fd5b50610666610661366004614532565b611364565b60405161021f9190614fb3565b60006001600160e01b0319821663160841b160e01b14806106a457506301ffc9a760e01b6001600160e01b03198316145b92915050565b60006106b860058484611378565b9392505050565b6106c761424e565b6106d2600a83611395565b6040805160e0810190915281546001600160a01b03168152600182018054919291602084019190610702906150af565b80601f016020809104026020016040519081016040528092919081815260200182805461072e906150af565b801561077b5780601f106107505761010080835404028352916020019161077b565b820191906000526020600020905b81548152906001019060200180831161075e57829003601f168201915b50505050508152602001600282016040518060a0016040529081600082015481526020016001820154815260200160028201548152602001600382015481526020016004820180546107cc906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546107f8906150af565b80156108455780601f1061081a57610100808354040283529160200191610845565b820191906000526020600020905b81548152906001019060200180831161082857829003601f168201915b505050919092525050508152600782015460208083019190915260088301546001600160a01b038116604080850191909152600160a01b90910460ff1615156060840152600984018054825181850281018501909352808352608090940193919290919060009084015b8282101561095b5783829060005260206000200180546108ce906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546108fa906150af565b80156109475780601f1061091c57610100808354040283529160200191610947565b820191906000526020600020905b81548152906001019060200180831161092a57829003601f168201915b5050505050815260200190600101906108af565b505050915250909392505050565b6060600082158061097b575060328311155b6109a05760405162461bcd60e51b8152600401610997906150e9565b60405180910390fd5b6109ad60058686866113a1565b915091505b935093915050565b60606109c6600a611612565b905090565b60006106b860058484611950565b610a243388888080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250600a949392508a915089905088888861196b565b336001600160a01b03167f9657518f02d23efc8a15c042c006a06464dd791f65394ff87310a287c6949462888888888888604051610a6796959493929190615112565b60405180910390a250505050505050565b600354600090819081906001600160a01b03163314610aa95760405162461bcd60e51b81526004016109979061517a565b600254610abc9060059087908790611a90565b919450925090506000839003610ad55760009250610b5a565b604051339084156108fc029085906000818181858888f19350505050158015610b02573d6000803e3d6000fd5b50836001600160a01b0316856001600160a01b03167f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c7768484604051610b51929190918252602082015260400190565b60405180910390a35b9250925092565b60606000821580610b73575060328311155b610b8f5760405162461bcd60e51b8152600401610997906150e9565b6109ad6005868686611ce6565b60606000821580610bae575060328311155b610bca5760405162461bcd60e51b8152600401610997906150e9565b610bd660058585611f41565b915091505b9250929050565b6003546001600160a01b03163314610c0c5760405162461bcd60e51b81526004016109979061517a565b610c186005838361217a565b5050565b610c2b60058533868686612328565b50505050565b610c3961268a565b610c4360006126e4565b565b6003546001600160a01b03163314610c6f5760405162461bcd60e51b81526004016109979061517a565b600080610c80600586868634612734565b91509150836001600160a01b0316856001600160a01b03167f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c7768484604051610cd2929190918252602082015260400190565b60405180910390a35050505050565b6000610d00610cf7610100840160e08501614565565b6005903361295b565b9050610d1260a0830160808401614565565b60078201546001600160a01b03908116911614610d875760405163de83c54360e01b815260206004820152602c60248201527f70726f7669646572207369676e696e672061646472657373206973206e6f742060448201526b1858dadb9bdddb195919d95960a21b6064820152608401610997565b8160600135816002015410610df25760405163de83c54360e01b815260206004820152602a60248201527f6e6f6e63652073686f756c64206c6172676572207468616e207468652063757260448201526972656e74206e6f6e636560b01b6064820152608401610997565b8160c0013581600301541015610e425760405163de83c54360e01b8152602060048201526014602482015273696e73756666696369656e742062616c616e636560601b6044820152606401610997565b60088101610e5083806151bb565b604051610e5e929190615201565b9081526040519081900360200190208054610e78906150af565b9050600003610e995760405162461bcd60e51b815260040161099790615211565b600060088201610ea984806151bb565b604051610eb7929190615201565b90815260200160405180910390209050828060400190610ed791906151bb565b604051610ee5929190615201565b604051809103902081600101604051610efe9190615248565b604051809103902014610f545760405163de83c54360e01b815260206004820152601860248201527f6d6f64656c20726f6f742068617368206d69736d6174636800000000000000006044820152606401610997565b6007820154600090610f78906001600160a01b0316610f72866152be565b90612968565b905080610fc85760405163de83c54360e01b815260206004820181905260248201527f54454520736574746c656d656e742076616c69646174696f6e206661696c65646044820152606401610997565b600382015460c08501359060ff161561105c57610fe860208601866151bb565b90506000036110395760405162461bcd60e51b815260206004820152601a60248201527f7365637265742073686f756c64206e6f7420626520656d7074790000000000006044820152606401610997565b61104660208601866151bb565b60028501916110569190836153f9565b506110ce565b61106960208601866151bb565b1590506110b15760405162461bcd60e51b81526020600482015260166024820152757365637265742073686f756c6420626520656d70747960501b6044820152606401610997565b6064600d54826110c191906154ce565b6110cb91906154fb565b90505b606085013560028501556110e284826129ae565b5050505050565b60606106b860058484612c35565b6003546001600160a01b031633146111215760405162461bcd60e51b81526004016109979061517a565b610c1860058383612f32565b6111616040518060a00160405280606081526020016060815260200160608152602001600015158152602001600081525090565b61116f600586868686613042565b95945050505050565b6111866005338585856132dc565b505050565b60606106b860058484336133b9565b6111a5600a33613606565b60405133907f29d546abb6e94f4f04d5bdccb6682316f597d43776078f47e273f000e77b2a9190600090a2565b600054600160a01b900460ff16156112375760405162461bcd60e51b815260206004820152602260248201527f496e697469616c697a61626c653a20616c726561647920696e697469616c697a604482015261195960f21b6064820152608401610997565b6000805460ff60a01b1916600160a01b179055611253826126e4565b60029390935550600380546001600160a01b039092166001600160a01b0319928316811790915560048054909216179055600d55565b6003546001600160a01b031633146112b35760405162461bcd60e51b81526004016109979061517a565b600080610c8060058686348761364f565b6112cc61268a565b600d55565b610c186005338484613702565b6112e661268a565b6001600160a01b03811661134b5760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b6064820152608401610997565b611354816126e4565b50565b61135f61268a565b600255565b61136c6142cf565b6106b860058484613775565b600061138d84611388858561393b565b613973565b949350505050565b60006106b8838361397f565b6001600160a01b03831660009081526003850160205260408120606091906113c8816139d0565b915081851061140b576040805160008082526020820190925290611402565b6113ef61434b565b8152602001906001900390816113e75790505b50925050611609565b600084156114225761141d858761550f565b611424565b825b9050828111156114315750815b600061143d8783615522565b9050806001600160401b03811115611457576114576148bc565b60405190808252806020026020018201604052801561149057816020015b61147d61434b565b8152602001906001900390816114755790505b50945060005b818110156116045760006114b46114ad838b61550f565b86906139da565b60008181526002808e01602090815260409283902083516101208101855281546001600160a01b0390811682526001830154169281019290925291820154928101929092526003810154606083015260048101546080830152600681018054939450909260a083019190611527906150af565b80601f0160208091040260200160405190810160405280929190818152602001828054611553906150af565b80156115a05780601f10611575576101008083540402835291602001916115a0565b820191906000526020600020905b81548152906001019060200180831161158357829003601f168201915b505050918352505060078301546001600160a01b03166020820152601d8301546040820152601f83015460609091015288518990859081106115e4576115e4615535565b6020026020010181905250505080806115fc9061554b565b915050611496565b505050505b94509492505050565b6060600061161f836139e6565b9050806001600160401b03811115611639576116396148bc565b60405190808252806020026020018201604052801561167257816020015b61165f61424e565b8152602001906001900390816116575790505b50915060005b818110156119495761168a84826139f1565b6040805160e0810190915281546001600160a01b031681526001820180549192916020840191906116ba906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546116e6906150af565b80156117335780601f1061170857610100808354040283529160200191611733565b820191906000526020600020905b81548152906001019060200180831161171657829003601f168201915b50505050508152602001600282016040518060a001604052908160008201548152602001600182015481526020016002820154815260200160038201548152602001600482018054611784906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546117b0906150af565b80156117fd5780601f106117d2576101008083540402835291602001916117fd565b820191906000526020600020905b8154815290600101906020018083116117e057829003601f168201915b505050919092525050508152600782015460208083019190915260088301546001600160a01b038116604080850191909152600160a01b90910460ff1615156060840152600984018054825181850281018501909352808352608090940193919290919060009084015b82821015611913578382906000526020600020018054611886906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546118b2906150af565b80156118ff5780601f106118d4576101008083540402835291602001916118ff565b820191906000526020600020905b8154815290600101906020018083116118e257829003601f168201915b505050505081526020019060010190611867565b505050508152505083828151811061192d5761192d615535565b6020026020010181905250806119429061554b565b9050611678565b5050919050565b60008061195e858585613a17565b6004015495945050505050565b600061197688613a71565b90506119828982613973565b6119df576119d889826040518060e001604052808c6001600160a01b031681526020018b81526020018a8152602001898152602001886001600160a01b0316815260200160001515815260200186815250613aa6565b5050611a86565b60006119eb8a8a61397f565b9050600181016119fb8982615564565b5086516002820190815560208801516003830155604088015160048301556060880151600583015560808801518891906006840190611a3a9082615564565b50505060078101869055600881018054851515600160a01b026001600160a81b03199091166001600160a01b038816171790558251611a8290600983019060208601906143b2565b5050505b5050505050505050565b600080600080611aa1888888613a17565b6005810154909150600003611ac85760008160030154826004015493509350935050611cdc565b600093508391508142815b6005840154811015611c16576000846005018281548110611af657611af6615535565b60009182526020909120600490910201600381015490915060ff1615611b1c5750611c04565b888160020154611b2c919061550f565b8310611b57576001810154611b41908961550f565b60038201805460ff191660011790559750611c02565b6001810154611b66908761550f565b9550838214611bf45780856005018581548110611b8557611b85615535565b60009182526020909120825460049092020190815560018083015490820155600280830154908201556003918201549101805460ff191660ff909216151591909117905560058501805485919082908110611be257611be2615535565b60009182526020909120600490910201555b83611bfe8161554b565b9450505b505b80611c0e8161554b565b915050611ad3565b50601d83018290556005830154821015611cb3576005830154600090611c3d908490615522565b9050600f8110611c5657611c518484613ba1565b611cb1565b825b6005850154811015611caf576001856005018281548110611c7b57611c7b615535565b60009182526020909120600490910201600301805460ff191691151591909117905580611ca78161554b565b915050611c58565b505b505b85836003016000828254611cc79190615522565b90915550505050600481018290556003015491505b9450945094915050565b6001600160a01b0383166000908152600485016020526040812060609190611d0d816139d0565b9150818510611d4f576040805160008082526020820190925290611402565b611d3461434b565b815260200190600190039081611d2c57905050925050611609565b60008415611d6657611d61858761550f565b611d68565b825b905082811115611d755750815b6000611d818783615522565b9050806001600160401b03811115611d9b57611d9b6148bc565b604051908082528060200260200182016040528015611dd457816020015b611dc161434b565b815260200190600190039081611db95790505b50945060005b81811015611604576000611df16114ad838b61550f565b60008181526002808e01602090815260409283902083516101208101855281546001600160a01b0390811682526001830154169281019290925291820154928101929092526003810154606083015260048101546080830152600681018054939450909260a083019190611e64906150af565b80601f0160208091040260200160405190810160405280929190818152602001828054611e90906150af565b8015611edd5780601f10611eb257610100808354040283529160200191611edd565b820191906000526020600020905b815481529060010190602001808311611ec057829003601f168201915b505050918352505060078301546001600160a01b03166020820152601d8301546040820152601f8301546060909101528851899085908110611f2157611f21615535565b602002602001018190525050508080611f399061554b565b915050611dda565b60606000611f4e856139e6565b9050808410611f90576040805160008082526020820190925290611f88565b611f7561434b565b815260200190600190039081611f6d5790505b5091506109b2565b6000611f9c848661550f565b9050831580611faa57508181115b15611fb25750805b6000611fbe8683615522565b9050806001600160401b03811115611fd857611fd86148bc565b60405190808252806020026020018201604052801561201157816020015b611ffe61434b565b815260200190600190039081611ff65790505b50935060005b8181101561216f5760006120348961202f848b61550f565b6139f1565b604080516101208101825282546001600160a01b03908116825260018401541660208201526002830154918101919091526003820154606082015260048201546080820152600682018054929350909160a083019190612093906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546120bf906150af565b801561210c5780601f106120e15761010080835404028352916020019161210c565b820191906000526020600020905b8154815290600101906020018083116120ef57829003601f168201915b505050918352505060078301546001600160a01b03166020820152601d8301546040820152601f830154606090910152865187908490811061215057612150615535565b60200260200101819052505080806121679061554b565b915050612017565b505050935093915050565b6000612187848484613a17565b905060008160040154826003015461219f9190615522565b9050806000036121b0575050505050565b601e82601d0154106121e857604051639edd285f60e01b81526001600160a01b03808616600483015284166024820152604401610997565b6005820154601d83015460009111156122845782601d0154905060405180608001604052808281526020018381526020014281526020016000151581525083600501828154811061223b5761223b615535565b6000918252602091829020835160049290920201908155908201516001820155604082015160028201556060909101516003909101805460ff19169115159190911790556122f0565b50600582018054604080516080810182528281526020808201868152429383019384526000606084018181526001808801895597825292902092516004860290930192835551948201949094559051600282015591516003909201805460ff1916921515929092179091555b601d830180549060006123028361554b565b91905055508183600401600082825461231b919061550f565b9091555050505050505050565b61233686611388878761393b565b6123665760405163023280eb60e21b81526001600160a01b03808716600483015285166024820152604401610997565b6000612373878787613a17565b9050806008018484604051612389929190615201565b90815260405190819003602001902080546123a3906150af565b1590506123f25760405162461bcd60e51b815260206004820152601d60248201527f44656c6976657261626c6520494420616c7265616479206578697374730000006044820152606401610997565b6040805160c06020601f8701819004028201810190925260a08101858152600092829190889088908190850183828082843760009201829052509385525050506020808301879052604080519182018152828252830152606082015242608090910152601f830154909150601411156124aa5784848360090184601f01546014811061248057612480615535565b019161248d9190836153f9565b50601f820180549060006124a08361554b565b91905055506125ff565b60008260090183601e0154601481106124c5576124c5615535565b0180546124d1906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546124fd906150af565b801561254a5780601f1061251f5761010080835404028352916020019161254a565b820191906000526020600020905b81548152906001019060200180831161252d57829003601f168201915b5050505050905082600801816040516125639190615623565b908152604051908190036020019020600061257e8282614408565b61258c600183016000614408565b61259a600283016000614408565b5060038101805460ff191690556000600490910155601e830154869086906009860190601481106125cd576125cd615535565b01916125da9190836153f9565b50601483601e015460016125ee919061550f565b6125f8919061563f565b601e840155505b80826008018686604051612614929190615201565b908152604051908190036020019020815181906126319082615564565b50602082015160018201906126469082615564565b506040820151600282019061265b9082615564565b50606082015160038201805460ff19169115159190911790556080909101516004909101555050505050505050565b6000546001600160a01b03163314610c435760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e65726044820152606401610997565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6000806000612744888888613a17565b90506000851180156127595750600581015415155b1561292957600481015485906000805b600585015481101561290357600085600501828154811061278c5761278c615535565b60009182526020909120600490910201600381015490915060ff16156127b257506128f1565b806001015485106127f45760018101546127cc9086615522565b94508060010154846127de9190615522565b60038201805460ff191660011790559350612825565b8415612825578481600101600082825461280e9190615522565b9091555061281e90508585615522565b9350600094505b600381015460ff1615801561283a5750828214155b156128d5578086600501848154811061285557612855615535565b60009182526020909120825460049092020190815560018083015490820155600280830154908201556003918201549101805460ff191660ff9092161515919091179055600586018054849190829081106128b2576128b2615535565b6000918252602090912060049091020155826128cd8161554b565b9350506128ef565b600381015460ff166128ef57826128eb8161554b565b9350505b505b806128fb8161554b565b915050612769565b50601d84018190556005840154811015612921576129218482613ba1565b506004830155505b8381600301600082825461293d919061550f565b90915550506003810154600490910154909890975095505050505050565b600061138d848484613a17565b60008061297484613c09565b9050600061298182613c3a565b9050836001600160a01b031661299b828760a00151613c75565b6001600160a01b03161495945050505050565b6000826004015483600301546129c49190615522565b905080821115612b325760006129da8284615522565b90508084600401541015612a3f5760405163de83c54360e01b815260206004820152602560248201527f696e73756666696369656e742062616c616e636520696e2070656e64696e675260448201526419599d5b9960da1b6064820152608401610997565b80846004016000828254612a539190615522565b90915550506005840154805b600081118015612a6f5750600083115b15612b2e57600060058701612a85600184615522565b81548110612a9557612a95615535565b60009182526020909120600490910201600381015490915060ff1615612abb5750612b1c565b83816001015411612af6576001810154612ad59085615522565b600060018084019190915560038301805460ff191690911790559350612b1a565b83816001016000828254612b0a9190615522565b9091555060009450612b2e915050565b505b80612b2681615653565b915050612a5f565b5050505b81836003016000828254612b469190615522565b9091555050600480548454604051631bb1482360e31b81526001600160a01b039182169381019390935260248301859052169063dd8a411890604401600060405180830381600087803b158015612b9c57600080fd5b505af1158015612bb0573d6000803e3d6000fd5b50508454600386015460048701546040805192835260208301919091523394506001600160a01b0390921692507f526824944047da5b81071fb6349412005c5da81380b336103fbe5dd34556c776910160405180910390a3604051339083156108fc029084906000818181858888f19350505050158015610c2b573d6000803e3d6000fd5b60606000612c44858585613cf4565b905080516001600160401b03811115612c5f57612c5f6148bc565b604051908082528060200260200182016040528015612cc457816020015b612cb16040518060a00160405280606081526020016060815260200160608152602001600015158152602001600081525090565b815260200190600190039081612c7d5790505b5091506000612cd4868686613a17565b905060005b8251811015612f285781600801838281518110612cf857612cf8615535565b6020026020010151604051612d0d9190615623565b90815260200160405180910390206040518060a0016040529081600082018054612d36906150af565b80601f0160208091040260200160405190810160405280929190818152602001828054612d62906150af565b8015612daf5780601f10612d8457610100808354040283529160200191612daf565b820191906000526020600020905b815481529060010190602001808311612d9257829003601f168201915b50505050508152602001600182018054612dc8906150af565b80601f0160208091040260200160405190810160405280929190818152602001828054612df4906150af565b8015612e415780601f10612e1657610100808354040283529160200191612e41565b820191906000526020600020905b815481529060010190602001808311612e2457829003601f168201915b50505050508152602001600282018054612e5a906150af565b80601f0160208091040260200160405190810160405280929190818152602001828054612e86906150af565b8015612ed35780601f10612ea857610100808354040283529160200191612ed3565b820191906000526020600020905b815481529060010190602001808311612eb657829003601f168201915b5050509183525050600382015460ff16151560208201526004909101546040909101528451859083908110612f0a57612f0a615535565b60200260200101819052508080612f209061554b565b915050612cd9565b5050509392505050565b6000612f3e838361393b565b9050612f4a8482613973565b612f545750505050565b6001600160a01b03821660009081526003850160205260409020612f789082613f86565b506001600160a01b03831660009081526004850160205260409020612f9d9082613f86565b50612fa88482613f86565b50600081815260028086016020526040822080546001600160a01b031990811682556001820180549091169055908101829055600381018290556004810182905590612ff76005830182614442565b613005600683016000614408565b6007820180546001600160a01b0319169055613025600983016000614463565b506000601d8201819055601e8201819055601f9091015550505050565b6130766040518060a00160405280606081526020016060815260200160608152602001600015158152602001600081525090565b6000613083878787613a17565b9050806008018484604051613099929190615201565b90815260405190819003602001902080546130b3906150af565b90506000036130d45760405162461bcd60e51b815260040161099790615211565b8060080184846040516130e8929190615201565b90815260200160405180910390206040518060a0016040529081600082018054613111906150af565b80601f016020809104026020016040519081016040528092919081815260200182805461313d906150af565b801561318a5780601f1061315f5761010080835404028352916020019161318a565b820191906000526020600020905b81548152906001019060200180831161316d57829003601f168201915b505050505081526020016001820180546131a3906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546131cf906150af565b801561321c5780601f106131f15761010080835404028352916020019161321c565b820191906000526020600020905b8154815290600101906020018083116131ff57829003601f168201915b50505050508152602001600282018054613235906150af565b80601f0160208091040260200160405190810160405280929190818152602001828054613261906150af565b80156132ae5780601f10613283576101008083540402835291602001916132ae565b820191906000526020600020905b81548152906001019060200180831161329157829003601f168201915b5050509183525050600382015460ff1615156020820152600490910154604090910152979650505050505050565b6132ea85611388868661393b565b61331a5760405163023280eb60e21b81526001600160a01b03808616600483015284166024820152604401610997565b6000613327868686613a17565b905080600801838360405161333d929190615201565b9081526040519081900360200190208054613357906150af565b90506000036133785760405162461bcd60e51b815260040161099790615211565b600181600801848460405161338e929190615201565b908152604051908190036020019020600301805491151560ff19909216919091179055505050505050565b60606101f483111561340d5760405162461bcd60e51b815260206004820152601e60248201527f42617463682073697a6520746f6f206c6172676520286d6178203530302900006044820152606401610997565b826001600160401b03811115613425576134256148bc565b60405190808252806020026020018201604052801561345e57816020015b61344b61434b565b8152602001906001900390816134435790505b50905060005b838110156135fd57600061349e86868481811061348357613483615535565b90506020020160208101906134989190614565565b8561393b565b90506134aa8782613973565b156135ea5760008181526002808901602090815260409283902083516101208101855281546001600160a01b039081168252600183015416928101929092529182015492810192909252600381015460608301526004810154608083015260068101805491929160a083019190613520906150af565b80601f016020809104026020016040519081016040528092919081815260200182805461354c906150af565b80156135995780601f1061356e57610100808354040283529160200191613599565b820191906000526020600020905b81548152906001019060200180831161357c57829003601f168201915b505050918352505060078301546001600160a01b03166020820152601d8301546040820152601f83015460609091015284518590859081106135dd576135dd615535565b6020026020010181905250505b50806135f58161554b565b915050613464565b50949350505050565b600061361182613a71565b905061361d8382613973565b613645576040516304c76d3f60e11b81526001600160a01b0383166004820152602401610997565b610c2b8382613f92565b600080600061365e878761393b565b905061366a8882613973565b1561369b57604051632cf0675960e21b81526001600160a01b03808916600483015287166024820152604401610997565b6136a9888289898989614022565b6001600160a01b038616600090815260038901602052604090206136cd908261408f565b506001600160a01b038716600090815260048901602052604090206136f2908261408f565b5093976000975095505050505050565b61371084611388858561393b565b6137405760405163023280eb60e21b81526001600160a01b03808516600483015283166024820152604401610997565b600061374d858585613a17565b60070180546001600160a01b0319166001600160a01b03939093169290921790915550505050565b61377d6142cf565b600061378a858585613a17565b90506000613799868686612c35565b604080516101808101825284546001600160a01b0390811682526001860154166020808301919091526002860154828401526003860154606083015260048601546080830152600586018054845181840281018401909552808552949550919360a0850193929160009084015b8282101561385f576000848152602090819020604080516080810182526004860290920180548352600180820154848601526002820154928401929092526003015460ff16151560608301529083529092019101613806565b505050508152602001836006018054613877906150af565b80601f01602080910402602001604051908101604052809291908181526020018280546138a3906150af565b80156138f05780601f106138c5576101008083540402835291602001916138f0565b820191906000526020600020905b8154815290600101906020018083116138d357829003601f168201915b505050918352505060078401546001600160a01b031660208201526040810192909252601d8301546060830152601e8301546080830152601f9092015460a090910152949350505050565b604080516001600160a01b03938416602080830191909152929093168382015280518084038201815260609093019052815191012090565b60006106b8838361409b565b60008061398b83613a71565b600081815260028601602052604090209091506139a88583613973565b61138d576040516304c76d3f60e11b81526001600160a01b0385166004820152602401610997565b60006106a4825490565b60006106b883836140b3565b60006106a4826139d0565b6000806139fe84846139da565b6000908152600285016020526040902091505092915050565b600080613a24848461393b565b60008181526002870160205260409020909150613a418683613973565b61116f5760405163023280eb60e21b81526001600160a01b03808716600483015285166024820152604401610997565b604080516001600160a01b0383166020820152600091015b604051602081830303815290604052805190602001209050919050565b600082815260028401602090815260408220835181546001600160a01b0319166001600160a01b03909116178155908301518391906001820190613aea9082615564565b50604082015181600201600082015181600001556020820151816001015560408201518160020155606082015181600301556080820151816004019081613b319190615564565b50505060608201516007820155608082015160088201805460a08501511515600160a01b026001600160a81b03199091166001600160a01b039093169290921791909117905560c08201518051613b929160098401916020909101906143b2565b5061138d91508590508461408f565b6005820154805b82811115610c2b5783600501805480613bc357613bc361566a565b600082815260208120600460001990930192830201818155600181018290556002810191909155600301805460ff19169055905580613c0181615653565b915050613ba8565b6020808201516040808401516060850151608086015160c087015160e08801519451600097613a8997969101615680565b6040517f19457468657265756d205369676e6564204d6573736167653a0a3332000000006020820152603c8101829052600090605c01613a89565b600080600080613c84856140dd565b6040805160008152602081018083528b905260ff8516918101919091526060810183905260808101829052929550909350915060019060a0016020604051602081039080840390855afa158015613cdf573d6000803e3d6000fd5b5050604051601f190151979650505050505050565b60606000613d03858585613a17565b601f8101549091506000819003613d49576040805160008082526020820190925290613d3f565b6060815260200190600190039081613d2a5790505b50925050506106b8565b806001600160401b03811115613d6157613d616148bc565b604051908082528060200260200182016040528015613d9457816020015b6060815260200190600190039081613d7f5790505b5092506014811015613e805760005b81811015613e7a57826009018160148110613dc057613dc0615535565b018054613dcc906150af565b80601f0160208091040260200160405190810160405280929190818152602001828054613df8906150af565b8015613e455780601f10613e1a57610100808354040283529160200191613e45565b820191906000526020600020905b815481529060010190602001808311613e2857829003601f168201915b5050505050848281518110613e5c57613e5c615535565b60200260200101819052508080613e729061554b565b915050613da3565b50613f7d565b601e82015460005b82811015613f7a5760006014613e9e838561550f565b613ea8919061563f565b9050846009018160148110613ebf57613ebf615535565b018054613ecb906150af565b80601f0160208091040260200160405190810160405280929190818152602001828054613ef7906150af565b8015613f445780601f10613f1957610100808354040283529160200191613f44565b820191906000526020600020905b815481529060010190602001808311613f2757829003601f168201915b5050505050868381518110613f5b57613f5b615535565b6020026020010181905250508080613f729061554b565b915050613e88565b50505b50509392505050565b60006106b8838361410c565b6000818152600283016020526040812080546001600160a01b031916815581613fbe6001830182614408565b60006002830181815560038401829055600484018290556005840182905590613fea6006850182614408565b50506000600783018190556008830180546001600160a81b0319169055614015906009840190614472565b506106b890508383613f86565b600085815260028701602052604090206003810183905580546001600160a01b038087166001600160a01b031992831617835560018301805491871691909216179055600681016140738382615564565b506000601d8201819055601e8201819055601f820155611a8687875b60006106b883836141ff565b600081815260018301602052604081205415156106b8565b60008260000182815481106140ca576140ca615535565b9060005260206000200154905092915050565b600080600083516041146140f057600080fd5b5050506020810151604082015160609092015160001a92909190565b600081815260018301602052604081205480156141f5576000614130600183615522565b855490915060009061414490600190615522565b90508181146141a957600086600001828154811061416457614164615535565b906000526020600020015490508087600001848154811061418757614187615535565b6000918252602080832090910192909255918252600188019052604090208390555b85548690806141ba576141ba61566a565b6001900381819060005260206000200160009055905585600101600086815260200190815260200160002060009055600193505050506106a4565b60009150506106a4565b6000818152600183016020526040812054614246575081546001818101845560008481526020808220909301849055845484825282860190935260409020919091556106a4565b5060006106a4565b6040518060e0016040528060006001600160a01b03168152602001606081526020016142a26040518060a0016040528060008152602001600081526020016000815260200160008152602001606081525090565b81526020016000815260200160006001600160a01b03168152602001600015158152602001606081525090565b60405180610180016040528060006001600160a01b0316815260200160006001600160a01b03168152602001600081526020016000815260200160008152602001606081526020016060815260200160006001600160a01b03168152602001606081526020016000815260200160008152602001600081525090565b60405180610120016040528060006001600160a01b0316815260200160006001600160a01b031681526020016000815260200160008152602001600081526020016060815260200160006001600160a01b0316815260200160008152602001600081525090565b8280548282559060005260206000209081019282156143f8579160200282015b828111156143f857825182906143e89082615564565b50916020019190600101906143d2565b5061440492915061448c565b5090565b508054614414906150af565b6000825580601f10614424575050565b601f01602090049060005260206000209081019061135491906144a9565b508054600082556004029060005260206000209081019061135491906144be565b5061135490601481019061448c565b508054600082559060005260206000209081019061135491905b808211156144045760006144a08282614408565b5060010161448c565b5b8082111561440457600081556001016144aa565b5b8082111561440457600080825560018201819055600282015560038101805460ff191690556004016144bf565b6000602082840312156144fe57600080fd5b81356001600160e01b0319811681146106b857600080fd5b80356001600160a01b038116811461452d57600080fd5b919050565b6000806040838503121561454557600080fd5b61454e83614516565b915061455c60208401614516565b90509250929050565b60006020828403121561457757600080fd5b6106b882614516565b60005b8381101561459b578181015183820152602001614583565b50506000910152565b600081518084526145bc816020860160208601614580565b601f01601f19169290920160200192915050565b805182526020810151602083015260408101516040830152606081015160608301526000608082015160a0608085015261138d60a08501826145a4565b600060018060a01b0380835116845260208084015160e08287015261463560e08701826145a4565b90506040850151868203604088015261464e82826145d0565b9150506060850151606087015282608086015116608087015260a0850151151560a087015260c0850151925085810360c08701528083518083528383019150838160051b840101848601955060005b828110156146cb57601f198583030184526146b98288516145a4565b9686019693860193915060010161469d565b5098975050505050505050565b6020815260006106b8602083018461460d565b60008060006060848603121561470057600080fd5b61470984614516565b95602085013595506040909401359392505050565b600081518084526020808501808196508360051b8101915082860160005b858110156147ea578284038952815180516001600160a01b03168552610120818701516001600160a01b038116878901525060408281015190870152606080830151908701526080808301519087015260a0808301518188018390526147a4838901826145a4565b9250505060c0808301516147c2828901826001600160a01b03169052565b505060e08281015190870152610100918201519190950152978401979084019060010161473c565b5091979650505050505050565b60408152600061480a604083018561471e565b90508260208301529392505050565b6000602080830181845280855180835260408601915060408160051b870101925083870160005b8281101561486e57603f1988860301845261485c85835161460d565b94509285019290850190600101614840565b5092979650505050505050565b60008083601f84011261488d57600080fd5b5081356001600160401b038111156148a457600080fd5b602083019150836020828501011115610bdb57600080fd5b634e487b7160e01b600052604160045260246000fd5b60405160a081016001600160401b03811182821017156148f4576148f46148bc565b60405290565b60405161010081016001600160401b03811182821017156148f4576148f46148bc565b604051601f8201601f191681016001600160401b0381118282101715614945576149456148bc565b604052919050565b600082601f83011261495e57600080fd5b81356001600160401b03811115614977576149776148bc565b61498a601f8201601f191660200161491d565b81815284602083860101111561499f57600080fd5b816020850160208301376000918101602001919091529392505050565b8035801515811461452d57600080fd5b600082601f8301126149dd57600080fd5b813560206001600160401b03808311156149f9576149f96148bc565b8260051b614a0883820161491d565b9384528581018301938381019088861115614a2257600080fd5b84880192505b85831015614a5e57823584811115614a405760008081fd5b614a4e8a87838c010161494d565b8352509184019190840190614a28565b98975050505050505050565b600080600080600080600060c0888a031215614a8557600080fd5b87356001600160401b0380821115614a9c57600080fd5b614aa88b838c0161487b565b909950975060208a0135915080821115614ac157600080fd5b9089019060a0828c031215614ad557600080fd5b614add6148d2565b82358152602083013560208201526040830135604082015260608301356060820152608083013582811115614b1157600080fd5b614b1d8d82860161494d565b608083015250965060408a01359550614b3860608b01614516565b9450614b4660808b016149bc565b935060a08a0135915080821115614b5c57600080fd5b50614b698a828b016149cc565b91505092959891949750929550565b60008060408385031215614b8b57600080fd5b50508035926020909101359150565b60008060008060608587031215614bb057600080fd5b614bb985614516565b935060208501356001600160401b0380821115614bd557600080fd5b614be18883890161487b565b90955093506040870135915080821115614bfa57600080fd5b50614c078782880161494d565b91505092959194509250565b600080600060608486031215614c2857600080fd5b614c3184614516565b9250614c3f60208501614516565b9150604084013590509250925092565b600060208284031215614c6157600080fd5b81356001600160401b03811115614c7757600080fd5b820161010081850312156106b857600080fd5b6000815160a08452614c9f60a08501826145a4565b905060208301518482036020860152614cb882826145a4565b91505060408301518482036040860152614cd282826145a4565b915050606083015115156060850152608083015160808501528091505092915050565b600081518084526020808501808196508360051b8101915082860160005b858110156147ea578284038952614d2b848351614c8a565b98850198935090840190600101614d13565b6020815260006106b86020830184614cf5565b60008060008060608587031215614d6657600080fd5b614d6f85614516565b9350614d7d60208601614516565b925060408501356001600160401b03811115614d9857600080fd5b614da48782880161487b565b95989497509550505050565b6020815260006106b86020830184614c8a565b600080600060408486031215614dd857600080fd5b614de184614516565b925060208401356001600160401b03811115614dfc57600080fd5b614e088682870161487b565b9497909650939450505050565b60008060208385031215614e2857600080fd5b82356001600160401b0380821115614e3f57600080fd5b818501915085601f830112614e5357600080fd5b813581811115614e6257600080fd5b8660208260051b8501011115614e7757600080fd5b60209290920196919550909350505050565b6020815260006106b8602083018461471e565b60008060008060808587031215614eb257600080fd5b84359350614ec260208601614516565b9250614ed060408601614516565b9396929550929360600135925050565b600080600060608486031215614ef557600080fd5b614efe84614516565b9250614f0c60208501614516565b915060408401356001600160401b03811115614f2757600080fd5b614f338682870161494d565b9150509250925092565b600060208284031215614f4f57600080fd5b5035919050565b600081518084526020808501945080840160005b83811015614fa85781518051885283810151848901526040808201519089015260609081015115159088015260809096019590820190600101614f6a565b509495945050505050565b60208152614fcd6020820183516001600160a01b03169052565b60006020830151614fe960408401826001600160a01b03169052565b506040830151606083015260608301516080830152608083015160a083015260a08301516101808060c08501526150246101a0850183614f56565b915060c0850151601f19808685030160e087015261504284836145a4565b935060e08701519150610100615062818801846001600160a01b03169052565b8088015192505061012081878603018188015261507f8584614cf5565b90880151610140888101919091528801516101608089019190915290970151929095019190915250929392505050565b600181811c908216806150c357607f821691505b6020821081036150e357634e487b7160e01b600052602260045260246000fd5b50919050565b6020808252600f908201526e4c696d697420746f6f206c6172676560881b604082015260600190565b60a081528560a0820152858760c0830137600060c087830101526000601f19601f880116820160c083820301602084015261515060c08201886145d0565b604084019690965250506001600160a01b0392909216606083015215156080909101529392505050565b60208082526021908201527f43616c6c6572206973206e6f7420746865206c656467657220636f6e747261636040820152601d60fa1b606082015260800190565b6000808335601e198436030181126151d257600080fd5b8301803591506001600160401b038211156151ec57600080fd5b602001915036819003821315610bdb57600080fd5b8183823760009101908152919050565b6020808252601a908201527f44656c6976657261626c6520646f6573206e6f74206578697374000000000000604082015260600190565b6000808354615256816150af565b6001828116801561526e5760018114615283576152b2565b60ff19841687528215158302870194506152b2565b8760005260208060002060005b858110156152a95781548a820152908401908201615290565b50505082870194505b50929695505050505050565b600061010082360312156152d157600080fd5b6152d96148fa565b82356001600160401b03808211156152f057600080fd5b6152fc3683870161494d565b8352602085013591508082111561531257600080fd5b61531e3683870161494d565b6020840152604085013591508082111561533757600080fd5b6153433683870161494d565b60408401526060850135606084015261535e60808601614516565b608084015260a085013591508082111561537757600080fd5b506153843682860161494d565b60a08301525060c083013560c08201526153a060e08401614516565b60e082015292915050565b601f82111561118657600081815260208120601f850160051c810160208610156153d25750805b601f850160051c820191505b818110156153f1578281556001016153de565b505050505050565b6001600160401b03831115615410576154106148bc565b6154248361541e83546150af565b836153ab565b6000601f84116001811461545857600085156154405750838201355b600019600387901b1c1916600186901b1783556110e2565b600083815260209020601f19861690835b828110156154895786850135825560209485019460019092019101615469565b50868210156154a65760001960f88860031b161c19848701351681555b505060018560011b0183555050505050565b634e487b7160e01b600052601160045260246000fd5b80820281158282048414176106a4576106a46154b8565b634e487b7160e01b600052601260045260246000fd5b60008261550a5761550a6154e5565b500490565b808201808211156106a4576106a46154b8565b818103818111156106a4576106a46154b8565b634e487b7160e01b600052603260045260246000fd5b60006001820161555d5761555d6154b8565b5060010190565b81516001600160401b0381111561557d5761557d6148bc565b6155918161558b84546150af565b846153ab565b602080601f8311600181146155c657600084156155ae5750858301515b600019600386901b1c1916600185901b1785556153f1565b600085815260208120601f198616915b828110156155f5578886015182559484019460019091019084016155d6565b50858210156156135787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b60008251615635818460208701614580565b9190910192915050565b60008261564e5761564e6154e5565b500690565b600081615662576156626154b8565b506000190190565b634e487b7160e01b600052603160045260246000fd5b60008751615692818460208c01614580565b8751908301906156a6818360208c01614580565b0195865250506bffffffffffffffffffffffff19606093841b81166020860152603485019290925290911b1660548201526068019291505056fea2646970667358221220114511aedfca70fee55dada06f3a2b1974713a2ba44d623143a597464f82970d64736f6c63430008140033';
const isSuperArgs = (xs) => xs.length > 1;
class FineTuningServing__factory extends ContractFactory {
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

// Create interfaces from the contract factories
const ledgerInterface = new Interface(LedgerManager__factory.abi);
const inferenceInterface = new Interface(InferenceServing__factory.abi);
const fineTuningInterface = new Interface(FineTuningServing__factory.abi);
const contractInterfaces = {
    ledger: ledgerInterface,
    inference: inferenceInterface,
    fineTuning: fineTuningInterface,
};
function decodeCustomError(error) {
    try {
        // Type guard for error with data property
        const errorWithData = error;
        // Check if it's an ethers error with custom error data
        if (errorWithData.data && typeof errorWithData.data === 'string') {
            const errorData = errorWithData.data;
            // Try to decode with each contract interface
            for (const [, contractInterface] of Object.entries(contractInterfaces)) {
                try {
                    // Parse the custom error
                    const decodedError = contractInterface.parseError(errorData);
                    if (decodedError) {
                        // Format the error message based on the error name
                        const errorMessages = {
                            LedgerNotExists: 'Account does not exist. Please create an account first using "add-account".',
                            LedgerExists: 'Account already exists. Use "deposit" to add funds or "get-account" to view details.',
                            InsufficientBalance: 'Insufficient balance in the account.',
                            ServiceNotExist: 'Service provider does not exist. Please check the provider address.',
                            AccountNotExist: 'Sub-account does not exist for this provider.',
                            AccountExist: 'Sub-account already exists for this provider.',
                            InvalidVerifierInput: 'Invalid verification input provided.',
                            Unauthorized: 'Unauthorized. You do not have permission to perform this action.',
                            InvalidInput: 'Invalid input parameters provided.',
                        };
                        let message = errorMessages[decodedError.name] ||
                            `Error: ${decodedError.name}`;
                        // Add parameter details if available
                        if (decodedError.args && decodedError.args.length > 0) {
                            const argDetails = decodedError.args
                                .map((arg, index) => {
                                // Check if it's an address
                                if (typeof arg === 'string' &&
                                    arg.startsWith('0x') &&
                                    arg.length === 42) {
                                    return `Address: ${arg}`;
                                }
                                return `Arg${index}: ${arg}`;
                            })
                                .filter(Boolean)
                                .join(', ');
                            if (argDetails) {
                                message += ` (${argDetails})`;
                            }
                        }
                        return message;
                    }
                }
                catch {
                    // Continue to next interface if this one doesn't match
                    continue;
                }
            }
        }
        // Check for error reason
        if (errorWithData.reason) {
            return errorWithData.reason;
        }
        // Check for shortMessage
        if (errorWithData.shortMessage) {
            return errorWithData.shortMessage;
        }
        return null;
    }
    catch {
        return null;
    }
}
function formatError(error) {
    // First try to decode custom error
    const decodedError = decodeCustomError(error);
    if (decodedError) {
        return decodedError;
    }
    const errorWithMessage = error;
    // Check for common error patterns
    if (errorWithMessage.message) {
        // Check for gas estimation errors
        if (errorWithMessage.message.includes('execution reverted')) {
            const decoded = decodeCustomError(error);
            if (decoded) {
                return `Transaction failed: ${decoded}`;
            }
            return 'Transaction execution reverted. This usually means a requirement was not met.';
        }
        // Check for insufficient funds
        if (errorWithMessage.message.includes('insufficient funds')) {
            return 'Insufficient funds for transaction. Please check your wallet balance.';
        }
        // Check for nonce errors
        if (errorWithMessage.message.includes('nonce')) {
            return 'Transaction nonce error. Please wait a moment and try again.';
        }
        // Check for user rejected
        if (errorWithMessage.message.includes('user rejected') ||
            errorWithMessage.message.includes('User denied')) {
            return 'Transaction was rejected by the user.';
        }
        // Check for additional specific patterns
        if (errorWithMessage.message.includes('Deliverable not acknowledged yet')) {
            return "Deliverable not acknowledged yet. Please use 'acknowledge-model' to acknowledge the deliverable.";
        }
        if (errorWithMessage.message.includes('EncryptedSecret not found')) {
            return "Secret to decrypt model not found. Please ensure the task status is 'Finished'.";
        }
    }
    // Return original error message
    return errorWithMessage.message || String(error);
}
// Helper function to throw formatted errors from within SDK functions
function throwFormattedError(error) {
    const formattedMessage = formatError(error);
    const formattedError = new Error(formattedMessage);
    // Preserve original error properties if possible
    if (error && typeof error === 'object') {
        Object.assign(formattedError, error);
        formattedError.message = formattedMessage;
    }
    throw formattedError;
}

/**
 * Centralized cache key management
 * This file contains all cache key constants and helper functions
 * to ensure no key conflicts across different storage objects
 */
// Fixed cache keys
const CACHE_KEYS = {
    // Nonce related
    NONCE: 'nonce',
    NONCE_LOCK: 'nonce_lock',
    // First round marker
    FIRST_ROUND: 'firstRound',
};
// Cache key prefix patterns
const CACHE_KEY_PREFIXES = {
    // Service cache
    SERVICE: 'service_',
    // User acknowledgment
    USER_ACK: '_ack',
    // Cached fee
    CACHED_FEE: '_cachedFee',
    // Session token cache
    SESSION_TOKEN: 'session_',
};
// Metadata key suffixes
const METADATA_KEY_SUFFIXES = {
    // SETTLE_SIGNER_PRIVATE_KEY removed - no longer needed
    SIGNING_KEY: '_signingKey',
};
// Helper functions to generate dynamic cache keys
const CacheKeyHelpers = {
    // Service cache key
    getServiceKey(providerAddress) {
        return `${CACHE_KEY_PREFIXES.SERVICE}${providerAddress}`;
    },
    // User acknowledgment key
    getUserAckKey(userAddress, providerAddress) {
        return `${userAddress}_${providerAddress}${CACHE_KEY_PREFIXES.USER_ACK}`;
    },
    // Cached fee key
    getCachedFeeKey(provider) {
        return `${provider}${CACHE_KEY_PREFIXES.CACHED_FEE}`;
    },
    // getSettleSignerPrivateKeyKey removed - no longer needed
    // Metadata: signing key
    getSigningKeyKey(key) {
        return `${key}${METADATA_KEY_SUFFIXES.SIGNING_KEY}`;
    },
    // Dynamic content key (for inference server)
    getContentKey(id) {
        return id; // Keep as is since it's already unique
    },
    // Session token key
    getSessionTokenKey(providerAddress) {
        return `${CACHE_KEY_PREFIXES.SESSION_TOKEN}${providerAddress}`;
    },
};

class Metadata {
    nodeStorage = {};
    initialized = false;
    isBrowser = typeof window !== 'undefined' &&
        typeof window.localStorage !== 'undefined';
    storagePrefix = '0g_metadata_';
    constructor() { }
    async initialize() {
        if (this.initialized) {
            return;
        }
        if (!this.isBrowser) {
            this.nodeStorage = {};
        }
        this.initialized = true;
    }
    async setItem(key, value) {
        await this.initialize();
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
                console.log('Setting localStorage item:', fullKey, value);
                window.localStorage.setItem(fullKey, value);
            }
            catch (e) {
                console.warn('Failed to set localStorage item:', e);
                this.nodeStorage[key] = value;
            }
        }
        else {
            this.nodeStorage[key] = value;
        }
    }
    async getItem(key) {
        await this.initialize();
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
                return window.localStorage.getItem(fullKey);
            }
            catch (e) {
                console.warn('Failed to get localStorage item:', e);
                return this.nodeStorage[key] ?? null;
            }
        }
        else {
            return this.nodeStorage[key] ?? null;
        }
    }
    // storeSettleSignerPrivateKey removed - no longer needed
    async storeSigningKey(key, value) {
        await this.setItem(CacheKeyHelpers.getSigningKeyKey(key), value);
    }
    // getSettleSignerPrivateKey removed - no longer needed
    async getSigningKey(key) {
        const value = await this.getItem(CacheKeyHelpers.getSigningKeyKey(key));
        return value ?? null;
    }
}

var CacheValueTypeEnum;
(function (CacheValueTypeEnum) {
    CacheValueTypeEnum["Service"] = "service";
    CacheValueTypeEnum["BigInt"] = "bigint";
    CacheValueTypeEnum["Other"] = "other";
    CacheValueTypeEnum["Session"] = "session";
})(CacheValueTypeEnum || (CacheValueTypeEnum = {}));
class Cache {
    nodeStorage = {};
    initialized = false;
    isBrowser = typeof window !== 'undefined' &&
        typeof window.localStorage !== 'undefined';
    storagePrefix = '0g_cache_';
    constructor() { }
    setLock(key, value, ttl, type) {
        this.initialize();
        if (this.getStorageItem(key)) {
            return false;
        }
        this.setItem(key, value, ttl, type);
        return true;
    }
    removeLock(key) {
        this.initialize();
        this.removeStorageItem(key);
    }
    setItem(key, value, ttl, type) {
        this.initialize();
        const now = new Date();
        const item = {
            type,
            value: Cache.encodeValue(value),
            expiry: now.getTime() + ttl,
        };
        this.setStorageItem(key, JSON.stringify(item));
    }
    getItem(key) {
        this.initialize();
        const itemStr = this.getStorageItem(key);
        if (!itemStr) {
            return null;
        }
        const item = JSON.parse(itemStr);
        const now = new Date();
        if (now.getTime() > item.expiry) {
            this.removeStorageItem(key);
            return null;
        }
        return Cache.decodeValue(item.value, item.type);
    }
    initialize() {
        if (this.initialized) {
            return;
        }
        if (!this.isBrowser) {
            this.nodeStorage = {};
        }
        else {
            this.cleanupExpiredItems();
        }
        this.initialized = true;
    }
    setStorageItem(key, value) {
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
                window.localStorage.setItem(fullKey, value);
            }
            catch (e) {
                console.warn('Failed to set localStorage item:', e);
                this.nodeStorage[key] = value;
            }
        }
        else {
            this.nodeStorage[key] = value;
        }
    }
    getStorageItem(key) {
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
                return window.localStorage.getItem(fullKey);
            }
            catch (e) {
                console.warn('Failed to get localStorage item:', e);
                return this.nodeStorage[key] ?? null;
            }
        }
        else {
            return this.nodeStorage[key] ?? null;
        }
    }
    removeStorageItem(key) {
        const fullKey = this.storagePrefix + key;
        if (this.isBrowser) {
            try {
                window.localStorage.removeItem(fullKey);
            }
            catch (e) {
                console.warn('Failed to remove localStorage item:', e);
                delete this.nodeStorage[key];
            }
        }
        else {
            delete this.nodeStorage[key];
        }
    }
    cleanupExpiredItems() {
        if (!this.isBrowser)
            return;
        try {
            const keysToRemove = [];
            for (let i = 0; i < window.localStorage.length; i++) {
                const key = window.localStorage.key(i);
                if (key && key.startsWith(this.storagePrefix)) {
                    const itemStr = window.localStorage.getItem(key);
                    if (itemStr) {
                        try {
                            const item = JSON.parse(itemStr);
                            if (new Date().getTime() > item.expiry) {
                                keysToRemove.push(key);
                            }
                        }
                        catch (e) {
                            keysToRemove.push(key);
                        }
                    }
                }
            }
            keysToRemove.forEach((key) => window.localStorage.removeItem(key));
        }
        catch (e) {
            console.warn('Failed to cleanup expired items:', e);
        }
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
            additionalInfo: fields[8],
        };
        return Object.assign(tuple, object);
    }
}

class ZGServingUserBrokerBase {
    contract;
    metadata;
    cache;
    checkAccountThreshold = BigInt(100);
    topUpTriggerThreshold = BigInt(1000000);
    topUpTargetThreshold = BigInt(2000000);
    ledger;
    sessionDuration = 24 * 60 * 60 * 1000; // 24 hours validity
    constructor(contract, ledger, metadata, cache) {
        this.contract = contract;
        this.ledger = ledger;
        this.metadata = metadata;
        this.cache = cache;
    }
    async getService(providerAddress, useCache = true) {
        const key = CacheKeyHelpers.getServiceKey(providerAddress);
        const cachedSvc = await this.cache.getItem(key);
        if (cachedSvc && useCache) {
            return cachedSvc;
        }
        try {
            const svc = await this.contract.getService(providerAddress);
            await this.cache.setItem(key, svc, 10 * 60 * 1000, CacheValueTypeEnum.Service);
            return svc;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getQuote(providerAddress) {
        try {
            const service = await this.getService(providerAddress);
            const url = service.url;
            const endpoint = `${url}/v1/quote`;
            const rawReport = await this.fetchText(endpoint, {
                method: 'GET',
            });
            const ret = JSON.parse(rawReport);
            const decodedData = Buffer.from(ret['report_data'], 'base64').toString('utf-8');
            // Remove NULL characters that pad the address
            const signingAddress = decodedData.replace(/\0/g, '');
            return {
                rawReport,
                signingAddress: signingAddress,
            };
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async downloadQuoteReport(providerAddress, outputPath) {
        try {
            const service = await this.getService(providerAddress);
            const url = service.url;
            const endpoint = `${url}/v1/quote`;
            const quoteString = await this.fetchText(endpoint, {
                method: 'GET',
            });
            await fs$1.writeFile(outputPath, quoteString);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async userAcknowledged(providerAddress) {
        const userAddress = this.contract.getUserAddress();
        const key = CacheKeyHelpers.getUserAckKey(userAddress, providerAddress);
        const cachedSvc = await this.cache.getItem(key);
        if (cachedSvc) {
            return true;
        }
        try {
            const account = await this.contract.getAccount(providerAddress);
            if (account.teeSignerAddress !== ZeroAddress) {
                await this.cache.setItem(key, account.providerPubKey, 10 * 60 * 1000, CacheValueTypeEnum.Other);
                return true;
            }
            else {
                return false;
            }
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
        }
    }
    async getExtractor(providerAddress, useCache = true) {
        try {
            const svc = await this.getService(providerAddress, useCache);
            const extractor = this.createExtractor(svc);
            return extractor;
        }
        catch (error) {
            throwFormattedError(error);
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
    generateNonce() {
        if (typeof window !== 'undefined' && window.crypto) {
            // Browser environment - use Web Crypto API
            const array = new Uint8Array(16);
            window.crypto.getRandomValues(array);
            return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
        }
        else {
            // Node.js or other environment - use timestamp-based nonce
            const timestamp = Date.now();
            const random = Math.random();
            const randomStr = random.toString(36).substring(2, 15);
            return `${timestamp}-${randomStr}`.padEnd(32, '0');
        }
    }
    async generateSessionToken(providerAddress) {
        const userAddress = this.contract.getUserAddress();
        const timestamp = Date.now();
        const expiresAt = timestamp + this.sessionDuration;
        const nonce = this.generateNonce();
        const token = {
            address: userAddress,
            provider: providerAddress,
            timestamp,
            expiresAt,
            nonce,
        };
        // Create message to be signed
        const message = JSON.stringify(token);
        // Create hash using the same method as signRequest in encrypt.ts
        const messageHash = keccak256(toUtf8Bytes(message));
        // Sign using the same pattern as signRequest: signMessage with toBeArray
        const signature = await this.contract.signer.signMessage(Buffer.from(messageHash.slice(2), 'hex'));
        const session = {
            token,
            signature,
            rawMessage: message,
        };
        // Cache the session using the existing cache with proper TTL
        const cacheKey = CacheKeyHelpers.getSessionTokenKey(providerAddress);
        await this.cache.setItem(cacheKey, session, this.sessionDuration, CacheValueTypeEnum.Session);
        return session;
    }
    async getOrCreateSession(providerAddress) {
        const cacheKey = CacheKeyHelpers.getSessionTokenKey(providerAddress);
        const cached = (await this.cache.getItem(cacheKey));
        // Check if cached session exists and is not expired (with 1 hour buffer)
        if (cached && cached.token.expiresAt > Date.now() + 60 * 60 * 1000) {
            return cached;
        }
        // Generate new session
        return await this.generateSessionToken(providerAddress);
    }
    async getHeader(providerAddress, vllmProxy) {
        const userAddress = this.contract.getUserAddress();
        // Check if provider is acknowledged - this is still necessary
        if (!(await this.userAcknowledged(providerAddress))) {
            throw new Error('Provider signer is not acknowledged');
        }
        // Get or create session token
        const session = await this.getOrCreateSession(providerAddress);
        return {
            Address: userAddress,
            'VLLM-Proxy': `${vllmProxy}`,
            'Session-Token': session.rawMessage,
            'Session-Signature': session.signature,
        };
    }
    async calculateInputFees(extractor, content) {
        const svc = await extractor.getSvcInfo();
        const inputCount = await extractor.getInputCount(content);
        const inputFee = BigInt(inputCount) * BigInt(svc.inputPrice);
        return inputFee;
    }
    async updateCachedFee(provider, fee) {
        try {
            const key = CacheKeyHelpers.getCachedFeeKey(provider);
            const curFee = (await this.cache.getItem(key)) || BigInt(0);
            await this.cache.setItem(key, BigInt(curFee) + fee, 1 * 60 * 1000, CacheValueTypeEnum.BigInt);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async clearCacheFee(provider, fee) {
        try {
            const key = CacheKeyHelpers.getCachedFeeKey(provider);
            const curFee = (await this.cache.getItem(key)) || BigInt(0);
            await this.cache.setItem(key, BigInt(curFee) + fee, 1 * 60 * 1000, CacheValueTypeEnum.BigInt);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    /**
     * Transfer fund from ledger if fund in the inference account is less than a topUpTriggerThreshold * (inputPrice + outputPrice)
     */
    async topUpAccountIfNeeded(provider, content, gasPrice) {
        try {
            // Exit early if running in browser environment
            if (typeof window !== 'undefined' &&
                typeof window.document !== 'undefined') {
                return;
            }
            const extractor = await this.getExtractor(provider);
            const svc = await extractor.getSvcInfo();
            // Calculate target and trigger thresholds
            const targetThreshold = this.topUpTargetThreshold *
                (BigInt(svc.inputPrice) + BigInt(svc.outputPrice));
            const triggerThreshold = this.topUpTriggerThreshold *
                (BigInt(svc.inputPrice) + BigInt(svc.outputPrice));
            // Check if it's the first round
            const isFirstRound = (await this.cache.getItem(CACHE_KEYS.FIRST_ROUND)) !== 'false';
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
                try {
                    await this.ledger.transferFund(provider, 'inference', targetThreshold, gasPrice);
                }
                catch (error) {
                    // Check if it's an insufficient balance error
                    const errorMessage = error?.message?.toLowerCase() || '';
                    if (errorMessage.includes('insufficient')) {
                        console.warn(`Warning: To ensure stable service from the provider, ${targetThreshold} neuron needs to be transferred from the balance, but the current balance is insufficient.`);
                        return;
                    }
                    console.warn(`Warning: Failed to transfer funds: ${error?.message || error}`);
                    return;
                }
            }
            await this.clearCacheFee(provider, newFee);
        }
        catch (error) {
            console.warn(`Warning: Top up account failed: ${error?.message || error}`);
        }
    }
    async handleFirstRound(provider, triggerThreshold, targetThreshold, gasPrice) {
        let needTransfer = false;
        try {
            const acc = await this.contract.getAccount(provider);
            const lockedFund = acc.balance - acc.pendingRefund;
            needTransfer = lockedFund < triggerThreshold;
        }
        catch {
            needTransfer = true;
        }
        if (needTransfer) {
            try {
                await this.ledger.transferFund(provider, 'inference', targetThreshold, gasPrice);
            }
            catch (error) {
                // Check if it's an insufficient balance error
                const errorMessage = error?.message?.toLowerCase() || '';
                if (errorMessage.includes('insufficient')) {
                    console.warn(`Warning: To ensure stable service from the provider, ${targetThreshold} neuron needs to be transferred from the balance, but the current balance is insufficient.`);
                    return;
                }
                console.warn(`Warning: Failed to transfer funds: ${error?.message || error}`);
                return;
            }
        }
        // Mark the first round as complete
        await this.cache.setItem(CACHE_KEYS.FIRST_ROUND, 'false', 10000000 * 60 * 1000, CacheValueTypeEnum.Other);
    }
    /**
     * Check the cache fund for this provider, return true if the fund is above checkAccountThreshold * (inputPrice + outputPrice)
     * @param svc
     */
    async shouldCheckAccount(svc) {
        try {
            const key = CacheKeyHelpers.getCachedFeeKey(svc.provider);
            const usedFund = (await this.cache.getItem(key)) || BigInt(0);
            return (usedFund >
                this.checkAccountThreshold * (svc.inputPrice + svc.outputPrice));
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
        }
    }
    async getAccountWithDetail(provider) {
        try {
            const [account, lockTime] = await Promise.all([
                this.contract.getAccount(provider),
                this.contract.lockTime(),
            ]);
            const now = BigInt(Math.floor(Date.now() / 1000));
            const refunds = account.refunds
                .filter((refund) => !refund.processed)
                .filter((refund) => refund.amount !== BigInt(0))
                .map((refund) => ({
                amount: refund.amount,
                remainTime: lockTime - (now - refund.createdAt),
            }));
            return [account, refunds];
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async listAccount() {
        try {
            return await this.contract.listAccount();
        }
        catch (error) {
            throwFormattedError(error);
        }
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
            throwFormattedError(error);
        }
    }
    async listAccount(offset = 0, limit = 50) {
        try {
            const result = await this.serving.getAllAccounts(offset, limit);
            return result.accounts;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getAccount(provider) {
        try {
            const user = this.getUserAddress();
            const account = await this.serving.getAccount(user, provider);
            return account;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async acknowledgeTEESigner(providerAddress, providerSigner) {
        try {
            const tx = await this.serving.acknowledgeTEESigner(providerAddress, providerSigner);
            const receipt = await tx.wait();
            if (!receipt || receipt.status !== 1) {
                const error = new Error('Transaction failed');
                throw error;
            }
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getService(providerAddress) {
        try {
            return this.serving.getService(providerAddress);
        }
        catch (error) {
            throwFormattedError(error);
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
const INDEXER_URL_TURBO = 'http://47.251.40.189:12345';
const TOKEN_COUNTER_MERKLE_ROOT = '0x4e8ae3790920b9971397f088fcfacbb9dad0c28ec2831f37f3481933b1fdbdbc';
const TOKEN_COUNTER_FILE_HASH = '26ab266a12c9ce34611aba3f82baf056dc683181236d5fa15edb8eb8c8db3872';
const MODEL_HASH_MAP = {
    'distilbert-base-uncased': {
        turbo: '0x7f2244b25cd2219dfd9d14c052982ecce409356e0f08e839b79796e270d110a7',
        standard: '',
        description: 'DistilBERT is a transformers model, smaller and faster than BERT, which was pretrained on the same corpus in a self-supervised fashion, using the BERT base model as a teacher. More details can be found at: https://huggingface.co/distilbert/distilbert-base-uncased',
        tokenizer: '0x3317127671a3217583069001b2a00454ef4d1e838f8f1f4ffbe64db0ec7ed960',
        type: 'text',
    },
    // mobilenet_v2: {
    //     turbo: '0x8645816c17a8a70ebf32bcc7e621c659e8d0150b1a6bfca27f48f83010c6d12e',
    //     standard: '',
    //     description:
    //         'MobileNet V2 model pre-trained on ImageNet-1k at resolution 224x224. More details can be found at: https://huggingface.co/google/mobilenet_v2_1.0_224',
    // tokenizer:
    //     '0xcfdb4cf199829a3cbd453dd39cea5c337a29d4be5a87bad99d76f5a33ac2dfba',
    // type: 'image',
    // },
    // 'deepseek-r1-distill-qwen-1.5b': {
    //     turbo: '0x2084fdd904c9a3317dde98147d4e7778a40e076b5b0eb469f7a8f27ae5b13e7f',
    //     standard: '',
    //     description:
    //         'DeepSeek-R1-Zero, a model trained via large-scale reinforcement learning (RL) without supervised fine-tuning (SFT) as a preliminary step, demonstrated remarkable performance on reasoning. More details can be found at: https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B',
    // tokenizer:
    //     '0x382842561e59d71f90c1861041989428dd2c1f664e65a56ea21f3ade216b2046',
    // type: 'text',
    // },
    // 'cocktailsgd-opt-1.3b': {
    //     turbo: '0x02ed6d3889bebad9e2cd4008066478654c0886b12ad25ea7cf7d31df3441182e',
    //     standard: '',
    //     description:
    //         'CocktailSGD-opt-1.3B finetunes the Opt-1.3B langauge model with CocktailSGD, which is a novel distributed finetuning framework. More details can be found at: https://github.com/DS3Lab/CocktailSGD',
    //     tokenizer:
    //         '0x459311517bdeb3a955466d4e5e396944b2fdc68890de78f506261d95e6d1b000',
    //     type: 'text',
    // },
    // // TODO: remove
    // 'mock-model': {
    //     turbo: '0xcb42b5ca9e998c82dd239ef2d20d22a4ae16b3dc0ce0a855c93b52c7c2bab6dc',
    //     standard: '',
    //     description: '',
    //     tokenizer:
    //         '0x382842561e59d71f90c1861041989428dd2c1f664e65a56ea21f3ade216b2046',
    //     type: 'text',
    // },
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

/**
 * RequestProcessor is a subclass of ZGServingUserBroker.
 * It needs to be initialized with createZGServingUserBroker
 * before use.
 */
class RequestProcessor extends ZGServingUserBrokerBase {
    automata;
    constructor(contract, metadata, cache, ledger) {
        super(contract, ledger, metadata, cache);
        this.automata = new Automata();
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
     * if the actual balance of the customer's account is less than 500, settlement will be triggered immediately.
     * The actual balance is defined as the customer's inference account balance minus any unsettled amounts.
     *
     * This way, if the customer checks their account and sees a balance greater than 500, even if the provider settles
     * immediately, the deduction will leave about 500, ensuring that no insufficient balance situation occurs.
     *
     * 2. To Avoid Frequent Transfers
     *
     * On the customer's side, if the balance falls below 500, it should be topped up to 1000. This is to avoid frequent
     * transfers.
     *
     * 3. To Avoid Having to Check the Balance on Every Customer Request
     *
     * Record expenditures in processResponse and maintain a total consumption amount. Every time the total expenditure
     * reaches 1000, recheck the balance and perform a transfer if necessary.
     *
     * ps: The units for 500 and 1000 can be (service.inputPricePerToken + service.outputPricePerToken).
     */
    async getRequestHeaders(providerAddress, content, vllmProxy) {
        try {
            await this.topUpAccountIfNeeded(providerAddress, content);
            if (vllmProxy === undefined) {
                vllmProxy = true;
            }
            // Simplified call - only pass required parameters
            return await this.getHeader(providerAddress, vllmProxy);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async acknowledgeProviderSigner(providerAddress, gasPrice) {
        try {
            try {
                await this.contract.getAccount(providerAddress);
            }
            catch {
                await this.ledger.transferFund(providerAddress, 'inference', BigInt(0), gasPrice);
            }
            const { rawReport, signingAddress } = await this.getQuote(providerAddress);
            if (!rawReport || !signingAddress) {
                throw new Error('Invalid intel_quote');
            }
            // TODO: Verify the quote here
            const account = await this.contract.getAccount(providerAddress);
            if (account.teeSignerAddress === signingAddress) {
                console.log('Provider signer already acknowledged');
                return;
            }
            await this.contract.acknowledgeTEESigner(providerAddress, signingAddress);
            const userAddress = this.contract.getUserAddress();
            const cacheKey = CacheKeyHelpers.getUserAckKey(userAddress, providerAddress);
            this.cache.setItem(cacheKey, signingAddress, 1 * 60 * 1000, CacheValueTypeEnum.Other);
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
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
    automata;
    constructor(contract, ledger, metadata, cache) {
        super(contract, ledger, metadata, cache);
        this.automata = new Automata();
    }
    async verifyService(providerAddress) {
        try {
            const { valid } = await this.getSigningAddress(providerAddress, true);
            return valid;
        }
        catch (error) {
            throwFormattedError(error);
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
    async getSigningAddress(providerAddress, verifyRA = false, vllmProxy = true) {
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
            const { signingAddress } = vllmProxy
                ? await this.getQuoteInLLMServer(svc.url, svc.model)
                : await this.getQuote(providerAddress);
            if (!signingAddress) {
                throw new Error('signing address does not exist');
            }
            signingKey = `${this.contract.getUserAddress()}_${providerAddress}`;
            await this.metadata.storeSigningKey(signingKey, signingAddress);
            // Verification of RA should be separated from fetching signing address
            // const rpc = process.env.RPC_ENDPOINT
            // // bypass quote verification if testing on localhost
            // if (!rpc || !/localhost|127\.0\.0\.1/.test(rpc)) {
            //     valid =
            //         (await this.automata.verifyQuote(signerRA.intel_quote)) ||
            //         false
            //     console.log(
            //         'Quote verification when verify signing key quote:',
            //         valid
            //     )
            //     // if (nvidia_payload) {
            //     //     const svc = await this.getService(providerAddress)
            //     //     const valid = await Verifier.verifyRA(
            //     //         svc.url,
            //     //         nvidia_payload
            //     //     )
            //     //     console.log('nvidia payload verification:', valid)
            //     //     if (!valid) {
            //     //         throw new Error('nvidia payload verify failed')
            //     //     }
            //     // }
            // }
            // TODO: use intel_quote to verify signing address
            // valid = await Verifier.verifyRA(svc.url, signerRA.nvidia_payload)
            return {
                valid: true,
                signingAddress,
            };
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getSignerRaDownloadLink(providerAddress) {
        try {
            const svc = await this.getService(providerAddress);
            return `${svc.url}/v1/proxy/attestation/report`;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getChatSignatureDownloadLink(providerAddress, chatID) {
        try {
            const svc = await this.getService(providerAddress);
            return `${svc.url}/v1/proxy/signature/${chatID}`;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    static async verifyRA(providerBrokerURL, nvidia_payload) {
        return fetch(`${providerBrokerURL}/v1/quote/verify/gpu`, {
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
    // async fetSignerRA(
    //     providerBrokerURL: string,
    //     model: string
    // ): Promise<string> {
    //     const endpoint = `${providerBrokerURL}/v1/proxy/attestation/report?model=${model}`
    //     const quoteString = await this.fetchText(endpoint, {
    //         method: 'GET',
    //     })
    //     // Write quoteString to /tmp/del
    //     await fs.promises.writeFile('/tmp/del', quoteString)
    //     return quoteString
    // }
    async getQuoteInLLMServer(providerBrokerURL, model) {
        try {
            const rawReport = await this.fetchText(`${providerBrokerURL}/v1/proxy/attestation/report?model=${model}`, {
                method: 'GET',
            });
            const ret = JSON.parse(rawReport);
            return {
                rawReport,
                signingAddress: ret['signing_address'],
            };
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    static async fetSignatureByChatID(providerBrokerURL, chatID, model, vllmProxy) {
        return fetch(`${providerBrokerURL}/v1/proxy/signature/${chatID}?model=${model}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'VLLM-Proxy': `${vllmProxy}`,
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
            throwFormattedError(error);
        });
    }
    static verifySignature(message, signature, expectedAddress) {
        const messageHash = ethers.hashMessage(message);
        const recoveredAddress = ethers.recoverAddress(messageHash, signature);
        return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
    }
}

/**
 * Simple logger utility that supports debug mode
 * Set DEBUG=true or NODE_ENV=development to enable debug logs
 */
class Logger {
    static instance;
    debugMode;
    constructor() {
        // Check multiple environment variables for debug mode
        this.debugMode =
            process.env.DEBUG === 'true' ||
                process.env.DEBUG === '1' ||
                process.env.NODE_ENV === 'development' ||
                process.env.ZG_DEBUG === 'true' ||
                process.env.ZG_DEBUG === '1';
    }
    static getInstance() {
        if (!Logger.instance) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }
    /**
     * Enable or disable debug mode programmatically
     */
    setDebugMode(enabled) {
        this.debugMode = enabled;
    }
    /**
     * Check if debug mode is enabled
     */
    isDebugMode() {
        return this.debugMode;
    }
    /**
     * Log debug messages (only in debug mode)
     */
    debug(message, ...args) {
        if (this.debugMode) {
            console.log(`[DEBUG] ${new Date().toISOString()} - ${message}`, ...args);
        }
    }
    /**
     * Log info messages (always)
     */
    info(message, ...args) {
        console.log(`[INFO] ${new Date().toISOString()} - ${message}`, ...args);
    }
    /**
     * Log warning messages (always)
     */
    warn(message, ...args) {
        console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, ...args);
    }
    /**
     * Log error messages (always)
     */
    error(message, ...args) {
        console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, ...args);
    }
}
// Export singleton instance
const logger = Logger.getInstance();

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
    async processResponse(providerAddress, content, chatID, vllmProxy) {
        try {
            const extractor = await this.getExtractor(providerAddress);
            const outputFee = await this.calculateOutputFees(extractor, content);
            await this.updateCachedFee(providerAddress, outputFee);
            const svc = await extractor.getSvcInfo();
            if (!isVerifiability(svc.verifiability)) {
                return false;
            }
            if (!chatID) {
                throw new Error('Chat ID does not exist');
            }
            logger.debug('Chat ID:', chatID);
            if (vllmProxy === undefined) {
                vllmProxy = true;
            }
            let singerRAVerificationResult = await this.verifier.getSigningAddress(providerAddress, false, vllmProxy);
            logger.debug('Singer RA Verification Result:', singerRAVerificationResult);
            if (!singerRAVerificationResult.valid) {
                singerRAVerificationResult =
                    await this.verifier.getSigningAddress(providerAddress, true, vllmProxy);
            }
            if (!singerRAVerificationResult.valid) {
                throw new Error('Signing address is invalid');
            }
            logger.debug('Fetching signature from provider broker URL:', svc.url, vllmProxy
                ? 'with proxied LLM server'
                : 'with original LLM server');
            const ResponseSignature = await Verifier.fetSignatureByChatID(svc.url, chatID, svc.model, vllmProxy);
            return Verifier.verifySignature(ResponseSignature.text, ResponseSignature.signature, singerRAVerificationResult.signingAddress);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async calculateOutputFees(extractor, content) {
        const svc = await extractor.getSvcInfo();
        logger.debug('Service Info:', svc);
        const outputCount = await extractor.getOutputCount(content);
        return BigInt(outputCount) * BigInt(svc.outputPrice);
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
            throwFormattedError(error);
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
            throwFormattedError(error);
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
            throwFormattedError(error);
        }
    };
    getAccountWithDetail = async (providerAddress) => {
        try {
            return await this.accountProcessor.getAccountWithDetail(providerAddress);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    /**
     * checks if the user has acknowledged the provider signer.
     *
     * @param {string} providerAddress - The address of the provider.
     * @returns {Promise<boolean>} A promise that resolves to a boolean indicating whether the user
     * has acknowledged the provider signer.
     * @throws Will throw an error if the acknowledgment check fails.
     */
    userAcknowledged = async (providerAddress) => {
        try {
            return await this.requestProcessor.userAcknowledged(providerAddress);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    /**
     * Acknowledge the given provider address.
     *
     * @param {string} providerAddress - The address of the provider identifying the account.
     *
     *
     * @throws Will throw an error if failed to acknowledge.
     */
    acknowledgeProviderSigner = async (providerAddress, gasPrice) => {
        try {
            return await this.requestProcessor.acknowledgeProviderSigner(providerAddress, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    /**
     * Downloads quote report data from the provider service to a specified file.
     *
     * @param {string} providerAddress - The address of the provider.
     * @param {string} outputPath - The file path where the quote report will be saved.
     *
     * @throws Will throw an error if failed to download the quote report.
     */
    downloadQuoteReport = async (providerAddress, outputPath) => {
        try {
            return await this.requestProcessor.downloadQuoteReport(providerAddress, outputPath);
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
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
    getRequestHeaders = async (providerAddress, content, vllmProxy) => {
        try {
            return await this.requestProcessor.getRequestHeaders(providerAddress, content, vllmProxy);
        }
        catch (error) {
            throwFormattedError(error);
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
     * @param {boolean} vllmProxy - Chat signature proxy, default is true
     *
     * @returns A boolean value. True indicates the returned content is valid, otherwise it is invalid.
     *
     * @throws An error if any issues occur during the processing of the response.
     */
    processResponse = async (providerAddress, content, chatID, vllmProxy) => {
        try {
            return await this.responseProcessor.processResponse(providerAddress, content, chatID, vllmProxy);
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
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
            throwFormattedError(error);
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
    getChatSignatureDownloadLink = async (providerAddress, chatID) => {
        try {
            return await this.verifier.getChatSignatureDownloadLink(providerAddress, chatID);
        }
        catch (error) {
            throwFormattedError(error);
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

// Define which errors to retry on
const RETRY_ERROR_SUBSTRINGS = [
    'transaction underpriced',
    'replacement transaction underpriced',
    'fee too low',
    'mempool',
];

const TIMEOUT_MS$1 = 300_000;
class FineTuningServingContract {
    serving;
    signer;
    _userAddress;
    _gasPrice;
    _maxGasPrice;
    _step;
    constructor(signer, contractAddress, userAddress, gasPrice, maxGasPrice, step) {
        this.serving = FineTuningServing__factory.connect(contractAddress, signer);
        this.signer = signer;
        this._userAddress = userAddress;
        this._gasPrice = gasPrice;
        if (maxGasPrice) {
            this._maxGasPrice = BigInt(maxGasPrice);
        }
        this._step = step || 11;
    }
    lockTime() {
        return this.serving.lockTime();
    }
    async sendTx(name, txArgs, txOptions) {
        if (txOptions.gasPrice === undefined) {
            txOptions.gasPrice = (await this.signer.provider?.getFeeData())?.gasPrice;
            // Add a delay to avoid too frequent RPC calls
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        else {
            txOptions.gasPrice = BigInt(txOptions.gasPrice);
        }
        while (true) {
            try {
                console.log('sending tx with gas price', txOptions.gasPrice);
                const tx = await this.serving.getFunction(name)(...txArgs, txOptions);
                console.log('tx hash:', tx.hash);
                const receipt = (await Promise.race([
                    tx.wait(),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('Get Receipt timeout, try set higher gas price')), TIMEOUT_MS$1)),
                ]));
                this.checkReceipt(receipt);
                break;
            }
            catch (error) {
                if (error.message ===
                    'Get Receipt timeout, try set higher gas price') {
                    const nonce = await this.signer.getNonce();
                    const pendingNonce = await this.signer.provider?.getTransactionCount(this._userAddress, 'pending');
                    if (pendingNonce !== undefined &&
                        pendingNonce - nonce > 5 &&
                        txOptions.nonce === undefined) {
                        console.warn(`Significant gap detected between pending nonce (${pendingNonce}) and current nonce (${nonce}). This may indicate skipped or missing transactions. Using the current confirmed nonce for the transaction.`);
                        txOptions.nonce = nonce;
                    }
                }
                if (this._maxGasPrice === undefined) {
                    throwFormattedError(error);
                }
                let errorMessage = '';
                if (error.message) {
                    errorMessage = error.message;
                }
                else if (error.info?.error?.message) {
                    errorMessage = error.info.error.message;
                }
                const shouldRetry = RETRY_ERROR_SUBSTRINGS.some((substr) => errorMessage.includes(substr));
                if (!shouldRetry) {
                    throwFormattedError(error);
                }
                console.log('Retrying transaction with higher gas price due to:', errorMessage);
                let currentGasPrice = txOptions.gasPrice;
                if (currentGasPrice >= this._maxGasPrice) {
                    throwFormattedError(error);
                }
                currentGasPrice =
                    (currentGasPrice * BigInt(this._step)) / BigInt(10);
                if (currentGasPrice > this._maxGasPrice) {
                    currentGasPrice = this._maxGasPrice;
                }
                txOptions.gasPrice = currentGasPrice;
            }
        }
    }
    async listService() {
        try {
            const services = await this.serving.getAllServices();
            return services;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async listAccount(offset = 0, limit = 50) {
        try {
            const result = await this.serving.getAllAccounts(offset, limit);
            return result.accounts;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getAccount(provider) {
        try {
            const user = this.getUserAddress();
            const account = await this.serving.getAccount(user, provider);
            return account;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async acknowledgeProviderSigner(providerAddress, providerSigner, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('acknowledgeProviderSigner', [providerAddress, providerSigner], txOptions);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async acknowledgeDeliverable(providerAddress, id, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('acknowledgeDeliverable', [providerAddress, id], txOptions);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getService(providerAddress) {
        try {
            return this.serving.getService(providerAddress);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getDeliverable(providerAddress, id) {
        try {
            const user = this.getUserAddress();
            return this.serving.getDeliverable(user, providerAddress, id);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    getUserAddress() {
        return this._userAddress;
    }
    checkReceipt(receipt) {
        if (!receipt) {
            throw new Error('Transaction failed with no receipt');
        }
        if (receipt.status !== 1) {
            throw new Error('Transaction reverted');
        }
    }
}

async function upload(privateKey, dataPath, gasPrice, maxGasPrice) {
    try {
        const fileSize = await getFileContentSize(dataPath);
        return new Promise((resolve, reject) => {
            const command = path__default.join(__dirname, '..', '..', '..', '..', 'binary', '0g-storage-client');
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
                '--skip-tx=false',
                '--log-level=debug',
            ];
            if (gasPrice) {
                args.push('--gas-price', gasPrice.toString());
            }
            if (maxGasPrice) {
                args.push('--max-gas-price', maxGasPrice.toString());
            }
            const process = spawn$1(command, args);
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
        const command = path__default.join(__dirname, '..', '..', '..', '..', 'binary', '0g-storage-client');
        const args = [
            'download',
            '--file',
            dataPath,
            '--indexer',
            INDEXER_URL_TURBO,
            '--roots',
            dataRoot,
        ];
        const process = spawn$1(command, args);
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
        const fileHandle = await fs$1.open(filePath, 'r');
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

// Dynamic imports for Node.js specific modules
let fs;
let os;
let path;
let AdmZip;
let spawn;
let exec;
let createHash;
let createReadStream;
async function initNodeModules() {
    if (isBrowser()) {
        throw new Error('Token calculation functions are not available in browser environment. Please use these functions in a Node.js environment.');
    }
    if (!fs) {
        fs =
            (await import('fs/promises')).default ||
                (await import('fs/promises'));
        os = (await import('os')).default || (await import('os'));
        path = (await import('path')).default || (await import('path'));
        AdmZip = (await import('./adm-zip-86f30d47.js').then(function (n) { return n.a; })).default;
        const childProcess = await import('child_process');
        spawn = childProcess.spawn;
        exec = childProcess.exec;
        const crypto = await import('crypto');
        createHash = crypto.createHash;
        createReadStream = (await import('fs')).createReadStream;
    }
}
// Re-export download with browser check
async function safeDynamicImport() {
    if (isBrowser()) {
        throw new Error('ZG Storage operations are not available in browser environment.');
    }
    const { download } = await import('./index-c3f81539.js');
    return { download };
}
async function calculateTokenSizeViaExe(tokenizerRootHash, datasetPath, datasetType, tokenCounterMerkleRoot, tokenCounterFileHash) {
    await initNodeModules();
    const { download } = await safeDynamicImport();
    const executorDir = path.join(__dirname, '..', '..', '..', '..', 'binary');
    const binaryFile = path.join(executorDir, 'token_counter');
    let needDownload = false;
    try {
        await fs.access(binaryFile);
        console.log('calculating file Hash');
        const hash = await calculateFileHash(binaryFile);
        console.log('file hash: ', hash);
        if (tokenCounterFileHash !== hash) {
            console.log(`file hash mismatch, expected: `, tokenCounterFileHash);
            needDownload = true;
        }
    }
    catch (error) {
        console.log(`File ${binaryFile} does not exist.`);
        needDownload = true;
    }
    if (needDownload) {
        try {
            await fs.unlink(binaryFile);
        }
        catch (error) {
            console.error(`Failed to delete ${binaryFile}:`, error);
        }
        console.log(`Downloading ${binaryFile}`);
        await download(binaryFile, tokenCounterMerkleRoot);
        await fs.chmod(binaryFile, 0o755);
    }
    return await calculateTokenSize(tokenizerRootHash, datasetPath, datasetType, binaryFile, []);
}
async function calculateTokenSizeViaPython(tokenizerRootHash, datasetPath, datasetType) {
    await initNodeModules();
    const isPythonInstalled = await checkPythonInstalled();
    if (!isPythonInstalled) {
        throw new Error('Python is required but not installed. Please install Python first.');
    }
    for (const packageName of ['transformers', 'datasets']) {
        const isPackageInstalled = await checkPackageInstalled(packageName);
        if (!isPackageInstalled) {
            console.log(`${packageName} is not installed. Installing...`);
            try {
                await installPackage(packageName);
            }
            catch (error) {
                throw new Error(`Failed to install ${packageName}: ${error}`);
            }
        }
    }
    const projectRoot = path.resolve(__dirname, '../../../../');
    return await calculateTokenSize(tokenizerRootHash, datasetPath, datasetType, 'python3', [path.join(projectRoot, 'token.counter', 'token_counter.py')]);
}
async function calculateTokenSize(tokenizerRootHash, datasetPath, datasetType, executor, args) {
    const { download } = await safeDynamicImport();
    const tmpDir = await fs.mkdtemp(`${os.tmpdir()}${path.sep}`);
    console.log(`current temporary directory ${tmpDir}`);
    const tokenizerPath = path.join(tmpDir, 'tokenizer.zip');
    await download(tokenizerPath, tokenizerRootHash);
    const subDirectories = await getSubdirectories(tmpDir);
    unzipFile(tokenizerPath, tmpDir);
    const newDirectories = new Set();
    for (const item of await getSubdirectories(tmpDir)) {
        if (!subDirectories.has(item)) {
            newDirectories.add(item);
        }
    }
    if (newDirectories.size !== 1) {
        throw new Error('Invalid tokenizer directory');
    }
    const tokenizerUnzipPath = path.join(tmpDir, Array.from(newDirectories)[0]);
    let datasetUnzipPath = datasetPath;
    if (await isZipFile(datasetPath)) {
        unzipFile(datasetPath, tmpDir);
        datasetUnzipPath = path.join(tmpDir, 'data');
        try {
            await fs.access(datasetUnzipPath);
        }
        catch (error) {
            await fs.mkdir(datasetUnzipPath, { recursive: true });
        }
    }
    return runExecutor(executor, [
        ...args,
        datasetUnzipPath,
        datasetType,
        tokenizerUnzipPath,
    ])
        .then((output) => {
        console.log('token_counter script output:', output);
        if (!output || typeof output !== 'string') {
            throw new Error('Invalid output from token counter');
        }
        const [num1, num2] = output
            .split(' ')
            .map((str) => parseInt(str, 10));
        if (isNaN(num1) || isNaN(num2)) {
            throw new Error('Invalid number');
        }
        return num1;
    })
        .catch((error) => {
        console.error('Error running Python script:', error);
        throwFormattedError(error);
    });
}
function checkPythonInstalled() {
    return new Promise((resolve, reject) => {
        exec('python3 --version', (error, stdout, stderr) => {
            if (error) {
                console.error('Python is not installed or not in PATH');
                resolve(false);
            }
            else {
                resolve(true);
            }
        });
    });
}
function checkPackageInstalled(packageName) {
    return new Promise((resolve, reject) => {
        exec(`pip show ${packageName}`, (error, stdout, stderr) => {
            if (error) {
                resolve(false);
            }
            else {
                resolve(true);
            }
        });
    });
}
function installPackage(packageName) {
    return new Promise((resolve, reject) => {
        exec(`pip install ${packageName}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Failed to install ${packageName}`);
                reject(error);
            }
            else {
                console.log(`${packageName} installed successfully`);
                resolve();
            }
        });
    });
}
function runExecutor(executor, args) {
    return new Promise((resolve, reject) => {
        console.log(`Run ${executor} ${args}`);
        const pythonProcess = spawn(executor, [...args]);
        let output = '';
        let errorOutput = '';
        pythonProcess.stdout.on('data', (data) => {
            output += data.toString();
        });
        pythonProcess.stderr.on('data', (data) => {
            errorOutput += data.toString();
            console.error(`Python error: ${errorOutput}`);
        });
        pythonProcess.on('close', (code) => {
            if (code === 0) {
                resolve(output.trim());
            }
            else {
                reject(`Python script failed with code ${code}: ${errorOutput.trim()}`);
            }
        });
    });
}
function unzipFile(zipFilePath, targetDir) {
    try {
        const zip = new AdmZip(zipFilePath);
        zip.extractAllTo(targetDir, true);
        console.log(`Successfully unzipped to ${targetDir}`);
    }
    catch (error) {
        console.error('Error during unzipping:', error);
        throw error;
    }
}
async function isZipFile(targetPath) {
    try {
        const stats = await fs.stat(targetPath);
        return (stats.isFile() && path.extname(targetPath).toLowerCase() === '.zip');
    }
    catch (error) {
        return false;
    }
}
async function getSubdirectories(dirPath) {
    try {
        const entries = await fs.readdir(dirPath, { withFileTypes: true });
        const subdirectories = new Set(entries
            .filter((entry) => entry.isDirectory()) // Only keep directories
            .map((entry) => entry.name));
        return subdirectories;
    }
    catch (error) {
        console.error('Error reading directory:', error);
        return new Set();
    }
}
async function calculateFileHash(filePath, algorithm = 'sha256') {
    return new Promise((resolve, reject) => {
        const hash = createHash(algorithm);
        const stream = createReadStream(filePath);
        stream.on('data', (chunk) => {
            hash.update(chunk);
        });
        stream.on('end', () => {
            resolve(hash.digest('hex'));
        });
        stream.on('error', (err) => {
            reject(err);
        });
    });
}

class ModelProcessor extends BrokerBase {
    async listModel() {
        const services = await this.contract.listService();
        let customizedModels = [];
        for (const service of services) {
            if (service.models.length !== 0) {
                const url = service.url;
                const models = await this.servingProvider.getCustomizedModels(url);
                for (const item of models) {
                    customizedModels.push([
                        item.name,
                        {
                            description: item.description,
                            provider: service.provider,
                        },
                    ]);
                }
            }
        }
        return [Object.entries(MODEL_HASH_MAP), customizedModels];
    }
    async uploadDataset(privateKey, dataPath, gasPrice, maxGasPrice) {
        await upload(privateKey, dataPath, gasPrice);
    }
    async calculateToken(datasetPath, usePython, preTrainedModelName, providerAddress) {
        let tokenizer;
        let dataType;
        if (preTrainedModelName in MODEL_HASH_MAP) {
            tokenizer = MODEL_HASH_MAP[preTrainedModelName].tokenizer;
            dataType = MODEL_HASH_MAP[preTrainedModelName].type;
        }
        else {
            if (providerAddress === undefined) {
                throw new Error('Provider address is required for customized model');
            }
            let model = await this.servingProvider.getCustomizedModel(providerAddress, preTrainedModelName);
            tokenizer = model.tokenizer;
            dataType = model.dataType;
        }
        let dataSize = 0;
        if (usePython) {
            dataSize = await calculateTokenSizeViaPython(tokenizer, datasetPath, dataType);
        }
        else {
            dataSize = await calculateTokenSizeViaExe(tokenizer, datasetPath, dataType, TOKEN_COUNTER_MERKLE_ROOT, TOKEN_COUNTER_FILE_HASH);
        }
        console.log(`The token size for the dataset ${datasetPath} is ${dataSize}`);
    }
    async downloadDataset(dataPath, dataRoot) {
        download(dataPath, dataRoot);
    }
    async acknowledgeModel(providerAddress, taskId, dataPath, gasPrice) {
        try {
            const deliverable = await this.contract.getDeliverable(providerAddress, taskId);
            if (!deliverable) {
                throw new Error('No deliverable found');
            }
            await download(dataPath, hexToRoots(deliverable.modelRootHash));
            await this.contract.acknowledgeDeliverable(providerAddress, taskId, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async decryptModel(providerAddress, taskId, encryptedModelPath, decryptedModelPath) {
        try {
            const [account, deliverable] = await Promise.all([
                this.contract.getAccount(providerAddress),
                this.contract.getDeliverable(providerAddress, taskId),
            ]);
            if (!deliverable) {
                throw new Error('No deliverable found');
            }
            if (!deliverable.acknowledged) {
                throw new Error('Deliverable not acknowledged yet');
            }
            if (!deliverable.encryptedSecret) {
                throw new Error('EncryptedSecret not found');
            }
            const secret = await eciesDecrypt(this.contract.signer, deliverable.encryptedSecret);
            await aesGCMDecryptToFile(secret, encryptedModelPath, decryptedModelPath, account.providerSigner);
        }
        catch (error) {
            throwFormattedError(error);
        }
        return;
    }
}

// Browser-safe function to avoid readline dependency
async function askUser(question) {
    if (isBrowser()) {
        throw new Error('Interactive input operations are not available in browser environment. Please use these functions in a Node.js environment.');
    }
    // Only import readline in Node.js environment
    try {
        const readline = await import('readline');
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
        });
        return new Promise((resolve) => {
            rl.question(question, (answer) => {
                rl.close();
                resolve(answer.trim());
            });
        });
    }
    catch (error) {
        throw new Error('readline module is not available. This function can only be used in Node.js environment.');
    }
}
// Browser-safe function to avoid fs dependency
async function readFileContent(filePath) {
    if (isBrowser()) {
        throw new Error('File system operations are not available in browser environment. Please use these functions in a Node.js environment.');
    }
    try {
        const fs = await import('fs/promises');
        return await fs.readFile(filePath, 'utf-8');
    }
    catch (error) {
        throw new Error('fs module is not available. This function can only be used in Node.js environment.');
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
            throwFormattedError(error);
        }
    }
    async getAccount(provider) {
        try {
            const account = await this.contract.getAccount(provider);
            return account;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getAccountWithDetail(provider) {
        try {
            const account = await this.contract.getAccount(provider);
            const lockTime = await this.getLockTime();
            const now = BigInt(Math.floor(Date.now() / 1000)); // Converts milliseconds to seconds
            const refunds = account.refunds
                .filter((refund) => !refund.processed)
                .filter((refund) => refund.amount !== BigInt(0))
                .map((refund) => ({
                amount: refund.amount,
                remainTime: lockTime - (now - refund.createdAt),
            }));
            return { account, refunds };
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async listService() {
        try {
            const services = await this.contract.listService();
            return services;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async acknowledgeProviderSigner(providerAddress, gasPrice) {
        try {
            try {
                await this.contract.getAccount(providerAddress);
            }
            catch {
                await this.ledger.transferFund(providerAddress, 'fine-tuning', BigInt(0), gasPrice);
            }
            const { rawReport, signingAddress } = await this.servingProvider.getQuote(providerAddress);
            if (!rawReport || !signingAddress) {
                throw new Error('Invalid quote');
            }
            // TODO: separate automata verification logic
            // const rpc = process.env.RPC_ENDPOINT
            // // bypass quote verification if testing on localhost
            // if (!rpc || !/localhost|127\.0\.0\.1/.test(rpc)) {
            //     const isVerified = await this.automata.verifyQuote(intel_quote)
            //     console.log('Quote verification:', isVerified)
            //     if (!isVerified) {
            //         throw new Error('Quote verification failed')
            //     }
            // }
            const account = await this.contract.getAccount(providerAddress);
            if (account.providerSigner === signingAddress) {
                console.log('Provider signer already acknowledged');
                return;
            }
            await this.contract.acknowledgeProviderSigner(providerAddress, signingAddress, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async createTask(providerAddress, preTrainedModelName, dataSize, datasetHash, trainingPath, gasPrice) {
        try {
            let preTrainedModelHash;
            if (preTrainedModelName in MODEL_HASH_MAP) {
                preTrainedModelHash = MODEL_HASH_MAP[preTrainedModelName].turbo;
            }
            else {
                const model = await this.servingProvider.getCustomizedModel(providerAddress, preTrainedModelName);
                preTrainedModelHash = model.hash;
                console.log(`customized model hash: ${preTrainedModelHash}`);
            }
            const service = await this.contract.getService(providerAddress);
            const trainingParams = await readFileContent(trainingPath);
            const parsedParams = this.verifyTrainingParams(trainingParams);
            const trainEpochs = (parsedParams.num_train_epochs || parsedParams.total_steps) ?? 3;
            const fee = service.pricePerToken * BigInt(dataSize) * BigInt(trainEpochs);
            console.log(`Estimated fee: ${fee} (neuron), data size: ${dataSize}, train epochs: ${trainEpochs}, price per token: ${service.pricePerToken} (neuron)`);
            const account = await this.contract.getAccount(providerAddress);
            if (account.balance - account.pendingRefund < fee) {
                await this.ledger.transferFund(providerAddress, 'fine-tuning', fee, gasPrice);
            }
            const nonce = getNonce();
            const signature = await signRequest(this.contract.signer, this.contract.getUserAddress(), BigInt(nonce), datasetHash, fee);
            let wait = false;
            const counter = await this.servingProvider.getPendingTaskCounter(providerAddress);
            if (counter > 0) {
                while (true) {
                    const answer = await askUser(`There are ${counter} tasks in the queue. Do you want to continue? (yes/no): `);
                    if (answer.toLowerCase() === 'yes' ||
                        answer.toLowerCase() === 'y') {
                        wait = true;
                        break;
                    }
                    else if (['no', 'n'].includes(answer.toLowerCase())) {
                        throw new Error('User opted not to continue due to pending tasks in the queue.');
                    }
                    else {
                        console.log('Invalid input. Please respond with yes/y or no/n.');
                    }
                }
            }
            const task = {
                userAddress: this.contract.getUserAddress(),
                datasetHash,
                trainingParams,
                preTrainedModelHash,
                fee: fee.toString(),
                nonce: nonce.toString(),
                signature,
                wait,
            };
            return await this.servingProvider.createTask(providerAddress, task);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async cancelTask(providerAddress, taskID) {
        try {
            const signature = await signTaskID(this.contract.signer, taskID);
            return await this.servingProvider.cancelTask(providerAddress, signature, taskID);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async listTask(providerAddress) {
        try {
            return await this.servingProvider.listTask(providerAddress, this.contract.getUserAddress());
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
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
    async modelUsage(providerAddress, preTrainedModelName, output) {
        try {
            return await this.servingProvider.getCustomizedModelDetailUsage(providerAddress, preTrainedModelName, output);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    verifyTrainingParams(trainingParams) {
        try {
            return JSON.parse(trainingParams);
        }
        catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'An unknown error occurred';
            throw new Error(`Invalid JSON in trainingPath file: ${errorMessage}`);
        }
    }
}

function bind(fn, thisArg) {
  return function wrap() {
    return fn.apply(thisArg, arguments);
  };
}

// utils is a library of generic helper functions non-specific to axios

const {toString} = Object.prototype;
const {getPrototypeOf} = Object;

const kindOf = (cache => thing => {
    const str = toString.call(thing);
    return cache[str] || (cache[str] = str.slice(8, -1).toLowerCase());
})(Object.create(null));

const kindOfTest = (type) => {
  type = type.toLowerCase();
  return (thing) => kindOf(thing) === type
};

const typeOfTest = type => thing => typeof thing === type;

/**
 * Determine if a value is an Array
 *
 * @param {Object} val The value to test
 *
 * @returns {boolean} True if value is an Array, otherwise false
 */
const {isArray} = Array;

/**
 * Determine if a value is undefined
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if the value is undefined, otherwise false
 */
const isUndefined = typeOfTest('undefined');

/**
 * Determine if a value is a Buffer
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a Buffer, otherwise false
 */
function isBuffer(val) {
  return val !== null && !isUndefined(val) && val.constructor !== null && !isUndefined(val.constructor)
    && isFunction(val.constructor.isBuffer) && val.constructor.isBuffer(val);
}

/**
 * Determine if a value is an ArrayBuffer
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is an ArrayBuffer, otherwise false
 */
const isArrayBuffer = kindOfTest('ArrayBuffer');


/**
 * Determine if a value is a view on an ArrayBuffer
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a view on an ArrayBuffer, otherwise false
 */
function isArrayBufferView(val) {
  let result;
  if ((typeof ArrayBuffer !== 'undefined') && (ArrayBuffer.isView)) {
    result = ArrayBuffer.isView(val);
  } else {
    result = (val) && (val.buffer) && (isArrayBuffer(val.buffer));
  }
  return result;
}

/**
 * Determine if a value is a String
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a String, otherwise false
 */
const isString = typeOfTest('string');

/**
 * Determine if a value is a Function
 *
 * @param {*} val The value to test
 * @returns {boolean} True if value is a Function, otherwise false
 */
const isFunction = typeOfTest('function');

/**
 * Determine if a value is a Number
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a Number, otherwise false
 */
const isNumber = typeOfTest('number');

/**
 * Determine if a value is an Object
 *
 * @param {*} thing The value to test
 *
 * @returns {boolean} True if value is an Object, otherwise false
 */
const isObject = (thing) => thing !== null && typeof thing === 'object';

/**
 * Determine if a value is a Boolean
 *
 * @param {*} thing The value to test
 * @returns {boolean} True if value is a Boolean, otherwise false
 */
const isBoolean = thing => thing === true || thing === false;

/**
 * Determine if a value is a plain Object
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a plain Object, otherwise false
 */
const isPlainObject = (val) => {
  if (kindOf(val) !== 'object') {
    return false;
  }

  const prototype = getPrototypeOf(val);
  return (prototype === null || prototype === Object.prototype || Object.getPrototypeOf(prototype) === null) && !(Symbol.toStringTag in val) && !(Symbol.iterator in val);
};

/**
 * Determine if a value is a Date
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a Date, otherwise false
 */
const isDate = kindOfTest('Date');

/**
 * Determine if a value is a File
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a File, otherwise false
 */
const isFile = kindOfTest('File');

/**
 * Determine if a value is a Blob
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a Blob, otherwise false
 */
const isBlob = kindOfTest('Blob');

/**
 * Determine if a value is a FileList
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a File, otherwise false
 */
const isFileList = kindOfTest('FileList');

/**
 * Determine if a value is a Stream
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a Stream, otherwise false
 */
const isStream = (val) => isObject(val) && isFunction(val.pipe);

/**
 * Determine if a value is a FormData
 *
 * @param {*} thing The value to test
 *
 * @returns {boolean} True if value is an FormData, otherwise false
 */
const isFormData = (thing) => {
  let kind;
  return thing && (
    (typeof FormData === 'function' && thing instanceof FormData) || (
      isFunction(thing.append) && (
        (kind = kindOf(thing)) === 'formdata' ||
        // detect form-data instance
        (kind === 'object' && isFunction(thing.toString) && thing.toString() === '[object FormData]')
      )
    )
  )
};

/**
 * Determine if a value is a URLSearchParams object
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a URLSearchParams object, otherwise false
 */
const isURLSearchParams = kindOfTest('URLSearchParams');

const [isReadableStream, isRequest, isResponse, isHeaders] = ['ReadableStream', 'Request', 'Response', 'Headers'].map(kindOfTest);

/**
 * Trim excess whitespace off the beginning and end of a string
 *
 * @param {String} str The String to trim
 *
 * @returns {String} The String freed of excess whitespace
 */
const trim = (str) => str.trim ?
  str.trim() : str.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, '');

/**
 * Iterate over an Array or an Object invoking a function for each item.
 *
 * If `obj` is an Array callback will be called passing
 * the value, index, and complete array for each item.
 *
 * If 'obj' is an Object callback will be called passing
 * the value, key, and complete object for each property.
 *
 * @param {Object|Array} obj The object to iterate
 * @param {Function} fn The callback to invoke for each item
 *
 * @param {Boolean} [allOwnKeys = false]
 * @returns {any}
 */
function forEach(obj, fn, {allOwnKeys = false} = {}) {
  // Don't bother if no value provided
  if (obj === null || typeof obj === 'undefined') {
    return;
  }

  let i;
  let l;

  // Force an array if not already something iterable
  if (typeof obj !== 'object') {
    /*eslint no-param-reassign:0*/
    obj = [obj];
  }

  if (isArray(obj)) {
    // Iterate over array values
    for (i = 0, l = obj.length; i < l; i++) {
      fn.call(null, obj[i], i, obj);
    }
  } else {
    // Iterate over object keys
    const keys = allOwnKeys ? Object.getOwnPropertyNames(obj) : Object.keys(obj);
    const len = keys.length;
    let key;

    for (i = 0; i < len; i++) {
      key = keys[i];
      fn.call(null, obj[key], key, obj);
    }
  }
}

function findKey(obj, key) {
  key = key.toLowerCase();
  const keys = Object.keys(obj);
  let i = keys.length;
  let _key;
  while (i-- > 0) {
    _key = keys[i];
    if (key === _key.toLowerCase()) {
      return _key;
    }
  }
  return null;
}

const _global = (() => {
  /*eslint no-undef:0*/
  if (typeof globalThis !== "undefined") return globalThis;
  return typeof self !== "undefined" ? self : (typeof window !== 'undefined' ? window : global)
})();

const isContextDefined = (context) => !isUndefined(context) && context !== _global;

/**
 * Accepts varargs expecting each argument to be an object, then
 * immutably merges the properties of each object and returns result.
 *
 * When multiple objects contain the same key the later object in
 * the arguments list will take precedence.
 *
 * Example:
 *
 * ```js
 * var result = merge({foo: 123}, {foo: 456});
 * console.log(result.foo); // outputs 456
 * ```
 *
 * @param {Object} obj1 Object to merge
 *
 * @returns {Object} Result of all merge properties
 */
function merge(/* obj1, obj2, obj3, ... */) {
  const {caseless} = isContextDefined(this) && this || {};
  const result = {};
  const assignValue = (val, key) => {
    const targetKey = caseless && findKey(result, key) || key;
    if (isPlainObject(result[targetKey]) && isPlainObject(val)) {
      result[targetKey] = merge(result[targetKey], val);
    } else if (isPlainObject(val)) {
      result[targetKey] = merge({}, val);
    } else if (isArray(val)) {
      result[targetKey] = val.slice();
    } else {
      result[targetKey] = val;
    }
  };

  for (let i = 0, l = arguments.length; i < l; i++) {
    arguments[i] && forEach(arguments[i], assignValue);
  }
  return result;
}

/**
 * Extends object a by mutably adding to it the properties of object b.
 *
 * @param {Object} a The object to be extended
 * @param {Object} b The object to copy properties from
 * @param {Object} thisArg The object to bind function to
 *
 * @param {Boolean} [allOwnKeys]
 * @returns {Object} The resulting value of object a
 */
const extend = (a, b, thisArg, {allOwnKeys}= {}) => {
  forEach(b, (val, key) => {
    if (thisArg && isFunction(val)) {
      a[key] = bind(val, thisArg);
    } else {
      a[key] = val;
    }
  }, {allOwnKeys});
  return a;
};

/**
 * Remove byte order marker. This catches EF BB BF (the UTF-8 BOM)
 *
 * @param {string} content with BOM
 *
 * @returns {string} content value without BOM
 */
const stripBOM = (content) => {
  if (content.charCodeAt(0) === 0xFEFF) {
    content = content.slice(1);
  }
  return content;
};

/**
 * Inherit the prototype methods from one constructor into another
 * @param {function} constructor
 * @param {function} superConstructor
 * @param {object} [props]
 * @param {object} [descriptors]
 *
 * @returns {void}
 */
const inherits = (constructor, superConstructor, props, descriptors) => {
  constructor.prototype = Object.create(superConstructor.prototype, descriptors);
  constructor.prototype.constructor = constructor;
  Object.defineProperty(constructor, 'super', {
    value: superConstructor.prototype
  });
  props && Object.assign(constructor.prototype, props);
};

/**
 * Resolve object with deep prototype chain to a flat object
 * @param {Object} sourceObj source object
 * @param {Object} [destObj]
 * @param {Function|Boolean} [filter]
 * @param {Function} [propFilter]
 *
 * @returns {Object}
 */
const toFlatObject = (sourceObj, destObj, filter, propFilter) => {
  let props;
  let i;
  let prop;
  const merged = {};

  destObj = destObj || {};
  // eslint-disable-next-line no-eq-null,eqeqeq
  if (sourceObj == null) return destObj;

  do {
    props = Object.getOwnPropertyNames(sourceObj);
    i = props.length;
    while (i-- > 0) {
      prop = props[i];
      if ((!propFilter || propFilter(prop, sourceObj, destObj)) && !merged[prop]) {
        destObj[prop] = sourceObj[prop];
        merged[prop] = true;
      }
    }
    sourceObj = filter !== false && getPrototypeOf(sourceObj);
  } while (sourceObj && (!filter || filter(sourceObj, destObj)) && sourceObj !== Object.prototype);

  return destObj;
};

/**
 * Determines whether a string ends with the characters of a specified string
 *
 * @param {String} str
 * @param {String} searchString
 * @param {Number} [position= 0]
 *
 * @returns {boolean}
 */
const endsWith = (str, searchString, position) => {
  str = String(str);
  if (position === undefined || position > str.length) {
    position = str.length;
  }
  position -= searchString.length;
  const lastIndex = str.indexOf(searchString, position);
  return lastIndex !== -1 && lastIndex === position;
};


/**
 * Returns new array from array like object or null if failed
 *
 * @param {*} [thing]
 *
 * @returns {?Array}
 */
const toArray = (thing) => {
  if (!thing) return null;
  if (isArray(thing)) return thing;
  let i = thing.length;
  if (!isNumber(i)) return null;
  const arr = new Array(i);
  while (i-- > 0) {
    arr[i] = thing[i];
  }
  return arr;
};

/**
 * Checking if the Uint8Array exists and if it does, it returns a function that checks if the
 * thing passed in is an instance of Uint8Array
 *
 * @param {TypedArray}
 *
 * @returns {Array}
 */
// eslint-disable-next-line func-names
const isTypedArray = (TypedArray => {
  // eslint-disable-next-line func-names
  return thing => {
    return TypedArray && thing instanceof TypedArray;
  };
})(typeof Uint8Array !== 'undefined' && getPrototypeOf(Uint8Array));

/**
 * For each entry in the object, call the function with the key and value.
 *
 * @param {Object<any, any>} obj - The object to iterate over.
 * @param {Function} fn - The function to call for each entry.
 *
 * @returns {void}
 */
const forEachEntry = (obj, fn) => {
  const generator = obj && obj[Symbol.iterator];

  const iterator = generator.call(obj);

  let result;

  while ((result = iterator.next()) && !result.done) {
    const pair = result.value;
    fn.call(obj, pair[0], pair[1]);
  }
};

/**
 * It takes a regular expression and a string, and returns an array of all the matches
 *
 * @param {string} regExp - The regular expression to match against.
 * @param {string} str - The string to search.
 *
 * @returns {Array<boolean>}
 */
const matchAll = (regExp, str) => {
  let matches;
  const arr = [];

  while ((matches = regExp.exec(str)) !== null) {
    arr.push(matches);
  }

  return arr;
};

/* Checking if the kindOfTest function returns true when passed an HTMLFormElement. */
const isHTMLForm = kindOfTest('HTMLFormElement');

const toCamelCase = str => {
  return str.toLowerCase().replace(/[-_\s]([a-z\d])(\w*)/g,
    function replacer(m, p1, p2) {
      return p1.toUpperCase() + p2;
    }
  );
};

/* Creating a function that will check if an object has a property. */
const hasOwnProperty = (({hasOwnProperty}) => (obj, prop) => hasOwnProperty.call(obj, prop))(Object.prototype);

/**
 * Determine if a value is a RegExp object
 *
 * @param {*} val The value to test
 *
 * @returns {boolean} True if value is a RegExp object, otherwise false
 */
const isRegExp = kindOfTest('RegExp');

const reduceDescriptors = (obj, reducer) => {
  const descriptors = Object.getOwnPropertyDescriptors(obj);
  const reducedDescriptors = {};

  forEach(descriptors, (descriptor, name) => {
    let ret;
    if ((ret = reducer(descriptor, name, obj)) !== false) {
      reducedDescriptors[name] = ret || descriptor;
    }
  });

  Object.defineProperties(obj, reducedDescriptors);
};

/**
 * Makes all methods read-only
 * @param {Object} obj
 */

const freezeMethods = (obj) => {
  reduceDescriptors(obj, (descriptor, name) => {
    // skip restricted props in strict mode
    if (isFunction(obj) && ['arguments', 'caller', 'callee'].indexOf(name) !== -1) {
      return false;
    }

    const value = obj[name];

    if (!isFunction(value)) return;

    descriptor.enumerable = false;

    if ('writable' in descriptor) {
      descriptor.writable = false;
      return;
    }

    if (!descriptor.set) {
      descriptor.set = () => {
        throw Error('Can not rewrite read-only method \'' + name + '\'');
      };
    }
  });
};

const toObjectSet = (arrayOrString, delimiter) => {
  const obj = {};

  const define = (arr) => {
    arr.forEach(value => {
      obj[value] = true;
    });
  };

  isArray(arrayOrString) ? define(arrayOrString) : define(String(arrayOrString).split(delimiter));

  return obj;
};

const noop = () => {};

const toFiniteNumber = (value, defaultValue) => {
  return value != null && Number.isFinite(value = +value) ? value : defaultValue;
};

const ALPHA = 'abcdefghijklmnopqrstuvwxyz';

const DIGIT = '0123456789';

const ALPHABET = {
  DIGIT,
  ALPHA,
  ALPHA_DIGIT: ALPHA + ALPHA.toUpperCase() + DIGIT
};

const generateString = (size = 16, alphabet = ALPHABET.ALPHA_DIGIT) => {
  let str = '';
  const {length} = alphabet;
  while (size--) {
    str += alphabet[Math.random() * length|0];
  }

  return str;
};

/**
 * If the thing is a FormData object, return true, otherwise return false.
 *
 * @param {unknown} thing - The thing to check.
 *
 * @returns {boolean}
 */
function isSpecCompliantForm(thing) {
  return !!(thing && isFunction(thing.append) && thing[Symbol.toStringTag] === 'FormData' && thing[Symbol.iterator]);
}

const toJSONObject = (obj) => {
  const stack = new Array(10);

  const visit = (source, i) => {

    if (isObject(source)) {
      if (stack.indexOf(source) >= 0) {
        return;
      }

      if(!('toJSON' in source)) {
        stack[i] = source;
        const target = isArray(source) ? [] : {};

        forEach(source, (value, key) => {
          const reducedValue = visit(value, i + 1);
          !isUndefined(reducedValue) && (target[key] = reducedValue);
        });

        stack[i] = undefined;

        return target;
      }
    }

    return source;
  };

  return visit(obj, 0);
};

const isAsyncFn = kindOfTest('AsyncFunction');

const isThenable = (thing) =>
  thing && (isObject(thing) || isFunction(thing)) && isFunction(thing.then) && isFunction(thing.catch);

// original code
// https://github.com/DigitalBrainJS/AxiosPromise/blob/16deab13710ec09779922131f3fa5954320f83ab/lib/utils.js#L11-L34

const _setImmediate = ((setImmediateSupported, postMessageSupported) => {
  if (setImmediateSupported) {
    return setImmediate;
  }

  return postMessageSupported ? ((token, callbacks) => {
    _global.addEventListener("message", ({source, data}) => {
      if (source === _global && data === token) {
        callbacks.length && callbacks.shift()();
      }
    }, false);

    return (cb) => {
      callbacks.push(cb);
      _global.postMessage(token, "*");
    }
  })(`axios@${Math.random()}`, []) : (cb) => setTimeout(cb);
})(
  typeof setImmediate === 'function',
  isFunction(_global.postMessage)
);

const asap = typeof queueMicrotask !== 'undefined' ?
  queueMicrotask.bind(_global) : ( typeof process !== 'undefined' && process.nextTick || _setImmediate);

// *********************

var utils$1 = {
  isArray,
  isArrayBuffer,
  isBuffer,
  isFormData,
  isArrayBufferView,
  isString,
  isNumber,
  isBoolean,
  isObject,
  isPlainObject,
  isReadableStream,
  isRequest,
  isResponse,
  isHeaders,
  isUndefined,
  isDate,
  isFile,
  isBlob,
  isRegExp,
  isFunction,
  isStream,
  isURLSearchParams,
  isTypedArray,
  isFileList,
  forEach,
  merge,
  extend,
  trim,
  stripBOM,
  inherits,
  toFlatObject,
  kindOf,
  kindOfTest,
  endsWith,
  toArray,
  forEachEntry,
  matchAll,
  isHTMLForm,
  hasOwnProperty,
  hasOwnProp: hasOwnProperty, // an alias to avoid ESLint no-prototype-builtins detection
  reduceDescriptors,
  freezeMethods,
  toObjectSet,
  toCamelCase,
  noop,
  toFiniteNumber,
  findKey,
  global: _global,
  isContextDefined,
  ALPHABET,
  generateString,
  isSpecCompliantForm,
  toJSONObject,
  isAsyncFn,
  isThenable,
  setImmediate: _setImmediate,
  asap
};

/**
 * Create an Error with the specified message, config, error code, request and response.
 *
 * @param {string} message The error message.
 * @param {string} [code] The error code (for example, 'ECONNABORTED').
 * @param {Object} [config] The config.
 * @param {Object} [request] The request.
 * @param {Object} [response] The response.
 *
 * @returns {Error} The created error.
 */
function AxiosError(message, code, config, request, response) {
  Error.call(this);

  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor);
  } else {
    this.stack = (new Error()).stack;
  }

  this.message = message;
  this.name = 'AxiosError';
  code && (this.code = code);
  config && (this.config = config);
  request && (this.request = request);
  if (response) {
    this.response = response;
    this.status = response.status ? response.status : null;
  }
}

utils$1.inherits(AxiosError, Error, {
  toJSON: function toJSON() {
    return {
      // Standard
      message: this.message,
      name: this.name,
      // Microsoft
      description: this.description,
      number: this.number,
      // Mozilla
      fileName: this.fileName,
      lineNumber: this.lineNumber,
      columnNumber: this.columnNumber,
      stack: this.stack,
      // Axios
      config: utils$1.toJSONObject(this.config),
      code: this.code,
      status: this.status
    };
  }
});

const prototype$1 = AxiosError.prototype;
const descriptors = {};

[
  'ERR_BAD_OPTION_VALUE',
  'ERR_BAD_OPTION',
  'ECONNABORTED',
  'ETIMEDOUT',
  'ERR_NETWORK',
  'ERR_FR_TOO_MANY_REDIRECTS',
  'ERR_DEPRECATED',
  'ERR_BAD_RESPONSE',
  'ERR_BAD_REQUEST',
  'ERR_CANCELED',
  'ERR_NOT_SUPPORT',
  'ERR_INVALID_URL'
// eslint-disable-next-line func-names
].forEach(code => {
  descriptors[code] = {value: code};
});

Object.defineProperties(AxiosError, descriptors);
Object.defineProperty(prototype$1, 'isAxiosError', {value: true});

// eslint-disable-next-line func-names
AxiosError.from = (error, code, config, request, response, customProps) => {
  const axiosError = Object.create(prototype$1);

  utils$1.toFlatObject(error, axiosError, function filter(obj) {
    return obj !== Error.prototype;
  }, prop => {
    return prop !== 'isAxiosError';
  });

  AxiosError.call(axiosError, error.message, code, config, request, response);

  axiosError.cause = error;

  axiosError.name = error.name;

  customProps && Object.assign(axiosError, customProps);

  return axiosError;
};

// eslint-disable-next-line strict
var httpAdapter = null;

/**
 * Determines if the given thing is a array or js object.
 *
 * @param {string} thing - The object or array to be visited.
 *
 * @returns {boolean}
 */
function isVisitable(thing) {
  return utils$1.isPlainObject(thing) || utils$1.isArray(thing);
}

/**
 * It removes the brackets from the end of a string
 *
 * @param {string} key - The key of the parameter.
 *
 * @returns {string} the key without the brackets.
 */
function removeBrackets(key) {
  return utils$1.endsWith(key, '[]') ? key.slice(0, -2) : key;
}

/**
 * It takes a path, a key, and a boolean, and returns a string
 *
 * @param {string} path - The path to the current key.
 * @param {string} key - The key of the current object being iterated over.
 * @param {string} dots - If true, the key will be rendered with dots instead of brackets.
 *
 * @returns {string} The path to the current key.
 */
function renderKey(path, key, dots) {
  if (!path) return key;
  return path.concat(key).map(function each(token, i) {
    // eslint-disable-next-line no-param-reassign
    token = removeBrackets(token);
    return !dots && i ? '[' + token + ']' : token;
  }).join(dots ? '.' : '');
}

/**
 * If the array is an array and none of its elements are visitable, then it's a flat array.
 *
 * @param {Array<any>} arr - The array to check
 *
 * @returns {boolean}
 */
function isFlatArray(arr) {
  return utils$1.isArray(arr) && !arr.some(isVisitable);
}

const predicates = utils$1.toFlatObject(utils$1, {}, null, function filter(prop) {
  return /^is[A-Z]/.test(prop);
});

/**
 * Convert a data object to FormData
 *
 * @param {Object} obj
 * @param {?Object} [formData]
 * @param {?Object} [options]
 * @param {Function} [options.visitor]
 * @param {Boolean} [options.metaTokens = true]
 * @param {Boolean} [options.dots = false]
 * @param {?Boolean} [options.indexes = false]
 *
 * @returns {Object}
 **/

/**
 * It converts an object into a FormData object
 *
 * @param {Object<any, any>} obj - The object to convert to form data.
 * @param {string} formData - The FormData object to append to.
 * @param {Object<string, any>} options
 *
 * @returns
 */
function toFormData(obj, formData, options) {
  if (!utils$1.isObject(obj)) {
    throw new TypeError('target must be an object');
  }

  // eslint-disable-next-line no-param-reassign
  formData = formData || new (FormData)();

  // eslint-disable-next-line no-param-reassign
  options = utils$1.toFlatObject(options, {
    metaTokens: true,
    dots: false,
    indexes: false
  }, false, function defined(option, source) {
    // eslint-disable-next-line no-eq-null,eqeqeq
    return !utils$1.isUndefined(source[option]);
  });

  const metaTokens = options.metaTokens;
  // eslint-disable-next-line no-use-before-define
  const visitor = options.visitor || defaultVisitor;
  const dots = options.dots;
  const indexes = options.indexes;
  const _Blob = options.Blob || typeof Blob !== 'undefined' && Blob;
  const useBlob = _Blob && utils$1.isSpecCompliantForm(formData);

  if (!utils$1.isFunction(visitor)) {
    throw new TypeError('visitor must be a function');
  }

  function convertValue(value) {
    if (value === null) return '';

    if (utils$1.isDate(value)) {
      return value.toISOString();
    }

    if (!useBlob && utils$1.isBlob(value)) {
      throw new AxiosError('Blob is not supported. Use a Buffer instead.');
    }

    if (utils$1.isArrayBuffer(value) || utils$1.isTypedArray(value)) {
      return useBlob && typeof Blob === 'function' ? new Blob([value]) : Buffer.from(value);
    }

    return value;
  }

  /**
   * Default visitor.
   *
   * @param {*} value
   * @param {String|Number} key
   * @param {Array<String|Number>} path
   * @this {FormData}
   *
   * @returns {boolean} return true to visit the each prop of the value recursively
   */
  function defaultVisitor(value, key, path) {
    let arr = value;

    if (value && !path && typeof value === 'object') {
      if (utils$1.endsWith(key, '{}')) {
        // eslint-disable-next-line no-param-reassign
        key = metaTokens ? key : key.slice(0, -2);
        // eslint-disable-next-line no-param-reassign
        value = JSON.stringify(value);
      } else if (
        (utils$1.isArray(value) && isFlatArray(value)) ||
        ((utils$1.isFileList(value) || utils$1.endsWith(key, '[]')) && (arr = utils$1.toArray(value))
        )) {
        // eslint-disable-next-line no-param-reassign
        key = removeBrackets(key);

        arr.forEach(function each(el, index) {
          !(utils$1.isUndefined(el) || el === null) && formData.append(
            // eslint-disable-next-line no-nested-ternary
            indexes === true ? renderKey([key], index, dots) : (indexes === null ? key : key + '[]'),
            convertValue(el)
          );
        });
        return false;
      }
    }

    if (isVisitable(value)) {
      return true;
    }

    formData.append(renderKey(path, key, dots), convertValue(value));

    return false;
  }

  const stack = [];

  const exposedHelpers = Object.assign(predicates, {
    defaultVisitor,
    convertValue,
    isVisitable
  });

  function build(value, path) {
    if (utils$1.isUndefined(value)) return;

    if (stack.indexOf(value) !== -1) {
      throw Error('Circular reference detected in ' + path.join('.'));
    }

    stack.push(value);

    utils$1.forEach(value, function each(el, key) {
      const result = !(utils$1.isUndefined(el) || el === null) && visitor.call(
        formData, el, utils$1.isString(key) ? key.trim() : key, path, exposedHelpers
      );

      if (result === true) {
        build(el, path ? path.concat(key) : [key]);
      }
    });

    stack.pop();
  }

  if (!utils$1.isObject(obj)) {
    throw new TypeError('data must be an object');
  }

  build(obj);

  return formData;
}

/**
 * It encodes a string by replacing all characters that are not in the unreserved set with
 * their percent-encoded equivalents
 *
 * @param {string} str - The string to encode.
 *
 * @returns {string} The encoded string.
 */
function encode$1(str) {
  const charMap = {
    '!': '%21',
    "'": '%27',
    '(': '%28',
    ')': '%29',
    '~': '%7E',
    '%20': '+',
    '%00': '\x00'
  };
  return encodeURIComponent(str).replace(/[!'()~]|%20|%00/g, function replacer(match) {
    return charMap[match];
  });
}

/**
 * It takes a params object and converts it to a FormData object
 *
 * @param {Object<string, any>} params - The parameters to be converted to a FormData object.
 * @param {Object<string, any>} options - The options object passed to the Axios constructor.
 *
 * @returns {void}
 */
function AxiosURLSearchParams(params, options) {
  this._pairs = [];

  params && toFormData(params, this, options);
}

const prototype = AxiosURLSearchParams.prototype;

prototype.append = function append(name, value) {
  this._pairs.push([name, value]);
};

prototype.toString = function toString(encoder) {
  const _encode = encoder ? function(value) {
    return encoder.call(this, value, encode$1);
  } : encode$1;

  return this._pairs.map(function each(pair) {
    return _encode(pair[0]) + '=' + _encode(pair[1]);
  }, '').join('&');
};

/**
 * It replaces all instances of the characters `:`, `$`, `,`, `+`, `[`, and `]` with their
 * URI encoded counterparts
 *
 * @param {string} val The value to be encoded.
 *
 * @returns {string} The encoded value.
 */
function encode(val) {
  return encodeURIComponent(val).
    replace(/%3A/gi, ':').
    replace(/%24/g, '$').
    replace(/%2C/gi, ',').
    replace(/%20/g, '+').
    replace(/%5B/gi, '[').
    replace(/%5D/gi, ']');
}

/**
 * Build a URL by appending params to the end
 *
 * @param {string} url The base of the url (e.g., http://www.google.com)
 * @param {object} [params] The params to be appended
 * @param {?(object|Function)} options
 *
 * @returns {string} The formatted url
 */
function buildURL(url, params, options) {
  /*eslint no-param-reassign:0*/
  if (!params) {
    return url;
  }
  
  const _encode = options && options.encode || encode;

  if (utils$1.isFunction(options)) {
    options = {
      serialize: options
    };
  } 

  const serializeFn = options && options.serialize;

  let serializedParams;

  if (serializeFn) {
    serializedParams = serializeFn(params, options);
  } else {
    serializedParams = utils$1.isURLSearchParams(params) ?
      params.toString() :
      new AxiosURLSearchParams(params, options).toString(_encode);
  }

  if (serializedParams) {
    const hashmarkIndex = url.indexOf("#");

    if (hashmarkIndex !== -1) {
      url = url.slice(0, hashmarkIndex);
    }
    url += (url.indexOf('?') === -1 ? '?' : '&') + serializedParams;
  }

  return url;
}

class InterceptorManager {
  constructor() {
    this.handlers = [];
  }

  /**
   * Add a new interceptor to the stack
   *
   * @param {Function} fulfilled The function to handle `then` for a `Promise`
   * @param {Function} rejected The function to handle `reject` for a `Promise`
   *
   * @return {Number} An ID used to remove interceptor later
   */
  use(fulfilled, rejected, options) {
    this.handlers.push({
      fulfilled,
      rejected,
      synchronous: options ? options.synchronous : false,
      runWhen: options ? options.runWhen : null
    });
    return this.handlers.length - 1;
  }

  /**
   * Remove an interceptor from the stack
   *
   * @param {Number} id The ID that was returned by `use`
   *
   * @returns {Boolean} `true` if the interceptor was removed, `false` otherwise
   */
  eject(id) {
    if (this.handlers[id]) {
      this.handlers[id] = null;
    }
  }

  /**
   * Clear all interceptors from the stack
   *
   * @returns {void}
   */
  clear() {
    if (this.handlers) {
      this.handlers = [];
    }
  }

  /**
   * Iterate over all the registered interceptors
   *
   * This method is particularly useful for skipping over any
   * interceptors that may have become `null` calling `eject`.
   *
   * @param {Function} fn The function to call for each interceptor
   *
   * @returns {void}
   */
  forEach(fn) {
    utils$1.forEach(this.handlers, function forEachHandler(h) {
      if (h !== null) {
        fn(h);
      }
    });
  }
}

var InterceptorManager$1 = InterceptorManager;

var transitionalDefaults = {
  silentJSONParsing: true,
  forcedJSONParsing: true,
  clarifyTimeoutError: false
};

var URLSearchParams$1 = typeof URLSearchParams !== 'undefined' ? URLSearchParams : AxiosURLSearchParams;

var FormData$1 = typeof FormData !== 'undefined' ? FormData : null;

var Blob$1 = typeof Blob !== 'undefined' ? Blob : null;

var platform$1 = {
  isBrowser: true,
  classes: {
    URLSearchParams: URLSearchParams$1,
    FormData: FormData$1,
    Blob: Blob$1
  },
  protocols: ['http', 'https', 'file', 'blob', 'url', 'data']
};

const hasBrowserEnv = typeof window !== 'undefined' && typeof document !== 'undefined';

const _navigator = typeof navigator === 'object' && navigator || undefined;

/**
 * Determine if we're running in a standard browser environment
 *
 * This allows axios to run in a web worker, and react-native.
 * Both environments support XMLHttpRequest, but not fully standard globals.
 *
 * web workers:
 *  typeof window -> undefined
 *  typeof document -> undefined
 *
 * react-native:
 *  navigator.product -> 'ReactNative'
 * nativescript
 *  navigator.product -> 'NativeScript' or 'NS'
 *
 * @returns {boolean}
 */
const hasStandardBrowserEnv = hasBrowserEnv &&
  (!_navigator || ['ReactNative', 'NativeScript', 'NS'].indexOf(_navigator.product) < 0);

/**
 * Determine if we're running in a standard browser webWorker environment
 *
 * Although the `isStandardBrowserEnv` method indicates that
 * `allows axios to run in a web worker`, the WebWorker will still be
 * filtered out due to its judgment standard
 * `typeof window !== 'undefined' && typeof document !== 'undefined'`.
 * This leads to a problem when axios post `FormData` in webWorker
 */
const hasStandardBrowserWebWorkerEnv = (() => {
  return (
    typeof WorkerGlobalScope !== 'undefined' &&
    // eslint-disable-next-line no-undef
    self instanceof WorkerGlobalScope &&
    typeof self.importScripts === 'function'
  );
})();

const origin = hasBrowserEnv && window.location.href || 'http://localhost';

var utils = /*#__PURE__*/Object.freeze({
    __proto__: null,
    hasBrowserEnv: hasBrowserEnv,
    hasStandardBrowserEnv: hasStandardBrowserEnv,
    hasStandardBrowserWebWorkerEnv: hasStandardBrowserWebWorkerEnv,
    navigator: _navigator,
    origin: origin
});

var platform = {
  ...utils,
  ...platform$1
};

function toURLEncodedForm(data, options) {
  return toFormData(data, new platform.classes.URLSearchParams(), Object.assign({
    visitor: function(value, key, path, helpers) {
      if (platform.isNode && utils$1.isBuffer(value)) {
        this.append(key, value.toString('base64'));
        return false;
      }

      return helpers.defaultVisitor.apply(this, arguments);
    }
  }, options));
}

/**
 * It takes a string like `foo[x][y][z]` and returns an array like `['foo', 'x', 'y', 'z']
 *
 * @param {string} name - The name of the property to get.
 *
 * @returns An array of strings.
 */
function parsePropPath(name) {
  // foo[x][y][z]
  // foo.x.y.z
  // foo-x-y-z
  // foo x y z
  return utils$1.matchAll(/\w+|\[(\w*)]/g, name).map(match => {
    return match[0] === '[]' ? '' : match[1] || match[0];
  });
}

/**
 * Convert an array to an object.
 *
 * @param {Array<any>} arr - The array to convert to an object.
 *
 * @returns An object with the same keys and values as the array.
 */
function arrayToObject(arr) {
  const obj = {};
  const keys = Object.keys(arr);
  let i;
  const len = keys.length;
  let key;
  for (i = 0; i < len; i++) {
    key = keys[i];
    obj[key] = arr[key];
  }
  return obj;
}

/**
 * It takes a FormData object and returns a JavaScript object
 *
 * @param {string} formData The FormData object to convert to JSON.
 *
 * @returns {Object<string, any> | null} The converted object.
 */
function formDataToJSON(formData) {
  function buildPath(path, value, target, index) {
    let name = path[index++];

    if (name === '__proto__') return true;

    const isNumericKey = Number.isFinite(+name);
    const isLast = index >= path.length;
    name = !name && utils$1.isArray(target) ? target.length : name;

    if (isLast) {
      if (utils$1.hasOwnProp(target, name)) {
        target[name] = [target[name], value];
      } else {
        target[name] = value;
      }

      return !isNumericKey;
    }

    if (!target[name] || !utils$1.isObject(target[name])) {
      target[name] = [];
    }

    const result = buildPath(path, value, target[name], index);

    if (result && utils$1.isArray(target[name])) {
      target[name] = arrayToObject(target[name]);
    }

    return !isNumericKey;
  }

  if (utils$1.isFormData(formData) && utils$1.isFunction(formData.entries)) {
    const obj = {};

    utils$1.forEachEntry(formData, (name, value) => {
      buildPath(parsePropPath(name), value, obj, 0);
    });

    return obj;
  }

  return null;
}

/**
 * It takes a string, tries to parse it, and if it fails, it returns the stringified version
 * of the input
 *
 * @param {any} rawValue - The value to be stringified.
 * @param {Function} parser - A function that parses a string into a JavaScript object.
 * @param {Function} encoder - A function that takes a value and returns a string.
 *
 * @returns {string} A stringified version of the rawValue.
 */
function stringifySafely(rawValue, parser, encoder) {
  if (utils$1.isString(rawValue)) {
    try {
      (parser || JSON.parse)(rawValue);
      return utils$1.trim(rawValue);
    } catch (e) {
      if (e.name !== 'SyntaxError') {
        throw e;
      }
    }
  }

  return (encoder || JSON.stringify)(rawValue);
}

const defaults = {

  transitional: transitionalDefaults,

  adapter: ['xhr', 'http', 'fetch'],

  transformRequest: [function transformRequest(data, headers) {
    const contentType = headers.getContentType() || '';
    const hasJSONContentType = contentType.indexOf('application/json') > -1;
    const isObjectPayload = utils$1.isObject(data);

    if (isObjectPayload && utils$1.isHTMLForm(data)) {
      data = new FormData(data);
    }

    const isFormData = utils$1.isFormData(data);

    if (isFormData) {
      return hasJSONContentType ? JSON.stringify(formDataToJSON(data)) : data;
    }

    if (utils$1.isArrayBuffer(data) ||
      utils$1.isBuffer(data) ||
      utils$1.isStream(data) ||
      utils$1.isFile(data) ||
      utils$1.isBlob(data) ||
      utils$1.isReadableStream(data)
    ) {
      return data;
    }
    if (utils$1.isArrayBufferView(data)) {
      return data.buffer;
    }
    if (utils$1.isURLSearchParams(data)) {
      headers.setContentType('application/x-www-form-urlencoded;charset=utf-8', false);
      return data.toString();
    }

    let isFileList;

    if (isObjectPayload) {
      if (contentType.indexOf('application/x-www-form-urlencoded') > -1) {
        return toURLEncodedForm(data, this.formSerializer).toString();
      }

      if ((isFileList = utils$1.isFileList(data)) || contentType.indexOf('multipart/form-data') > -1) {
        const _FormData = this.env && this.env.FormData;

        return toFormData(
          isFileList ? {'files[]': data} : data,
          _FormData && new _FormData(),
          this.formSerializer
        );
      }
    }

    if (isObjectPayload || hasJSONContentType ) {
      headers.setContentType('application/json', false);
      return stringifySafely(data);
    }

    return data;
  }],

  transformResponse: [function transformResponse(data) {
    const transitional = this.transitional || defaults.transitional;
    const forcedJSONParsing = transitional && transitional.forcedJSONParsing;
    const JSONRequested = this.responseType === 'json';

    if (utils$1.isResponse(data) || utils$1.isReadableStream(data)) {
      return data;
    }

    if (data && utils$1.isString(data) && ((forcedJSONParsing && !this.responseType) || JSONRequested)) {
      const silentJSONParsing = transitional && transitional.silentJSONParsing;
      const strictJSONParsing = !silentJSONParsing && JSONRequested;

      try {
        return JSON.parse(data);
      } catch (e) {
        if (strictJSONParsing) {
          if (e.name === 'SyntaxError') {
            throw AxiosError.from(e, AxiosError.ERR_BAD_RESPONSE, this, null, this.response);
          }
          throw e;
        }
      }
    }

    return data;
  }],

  /**
   * A timeout in milliseconds to abort a request. If set to 0 (default) a
   * timeout is not created.
   */
  timeout: 0,

  xsrfCookieName: 'XSRF-TOKEN',
  xsrfHeaderName: 'X-XSRF-TOKEN',

  maxContentLength: -1,
  maxBodyLength: -1,

  env: {
    FormData: platform.classes.FormData,
    Blob: platform.classes.Blob
  },

  validateStatus: function validateStatus(status) {
    return status >= 200 && status < 300;
  },

  headers: {
    common: {
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': undefined
    }
  }
};

utils$1.forEach(['delete', 'get', 'head', 'post', 'put', 'patch'], (method) => {
  defaults.headers[method] = {};
});

var defaults$1 = defaults;

// RawAxiosHeaders whose duplicates are ignored by node
// c.f. https://nodejs.org/api/http.html#http_message_headers
const ignoreDuplicateOf = utils$1.toObjectSet([
  'age', 'authorization', 'content-length', 'content-type', 'etag',
  'expires', 'from', 'host', 'if-modified-since', 'if-unmodified-since',
  'last-modified', 'location', 'max-forwards', 'proxy-authorization',
  'referer', 'retry-after', 'user-agent'
]);

/**
 * Parse headers into an object
 *
 * ```
 * Date: Wed, 27 Aug 2014 08:58:49 GMT
 * Content-Type: application/json
 * Connection: keep-alive
 * Transfer-Encoding: chunked
 * ```
 *
 * @param {String} rawHeaders Headers needing to be parsed
 *
 * @returns {Object} Headers parsed into an object
 */
var parseHeaders = rawHeaders => {
  const parsed = {};
  let key;
  let val;
  let i;

  rawHeaders && rawHeaders.split('\n').forEach(function parser(line) {
    i = line.indexOf(':');
    key = line.substring(0, i).trim().toLowerCase();
    val = line.substring(i + 1).trim();

    if (!key || (parsed[key] && ignoreDuplicateOf[key])) {
      return;
    }

    if (key === 'set-cookie') {
      if (parsed[key]) {
        parsed[key].push(val);
      } else {
        parsed[key] = [val];
      }
    } else {
      parsed[key] = parsed[key] ? parsed[key] + ', ' + val : val;
    }
  });

  return parsed;
};

const $internals = Symbol('internals');

function normalizeHeader(header) {
  return header && String(header).trim().toLowerCase();
}

function normalizeValue(value) {
  if (value === false || value == null) {
    return value;
  }

  return utils$1.isArray(value) ? value.map(normalizeValue) : String(value);
}

function parseTokens(str) {
  const tokens = Object.create(null);
  const tokensRE = /([^\s,;=]+)\s*(?:=\s*([^,;]+))?/g;
  let match;

  while ((match = tokensRE.exec(str))) {
    tokens[match[1]] = match[2];
  }

  return tokens;
}

const isValidHeaderName = (str) => /^[-_a-zA-Z0-9^`|~,!#$%&'*+.]+$/.test(str.trim());

function matchHeaderValue(context, value, header, filter, isHeaderNameFilter) {
  if (utils$1.isFunction(filter)) {
    return filter.call(this, value, header);
  }

  if (isHeaderNameFilter) {
    value = header;
  }

  if (!utils$1.isString(value)) return;

  if (utils$1.isString(filter)) {
    return value.indexOf(filter) !== -1;
  }

  if (utils$1.isRegExp(filter)) {
    return filter.test(value);
  }
}

function formatHeader(header) {
  return header.trim()
    .toLowerCase().replace(/([a-z\d])(\w*)/g, (w, char, str) => {
      return char.toUpperCase() + str;
    });
}

function buildAccessors(obj, header) {
  const accessorName = utils$1.toCamelCase(' ' + header);

  ['get', 'set', 'has'].forEach(methodName => {
    Object.defineProperty(obj, methodName + accessorName, {
      value: function(arg1, arg2, arg3) {
        return this[methodName].call(this, header, arg1, arg2, arg3);
      },
      configurable: true
    });
  });
}

class AxiosHeaders {
  constructor(headers) {
    headers && this.set(headers);
  }

  set(header, valueOrRewrite, rewrite) {
    const self = this;

    function setHeader(_value, _header, _rewrite) {
      const lHeader = normalizeHeader(_header);

      if (!lHeader) {
        throw new Error('header name must be a non-empty string');
      }

      const key = utils$1.findKey(self, lHeader);

      if(!key || self[key] === undefined || _rewrite === true || (_rewrite === undefined && self[key] !== false)) {
        self[key || _header] = normalizeValue(_value);
      }
    }

    const setHeaders = (headers, _rewrite) =>
      utils$1.forEach(headers, (_value, _header) => setHeader(_value, _header, _rewrite));

    if (utils$1.isPlainObject(header) || header instanceof this.constructor) {
      setHeaders(header, valueOrRewrite);
    } else if(utils$1.isString(header) && (header = header.trim()) && !isValidHeaderName(header)) {
      setHeaders(parseHeaders(header), valueOrRewrite);
    } else if (utils$1.isHeaders(header)) {
      for (const [key, value] of header.entries()) {
        setHeader(value, key, rewrite);
      }
    } else {
      header != null && setHeader(valueOrRewrite, header, rewrite);
    }

    return this;
  }

  get(header, parser) {
    header = normalizeHeader(header);

    if (header) {
      const key = utils$1.findKey(this, header);

      if (key) {
        const value = this[key];

        if (!parser) {
          return value;
        }

        if (parser === true) {
          return parseTokens(value);
        }

        if (utils$1.isFunction(parser)) {
          return parser.call(this, value, key);
        }

        if (utils$1.isRegExp(parser)) {
          return parser.exec(value);
        }

        throw new TypeError('parser must be boolean|regexp|function');
      }
    }
  }

  has(header, matcher) {
    header = normalizeHeader(header);

    if (header) {
      const key = utils$1.findKey(this, header);

      return !!(key && this[key] !== undefined && (!matcher || matchHeaderValue(this, this[key], key, matcher)));
    }

    return false;
  }

  delete(header, matcher) {
    const self = this;
    let deleted = false;

    function deleteHeader(_header) {
      _header = normalizeHeader(_header);

      if (_header) {
        const key = utils$1.findKey(self, _header);

        if (key && (!matcher || matchHeaderValue(self, self[key], key, matcher))) {
          delete self[key];

          deleted = true;
        }
      }
    }

    if (utils$1.isArray(header)) {
      header.forEach(deleteHeader);
    } else {
      deleteHeader(header);
    }

    return deleted;
  }

  clear(matcher) {
    const keys = Object.keys(this);
    let i = keys.length;
    let deleted = false;

    while (i--) {
      const key = keys[i];
      if(!matcher || matchHeaderValue(this, this[key], key, matcher, true)) {
        delete this[key];
        deleted = true;
      }
    }

    return deleted;
  }

  normalize(format) {
    const self = this;
    const headers = {};

    utils$1.forEach(this, (value, header) => {
      const key = utils$1.findKey(headers, header);

      if (key) {
        self[key] = normalizeValue(value);
        delete self[header];
        return;
      }

      const normalized = format ? formatHeader(header) : String(header).trim();

      if (normalized !== header) {
        delete self[header];
      }

      self[normalized] = normalizeValue(value);

      headers[normalized] = true;
    });

    return this;
  }

  concat(...targets) {
    return this.constructor.concat(this, ...targets);
  }

  toJSON(asStrings) {
    const obj = Object.create(null);

    utils$1.forEach(this, (value, header) => {
      value != null && value !== false && (obj[header] = asStrings && utils$1.isArray(value) ? value.join(', ') : value);
    });

    return obj;
  }

  [Symbol.iterator]() {
    return Object.entries(this.toJSON())[Symbol.iterator]();
  }

  toString() {
    return Object.entries(this.toJSON()).map(([header, value]) => header + ': ' + value).join('\n');
  }

  get [Symbol.toStringTag]() {
    return 'AxiosHeaders';
  }

  static from(thing) {
    return thing instanceof this ? thing : new this(thing);
  }

  static concat(first, ...targets) {
    const computed = new this(first);

    targets.forEach((target) => computed.set(target));

    return computed;
  }

  static accessor(header) {
    const internals = this[$internals] = (this[$internals] = {
      accessors: {}
    });

    const accessors = internals.accessors;
    const prototype = this.prototype;

    function defineAccessor(_header) {
      const lHeader = normalizeHeader(_header);

      if (!accessors[lHeader]) {
        buildAccessors(prototype, _header);
        accessors[lHeader] = true;
      }
    }

    utils$1.isArray(header) ? header.forEach(defineAccessor) : defineAccessor(header);

    return this;
  }
}

AxiosHeaders.accessor(['Content-Type', 'Content-Length', 'Accept', 'Accept-Encoding', 'User-Agent', 'Authorization']);

// reserved names hotfix
utils$1.reduceDescriptors(AxiosHeaders.prototype, ({value}, key) => {
  let mapped = key[0].toUpperCase() + key.slice(1); // map `set` => `Set`
  return {
    get: () => value,
    set(headerValue) {
      this[mapped] = headerValue;
    }
  }
});

utils$1.freezeMethods(AxiosHeaders);

var AxiosHeaders$1 = AxiosHeaders;

/**
 * Transform the data for a request or a response
 *
 * @param {Array|Function} fns A single function or Array of functions
 * @param {?Object} response The response object
 *
 * @returns {*} The resulting transformed data
 */
function transformData(fns, response) {
  const config = this || defaults$1;
  const context = response || config;
  const headers = AxiosHeaders$1.from(context.headers);
  let data = context.data;

  utils$1.forEach(fns, function transform(fn) {
    data = fn.call(config, data, headers.normalize(), response ? response.status : undefined);
  });

  headers.normalize();

  return data;
}

function isCancel(value) {
  return !!(value && value.__CANCEL__);
}

/**
 * A `CanceledError` is an object that is thrown when an operation is canceled.
 *
 * @param {string=} message The message.
 * @param {Object=} config The config.
 * @param {Object=} request The request.
 *
 * @returns {CanceledError} The created error.
 */
function CanceledError(message, config, request) {
  // eslint-disable-next-line no-eq-null,eqeqeq
  AxiosError.call(this, message == null ? 'canceled' : message, AxiosError.ERR_CANCELED, config, request);
  this.name = 'CanceledError';
}

utils$1.inherits(CanceledError, AxiosError, {
  __CANCEL__: true
});

/**
 * Resolve or reject a Promise based on response status.
 *
 * @param {Function} resolve A function that resolves the promise.
 * @param {Function} reject A function that rejects the promise.
 * @param {object} response The response.
 *
 * @returns {object} The response.
 */
function settle(resolve, reject, response) {
  const validateStatus = response.config.validateStatus;
  if (!response.status || !validateStatus || validateStatus(response.status)) {
    resolve(response);
  } else {
    reject(new AxiosError(
      'Request failed with status code ' + response.status,
      [AxiosError.ERR_BAD_REQUEST, AxiosError.ERR_BAD_RESPONSE][Math.floor(response.status / 100) - 4],
      response.config,
      response.request,
      response
    ));
  }
}

function parseProtocol(url) {
  const match = /^([-+\w]{1,25})(:?\/\/|:)/.exec(url);
  return match && match[1] || '';
}

/**
 * Calculate data maxRate
 * @param {Number} [samplesCount= 10]
 * @param {Number} [min= 1000]
 * @returns {Function}
 */
function speedometer(samplesCount, min) {
  samplesCount = samplesCount || 10;
  const bytes = new Array(samplesCount);
  const timestamps = new Array(samplesCount);
  let head = 0;
  let tail = 0;
  let firstSampleTS;

  min = min !== undefined ? min : 1000;

  return function push(chunkLength) {
    const now = Date.now();

    const startedAt = timestamps[tail];

    if (!firstSampleTS) {
      firstSampleTS = now;
    }

    bytes[head] = chunkLength;
    timestamps[head] = now;

    let i = tail;
    let bytesCount = 0;

    while (i !== head) {
      bytesCount += bytes[i++];
      i = i % samplesCount;
    }

    head = (head + 1) % samplesCount;

    if (head === tail) {
      tail = (tail + 1) % samplesCount;
    }

    if (now - firstSampleTS < min) {
      return;
    }

    const passed = startedAt && now - startedAt;

    return passed ? Math.round(bytesCount * 1000 / passed) : undefined;
  };
}

/**
 * Throttle decorator
 * @param {Function} fn
 * @param {Number} freq
 * @return {Function}
 */
function throttle(fn, freq) {
  let timestamp = 0;
  let threshold = 1000 / freq;
  let lastArgs;
  let timer;

  const invoke = (args, now = Date.now()) => {
    timestamp = now;
    lastArgs = null;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    fn.apply(null, args);
  };

  const throttled = (...args) => {
    const now = Date.now();
    const passed = now - timestamp;
    if ( passed >= threshold) {
      invoke(args, now);
    } else {
      lastArgs = args;
      if (!timer) {
        timer = setTimeout(() => {
          timer = null;
          invoke(lastArgs);
        }, threshold - passed);
      }
    }
  };

  const flush = () => lastArgs && invoke(lastArgs);

  return [throttled, flush];
}

const progressEventReducer = (listener, isDownloadStream, freq = 3) => {
  let bytesNotified = 0;
  const _speedometer = speedometer(50, 250);

  return throttle(e => {
    const loaded = e.loaded;
    const total = e.lengthComputable ? e.total : undefined;
    const progressBytes = loaded - bytesNotified;
    const rate = _speedometer(progressBytes);
    const inRange = loaded <= total;

    bytesNotified = loaded;

    const data = {
      loaded,
      total,
      progress: total ? (loaded / total) : undefined,
      bytes: progressBytes,
      rate: rate ? rate : undefined,
      estimated: rate && total && inRange ? (total - loaded) / rate : undefined,
      event: e,
      lengthComputable: total != null,
      [isDownloadStream ? 'download' : 'upload']: true
    };

    listener(data);
  }, freq);
};

const progressEventDecorator = (total, throttled) => {
  const lengthComputable = total != null;

  return [(loaded) => throttled[0]({
    lengthComputable,
    total,
    loaded
  }), throttled[1]];
};

const asyncDecorator = (fn) => (...args) => utils$1.asap(() => fn(...args));

var isURLSameOrigin = platform.hasStandardBrowserEnv ? ((origin, isMSIE) => (url) => {
  url = new URL(url, platform.origin);

  return (
    origin.protocol === url.protocol &&
    origin.host === url.host &&
    (isMSIE || origin.port === url.port)
  );
})(
  new URL(platform.origin),
  platform.navigator && /(msie|trident)/i.test(platform.navigator.userAgent)
) : () => true;

var cookies = platform.hasStandardBrowserEnv ?

  // Standard browser envs support document.cookie
  {
    write(name, value, expires, path, domain, secure) {
      const cookie = [name + '=' + encodeURIComponent(value)];

      utils$1.isNumber(expires) && cookie.push('expires=' + new Date(expires).toGMTString());

      utils$1.isString(path) && cookie.push('path=' + path);

      utils$1.isString(domain) && cookie.push('domain=' + domain);

      secure === true && cookie.push('secure');

      document.cookie = cookie.join('; ');
    },

    read(name) {
      const match = document.cookie.match(new RegExp('(^|;\\s*)(' + name + ')=([^;]*)'));
      return (match ? decodeURIComponent(match[3]) : null);
    },

    remove(name) {
      this.write(name, '', Date.now() - 86400000);
    }
  }

  :

  // Non-standard browser env (web workers, react-native) lack needed support.
  {
    write() {},
    read() {
      return null;
    },
    remove() {}
  };

/**
 * Determines whether the specified URL is absolute
 *
 * @param {string} url The URL to test
 *
 * @returns {boolean} True if the specified URL is absolute, otherwise false
 */
function isAbsoluteURL(url) {
  // A URL is considered absolute if it begins with "<scheme>://" or "//" (protocol-relative URL).
  // RFC 3986 defines scheme name as a sequence of characters beginning with a letter and followed
  // by any combination of letters, digits, plus, period, or hyphen.
  return /^([a-z][a-z\d+\-.]*:)?\/\//i.test(url);
}

/**
 * Creates a new URL by combining the specified URLs
 *
 * @param {string} baseURL The base URL
 * @param {string} relativeURL The relative URL
 *
 * @returns {string} The combined URL
 */
function combineURLs(baseURL, relativeURL) {
  return relativeURL
    ? baseURL.replace(/\/?\/$/, '') + '/' + relativeURL.replace(/^\/+/, '')
    : baseURL;
}

/**
 * Creates a new URL by combining the baseURL with the requestedURL,
 * only when the requestedURL is not already an absolute URL.
 * If the requestURL is absolute, this function returns the requestedURL untouched.
 *
 * @param {string} baseURL The base URL
 * @param {string} requestedURL Absolute or relative URL to combine
 *
 * @returns {string} The combined full path
 */
function buildFullPath(baseURL, requestedURL) {
  if (baseURL && !isAbsoluteURL(requestedURL)) {
    return combineURLs(baseURL, requestedURL);
  }
  return requestedURL;
}

const headersToObject = (thing) => thing instanceof AxiosHeaders$1 ? { ...thing } : thing;

/**
 * Config-specific merge-function which creates a new config-object
 * by merging two configuration objects together.
 *
 * @param {Object} config1
 * @param {Object} config2
 *
 * @returns {Object} New object resulting from merging config2 to config1
 */
function mergeConfig(config1, config2) {
  // eslint-disable-next-line no-param-reassign
  config2 = config2 || {};
  const config = {};

  function getMergedValue(target, source, prop, caseless) {
    if (utils$1.isPlainObject(target) && utils$1.isPlainObject(source)) {
      return utils$1.merge.call({caseless}, target, source);
    } else if (utils$1.isPlainObject(source)) {
      return utils$1.merge({}, source);
    } else if (utils$1.isArray(source)) {
      return source.slice();
    }
    return source;
  }

  // eslint-disable-next-line consistent-return
  function mergeDeepProperties(a, b, prop , caseless) {
    if (!utils$1.isUndefined(b)) {
      return getMergedValue(a, b, prop , caseless);
    } else if (!utils$1.isUndefined(a)) {
      return getMergedValue(undefined, a, prop , caseless);
    }
  }

  // eslint-disable-next-line consistent-return
  function valueFromConfig2(a, b) {
    if (!utils$1.isUndefined(b)) {
      return getMergedValue(undefined, b);
    }
  }

  // eslint-disable-next-line consistent-return
  function defaultToConfig2(a, b) {
    if (!utils$1.isUndefined(b)) {
      return getMergedValue(undefined, b);
    } else if (!utils$1.isUndefined(a)) {
      return getMergedValue(undefined, a);
    }
  }

  // eslint-disable-next-line consistent-return
  function mergeDirectKeys(a, b, prop) {
    if (prop in config2) {
      return getMergedValue(a, b);
    } else if (prop in config1) {
      return getMergedValue(undefined, a);
    }
  }

  const mergeMap = {
    url: valueFromConfig2,
    method: valueFromConfig2,
    data: valueFromConfig2,
    baseURL: defaultToConfig2,
    transformRequest: defaultToConfig2,
    transformResponse: defaultToConfig2,
    paramsSerializer: defaultToConfig2,
    timeout: defaultToConfig2,
    timeoutMessage: defaultToConfig2,
    withCredentials: defaultToConfig2,
    withXSRFToken: defaultToConfig2,
    adapter: defaultToConfig2,
    responseType: defaultToConfig2,
    xsrfCookieName: defaultToConfig2,
    xsrfHeaderName: defaultToConfig2,
    onUploadProgress: defaultToConfig2,
    onDownloadProgress: defaultToConfig2,
    decompress: defaultToConfig2,
    maxContentLength: defaultToConfig2,
    maxBodyLength: defaultToConfig2,
    beforeRedirect: defaultToConfig2,
    transport: defaultToConfig2,
    httpAgent: defaultToConfig2,
    httpsAgent: defaultToConfig2,
    cancelToken: defaultToConfig2,
    socketPath: defaultToConfig2,
    responseEncoding: defaultToConfig2,
    validateStatus: mergeDirectKeys,
    headers: (a, b , prop) => mergeDeepProperties(headersToObject(a), headersToObject(b),prop, true)
  };

  utils$1.forEach(Object.keys(Object.assign({}, config1, config2)), function computeConfigValue(prop) {
    const merge = mergeMap[prop] || mergeDeepProperties;
    const configValue = merge(config1[prop], config2[prop], prop);
    (utils$1.isUndefined(configValue) && merge !== mergeDirectKeys) || (config[prop] = configValue);
  });

  return config;
}

var resolveConfig = (config) => {
  const newConfig = mergeConfig({}, config);

  let {data, withXSRFToken, xsrfHeaderName, xsrfCookieName, headers, auth} = newConfig;

  newConfig.headers = headers = AxiosHeaders$1.from(headers);

  newConfig.url = buildURL(buildFullPath(newConfig.baseURL, newConfig.url), config.params, config.paramsSerializer);

  // HTTP basic authentication
  if (auth) {
    headers.set('Authorization', 'Basic ' +
      btoa((auth.username || '') + ':' + (auth.password ? unescape(encodeURIComponent(auth.password)) : ''))
    );
  }

  let contentType;

  if (utils$1.isFormData(data)) {
    if (platform.hasStandardBrowserEnv || platform.hasStandardBrowserWebWorkerEnv) {
      headers.setContentType(undefined); // Let the browser set it
    } else if ((contentType = headers.getContentType()) !== false) {
      // fix semicolon duplication issue for ReactNative FormData implementation
      const [type, ...tokens] = contentType ? contentType.split(';').map(token => token.trim()).filter(Boolean) : [];
      headers.setContentType([type || 'multipart/form-data', ...tokens].join('; '));
    }
  }

  // Add xsrf header
  // This is only done if running in a standard browser environment.
  // Specifically not if we're in a web worker, or react-native.

  if (platform.hasStandardBrowserEnv) {
    withXSRFToken && utils$1.isFunction(withXSRFToken) && (withXSRFToken = withXSRFToken(newConfig));

    if (withXSRFToken || (withXSRFToken !== false && isURLSameOrigin(newConfig.url))) {
      // Add xsrf header
      const xsrfValue = xsrfHeaderName && xsrfCookieName && cookies.read(xsrfCookieName);

      if (xsrfValue) {
        headers.set(xsrfHeaderName, xsrfValue);
      }
    }
  }

  return newConfig;
};

const isXHRAdapterSupported = typeof XMLHttpRequest !== 'undefined';

var xhrAdapter = isXHRAdapterSupported && function (config) {
  return new Promise(function dispatchXhrRequest(resolve, reject) {
    const _config = resolveConfig(config);
    let requestData = _config.data;
    const requestHeaders = AxiosHeaders$1.from(_config.headers).normalize();
    let {responseType, onUploadProgress, onDownloadProgress} = _config;
    let onCanceled;
    let uploadThrottled, downloadThrottled;
    let flushUpload, flushDownload;

    function done() {
      flushUpload && flushUpload(); // flush events
      flushDownload && flushDownload(); // flush events

      _config.cancelToken && _config.cancelToken.unsubscribe(onCanceled);

      _config.signal && _config.signal.removeEventListener('abort', onCanceled);
    }

    let request = new XMLHttpRequest();

    request.open(_config.method.toUpperCase(), _config.url, true);

    // Set the request timeout in MS
    request.timeout = _config.timeout;

    function onloadend() {
      if (!request) {
        return;
      }
      // Prepare the response
      const responseHeaders = AxiosHeaders$1.from(
        'getAllResponseHeaders' in request && request.getAllResponseHeaders()
      );
      const responseData = !responseType || responseType === 'text' || responseType === 'json' ?
        request.responseText : request.response;
      const response = {
        data: responseData,
        status: request.status,
        statusText: request.statusText,
        headers: responseHeaders,
        config,
        request
      };

      settle(function _resolve(value) {
        resolve(value);
        done();
      }, function _reject(err) {
        reject(err);
        done();
      }, response);

      // Clean up request
      request = null;
    }

    if ('onloadend' in request) {
      // Use onloadend if available
      request.onloadend = onloadend;
    } else {
      // Listen for ready state to emulate onloadend
      request.onreadystatechange = function handleLoad() {
        if (!request || request.readyState !== 4) {
          return;
        }

        // The request errored out and we didn't get a response, this will be
        // handled by onerror instead
        // With one exception: request that using file: protocol, most browsers
        // will return status as 0 even though it's a successful request
        if (request.status === 0 && !(request.responseURL && request.responseURL.indexOf('file:') === 0)) {
          return;
        }
        // readystate handler is calling before onerror or ontimeout handlers,
        // so we should call onloadend on the next 'tick'
        setTimeout(onloadend);
      };
    }

    // Handle browser request cancellation (as opposed to a manual cancellation)
    request.onabort = function handleAbort() {
      if (!request) {
        return;
      }

      reject(new AxiosError('Request aborted', AxiosError.ECONNABORTED, config, request));

      // Clean up request
      request = null;
    };

    // Handle low level network errors
    request.onerror = function handleError() {
      // Real errors are hidden from us by the browser
      // onerror should only fire if it's a network error
      reject(new AxiosError('Network Error', AxiosError.ERR_NETWORK, config, request));

      // Clean up request
      request = null;
    };

    // Handle timeout
    request.ontimeout = function handleTimeout() {
      let timeoutErrorMessage = _config.timeout ? 'timeout of ' + _config.timeout + 'ms exceeded' : 'timeout exceeded';
      const transitional = _config.transitional || transitionalDefaults;
      if (_config.timeoutErrorMessage) {
        timeoutErrorMessage = _config.timeoutErrorMessage;
      }
      reject(new AxiosError(
        timeoutErrorMessage,
        transitional.clarifyTimeoutError ? AxiosError.ETIMEDOUT : AxiosError.ECONNABORTED,
        config,
        request));

      // Clean up request
      request = null;
    };

    // Remove Content-Type if data is undefined
    requestData === undefined && requestHeaders.setContentType(null);

    // Add headers to the request
    if ('setRequestHeader' in request) {
      utils$1.forEach(requestHeaders.toJSON(), function setRequestHeader(val, key) {
        request.setRequestHeader(key, val);
      });
    }

    // Add withCredentials to request if needed
    if (!utils$1.isUndefined(_config.withCredentials)) {
      request.withCredentials = !!_config.withCredentials;
    }

    // Add responseType to request if needed
    if (responseType && responseType !== 'json') {
      request.responseType = _config.responseType;
    }

    // Handle progress if needed
    if (onDownloadProgress) {
      ([downloadThrottled, flushDownload] = progressEventReducer(onDownloadProgress, true));
      request.addEventListener('progress', downloadThrottled);
    }

    // Not all browsers support upload events
    if (onUploadProgress && request.upload) {
      ([uploadThrottled, flushUpload] = progressEventReducer(onUploadProgress));

      request.upload.addEventListener('progress', uploadThrottled);

      request.upload.addEventListener('loadend', flushUpload);
    }

    if (_config.cancelToken || _config.signal) {
      // Handle cancellation
      // eslint-disable-next-line func-names
      onCanceled = cancel => {
        if (!request) {
          return;
        }
        reject(!cancel || cancel.type ? new CanceledError(null, config, request) : cancel);
        request.abort();
        request = null;
      };

      _config.cancelToken && _config.cancelToken.subscribe(onCanceled);
      if (_config.signal) {
        _config.signal.aborted ? onCanceled() : _config.signal.addEventListener('abort', onCanceled);
      }
    }

    const protocol = parseProtocol(_config.url);

    if (protocol && platform.protocols.indexOf(protocol) === -1) {
      reject(new AxiosError('Unsupported protocol ' + protocol + ':', AxiosError.ERR_BAD_REQUEST, config));
      return;
    }


    // Send the request
    request.send(requestData || null);
  });
};

const composeSignals = (signals, timeout) => {
  const {length} = (signals = signals ? signals.filter(Boolean) : []);

  if (timeout || length) {
    let controller = new AbortController();

    let aborted;

    const onabort = function (reason) {
      if (!aborted) {
        aborted = true;
        unsubscribe();
        const err = reason instanceof Error ? reason : this.reason;
        controller.abort(err instanceof AxiosError ? err : new CanceledError(err instanceof Error ? err.message : err));
      }
    };

    let timer = timeout && setTimeout(() => {
      timer = null;
      onabort(new AxiosError(`timeout ${timeout} of ms exceeded`, AxiosError.ETIMEDOUT));
    }, timeout);

    const unsubscribe = () => {
      if (signals) {
        timer && clearTimeout(timer);
        timer = null;
        signals.forEach(signal => {
          signal.unsubscribe ? signal.unsubscribe(onabort) : signal.removeEventListener('abort', onabort);
        });
        signals = null;
      }
    };

    signals.forEach((signal) => signal.addEventListener('abort', onabort));

    const {signal} = controller;

    signal.unsubscribe = () => utils$1.asap(unsubscribe);

    return signal;
  }
};

var composeSignals$1 = composeSignals;

const streamChunk = function* (chunk, chunkSize) {
  let len = chunk.byteLength;

  if (!chunkSize || len < chunkSize) {
    yield chunk;
    return;
  }

  let pos = 0;
  let end;

  while (pos < len) {
    end = pos + chunkSize;
    yield chunk.slice(pos, end);
    pos = end;
  }
};

const readBytes = async function* (iterable, chunkSize) {
  for await (const chunk of readStream(iterable)) {
    yield* streamChunk(chunk, chunkSize);
  }
};

const readStream = async function* (stream) {
  if (stream[Symbol.asyncIterator]) {
    yield* stream;
    return;
  }

  const reader = stream.getReader();
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) {
        break;
      }
      yield value;
    }
  } finally {
    await reader.cancel();
  }
};

const trackStream = (stream, chunkSize, onProgress, onFinish) => {
  const iterator = readBytes(stream, chunkSize);

  let bytes = 0;
  let done;
  let _onFinish = (e) => {
    if (!done) {
      done = true;
      onFinish && onFinish(e);
    }
  };

  return new ReadableStream({
    async pull(controller) {
      try {
        const {done, value} = await iterator.next();

        if (done) {
         _onFinish();
          controller.close();
          return;
        }

        let len = value.byteLength;
        if (onProgress) {
          let loadedBytes = bytes += len;
          onProgress(loadedBytes);
        }
        controller.enqueue(new Uint8Array(value));
      } catch (err) {
        _onFinish(err);
        throw err;
      }
    },
    cancel(reason) {
      _onFinish(reason);
      return iterator.return();
    }
  }, {
    highWaterMark: 2
  })
};

const isFetchSupported = typeof fetch === 'function' && typeof Request === 'function' && typeof Response === 'function';
const isReadableStreamSupported = isFetchSupported && typeof ReadableStream === 'function';

// used only inside the fetch adapter
const encodeText = isFetchSupported && (typeof TextEncoder === 'function' ?
    ((encoder) => (str) => encoder.encode(str))(new TextEncoder()) :
    async (str) => new Uint8Array(await new Response(str).arrayBuffer())
);

const test = (fn, ...args) => {
  try {
    return !!fn(...args);
  } catch (e) {
    return false
  }
};

const supportsRequestStream = isReadableStreamSupported && test(() => {
  let duplexAccessed = false;

  const hasContentType = new Request(platform.origin, {
    body: new ReadableStream(),
    method: 'POST',
    get duplex() {
      duplexAccessed = true;
      return 'half';
    },
  }).headers.has('Content-Type');

  return duplexAccessed && !hasContentType;
});

const DEFAULT_CHUNK_SIZE = 64 * 1024;

const supportsResponseStream = isReadableStreamSupported &&
  test(() => utils$1.isReadableStream(new Response('').body));


const resolvers = {
  stream: supportsResponseStream && ((res) => res.body)
};

isFetchSupported && (((res) => {
  ['text', 'arrayBuffer', 'blob', 'formData', 'stream'].forEach(type => {
    !resolvers[type] && (resolvers[type] = utils$1.isFunction(res[type]) ? (res) => res[type]() :
      (_, config) => {
        throw new AxiosError(`Response type '${type}' is not supported`, AxiosError.ERR_NOT_SUPPORT, config);
      });
  });
})(new Response));

const getBodyLength = async (body) => {
  if (body == null) {
    return 0;
  }

  if(utils$1.isBlob(body)) {
    return body.size;
  }

  if(utils$1.isSpecCompliantForm(body)) {
    const _request = new Request(platform.origin, {
      method: 'POST',
      body,
    });
    return (await _request.arrayBuffer()).byteLength;
  }

  if(utils$1.isArrayBufferView(body) || utils$1.isArrayBuffer(body)) {
    return body.byteLength;
  }

  if(utils$1.isURLSearchParams(body)) {
    body = body + '';
  }

  if(utils$1.isString(body)) {
    return (await encodeText(body)).byteLength;
  }
};

const resolveBodyLength = async (headers, body) => {
  const length = utils$1.toFiniteNumber(headers.getContentLength());

  return length == null ? getBodyLength(body) : length;
};

var fetchAdapter = isFetchSupported && (async (config) => {
  let {
    url,
    method,
    data,
    signal,
    cancelToken,
    timeout,
    onDownloadProgress,
    onUploadProgress,
    responseType,
    headers,
    withCredentials = 'same-origin',
    fetchOptions
  } = resolveConfig(config);

  responseType = responseType ? (responseType + '').toLowerCase() : 'text';

  let composedSignal = composeSignals$1([signal, cancelToken && cancelToken.toAbortSignal()], timeout);

  let request;

  const unsubscribe = composedSignal && composedSignal.unsubscribe && (() => {
      composedSignal.unsubscribe();
  });

  let requestContentLength;

  try {
    if (
      onUploadProgress && supportsRequestStream && method !== 'get' && method !== 'head' &&
      (requestContentLength = await resolveBodyLength(headers, data)) !== 0
    ) {
      let _request = new Request(url, {
        method: 'POST',
        body: data,
        duplex: "half"
      });

      let contentTypeHeader;

      if (utils$1.isFormData(data) && (contentTypeHeader = _request.headers.get('content-type'))) {
        headers.setContentType(contentTypeHeader);
      }

      if (_request.body) {
        const [onProgress, flush] = progressEventDecorator(
          requestContentLength,
          progressEventReducer(asyncDecorator(onUploadProgress))
        );

        data = trackStream(_request.body, DEFAULT_CHUNK_SIZE, onProgress, flush);
      }
    }

    if (!utils$1.isString(withCredentials)) {
      withCredentials = withCredentials ? 'include' : 'omit';
    }

    // Cloudflare Workers throws when credentials are defined
    // see https://github.com/cloudflare/workerd/issues/902
    const isCredentialsSupported = "credentials" in Request.prototype;
    request = new Request(url, {
      ...fetchOptions,
      signal: composedSignal,
      method: method.toUpperCase(),
      headers: headers.normalize().toJSON(),
      body: data,
      duplex: "half",
      credentials: isCredentialsSupported ? withCredentials : undefined
    });

    let response = await fetch(request);

    const isStreamResponse = supportsResponseStream && (responseType === 'stream' || responseType === 'response');

    if (supportsResponseStream && (onDownloadProgress || (isStreamResponse && unsubscribe))) {
      const options = {};

      ['status', 'statusText', 'headers'].forEach(prop => {
        options[prop] = response[prop];
      });

      const responseContentLength = utils$1.toFiniteNumber(response.headers.get('content-length'));

      const [onProgress, flush] = onDownloadProgress && progressEventDecorator(
        responseContentLength,
        progressEventReducer(asyncDecorator(onDownloadProgress), true)
      ) || [];

      response = new Response(
        trackStream(response.body, DEFAULT_CHUNK_SIZE, onProgress, () => {
          flush && flush();
          unsubscribe && unsubscribe();
        }),
        options
      );
    }

    responseType = responseType || 'text';

    let responseData = await resolvers[utils$1.findKey(resolvers, responseType) || 'text'](response, config);

    !isStreamResponse && unsubscribe && unsubscribe();

    return await new Promise((resolve, reject) => {
      settle(resolve, reject, {
        data: responseData,
        headers: AxiosHeaders$1.from(response.headers),
        status: response.status,
        statusText: response.statusText,
        config,
        request
      });
    })
  } catch (err) {
    unsubscribe && unsubscribe();

    if (err && err.name === 'TypeError' && /fetch/i.test(err.message)) {
      throw Object.assign(
        new AxiosError('Network Error', AxiosError.ERR_NETWORK, config, request),
        {
          cause: err.cause || err
        }
      )
    }

    throw AxiosError.from(err, err && err.code, config, request);
  }
});

const knownAdapters = {
  http: httpAdapter,
  xhr: xhrAdapter,
  fetch: fetchAdapter
};

utils$1.forEach(knownAdapters, (fn, value) => {
  if (fn) {
    try {
      Object.defineProperty(fn, 'name', {value});
    } catch (e) {
      // eslint-disable-next-line no-empty
    }
    Object.defineProperty(fn, 'adapterName', {value});
  }
});

const renderReason = (reason) => `- ${reason}`;

const isResolvedHandle = (adapter) => utils$1.isFunction(adapter) || adapter === null || adapter === false;

var adapters = {
  getAdapter: (adapters) => {
    adapters = utils$1.isArray(adapters) ? adapters : [adapters];

    const {length} = adapters;
    let nameOrAdapter;
    let adapter;

    const rejectedReasons = {};

    for (let i = 0; i < length; i++) {
      nameOrAdapter = adapters[i];
      let id;

      adapter = nameOrAdapter;

      if (!isResolvedHandle(nameOrAdapter)) {
        adapter = knownAdapters[(id = String(nameOrAdapter)).toLowerCase()];

        if (adapter === undefined) {
          throw new AxiosError(`Unknown adapter '${id}'`);
        }
      }

      if (adapter) {
        break;
      }

      rejectedReasons[id || '#' + i] = adapter;
    }

    if (!adapter) {

      const reasons = Object.entries(rejectedReasons)
        .map(([id, state]) => `adapter ${id} ` +
          (state === false ? 'is not supported by the environment' : 'is not available in the build')
        );

      let s = length ?
        (reasons.length > 1 ? 'since :\n' + reasons.map(renderReason).join('\n') : ' ' + renderReason(reasons[0])) :
        'as no adapter specified';

      throw new AxiosError(
        `There is no suitable adapter to dispatch the request ` + s,
        'ERR_NOT_SUPPORT'
      );
    }

    return adapter;
  },
  adapters: knownAdapters
};

/**
 * Throws a `CanceledError` if cancellation has been requested.
 *
 * @param {Object} config The config that is to be used for the request
 *
 * @returns {void}
 */
function throwIfCancellationRequested(config) {
  if (config.cancelToken) {
    config.cancelToken.throwIfRequested();
  }

  if (config.signal && config.signal.aborted) {
    throw new CanceledError(null, config);
  }
}

/**
 * Dispatch a request to the server using the configured adapter.
 *
 * @param {object} config The config that is to be used for the request
 *
 * @returns {Promise} The Promise to be fulfilled
 */
function dispatchRequest(config) {
  throwIfCancellationRequested(config);

  config.headers = AxiosHeaders$1.from(config.headers);

  // Transform request data
  config.data = transformData.call(
    config,
    config.transformRequest
  );

  if (['post', 'put', 'patch'].indexOf(config.method) !== -1) {
    config.headers.setContentType('application/x-www-form-urlencoded', false);
  }

  const adapter = adapters.getAdapter(config.adapter || defaults$1.adapter);

  return adapter(config).then(function onAdapterResolution(response) {
    throwIfCancellationRequested(config);

    // Transform response data
    response.data = transformData.call(
      config,
      config.transformResponse,
      response
    );

    response.headers = AxiosHeaders$1.from(response.headers);

    return response;
  }, function onAdapterRejection(reason) {
    if (!isCancel(reason)) {
      throwIfCancellationRequested(config);

      // Transform response data
      if (reason && reason.response) {
        reason.response.data = transformData.call(
          config,
          config.transformResponse,
          reason.response
        );
        reason.response.headers = AxiosHeaders$1.from(reason.response.headers);
      }
    }

    return Promise.reject(reason);
  });
}

const VERSION = "1.7.9";

const validators$1 = {};

// eslint-disable-next-line func-names
['object', 'boolean', 'number', 'function', 'string', 'symbol'].forEach((type, i) => {
  validators$1[type] = function validator(thing) {
    return typeof thing === type || 'a' + (i < 1 ? 'n ' : ' ') + type;
  };
});

const deprecatedWarnings = {};

/**
 * Transitional option validator
 *
 * @param {function|boolean?} validator - set to false if the transitional option has been removed
 * @param {string?} version - deprecated version / removed since version
 * @param {string?} message - some message with additional info
 *
 * @returns {function}
 */
validators$1.transitional = function transitional(validator, version, message) {
  function formatMessage(opt, desc) {
    return '[Axios v' + VERSION + '] Transitional option \'' + opt + '\'' + desc + (message ? '. ' + message : '');
  }

  // eslint-disable-next-line func-names
  return (value, opt, opts) => {
    if (validator === false) {
      throw new AxiosError(
        formatMessage(opt, ' has been removed' + (version ? ' in ' + version : '')),
        AxiosError.ERR_DEPRECATED
      );
    }

    if (version && !deprecatedWarnings[opt]) {
      deprecatedWarnings[opt] = true;
      // eslint-disable-next-line no-console
      console.warn(
        formatMessage(
          opt,
          ' has been deprecated since v' + version + ' and will be removed in the near future'
        )
      );
    }

    return validator ? validator(value, opt, opts) : true;
  };
};

validators$1.spelling = function spelling(correctSpelling) {
  return (value, opt) => {
    // eslint-disable-next-line no-console
    console.warn(`${opt} is likely a misspelling of ${correctSpelling}`);
    return true;
  }
};

/**
 * Assert object's properties type
 *
 * @param {object} options
 * @param {object} schema
 * @param {boolean?} allowUnknown
 *
 * @returns {object}
 */

function assertOptions(options, schema, allowUnknown) {
  if (typeof options !== 'object') {
    throw new AxiosError('options must be an object', AxiosError.ERR_BAD_OPTION_VALUE);
  }
  const keys = Object.keys(options);
  let i = keys.length;
  while (i-- > 0) {
    const opt = keys[i];
    const validator = schema[opt];
    if (validator) {
      const value = options[opt];
      const result = value === undefined || validator(value, opt, options);
      if (result !== true) {
        throw new AxiosError('option ' + opt + ' must be ' + result, AxiosError.ERR_BAD_OPTION_VALUE);
      }
      continue;
    }
    if (allowUnknown !== true) {
      throw new AxiosError('Unknown option ' + opt, AxiosError.ERR_BAD_OPTION);
    }
  }
}

var validator = {
  assertOptions,
  validators: validators$1
};

const validators = validator.validators;

/**
 * Create a new instance of Axios
 *
 * @param {Object} instanceConfig The default config for the instance
 *
 * @return {Axios} A new instance of Axios
 */
class Axios {
  constructor(instanceConfig) {
    this.defaults = instanceConfig;
    this.interceptors = {
      request: new InterceptorManager$1(),
      response: new InterceptorManager$1()
    };
  }

  /**
   * Dispatch a request
   *
   * @param {String|Object} configOrUrl The config specific for this request (merged with this.defaults)
   * @param {?Object} config
   *
   * @returns {Promise} The Promise to be fulfilled
   */
  async request(configOrUrl, config) {
    try {
      return await this._request(configOrUrl, config);
    } catch (err) {
      if (err instanceof Error) {
        let dummy = {};

        Error.captureStackTrace ? Error.captureStackTrace(dummy) : (dummy = new Error());

        // slice off the Error: ... line
        const stack = dummy.stack ? dummy.stack.replace(/^.+\n/, '') : '';
        try {
          if (!err.stack) {
            err.stack = stack;
            // match without the 2 top stack lines
          } else if (stack && !String(err.stack).endsWith(stack.replace(/^.+\n.+\n/, ''))) {
            err.stack += '\n' + stack;
          }
        } catch (e) {
          // ignore the case where "stack" is an un-writable property
        }
      }

      throw err;
    }
  }

  _request(configOrUrl, config) {
    /*eslint no-param-reassign:0*/
    // Allow for axios('example/url'[, config]) a la fetch API
    if (typeof configOrUrl === 'string') {
      config = config || {};
      config.url = configOrUrl;
    } else {
      config = configOrUrl || {};
    }

    config = mergeConfig(this.defaults, config);

    const {transitional, paramsSerializer, headers} = config;

    if (transitional !== undefined) {
      validator.assertOptions(transitional, {
        silentJSONParsing: validators.transitional(validators.boolean),
        forcedJSONParsing: validators.transitional(validators.boolean),
        clarifyTimeoutError: validators.transitional(validators.boolean)
      }, false);
    }

    if (paramsSerializer != null) {
      if (utils$1.isFunction(paramsSerializer)) {
        config.paramsSerializer = {
          serialize: paramsSerializer
        };
      } else {
        validator.assertOptions(paramsSerializer, {
          encode: validators.function,
          serialize: validators.function
        }, true);
      }
    }

    validator.assertOptions(config, {
      baseUrl: validators.spelling('baseURL'),
      withXsrfToken: validators.spelling('withXSRFToken')
    }, true);

    // Set config.method
    config.method = (config.method || this.defaults.method || 'get').toLowerCase();

    // Flatten headers
    let contextHeaders = headers && utils$1.merge(
      headers.common,
      headers[config.method]
    );

    headers && utils$1.forEach(
      ['delete', 'get', 'head', 'post', 'put', 'patch', 'common'],
      (method) => {
        delete headers[method];
      }
    );

    config.headers = AxiosHeaders$1.concat(contextHeaders, headers);

    // filter out skipped interceptors
    const requestInterceptorChain = [];
    let synchronousRequestInterceptors = true;
    this.interceptors.request.forEach(function unshiftRequestInterceptors(interceptor) {
      if (typeof interceptor.runWhen === 'function' && interceptor.runWhen(config) === false) {
        return;
      }

      synchronousRequestInterceptors = synchronousRequestInterceptors && interceptor.synchronous;

      requestInterceptorChain.unshift(interceptor.fulfilled, interceptor.rejected);
    });

    const responseInterceptorChain = [];
    this.interceptors.response.forEach(function pushResponseInterceptors(interceptor) {
      responseInterceptorChain.push(interceptor.fulfilled, interceptor.rejected);
    });

    let promise;
    let i = 0;
    let len;

    if (!synchronousRequestInterceptors) {
      const chain = [dispatchRequest.bind(this), undefined];
      chain.unshift.apply(chain, requestInterceptorChain);
      chain.push.apply(chain, responseInterceptorChain);
      len = chain.length;

      promise = Promise.resolve(config);

      while (i < len) {
        promise = promise.then(chain[i++], chain[i++]);
      }

      return promise;
    }

    len = requestInterceptorChain.length;

    let newConfig = config;

    i = 0;

    while (i < len) {
      const onFulfilled = requestInterceptorChain[i++];
      const onRejected = requestInterceptorChain[i++];
      try {
        newConfig = onFulfilled(newConfig);
      } catch (error) {
        onRejected.call(this, error);
        break;
      }
    }

    try {
      promise = dispatchRequest.call(this, newConfig);
    } catch (error) {
      return Promise.reject(error);
    }

    i = 0;
    len = responseInterceptorChain.length;

    while (i < len) {
      promise = promise.then(responseInterceptorChain[i++], responseInterceptorChain[i++]);
    }

    return promise;
  }

  getUri(config) {
    config = mergeConfig(this.defaults, config);
    const fullPath = buildFullPath(config.baseURL, config.url);
    return buildURL(fullPath, config.params, config.paramsSerializer);
  }
}

// Provide aliases for supported request methods
utils$1.forEach(['delete', 'get', 'head', 'options'], function forEachMethodNoData(method) {
  /*eslint func-names:0*/
  Axios.prototype[method] = function(url, config) {
    return this.request(mergeConfig(config || {}, {
      method,
      url,
      data: (config || {}).data
    }));
  };
});

utils$1.forEach(['post', 'put', 'patch'], function forEachMethodWithData(method) {
  /*eslint func-names:0*/

  function generateHTTPMethod(isForm) {
    return function httpMethod(url, data, config) {
      return this.request(mergeConfig(config || {}, {
        method,
        headers: isForm ? {
          'Content-Type': 'multipart/form-data'
        } : {},
        url,
        data
      }));
    };
  }

  Axios.prototype[method] = generateHTTPMethod();

  Axios.prototype[method + 'Form'] = generateHTTPMethod(true);
});

var Axios$1 = Axios;

/**
 * A `CancelToken` is an object that can be used to request cancellation of an operation.
 *
 * @param {Function} executor The executor function.
 *
 * @returns {CancelToken}
 */
class CancelToken {
  constructor(executor) {
    if (typeof executor !== 'function') {
      throw new TypeError('executor must be a function.');
    }

    let resolvePromise;

    this.promise = new Promise(function promiseExecutor(resolve) {
      resolvePromise = resolve;
    });

    const token = this;

    // eslint-disable-next-line func-names
    this.promise.then(cancel => {
      if (!token._listeners) return;

      let i = token._listeners.length;

      while (i-- > 0) {
        token._listeners[i](cancel);
      }
      token._listeners = null;
    });

    // eslint-disable-next-line func-names
    this.promise.then = onfulfilled => {
      let _resolve;
      // eslint-disable-next-line func-names
      const promise = new Promise(resolve => {
        token.subscribe(resolve);
        _resolve = resolve;
      }).then(onfulfilled);

      promise.cancel = function reject() {
        token.unsubscribe(_resolve);
      };

      return promise;
    };

    executor(function cancel(message, config, request) {
      if (token.reason) {
        // Cancellation has already been requested
        return;
      }

      token.reason = new CanceledError(message, config, request);
      resolvePromise(token.reason);
    });
  }

  /**
   * Throws a `CanceledError` if cancellation has been requested.
   */
  throwIfRequested() {
    if (this.reason) {
      throw this.reason;
    }
  }

  /**
   * Subscribe to the cancel signal
   */

  subscribe(listener) {
    if (this.reason) {
      listener(this.reason);
      return;
    }

    if (this._listeners) {
      this._listeners.push(listener);
    } else {
      this._listeners = [listener];
    }
  }

  /**
   * Unsubscribe from the cancel signal
   */

  unsubscribe(listener) {
    if (!this._listeners) {
      return;
    }
    const index = this._listeners.indexOf(listener);
    if (index !== -1) {
      this._listeners.splice(index, 1);
    }
  }

  toAbortSignal() {
    const controller = new AbortController();

    const abort = (err) => {
      controller.abort(err);
    };

    this.subscribe(abort);

    controller.signal.unsubscribe = () => this.unsubscribe(abort);

    return controller.signal;
  }

  /**
   * Returns an object that contains a new `CancelToken` and a function that, when called,
   * cancels the `CancelToken`.
   */
  static source() {
    let cancel;
    const token = new CancelToken(function executor(c) {
      cancel = c;
    });
    return {
      token,
      cancel
    };
  }
}

var CancelToken$1 = CancelToken;

/**
 * Syntactic sugar for invoking a function and expanding an array for arguments.
 *
 * Common use case would be to use `Function.prototype.apply`.
 *
 *  ```js
 *  function f(x, y, z) {}
 *  var args = [1, 2, 3];
 *  f.apply(null, args);
 *  ```
 *
 * With `spread` this example can be re-written.
 *
 *  ```js
 *  spread(function(x, y, z) {})([1, 2, 3]);
 *  ```
 *
 * @param {Function} callback
 *
 * @returns {Function}
 */
function spread(callback) {
  return function wrap(arr) {
    return callback.apply(null, arr);
  };
}

/**
 * Determines whether the payload is an error thrown by Axios
 *
 * @param {*} payload The value to test
 *
 * @returns {boolean} True if the payload is an error thrown by Axios, otherwise false
 */
function isAxiosError(payload) {
  return utils$1.isObject(payload) && (payload.isAxiosError === true);
}

const HttpStatusCode = {
  Continue: 100,
  SwitchingProtocols: 101,
  Processing: 102,
  EarlyHints: 103,
  Ok: 200,
  Created: 201,
  Accepted: 202,
  NonAuthoritativeInformation: 203,
  NoContent: 204,
  ResetContent: 205,
  PartialContent: 206,
  MultiStatus: 207,
  AlreadyReported: 208,
  ImUsed: 226,
  MultipleChoices: 300,
  MovedPermanently: 301,
  Found: 302,
  SeeOther: 303,
  NotModified: 304,
  UseProxy: 305,
  Unused: 306,
  TemporaryRedirect: 307,
  PermanentRedirect: 308,
  BadRequest: 400,
  Unauthorized: 401,
  PaymentRequired: 402,
  Forbidden: 403,
  NotFound: 404,
  MethodNotAllowed: 405,
  NotAcceptable: 406,
  ProxyAuthenticationRequired: 407,
  RequestTimeout: 408,
  Conflict: 409,
  Gone: 410,
  LengthRequired: 411,
  PreconditionFailed: 412,
  PayloadTooLarge: 413,
  UriTooLong: 414,
  UnsupportedMediaType: 415,
  RangeNotSatisfiable: 416,
  ExpectationFailed: 417,
  ImATeapot: 418,
  MisdirectedRequest: 421,
  UnprocessableEntity: 422,
  Locked: 423,
  FailedDependency: 424,
  TooEarly: 425,
  UpgradeRequired: 426,
  PreconditionRequired: 428,
  TooManyRequests: 429,
  RequestHeaderFieldsTooLarge: 431,
  UnavailableForLegalReasons: 451,
  InternalServerError: 500,
  NotImplemented: 501,
  BadGateway: 502,
  ServiceUnavailable: 503,
  GatewayTimeout: 504,
  HttpVersionNotSupported: 505,
  VariantAlsoNegotiates: 506,
  InsufficientStorage: 507,
  LoopDetected: 508,
  NotExtended: 510,
  NetworkAuthenticationRequired: 511,
};

Object.entries(HttpStatusCode).forEach(([key, value]) => {
  HttpStatusCode[value] = key;
});

var HttpStatusCode$1 = HttpStatusCode;

/**
 * Create an instance of Axios
 *
 * @param {Object} defaultConfig The default config for the instance
 *
 * @returns {Axios} A new instance of Axios
 */
function createInstance(defaultConfig) {
  const context = new Axios$1(defaultConfig);
  const instance = bind(Axios$1.prototype.request, context);

  // Copy axios.prototype to instance
  utils$1.extend(instance, Axios$1.prototype, context, {allOwnKeys: true});

  // Copy context to instance
  utils$1.extend(instance, context, null, {allOwnKeys: true});

  // Factory for creating new instances
  instance.create = function create(instanceConfig) {
    return createInstance(mergeConfig(defaultConfig, instanceConfig));
  };

  return instance;
}

// Create the default instance to be exported
const axios = createInstance(defaults$1);

// Expose Axios class to allow class inheritance
axios.Axios = Axios$1;

// Expose Cancel & CancelToken
axios.CanceledError = CanceledError;
axios.CancelToken = CancelToken$1;
axios.isCancel = isCancel;
axios.VERSION = VERSION;
axios.toFormData = toFormData;

// Expose AxiosError class
axios.AxiosError = AxiosError;

// alias for CanceledError for backward compatibility
axios.Cancel = axios.CanceledError;

// Expose all/spread
axios.all = function all(promises) {
  return Promise.all(promises);
};

axios.spread = spread;

// Expose isAxiosError
axios.isAxiosError = isAxiosError;

// Expose mergeConfig
axios.mergeConfig = mergeConfig;

axios.AxiosHeaders = AxiosHeaders$1;

axios.formToJSON = thing => formDataToJSON(utils$1.isHTMLForm(thing) ? new FormData(thing) : thing);

axios.getAdapter = adapters.getAdapter;

axios.HttpStatusCode = HttpStatusCode$1;

axios.default = axios;

// this module should only have a default export
var axios$1 = axios;

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
            throwFormattedError(error);
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
            throwFormattedError(error);
        }
    }
    async getProviderUrl(providerAddress) {
        try {
            const service = await this.contract.getService(providerAddress);
            return service.url;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getQuote(providerAddress) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/quote`;
            const rawReport = await this.fetchText(endpoint, {
                method: 'GET',
            });
            const ret = JSON.parse(rawReport);
            return {
                rawReport,
                signingAddress: ret['report_data'],
            };
        }
        catch (error) {
            throwFormattedError(error);
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
    async cancelTask(providerAddress, signature, taskID) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const userAddress = this.contract.getUserAddress();
            const endpoint = `${url}/v1/user/${userAddress}/task/${taskID}/cancel`;
            const response = await this.fetchText(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    signature: signature,
                }),
            });
            return response;
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
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
            throwFormattedError(error);
        }
    }
    async getPendingTaskCounter(providerAddress) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/task/pending`;
            return Number(await this.fetchText(endpoint, {
                method: 'GET',
            }));
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getLog(providerAddress, userAddress, taskID) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/user/${userAddress}/task/${taskID}/log`;
            return this.fetchText(endpoint, { method: 'GET' });
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getCustomizedModels(url) {
        try {
            const endpoint = `${url}/v1/model`;
            const response = await this.fetchJSON(endpoint, { method: 'GET' });
            return response;
        }
        catch (error) {
            console.error(`Failed to get customized models: ${error}`);
            return [];
        }
    }
    async getCustomizedModel(providerAddress, moduleName) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/model/${moduleName}`;
            const response = await this.fetchJSON(endpoint, { method: 'GET' });
            return response;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getCustomizedModelDetailUsage(providerAddress, moduleName, outputPath) {
        try {
            const url = await this.getProviderUrl(providerAddress);
            const endpoint = `${url}/v1/model/desc/${moduleName}`;
            let destFile = outputPath;
            try {
                const stats = await fs$1.stat(outputPath);
                if (stats.isDirectory()) {
                    destFile = path$1.join(outputPath, `${moduleName}.zip`);
                }
                await fs$1.unlink(destFile);
            }
            catch (err) { }
            const response = await axios$1({
                method: 'get',
                url: endpoint,
                responseType: 'arraybuffer',
            });
            await fs$1.writeFile(destFile, response.data);
            console.log(`Model downloaded and saved to ${destFile}`);
        }
        catch (error) {
            throwFormattedError(error);
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
    _maxGasPrice;
    _step;
    constructor(signer, fineTuningCA, ledger, gasPrice, maxGasPrice, step) {
        this.signer = signer;
        this.fineTuningCA = fineTuningCA;
        this.ledger = ledger;
        this._gasPrice = gasPrice;
        this._maxGasPrice = maxGasPrice;
        this._step = step;
    }
    async initialize() {
        let userAddress;
        try {
            userAddress = await this.signer.getAddress();
        }
        catch (error) {
            throwFormattedError(error);
        }
        const contract = new FineTuningServingContract(this.signer, this.fineTuningCA, userAddress, this._gasPrice, this._maxGasPrice, this._step);
        this.serviceProvider = new Provider(contract);
        this.modelProcessor = new ModelProcessor(contract, this.ledger, this.serviceProvider);
        this.serviceProcessor = new ServiceProcessor(contract, this.ledger, this.serviceProvider);
    }
    listService = async () => {
        try {
            return await this.serviceProcessor.listService();
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    getLockedTime = async () => {
        try {
            return await this.serviceProcessor.getLockTime();
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    getAccount = async (providerAddress) => {
        try {
            return await this.serviceProcessor.getAccount(providerAddress);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    getAccountWithDetail = async (providerAddress) => {
        try {
            return await this.serviceProcessor.getAccountWithDetail(providerAddress);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    acknowledgeProviderSigner = async (providerAddress, gasPrice) => {
        try {
            return await this.serviceProcessor.acknowledgeProviderSigner(providerAddress, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    listModel = () => {
        try {
            return this.modelProcessor.listModel();
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    modelUsage = (providerAddress, preTrainedModelName, output) => {
        try {
            return this.serviceProcessor.modelUsage(providerAddress, preTrainedModelName, output);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    uploadDataset = async (dataPath, gasPrice, maxGasPrice) => {
        try {
            await this.modelProcessor.uploadDataset(this.signer.privateKey, dataPath, gasPrice || this._gasPrice, maxGasPrice || this._maxGasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    downloadDataset = async (dataPath, dataRoot) => {
        try {
            await this.modelProcessor.downloadDataset(dataPath, dataRoot);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    calculateToken = async (datasetPath, preTrainedModelName, usePython, providerAddress) => {
        try {
            await this.modelProcessor.calculateToken(datasetPath, usePython, preTrainedModelName, providerAddress);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    createTask = async (providerAddress, preTrainedModelName, dataSize, datasetHash, trainingPath, gasPrice) => {
        try {
            return await this.serviceProcessor.createTask(providerAddress, preTrainedModelName, dataSize, datasetHash, trainingPath, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    cancelTask = async (providerAddress, taskID) => {
        try {
            return await this.serviceProcessor.cancelTask(providerAddress, taskID);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    listTask = async (providerAddress) => {
        try {
            return await this.serviceProcessor.listTask(providerAddress);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    getTask = async (providerAddress, taskID) => {
        try {
            const task = await this.serviceProcessor.getTask(providerAddress, taskID);
            return task;
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    getLog = async (providerAddress, taskID) => {
        try {
            return await this.serviceProcessor.getLog(providerAddress, taskID);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    acknowledgeModel = async (providerAddress, taskId, dataPath, gasPrice) => {
        try {
            return await this.modelProcessor.acknowledgeModel(providerAddress, taskId, dataPath, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
    decryptModel = async (providerAddress, taskId, encryptedModelPath, decryptedModelPath) => {
        try {
            return await this.modelProcessor.decryptModel(providerAddress, taskId, encryptedModelPath, decryptedModelPath);
        }
        catch (error) {
            throwFormattedError(error);
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
async function createFineTuningBroker(signer, contractAddress, ledger, gasPrice, maxGasPrice, step) {
    const broker = new FineTuningBroker(signer, contractAddress, ledger, gasPrice, maxGasPrice, step);
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
    serviceNames;
    constructor(metadata, cache, ledgerContract, inferenceContract, fineTuningContract, serviceNames) {
        this.metadata = metadata;
        this.ledgerContract = ledgerContract;
        this.inferenceContract = inferenceContract;
        this.fineTuningContract = fineTuningContract;
        this.cache = cache;
        this.serviceNames = serviceNames;
    }
    async getLedger() {
        try {
            const ledger = await this.ledgerContract.getLedger();
            return ledger;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getLedgerWithDetail() {
        try {
            const ledger = await this.ledgerContract.getLedger();
            const ledgerInfo = [
                ledger.totalBalance,
                ledger.totalBalance - ledger.availableBalance,
            ];
            // Get providers using the new getLedgerProviders method with service names
            const userAddress = this.ledgerContract.getUserAddress();
            const inferenceProviders = await this.ledgerContract.getLedgerProviders(userAddress, this.serviceNames.inference);
            const infers = await Promise.all(inferenceProviders.map(async (provider) => {
                const account = await this.inferenceContract.getAccount(provider);
                return [provider, account.balance, account.pendingRefund];
            }));
            if (typeof this.fineTuningContract == 'undefined' ||
                !this.serviceNames.fineTuning) {
                return { ledgerInfo, infers, fines: [] };
            }
            const fineTuningProviders = await this.ledgerContract.getLedgerProviders(userAddress, this.serviceNames.fineTuning);
            const fines = await Promise.all(fineTuningProviders.map(async (provider) => {
                const account = await this.fineTuningContract?.getAccount(provider);
                return [provider, account.balance, account.pendingRefund];
            }));
            return { ledgerInfo, infers, fines };
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async listLedger() {
        try {
            const ledgers = await this.ledgerContract.listLedger();
            return ledgers;
        }
        catch (error) {
            throwFormattedError(error);
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
            catch (error) { }
            // Use placeholders since Inference contract doesn't use these values
            const placeholderInfo = '';
            await this.ledgerContract.addLedger(this.a0giToNeuron(balance), placeholderInfo, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async deleteLedger(gasPrice) {
        try {
            await this.ledgerContract.deleteLedger(gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async depositFund(balance, gasPrice) {
        try {
            const amount = this.a0giToNeuron(balance).toString();
            await this.ledgerContract.depositFund(amount, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async refund(balance, gasPrice) {
        try {
            const amount = this.a0giToNeuron(balance).toString();
            await this.ledgerContract.refund(amount, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async transferFund(to, serviceTypeStr, balance, gasPrice) {
        try {
            const amount = balance.toString();
            // Map service type to service name
            const serviceName = serviceTypeStr === 'inference'
                ? this.serviceNames.inference
                : this.serviceNames.fineTuning;
            if (!serviceName) {
                throw new Error(`Service name not available for ${serviceTypeStr}`);
            }
            await this.ledgerContract.transferFund(to, serviceName, amount, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
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
                .filter((x) => x[1] - x[2] >= 0n)
                .map((x) => x[0]);
            // Map service type to service name
            const serviceName = serviceTypeStr === 'inference'
                ? this.serviceNames.inference
                : this.serviceNames.fineTuning;
            if (!serviceName) {
                throw new Error(`Service name not available for ${serviceTypeStr}`);
            }
            await this.ledgerContract.retrieveFund(providerAddresses, serviceName, gasPrice);
            if (serviceTypeStr == 'inference') {
                await this.cache.setItem(CACHE_KEYS.FIRST_ROUND, 'true', 10000000 * 60 * 1000, CacheValueTypeEnum.Other);
            }
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    // Method removed: createSettleSignerKey is no longer needed
    // since we're using placeholders in addLedger
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

const TIMEOUT_MS = 300_000;
class LedgerManagerContract {
    ledger;
    signer;
    _userAddress;
    _gasPrice;
    _maxGasPrice;
    _step;
    constructor(signer, contractAddress, userAddress, gasPrice, maxGasPrice, step) {
        this.ledger = LedgerManager__factory.connect(contractAddress, signer);
        this.signer = signer;
        this._userAddress = userAddress;
        this._gasPrice = gasPrice;
        this._maxGasPrice = maxGasPrice;
        this._step = step || 1.1;
    }
    async sendTx(name, txArgs, txOptions) {
        if (txOptions.gasPrice === undefined) {
            txOptions.gasPrice = (await this.signer.provider?.getFeeData())?.gasPrice;
            // Add a delay to avoid too frequent RPC calls
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        else {
            txOptions.gasPrice = BigInt(txOptions.gasPrice);
        }
        while (true) {
            try {
                console.log('sending tx with gas price', txOptions.gasPrice);
                const tx = await this.ledger.getFunction(name)(...txArgs, txOptions);
                console.log('tx hash:', tx.hash);
                const receipt = (await Promise.race([
                    tx.wait(),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('Get Receipt timeout')), TIMEOUT_MS)),
                ]));
                this.checkReceipt(receipt);
                break;
            }
            catch (error) {
                if (error.message ===
                    'Get Receipt timeout, try set higher gas price') {
                    const nonce = await this.signer.getNonce();
                    const pendingNonce = await this.signer.provider?.getTransactionCount(this._userAddress, 'pending');
                    if (pendingNonce !== undefined &&
                        pendingNonce - nonce > 5 &&
                        txOptions.nonce === undefined) {
                        console.warn(`Significant gap detected between pending nonce (${pendingNonce}) and current nonce (${nonce}). This may indicate skipped or missing transactions. Using the current confirmed nonce for the transaction.`);
                        txOptions.nonce = nonce;
                    }
                }
                if (this._maxGasPrice === undefined) {
                    throwFormattedError(error);
                }
                let errorMessage = '';
                if (error.message) {
                    errorMessage = error.message;
                }
                else if (error.info?.error?.message) {
                    errorMessage = error.info.error.message;
                }
                const shouldRetry = RETRY_ERROR_SUBSTRINGS.some((substr) => errorMessage.includes(substr));
                if (!shouldRetry) {
                    throwFormattedError(error);
                }
                console.log('Retrying transaction with higher gas price due to:', errorMessage);
                let currentGasPrice = txOptions.gasPrice;
                if (currentGasPrice >= this._maxGasPrice) {
                    throwFormattedError(error);
                }
                currentGasPrice =
                    (currentGasPrice * BigInt(this._step)) / BigInt(10);
                if (currentGasPrice > this._maxGasPrice) {
                    currentGasPrice = this._maxGasPrice;
                }
                txOptions.gasPrice = currentGasPrice;
            }
        }
    }
    async addLedger(balance, settleSignerEncryptedPrivateKey, gasPrice) {
        try {
            const txOptions = { value: balance };
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('addLedger', [settleSignerEncryptedPrivateKey], txOptions);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async listLedger(offset = 0, limit = 50) {
        try {
            const result = await this.ledger.getAllLedgers(offset, limit);
            return result.ledgers;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getLedger() {
        try {
            const user = this.getUserAddress();
            const ledger = await this.ledger.getLedger(user);
            return ledger;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getLedgerProviders(user, serviceName) {
        try {
            const providers = await this.ledger.getLedgerProviders(user, serviceName);
            return providers;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async getServiceInfo(serviceAddress) {
        try {
            const serviceInfo = await this.ledger.getServiceInfo(serviceAddress);
            return serviceInfo;
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async depositFund(balance, gasPrice) {
        try {
            const txOptions = { value: balance };
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('depositFund', [], txOptions);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async refund(amount, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('refund', [amount], txOptions);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async transferFund(provider, serviceName, amount, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('transferFund', [provider, serviceName, amount], txOptions);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async retrieveFund(providers, serviceName, gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('retrieveFund', [providers, serviceName], txOptions);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    async deleteLedger(gasPrice) {
        try {
            const txOptions = {};
            if (gasPrice || this._gasPrice) {
                txOptions.gasPrice = gasPrice || this._gasPrice;
            }
            await this.sendTx('deleteLedger', [], txOptions);
        }
        catch (error) {
            throwFormattedError(error);
        }
    }
    getUserAddress() {
        return this._userAddress;
    }
    checkReceipt(receipt) {
        if (!receipt) {
            throw new Error('Transaction failed with no receipt');
        }
        if (receipt.status !== 1) {
            throw new Error('Transaction reverted');
        }
    }
}

class LedgerBroker {
    ledger;
    signer;
    ledgerCA;
    inferenceCA;
    fineTuningCA;
    gasPrice;
    maxGasPrice;
    step;
    constructor(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice, maxGasPrice, step) {
        this.signer = signer;
        this.ledgerCA = ledgerCA;
        this.inferenceCA = inferenceCA;
        this.fineTuningCA = fineTuningCA;
        this.gasPrice = gasPrice;
        this.maxGasPrice = maxGasPrice;
        this.step = step;
    }
    async initialize() {
        let userAddress;
        try {
            userAddress = await this.signer.getAddress();
        }
        catch (error) {
            throwFormattedError(error);
        }
        const ledgerContract = new LedgerManagerContract(this.signer, this.ledgerCA, userAddress, this.gasPrice, this.maxGasPrice, this.step);
        const inferenceContract = new InferenceServingContract(this.signer, this.inferenceCA, userAddress);
        let fineTuningContract;
        if (this.signer instanceof Wallet) {
            fineTuningContract = new FineTuningServingContract(this.signer, this.fineTuningCA, userAddress);
        }
        // Get service names from contract using getServiceInfo
        const serviceNames = await this.getServiceNames(ledgerContract, this.inferenceCA, this.fineTuningCA);
        const metadata = new Metadata();
        const cache = new Cache();
        this.ledger = new LedgerProcessor(metadata, cache, ledgerContract, inferenceContract, fineTuningContract, serviceNames);
    }
    async getServiceNames(ledgerContract, inferenceCA, fineTuningCA) {
        try {
            // Get service info for inference contract
            const inferenceServiceInfo = await ledgerContract.getServiceInfo(inferenceCA);
            const inferenceServiceName = inferenceServiceInfo.fullName;
            // Get service info for fine-tuning contract if using Wallet
            let fineTuningServiceName;
            if (this.signer instanceof Wallet) {
                try {
                    const fineTuningServiceInfo = await ledgerContract.getServiceInfo(fineTuningCA);
                    fineTuningServiceName = fineTuningServiceInfo.fullName;
                }
                catch (error) {
                    // Fine-tuning service might not be registered
                    console.warn('Fine-tuning service not registered in LedgerManager');
                }
            }
            return {
                inference: inferenceServiceName,
                fineTuning: fineTuningServiceName,
            };
        }
        catch (error) {
            throwFormattedError(error);
        }
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
            throwFormattedError(error);
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
            return await this.ledger.getLedger();
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
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
     * @remarks The amount should be a positive number.
     */
    refund = async (amount, gasPrice) => {
        try {
            return await this.ledger.refund(amount, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
        }
    };
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
    transferFund = async (provider, serviceTypeStr, amount, gasPrice) => {
        try {
            return await this.ledger.transferFund(provider, serviceTypeStr, amount, gasPrice);
        }
        catch (error) {
            throwFormattedError(error);
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
            throwFormattedError(error);
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
            throwFormattedError(error);
        }
    };
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
async function createLedgerBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice, maxGasPrice, step) {
    const broker = new LedgerBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice, maxGasPrice, step);
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
async function createZGComputeNetworkBroker(signer, ledgerCA = '0x09D00A2B31067da09bf0e873E58746d1285174Cc', inferenceCA = '0x4f850eb2abc036096999882b54e92ecd63aec13d', fineTuningCA = '0x677AB02CA1DAffEf7521858d3264E4574BEf7aA7', gasPrice, maxGasPrice, step) {
    try {
        const ledger = await createLedgerBroker(signer, ledgerCA, inferenceCA, fineTuningCA, gasPrice, maxGasPrice, step);
        const inferenceBroker = await createInferenceBroker(signer, inferenceCA, ledger);
        let fineTuningBroker;
        if (signer instanceof Wallet) {
            fineTuningBroker = await createFineTuningBroker(signer, fineTuningCA, ledger, gasPrice, maxGasPrice, step);
        }
        const broker = new ZGComputeNetworkBroker(ledger, inferenceBroker, fineTuningBroker);
        return broker;
    }
    catch (error) {
        throw error;
    }
}

export { AccountProcessor as A, FineTuningBroker as F, InferenceBroker as I, LedgerBroker as L, ModelProcessor$1 as M, RequestProcessor as R, Verifier as V, ZGComputeNetworkBroker as Z, ResponseProcessor as a, createFineTuningBroker as b, createInferenceBroker as c, download as d, createLedgerBroker as e, createZGComputeNetworkBroker as f, isNode as g, isWebWorker as h, isBrowser as i, hasWebCrypto as j, getCryptoAdapter as k, upload as u };
//# sourceMappingURL=index-459ecd50.js.map

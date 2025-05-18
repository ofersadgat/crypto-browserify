'use strict';


// limit of Crypto.getRandomValues()
// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
const MAX_BYTES = 65536;

// Node supports requesting up to this number of bytes
// https://github.com/nodejs/node/blob/master/lib/internal/crypto/random.js#L48
const MAX_UINT32 = 4294967295;

const _global = typeof globalThis !== 'undefined' ? globalThis : global
const crypto = _global.crypto || _global.msCrypto

function randomBytes (size, cb) {
  // phantomjs needs to throw
  if (size > MAX_UINT32) throw new RangeError('requested too many random bytes')

  const bytes = new Uint8Array(size);

  if (size > 0) { // getRandomValues fails on IE if size == 0
    if (size > MAX_BYTES) { // this is the max bytes crypto.getRandomValues
      // can do at once see https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues
      for (let generated = 0; generated < size; generated += MAX_BYTES) {
        // buffer.slice automatically checks if the end is past the end of
        // the buffer so we don't have to here
        crypto.getRandomValues(bytes.slice(generated, generated + MAX_BYTES))
      }
    } else {
      crypto.getRandomValues(bytes)
    }
  }

  if (typeof cb === 'function') {
    return Promise.resolve().then(function () {
      cb(null, bytes)
    });
  }

  return bytes
}


// eslint-disable-next-line no-multi-assign
exports.randomBytes = exports.rng = exports.pseudoRandomBytes = exports.prng = randomBytes;

// eslint-disable-next-line no-multi-assign
exports.createHash = exports.Hash = require('create-hash');

// eslint-disable-next-line no-multi-assign
exports.createHmac = exports.Hmac = require('create-hmac');

var algos = require('browserify-sign/algos');
var algoKeys = Object.keys(algos);
var hashes = [
	'sha1',
	'sha224',
	'sha256',
	'sha384',
	'sha512',
	'md5',
	'rmd160'
].concat(algoKeys);

exports.getHashes = function () {
	return hashes;
};

var p = require('pbkdf2');
exports.pbkdf2 = p.pbkdf2;
exports.pbkdf2Sync = p.pbkdf2Sync;

var aes = require('browserify-cipher');

exports.Cipher = aes.Cipher;
exports.createCipher = aes.createCipher;
exports.Cipheriv = aes.Cipheriv;
exports.createCipheriv = aes.createCipheriv;
exports.Decipher = aes.Decipher;
exports.createDecipher = aes.createDecipher;
exports.Decipheriv = aes.Decipheriv;
exports.createDecipheriv = aes.createDecipheriv;
exports.getCiphers = aes.getCiphers;
exports.listCiphers = aes.listCiphers;

var dh = require('diffie-hellman');

exports.DiffieHellmanGroup = dh.DiffieHellmanGroup;
exports.createDiffieHellmanGroup = dh.createDiffieHellmanGroup;
exports.getDiffieHellman = dh.getDiffieHellman;
exports.createDiffieHellman = dh.createDiffieHellman;
exports.DiffieHellman = dh.DiffieHellman;

var sign = require('browserify-sign');

exports.createSign = sign.createSign;
exports.Sign = sign.Sign;
exports.createVerify = sign.createVerify;
exports.Verify = sign.Verify;

exports.createECDH = require('create-ecdh');

var publicEncrypt = require('public-encrypt');

exports.publicEncrypt = publicEncrypt.publicEncrypt;
exports.privateEncrypt = publicEncrypt.privateEncrypt;
exports.publicDecrypt = publicEncrypt.publicDecrypt;
exports.privateDecrypt = publicEncrypt.privateDecrypt;

// the least I can do is make error messages for the rest of the node.js/crypto api.
// [
//   'createCredentials'
// ].forEach(function (name) {
//   exports[name] = function () {
//     throw new Error('sorry, ' + name + ' is not implemented yet\nwe accept pull requests\nhttps://github.com/browserify/crypto-browserify');
//   };
// });

var kBufferMaxLength = safeBuffer.kMaxLength;
var kMaxUint32 = Math.pow(2, 32) - 1;
function assertOffset (offset, length) {
  if (typeof offset !== 'number' || offset !== offset) { // eslint-disable-line no-self-compare
    throw new TypeError('offset must be a number');
  }

  if (offset > kMaxUint32 || offset < 0) {
    throw new TypeError('offset must be a uint32');
  }

  if (offset > kBufferMaxLength || offset > length) {
    throw new RangeError('offset out of range');
  }
}

function assertSize (size, offset, length) {
  if (typeof size !== 'number' || size !== size) { // eslint-disable-line no-self-compare
    throw new TypeError('size must be a number');
  }

  if (size > kMaxUint32 || size < 0) {
    throw new TypeError('size must be a uint32');
  }

  if (size + offset > length || size > kBufferMaxLength) {
    throw new RangeError('buffer too small');
  }
}

function randomFill (buf, offset, size, cb) {
  if (!(buf instanceof global.Uint8Array)) {
    throw new TypeError('"buf" argument must be a Buffer or Uint8Array');
  }

  if (typeof offset === 'function') {
    cb = offset;
    offset = 0;
    size = buf.length;
  } else if (typeof size === 'function') {
    cb = size;
    size = buf.length - offset;
  } else if (typeof cb !== 'function') {
    throw new TypeError('"cb" argument must be a function');
  }
  assertOffset(offset, buf.length);
  assertSize(size, offset, buf.length);
  return actualFill(buf, offset, size, cb);
}

function actualFill (buf, offset, size, cb) {
  var ourBuf = buf.buffer;
  var uint = new Uint8Array(ourBuf, offset, size);
  crypto.getRandomValues(uint);
  if (cb) {
    Promise.resolve().then(function () {
      cb(null, buf)
    });
    return;
  }
  return buf;
}
function randomFillSync (buf, offset, size) {
  if (typeof offset === 'undefined') {
    offset = 0;
  }
  if (!(buf instanceof global.Uint8Array)) {
    throw new TypeError('"buf" argument must be a Buffer or Uint8Array');
  }

  assertOffset(offset, buf.length);

  if (size === undefined) {
    size = buf.length - offset;
  }

  assertSize(size, offset, buf.length);

  return actualFill(buf, offset, size);
}


exports.randomFill = randomFill;
exports.randomFillSync = randomFillSync;

exports.createCredentials = function () {
	throw new Error('sorry, createCredentials is not implemented yet\nwe accept pull requests\nhttps://github.com/browserify/crypto-browserify');
};

exports.constants = {
	DH_CHECK_P_NOT_SAFE_PRIME: 2,
	DH_CHECK_P_NOT_PRIME: 1,
	DH_UNABLE_TO_CHECK_GENERATOR: 4,
	DH_NOT_SUITABLE_GENERATOR: 8,
	NPN_ENABLED: 1,
	ALPN_ENABLED: 1,
	RSA_PKCS1_PADDING: 1,
	RSA_SSLV23_PADDING: 2,
	RSA_NO_PADDING: 3,
	RSA_PKCS1_OAEP_PADDING: 4,
	RSA_X931_PADDING: 5,
	RSA_PKCS1_PSS_PADDING: 6,
	POINT_CONVERSION_COMPRESSED: 2,
	POINT_CONVERSION_UNCOMPRESSED: 4,
	POINT_CONVERSION_HYBRID: 6
};

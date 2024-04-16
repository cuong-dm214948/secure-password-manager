"use strict";
const crypto = require('crypto');

var sjcl = require("./sjcl");

const { getRandomValues } = require('crypto');

/**
 * Converts a plaintext string into a buffer for use in SubtleCrypto functions.
 * @param {string} str - A plaintext string
 * @returns {Buffer} A buffer representation for use in SubtleCrypto functions
 */
function stringToBuffer(str) {
    return Buffer.from(str);
}

/**
 * Converts a buffer object representing string data back into a string
 * @param {BufferSource} buf - A buffer containing string data
 * @returns {string} The original string
 */
function bufferToString(buf) {
    return Buffer.from(buf).toString();
}

/**
 * Converts a buffer to a Base64 string which can be used as a key in a map and
 * can be easily serialized.
 * @param {BufferSource} buf - A buffer-like object
 * @returns {string} A Base64 string representing the bytes in the buffer
 */
function encodeBuffer(buf) {
    return Buffer.from(buf).toString('base64');
}

/**
 * Converts a Base64 string back into a buffer
 * @param {string} base64 - A Base64 string representing a buffer
 * @returns {Buffer} A Buffer object
 */
function decodeBuffer(base64) {
    return Buffer.from(base64, "base64")
}

/**
 * Generates a buffer of random bytes
 * @param {number} len - The number of random bytes
 * @returns {Uint8Array} A buffer of `len` random bytes
 */
function getRandomBytes(len) {
    return getRandomValues(new Uint8Array(len))
}

function KDF(password, salt) {
  return sjcl.misc.pbkdf2(password, salt, 100000);
  // Takes about a second on a commodity laptop.
};

function hmac_fuction(key, data) {
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(data);
  return hmac.digest('hex');
}

function setup_cipher(secret_key) {
  // Takes a secret key (for AES-128) and initializes SJCL's internal
  // cipher data structure.
  if (bitarray_len(secret_key) != 128) {
    throw "setup_cipher: only accepts keys for AES-128";
  }
  return new sjcl.cipher.aes(secret_key);
};

function enc_gcm(key, value) {
  // Generate a random initialization vector (IV)
  const iv = crypto.randomBytes(12); // 96 bits IV for GCM

  // Create a cipher instance with AES-GCM algorithm
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  // Encrypt the value
  let encrypted = cipher.update(value, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Get the authentication tag (GCM mode)
  const tag = cipher.getAuthTag();

  // Return the IV, encrypted value, and authentication tag
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted,
    tag: tag.toString('hex')
  };
}

async function dec_gcm(aesKey, encryptedData) {
    const { iv, encryptedData: ciphertext, tag } = encryptedData;

    // Convert hex strings to buffers
    const ivBuffer = Buffer.from(iv, 'hex');
    const ciphertextBuffer = Buffer.from(ciphertext, 'hex');
    const tagBuffer = Buffer.from(tag, 'hex');

    // Create decipher instance with AES-GCM algorithm
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuffer);

    // Set authentication tag (GCM mode)
    decipher.setAuthTag(tagBuffer);

    // Decrypt the ciphertext
    let decrypted = decipher.update(ciphertextBuffer, null, 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

function bitarray_slice(bitarray, a, b) {
  // Returns bits [a,...,b) (half-open interval)
  //   -- i.e., slice(01010001, 1, 4) = 101
  return sjcl.bitArray.bitSlice(bitarray, a, b);
};

function bitarray_to_string(bitarray) {
  return sjcl.codec.utf8String.fromBits(bitarray);
};

function string_to_bitarray(str) {
  return sjcl.codec.utf8String.toBits(str);
};

function bitarray_to_hex(bitarray) {
  return sjcl.codec.hex.fromBits(bitarray);
};

function hex_to_bitarray(hex_str) {
  return sjcl.codec.hex.toBits(hex_str);
};

function bitarray_to_base64(bitarray) {
  return sjcl.codec.base64.fromBits(bitarray);
};

function base64_to_bitarray(base64_str) {
  // Throws an exception if the string is not valid base64.
  return sjcl.codec.base64.toBits(base64_str);
};

function byte_array_to_hex(a) {
  var s = "";
  for (var i = 0; i < a.length; i++) {
    if (a[i] < 0 || a[i] >= 256) {
      throw "byte_array_to_hex: value outside byte range";
    }
    s += ((a[i]|0) + 256).toString(16).substr(1);
  }
  return s;
};

function hex_to_byte_array(s) {
  var a = [];
  if (s.length % 2 != 0) {
    throw "hex_to_byte_array: odd length";
  }
  for (var i = 0; i < s.length; i += 2) {
    a.push(parseInt(s.substr(i,2),16)|0);
  }
  return a;
};

// Internal: you should not need this function.
function word_to_bytes_acc(word, bytes) { 
  // word is a nonnegative integer, at most 2^31-1
  if (word < 0) {
    throw "word_to_bytes_acc: can't convert negative integer";
  }
  for (var i = 0; i < 4; i++) {
    bytes.push(word & 0xff);
    word = word >>> 8;
  }
};

// Internal: you should not need this function.
function word_from_bytes_sub(bytes, i_start) {
  if (!Array.isArray(bytes)) {
    console.log(bytes);
    console.trace();
    throw "word_from_bytes_sub: received non-array";
  }
  if (bytes.length < 4) {
    throw "word_from_bytes_sub: array too short";
  }
  var word = 0;
  for (var i = i_start + 3; i >= i_start; i--) {
    word <<= 8;
    word |= bytes[i];
  }
  return word;
};




////////////////////////////////////////////////////////////////////////////////
//  Conversions including padding
////////////////////////////////////////////////////////////////////////////////

function string_to_padded_byte_array(s_utf8, padded_len) {
  if (typeof(s_utf8) !== "string") {
    throw "to_padded_byte_array: received non-string";
  }
  var s = unescape(encodeURIComponent(s_utf8));
  var l = s.length;
  if (l > padded_len) {
    throw "to_padded_byte_array: string too long";
  }
  var bytes = [];
  word_to_bytes_acc(l, bytes);
  for (var i = 0; i < padded_len; i++) {
    // Note: in general, this kind of code may be vulnerable to timing attacks
    // (not considered in our threat model).  For our use case, these attacks
    // do not seem relevant (nor is it clear how one could mitigate them, since
    // the user will eventually manipulate passwords in memory in the clear).
    if (i < l) {
      bytes.push(s.charCodeAt(i));
    } else {
      bytes.push(0);
    }
  }
  return bytes;
};

function string_to_padded_bitarray(s_utf8, padded_len) {
  return sjcl.codec.hex.toBits(
    byte_array_to_hex(string_to_padded_byte_array(s_utf8, padded_len)));
};

function string_from_padded_byte_array(a, padded_len) {
  if (a.length != padded_len + 4) {
    throw "string_from_padded_byte_array: wrong length";
  }
  var l = word_from_bytes_sub(a, 0);
  var s = "";
  for (var i = 4; i < Math.min(4 + l, a.length); i++) {
    s += String.fromCharCode(a[i]);
  }
  var s_utf8 = decodeURIComponent(escape(s));
  return s_utf8;
};

function string_from_padded_bitarray(a, padded_len) {
  return string_from_padded_byte_array(
    hex_to_byte_array(sjcl.codec.hex.fromBits(a)), padded_len)
};




////////////////////////////////////////////////////////////////////////////////
//  Other utility functions
////////////////////////////////////////////////////////////////////////////////

function random_bitarray(len) {
  if (len % 32 != 0) {
    throw "random_bit_array: len not divisible by 32";
  }
  return sjcl.random.randomWords(len / 32, 0);
};

function bitarray_equal(a1, a2) {
  return sjcl.bitArray.equal(a1, a2);
};

function bitarray_len(a) {
  return sjcl.bitArray.bitLength(a);
};

function bitarray_concat(a1, a2) {
  return sjcl.bitArray.concat(a1, a2);
};

function dict_num_keys(d) {
  var c = 0;
  for (var k in d) {
    if (d.hasOwnProperty(k)) {
      ++c;
    }
  }
  return c;
};

module.exports.KDF = KDF,
module.exports.setup_cipher = setup_cipher,
module.exports.bitarray_slice = bitarray_slice,
module.exports.bitarray_to_string = bitarray_to_string,
module.exports.string_to_bitarray = string_to_bitarray,
module.exports.bitarray_to_hex = bitarray_to_hex,
module.exports.hex_to_bitarray = hex_to_bitarray,
module.exports.base64_to_bitarray = base64_to_bitarray,
module.exports.byte_array_to_hex = byte_array_to_hex,
module.exports.hex_to_byte_array = hex_to_byte_array,
module.exports.string_to_padded_byte_array = string_to_padded_byte_array,
module.exports.string_to_padded_bitarray = string_to_padded_bitarray,
module.exports.string_from_padded_byte_array = string_from_padded_byte_array,
module.exports.string_from_padded_bitarray = string_from_padded_bitarray,
module.exports.random_bitarray = random_bitarray,
module.exports.bitarray_equal = bitarray_equal,
module.exports.bitarray_len = bitarray_len,
module.exports.bitarray_concat = bitarray_concat,
module.exports.dict_num_keys = dict_num_keys;

module.exports = {
    hmac_fuction,
    bitarray_to_base64,
    enc_gcm,
    dec_gcm,
    stringToBuffer,
    bufferToString,
    encodeBuffer,
    decodeBuffer,
    getRandomBytes
}
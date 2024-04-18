"use strict";
const crypto = require('crypto');
const { subtle } = require('crypto').webcrypto;

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


async function enc_gcm(aesKey, keyName, value) {
  // Generate a random initialization vector (IV)
  let iv = getRandomBytes(32); // 96 bits IV for GCM

  let keyTag = await subtle.importKey("raw", keyName, {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);

  // Encrypt the value
  let encrypted = await subtle.encrypt({name: "AES-GCM", iv: iv}, aesKey, stringToBuffer(value))

  // Get the authentication tag (GCM mode)
  let tag = await subtle.sign("HMAC", keyTag, encrypted);

  // Return the IV, encrypted value, and authentication tag
  return {
    iv: iv,
    encryptedPwd: encrypted,
    tag: tag
  };
}


async function dec_gcm(hmacKey, aesKey, name, kvs) {
  let keyName = await subtle.sign("HMAC",hmacKey, stringToBuffer(name));

  let hmacKeyTag = await subtle.importKey("raw", keyName, {name: "HMAC", hash: "SHA-256"}, false, ["verify"]);

  let decrypted = null;
  keyName = encodeBuffer(keyName);
  if(kvs.hasOwnProperty(keyName)){
    let { iv, encryptedPwd, tag } = kvs[keyName];

    let VF = await subtle.verify("HMAC", hmacKeyTag, tag, encryptedPwd);
    
    if(VF === false) throw "Tampering is detected!";

    decrypted = await subtle.decrypt({name: "AES-GCM", iv: iv}, aesKey, encryptedPwd);

    decrypted = bufferToString(decrypted);
  }
  return decrypted;
}

module.exports = {
    enc_gcm,
    dec_gcm,
    stringToBuffer,
    bufferToString,
    encodeBuffer,
    decodeBuffer,
    getRandomBytes
}
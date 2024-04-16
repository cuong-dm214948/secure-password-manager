"use strict";
/********* External Imports ********/
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes,hmac_fuction,enc_gcm,bitarray_to_base64 } = require("./lib");
//library: SubtleCrypto. 
const { subtle } = require('crypto').webcrypto;
const { dec_gcm}= require("./lib");
const { version } = require("os");

/********* Constants ********/
const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

var ready =false;

class Keychain {
  constructor(aesKey,hmacKey) {
    this.data = { 
      

    };
    this.secrets = {
      aesKey:aesKey,
      hmacKey:hmacKey

    };
  };
  static async init(password) {
  

    let masterSalt = getRandomBytes(128);

    let rawKey = await subtle.importKey("raw", stringToBuffer(password),"PBKDF2", false, ["deriveKey"]);
    

    // Key for encrypting password
    let aesKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      rawKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // Key for verifying domain
    let hmacKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      rawKey,
      { name: "HMAC", hash: {name: "SHA-256"}, length: 256 },
      true,
      ["sign", "verify"]
    );
    return new Keychain(aesKey,hmacKey); 
  }

  
  static async load(password, repr, trusted_data_check) {
    // let a = await crypto.subtle.digest('SHA-256', stringToBuffer(repr));
    // // Check if the provided SHA256 checksum matches the trusted data check
    // if ( a !== trusted_data_check) {
    //     throw "SHA256 does not match!";
    // }
    
    // Initialize the keychain with the provided password
    keychain.init(password);
    
    // Parse the JSON representation of the keychain
    keychain = JSON.parse(repr);


    // Decrypt each key-value pair in the keychain
    for (var keys in keychain) {
        dec_gcm(priv.data.cipher, base64_to_bitarray(keychain[keys]));
    }  


    const [encoded_json_Keychain, expected_checksum] = repr;
    // Hash the serialized JSON string from repr
    const hashBuffer = await crypto.subtle.digest('SHA-256', stringToBuffer(repr));
    // Convert ArrayBuffer to Array
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // Convert bytes to base64 string
    const actual_checksum = bitarray_to_base64(hashArray);
    // Verify checksum to ensure data integrity
    // Parse the JSON string and create a new Keychain object

    const keychainData = JSON.parse(repr);

    const { aesKey, hmacKey } = keychainData.secrets;
    return new Keychain(aesKey, hmacKey);
  };
  
  async dump() {
    // Serialize the Keychain object
    let serializedKeychain = JSON.stringify({kvs:this.data});
    console.log(serializedKeychain)

    const hashBuffer = await crypto.subtle.digest('SHA-256', stringToBuffer(serializedKeychain));
    const checksum = encodeBuffer(hashBuffer);
    return [serializedKeychain, checksum];
  }

  async get(name) {

    const keyName1 = hmac_fuction(this.secrets.hmacKey, name);
    const encryptedData = this.data[keyName1];
    
    // If encryptedData is undefined (i.e., the password doesn't exist), return null
    if (!encryptedData) {
        return null;
    }
    const value = dec_gcm(this.secrets.aesKey, encryptedData);
    return value;
  }

  async set(name, value) {
      const keyName = hmac_fuction(this.secrets.hmacKey, name);
      const keyValue = enc_gcm(this.secrets.aesKey, value);
      this.data[keyName] = keyValue;
  }

  async remove(name) {
    const keyName = hmac_fuction(this.secrets.hmacKey, name);
    if (this.data.hasOwnProperty(keyName)) { // Check if the password exists before removal
        delete this.data[keyName];
        return true; // Return true if removal was successful
    } else {
        return false; // Return false if the password doesn't exist
    }
  }
};

module.exports = { Keychain }
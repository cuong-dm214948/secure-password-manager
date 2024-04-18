"use strict";
/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes, enc_gcm, dec_gcm} = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {

  ready = false;
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */

  constructor(kvs, masterSalt, hmacSalt, hmacKey_sig, hmacKey, aesSalt, aesKey_sig, aesKey) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      kvs: kvs,
      masterSalt: masterSalt,
      hmacSalt: hmacSalt,
      hmacKey_sig: hmacKey_sig,
      hmacKey: hmacKey,
      aesSalt: aesSalt,
      aesKey_sig: aesKey_sig,
      aesKey: aesKey
    };
    this.ready = true;
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {

    let rawKey = await subtle.importKey("raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);

    // Master key for load()
    let masterSalt = getRandomBytes(16);
    let masterKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );

    // AES-GCM key for password
    let aesSalt = getRandomBytes(16);
    let aesKey_sig = await subtle.sign("HMAC", masterKey, aesSalt)

    let aesKey = await subtle.importKey("raw", aesKey_sig, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );

    // HMAC key for domain name
    let hmacSalt = getRandomBytes(16);
    let hmacKey_sig = await subtle.sign("HMAC", masterKey, hmacSalt)
    let hmacKey = await subtle.importKey("raw", hmacKey_sig, { name: "HMAC", hash: { name: "SHA-256" }, length: 256 }, true, ["sign"]
    );
    let kvs ={};
    return new Keychain(kvs, masterSalt, hmacSalt, hmacKey_sig, hmacKey, aesSalt, aesKey_sig, aesKey);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    if(trustedDataCheck !== undefined){
      let checksum = await subtle.digest("SHA-256", stringToBuffer(repr));
      if(encodeBuffer(checksum) !== trustedDataCheck){
        throw "Tampering is detected!";
      }
    }

    

    let serializedKeychain = JSON.parse(repr);

    let masterSalt = decodeBuffer(serializedKeychain["masterSalt"]);
    let hmacSalt = decodeBuffer(serializedKeychain["hmacSalt"]);
    let hmacKey_sig = decodeBuffer(serializedKeychain["hmacKey_sig"]);
    let aesSalt = decodeBuffer(serializedKeychain["aesSalt"]);
    let aesKey_sig = decodeBuffer(serializedKeychain["aesKey_sig"]);

    // authentication
    let rawKey = await subtle.importKey("raw", stringToBuffer(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    let masterKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: masterSalt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      rawKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );

    let hmacVf = await subtle.verify("HMAC", masterKey, hmacKey_sig, hmacSalt)

    let aesVf = await subtle.verify("HMAC", masterKey, aesKey_sig, aesSalt);

    // For avoiding timing attack
    if(hmacVf !== true || aesVf !== true){
      throw "incorect password!";
    }

    let hmacKey = await subtle.importKey("raw", hmacKey_sig, { name: "HMAC", hash: "SHA-256" }, true, ["sign"]);

    let aesKey = await subtle.importKey("raw", aesKey_sig, {name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"]);
    
    let kvs = {}
    for(const [keyName, value] of Object.entries(serializedKeychain["kvs"])){
      kvs[keyName] = {
        iv: decodeBuffer(value["iv"]),
        encryptedPwd: decodeBuffer(value["encryptedPwd"]),
        tag: decodeBuffer(value["tag"])
      };      
    }
    
    return new Keychain(kvs, masterSalt, hmacSalt, hmacKey_sig, hmacKey, aesSalt, aesKey_sig, aesKey);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    if(this.ready === false) throw "Keychain not initialized.";

    let serializedKeychain = this.secrets;
    const keysToEncode = ["masterSalt", "hmacSalt", "hmacKey_sig", "aesSalt", "aesKey_sig"];

    for (const key of keysToEncode) {
        serializedKeychain[key] = encodeBuffer(serializedKeychain[key]);
    }
    serializedKeychain["hmacKey"] = encodeBuffer(await subtle.exportKey("raw", serializedKeychain["hmacKey"]));
    serializedKeychain["aesKey"] = encodeBuffer(await subtle.exportKey("raw", serializedKeychain["aesKey"]));
    
    for(const [keyName, value] of Object.entries(serializedKeychain["kvs"])){
      serializedKeychain["kvs"][keyName] = {
        iv: encodeBuffer(value.iv),
        encryptedPwd: encodeBuffer(value.encryptedPwd),
        tag: encodeBuffer(value.tag)
      };  
    }

    serializedKeychain = JSON.stringify(serializedKeychain);
    let checksum = await subtle.digest("SHA-256", stringToBuffer(serializedKeychain));
    checksum = encodeBuffer(checksum);

    return [serializedKeychain, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    //return with decryption AES-GCM algorithm
    let plaintext = dec_gcm(this.secrets.hmacKey, this.secrets.aesKey, name, this.secrets.kvs)
    
    return plaintext;
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if(this.ready === false) throw "Keychain not initialized.";

    // key for domain name
    let keyName = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));

    // Encrypt the value and get the authentication tag with encryption AES-GCM algorithsm
    let { iv, encryptedPwd, tag } = await enc_gcm(this.secrets.aesKey, keyName, value);
  
    // Store the encrypted value along with the IV and tag
    this.secrets.kvs[encodeBuffer(keyName)] = { iv, encryptedPwd, tag };
  
  };


  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if(this.ready === false) throw "Keychain not initialized.";

    let keyName = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    keyName = encodeBuffer(keyName);

    // Remove the entry from KVS
    if(this.secrets.kvs.hasOwnProperty(keyName)){
      delete this.secrets.kvs[keyName];
      return true;
    }

    return false;
  };
};

module.exports = { Keychain }
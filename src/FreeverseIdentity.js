// Copyright (c) 2021 Freeverse.io <dev@freeverse.io>
// Library for creating and managing indentities that can hold assets.
// Account creation and derivation follows Crypto-JS
// Account export follows AES Standard to encrypt/decrypt private keys.

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// 'Software'), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

const Accounts = require('web3-eth-accounts').default;
const CryptoJS = require('crypto-js').default;
const EthCrypto = require('eth-crypto');

// Use a an AES-Standard KDF (Key Derivation Function) to generate (IV, key) from (password, salt)
// This is a standard step that makes brute-force attacks much harder
const applyKDF = (password, salt) => {
  const keyBytes = CryptoJS.PBKDF2(password, salt, { keySize: 48 / 4, iterations: 1000 });
  // take first 32 bytes as key
  const key = CryptoJS.lib.WordArray.create(keyBytes.words, 32);
  // skip first 32 bytes and take next 16 bytes as IV
  const iv = CryptoJS.lib.WordArray.create(keyBytes.words.splice(32 / 4), 16);
  return {
    key,
    iv,
  };
};

// Returns a Web3 Account with a brand new pair (privateKey/user_id)
// capable of signing on behalf of privateKey
const createNewAccount = () => new Accounts().create();

// Returns a Web3 Account from a given privateKey,
// capable of signing on behalf of privateKey
const accountFromPrivateKey = (privKey) => {
  try {
    return new Accounts().privateKeyToAccount(privKey);
  } catch {
    throw new Error('Private Key does not have correct format');
  }
};

/**
 * Returns the public freeverseID corresponding to the provided private key.
 * The freeverseID can be shared. The Private key should never leave the user's control.
 * @deprecated since version 1.0.7
 */
const freeverseIdFromPrivateKey = (privKey) => {
  const account = accountFromPrivateKey(privKey);
  return account.address;
};

/**
 * Returns the public freeverseID corresponding to the provided private key.
 * The freeverseID can be shared. The Private key should never leave the user's control.
 */
const web3AddressFromPrivateKey = (privKey) => {
  const account = accountFromPrivateKey(privKey);
  return account.address;
};

// Generates an Encrypted Identity, which is the concat of:
// - salt (32b)
// - the encryption of hte provided private key using the provided user password
// The encryption the AES standard with an AES recommended KDF.
// The user should store the Encrypted Identity in a safe place,
// an attacker would need access to it as well as knowledge of the user-entered password.
const encryptIdentity = (pvk, password) => {
  const salt = CryptoJS.lib.WordArray.random(16);
  // generate (IV, key) from an AES-secure Key Derivation Function
  const kdf = applyKDF(password, salt);
  const pvkNoTrail = (pvk.slice(0, 2) === '0x') ? pvk.slice(2) : pvk;
  const pvkWords = CryptoJS.enc.Hex.parse(pvkNoTrail);
  const encrypted = CryptoJS.AES.encrypt(pvkWords, kdf.key, { iv: kdf.iv });
  return salt.concat(encrypted.ciphertext).toString(CryptoJS.enc.Hex);
};

// Decryption of an encrypted private key, given a user-entered password, following AES standard.
const decryptIdentity = (encryptedIdentity, password) => {
  // An encrypted Identity is a hex-formatted string, which is the concat of:
  // ...salt (32bit)
  const salt = CryptoJS.enc.Hex.parse(encryptedIdentity.slice(0, 32));
  // ..and encrypted private key
  const cipherText = CryptoJS.enc.Hex.parse(encryptedIdentity.slice(32));

  // generate (IV, key) from an AES-secure Key Derivation Function, and decrypt
  const kdf = applyKDF(password, salt);
  const plaintextArray = CryptoJS.AES.decrypt(
    {
      ciphertext: cipherText,
      salt: '',
    },
    kdf.key,
    {
      iv: kdf.iv,
    },
  );
  const privKey = `0x${plaintextArray.toString(CryptoJS.enc.Hex)}`;

  // Before returning, check that a valid account can be generated from this privKey
  // Otherwise: throw.
  try {
    web3AddressFromPrivateKey(privKey);
  } catch {
    throw new Error('The Encrypted ID and Password entered do not match');
  }
  return privKey;
};

// encrypts a string so that it can only be decrypted
// by the owner of the privKey that corresponds to the publicKey
const encryptWithPublicKey = async (textToEncrypt, publicKey) => {
  // obtaining an object with the encrypted data
  const encryptedObject = await EthCrypto.encryptWithPublicKey(
    publicKey,
    textToEncrypt,
  );
  // converting the encrypted object into a encrypted String
  const encryptedString = EthCrypto.cipher.stringify(encryptedObject);
  return encryptedString;
};

// decrypts a string that was encrypted for a given publicKey
const decryptWithPrivateKey = async (encryptedString, privateKey) => {
  // converting the encypted String into an encrypted object
  const encryptedObject = EthCrypto.cipher.parse(encryptedString);
  // decrypt the en encrypted object with the private key
  const decrypted = await EthCrypto.decryptWithPrivateKey(
    privateKey,
    encryptedObject,
  );
  return decrypted;
};

const publicKeyFromPrivateKey = (privKey) => EthCrypto.publicKeyByPrivateKey(privKey);

module.exports = {
  freeverseIdFromPrivateKey,
  web3AddressFromPrivateKey,
  encryptIdentity,
  decryptIdentity,
  createNewAccount,
  accountFromPrivateKey,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  publicKeyFromPrivateKey,
};

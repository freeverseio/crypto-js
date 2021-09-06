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

/* eslint class-methods-use-this: 0 */
const CryptoJS = require('crypto-js');

// Use a an AES-Standard KDF (Key Derivation Function) to generate (IV, key) from (password, salt)
// This is a standard step that makes brute-force attacks much harder
function applyKDF(password, salt) {
  const keyBytes = CryptoJS.PBKDF2(password, salt, { keySize: 48 / 4, iterations: 1000 });
  // take first 32 bytes as key
  const key = CryptoJS.lib.WordArray.create(keyBytes.words, 32);
  // skip first 32 bytes and take next 16 bytes as IV
  const iv = CryptoJS.lib.WordArray.create(keyBytes.words.splice(32 / 4), 16);
  return {
    key,
    iv,
  };
}

/* MAIN CLASS */

class FreeverseIdentity {
  constructor(web3) {
    this.web3 = web3;
  }

  // Returns the public freeverseID corresponding to the provided private key.
  // The freeverseID can be shared. The Private key should never leave the user's control.
  FreeverseIdFromPrivateKey(privKey) {
    const account = this.AccountFromPrivateKey(privKey);
    return account.address;
  }

  // Generates an Encrypted Identity, which is the concat of:
  // - salt (32b)
  // - the encryption of hte provided private key using the provided user password
  // The encryption the AES standard with an AES recommended KDF.
  // The user should store the Encrypted Identity in a safe place,
  // an attacker would need access to it as well as knowledge of the user-entered password.
  EncryptIdentity(pvk, password) {
    const salt = CryptoJS.lib.WordArray.random(16);
    // generate (IV, key) from an AES-secure Key Derivation Function
    const kdf = applyKDF(password, salt);
    const pvkNoTrail = (pvk.slice(0, 2) === '0x') ? pvk.slice(2) : pvk;
    const pvkWords = CryptoJS.enc.Hex.parse(pvkNoTrail);
    const encrypted = CryptoJS.AES.encrypt(pvkWords, kdf.key, { iv: kdf.iv });
    return salt.concat(encrypted.ciphertext).toString(CryptoJS.enc.Hex);
  }

  // Decryption of an encrypted private key, given a user-entered password, following AES standard.
  DecryptIdentity(encryptedIdentity, password) {
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
      this.FreeverseIdFromPrivateKey(privKey);
    } catch {
      throw new Error('The Encrypted ID and Password entered do not match');
    }
    return privKey;
  }

  // Returns a Web3 Account with a brand new pair (privateKey/user_id)
  // capable of signing on behalf of privateKey
  CreateNewAccount() {
    return this.web3.eth.accounts.create();
  }

  // Returns a Web3 Account from a given privateKey,
  // capable of signing on behalf of privateKey
  AccountFromPrivateKey(privKey) {
    try {
      return this.web3.eth.accounts.privateKeyToAccount(privKey);
    } catch {
      throw new Error('Private Key does not have correct format');
    }
  }
}

module.exports = {
  FreeverseIdentity,
};

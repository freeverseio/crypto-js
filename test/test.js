const { assert } = require('chai');
const fs = require('fs');
const {
  freeverseIdFromPrivateKey,
  encryptIdentity,
  decryptIdentity,
  createNewAccount,
  accountFromPrivateKey,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  publicKeyFromPrivateKey,
} = require('../dist/main');

it('check decryption given encryptedID and user password', async () => {
  const tests = JSON.parse(fs.readFileSync('test/groundtruth.json', 'utf8'));
  tests.forEach((test) => {
    const decrypted = decryptIdentity(test.encryptedIdentity, test.userPassword);
    assert.equal(decrypted, test.privateKey);
  });
});

it('check obtention of freeverseId from private key', async () => {
  const tests = JSON.parse(fs.readFileSync('test/groundtruth.json', 'utf8'));
  tests.forEach((test) => {
    assert.equal(freeverseIdFromPrivateKey(test.privateKey), test.freeverseId);
  });
});

it('check generation of web3 accounts from privated key', async () => {
  // obtention of web3 accounts from private keys is only needed
  // by clients who need to sign with the private key
  const tests = JSON.parse(fs.readFileSync('test/groundtruth.json', 'utf8'));
  tests.forEach((test) => {
    const web3Account = accountFromPrivateKey(test.privateKey);
    assert.equal(web3Account.address, test.freeverseId);
    assert.equal(web3Account.privateKey, test.privateKey);
  });
});

it('check round trip encrypt + decrypt', async () => {
  const tests = JSON.parse(fs.readFileSync('test/groundtruth.json', 'utf8'));
  tests.forEach((test) => {
    const encrypted = encryptIdentity(test.privateKey, test.userPassword);
    const decrypted = decryptIdentity(encrypted, test.userPassword);
    assert.equal(decrypted, test.privateKey);
  });
});

it('check round trip encrypt + decrypt with brand new created web3 accounts', async () => {
  const acc = createNewAccount();
  freeverseIdFromPrivateKey(acc.privateKey);
  const password = 'P@ssw0rd';
  const encrypted = encryptIdentity(acc.privateKey, password);
  const decrypted = decryptIdentity(encrypted, password);
  assert.equal(decrypted, acc.privateKey);
});

it('check that encrypt produces different data every time, even for equal passwords', async () => {
  const acc = createNewAccount();
  const privKey = acc.privateKey;
  const userPassword = '1234';
  assert.notEqual(
    encryptIdentity(privKey, userPassword), encryptIdentity(privKey, userPassword),
  );
  assert.notEqual(
    encryptIdentity(privKey, userPassword), encryptIdentity(privKey, userPassword),
  );
});

it('check createNewAccount produces different private keys every time', async () => {
  const acc1 = createNewAccount();
  const acc2 = createNewAccount();
  assert.notEqual(acc1.privateKey, acc2.privateKey);
});

it('check decryptIdentity throws on wrong pair encryptedID - userPassword', async () => {
  const encrypted = '90b595e366140bb786ba5204fd5c7c7fe1302cba698492183f2c6c62149b0f90e18106f0b3014f2e7bb5d70f6210447ead622043f58b39a11480b123e8d3a3ab';
  const wrongUserPassword = 'P@ssw0rd1';
  assert.throws(() => decryptIdentity(encrypted, wrongUserPassword), 'The Encrypted ID and Password entered do not match');
  const userPassword = 'P@ssw0rd';
  decryptIdentity(encrypted, userPassword);
});

it('check error message provided on invalid private key', async () => {
  assert.throws(() => accountFromPrivateKey('123213123'), 'Private Key does not have correct format');
  assert.throws(() => freeverseIdFromPrivateKey('123213123'), 'Private Key does not have correct format');
});

it('Alice encrypts for a given pubKey by owned by Bob, who decrypts with the corresponding privKey', async () => {
  const bobPrivKey = '0x56450b9e335eb41b0c90454285001f793e7bac2b2c94c353c392b38a2292e7d0';
  const bobPubKey = publicKeyFromPrivateKey(bobPrivKey);

  // Alice wants to transmit this msg to Bob:
  const jsonObject = { email: 'test@freeverse.io', id: '0x4EB5DDc866e57029e5aDa56130083cfF1e388a33' };
  // Alice sends this string:
  const encryptedStr = await encryptWithPublicKey(JSON.stringify(jsonObject), bobPubKey);
  // Bob decrypts using his privKey
  const decryptedStr = await decryptWithPrivateKey(encryptedStr, bobPrivKey);
  const decryptedJson = JSON.parse(decryptedStr);
  assert.deepEqual(decryptedJson, jsonObject);
});

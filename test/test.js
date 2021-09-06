const { assert } = require('chai');
const fs = require('fs');
const {
  FreeverseIdFromPrivateKey,
  EncryptIdentity,
  DecryptIdentity,
  CreateNewAccount,
  AccountFromPrivateKey,
} = require('../src/FreeverseIdentity');

it('check decryption given encryptedID and user password', async () => {
  const tests = JSON.parse(fs.readFileSync('test/groundtruth.json', 'utf8'));
  tests.forEach((test) => {
    const decrypted = DecryptIdentity(test.encryptedIdentity, test.userPassword);
    assert.equal(decrypted, test.privateKey);
  });
});

it('check obtention of freeverseId from private key', async () => {
  const tests = JSON.parse(fs.readFileSync('test/groundtruth.json', 'utf8'));
  tests.forEach((test) => {
    assert.equal(FreeverseIdFromPrivateKey(test.privateKey), test.freeverseId);
  });
});

it('check generation of web3 accounts from privated key', async () => {
  // obtention of web3 accounts from private keys is only needed
  // by clients who need to sign with the private key
  const tests = JSON.parse(fs.readFileSync('test/groundtruth.json', 'utf8'));
  tests.forEach((test) => {
    const web3Account = AccountFromPrivateKey(test.privateKey);
    assert.equal(web3Account.address, test.freeverseId);
    assert.equal(web3Account.privateKey, test.privateKey);
  });
});

it('check round trip encrypt + decrypt', async () => {
  const tests = JSON.parse(fs.readFileSync('test/groundtruth.json', 'utf8'));
  tests.forEach((test) => {
    const encrypted = EncryptIdentity(test.privateKey, test.userPassword);
    const decrypted = DecryptIdentity(encrypted, test.userPassword);
    assert.equal(decrypted, test.privateKey);
  });
});

it('check round trip encrypt + decrypt with brand new created web3 accounts', async () => {
  const acc = CreateNewAccount();
  FreeverseIdFromPrivateKey(acc.privateKey);
  const password = 'P@ssw0rd';
  const encrypted = EncryptIdentity(acc.privateKey, password);
  const decrypted = DecryptIdentity(encrypted, password);
  assert.equal(decrypted, acc.privateKey);
});

it('check that encrypt produces different data every time, even for equal passwords', async () => {
  const acc = CreateNewAccount();
  const privKey = acc.privateKey;
  const userPassword = '1234';
  assert.notEqual(
    EncryptIdentity(privKey, userPassword), EncryptIdentity(privKey, userPassword),
  );
  assert.notEqual(
    EncryptIdentity(privKey, userPassword), EncryptIdentity(privKey, userPassword),
  );
});

it('check CreateNewAccount produces different private keys every time', async () => {
  const acc1 = CreateNewAccount();
  const acc2 = CreateNewAccount();
  assert.notEqual(acc1.privateKey, acc2.privateKey);
});

it('check DecryptIdentity throws on wrong pair encryptedID - userPassword', async () => {
  const encrypted = '90b595e366140bb786ba5204fd5c7c7fe1302cba698492183f2c6c62149b0f90e18106f0b3014f2e7bb5d70f6210447ead622043f58b39a11480b123e8d3a3ab';
  const wrongUserPassword = 'P@ssw0rd1';
  assert.throws(() => DecryptIdentity(encrypted, wrongUserPassword), 'The Encrypted ID and Password entered do not match');
  const userPassword = 'P@ssw0rd';
  DecryptIdentity(encrypted, userPassword);
});

it('check error message provided on invalid private key', async () => {
  assert.throws(() => AccountFromPrivateKey('123213123'), 'Private Key does not have correct format');
  assert.throws(() => FreeverseIdFromPrivateKey('123213123'), 'Private Key does not have correct format');
});

import { expect } from 'chai';
import { keyStore } from '../../src/key-store';
import { BitHash } from '../../src/bip32/bit-hash';
import * as ethUtil from 'ethereumjs-util';
import { utils as ethersUtils } from 'ethers';

const testData = require('../resources/test-data.json');

describe('Key Store', () => {
  it('IsValid DAG address', async () => {
    const result = keyStore.validateDagAddress(testData.DAG_ADDRESS);
    expect(result).to.equal(true);
  });

  it('IsInvalid DAG address', async () => {
    //Empty
    const result = keyStore.validateDagAddress('');
    expect(result).to.equal(false);

    //Bad length
    const result0 = keyStore.validateDagAddress('DAG2itmeekZLUS4vxCDhe9safyE6wFQ94EaczotNn');
    expect(result0).to.equal(false);

    //Bad prefix
    const result1 = keyStore.validateDagAddress('DOG2itmeekZLUS4vxCDhe9safyE6wFQ94EaczotN');
    expect(result1).to.equal(false);

    //Bad Parity
    const result2 = keyStore.validateDagAddress('DAGJitmeekZLUS4vxCDhe9safyE6wFQ94EaczotN');
    expect(result2).to.equal(false);

    //Bad Base58 Match
    const result3 = keyStore.validateDagAddress('DAG20itmeekZLUS4vxCDhe9safyE6wFQ94EaczotN');
    expect(result3).to.equal(false);
  });

  it('Public key from Private', () => {
    const result = keyStore.getPublicKeyFromPrivate(testData.PRIVATE_KEY);
    expect(result).to.equal(testData.PUBLIC_KEY);
  });

  it('Compact Public key from Private', () => {
    const result = keyStore.getPublicKeyFromPrivate(testData.PRIVATE_KEY, true);
    expect(result).to.equal(testData.COMPACT_PUBLIC_KEY);
  });

  it('DAG address from Public', () => {
    const result = keyStore.getDagAddressFromPublicKey(testData.PUBLIC_KEY);
    expect(result).to.equal(testData.DAG_ADDRESS);
  });

  it('Private Key from Mnemonic Seed Phrase', () => {
    const result = keyStore.getPrivateKeyFromMnemonic(testData.SEED_PHRASE);
    expect(result).to.equal(testData.SEED_PRIVATE_KEY);
  });

  it('Error-Check: Fee is less than 0', async () => {
    const keyTrio = { privateKey: testData.PRIVATE_KEY, publicKey: testData.PUBLIC_KEY, address: '1' };
    let tx;
    try {
      tx = await keyStore.generateTransaction(1, '2', keyTrio, null, -1);
    } catch (e) {
      expect(e.message).to.equal('KeyStore :: Send fee must be greater or equal to zero');
      return;
    }

    expect(tx).to.equal(undefined);
  });

  it('Error-Check: Amount is less than 0', async () => {
    const keyTrio = { privateKey: testData.PRIVATE_KEY, publicKey: testData.PUBLIC_KEY, address: '1' };
    const lastRef = { prevHash: 'abc123', ordinal: 1 };
    let tx;
    try {
      tx = await keyStore.generateTransaction(1e-9, '2', keyTrio, lastRef);
    } catch (e) {
      expect(e.message).to.equal('KeyStore :: Send amount must be greater than 1e-8');
      return;
    }

    expect(tx).to.equal(undefined);
  });

  it('ETH address from Public', () => {
    const result = ethFromPublicKey(testData.PUBLIC_KEY);
    const result2 = getAddressFromPublicKey(testData.PUBLIC_KEY.slice(2));

    console.log(result, result2);

    expect(result).to.equal(testData.ETH_ADDRESS);
  });

  it('BTC address from Public', () => {
    const result = btcFromPublicKey(testData.COMPACT_PUBLIC_KEY);
    expect(result).to.equal(testData.BTC_ADDRESS);
  });
});

const bs58 = require('bs58');

// Replace Hash.keccak256 with ethers.utils.keccak256
const toChecksum = (address) => {
  const addressHash = ethersUtils.keccak256(address.slice(2));
  let checksumAddress = '0x';
  for (let i = 0; i < 40; i++) {
    checksumAddress += parseInt(addressHash[i + 2], 16) > 7
      ? address[i + 2].toUpperCase()
      : address[i + 2];
  }
  return checksumAddress;
};

function ethFromPublicKey(publicKey) {
  publicKey = '0x' + publicKey.slice(2);
  const publicHash = ethersUtils.keccak256(publicKey);
  const address = toChecksum('0x' + publicHash.slice(-40));
  return address;
}

function getAddressFromPublicKey(publicKey) {
  const address = '0x' + ethUtil.publicToAddress(Buffer.from(publicKey, 'hex')).toString('hex');
  return ethUtil.toChecksumAddress(address);
}

function btcFromPublicKey(publicKey) {
  let base = '00' + BitHash.hash160(Buffer.from(publicKey, 'hex')).toString('hex');
  const shaSha = BitHash.dblHash256(Buffer.from(base, 'hex')).toString('hex');
  const result = base + shaSha.substring(0, 8);
  return bs58.encode(Buffer.from(result, 'hex'));
}

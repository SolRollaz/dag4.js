import { Buffer } from 'buffer';
import * as bs58 from 'bs58';
import * as jsSha256 from "js-sha256";
import { KeyringAssetType, KeyringNetwork } from '../kcs';
import { EcdsaAccount } from './ecdsa-account';
const BASE58_ALPHABET = /['123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+/;
const PKCS_PREFIX = '3056301006072a8648ce3d020106052b8104000a034200';
export class DagAccount extends EcdsaAccount {
    constructor() {
        super(...arguments);
        this.decimals = 8;
        this.network = KeyringNetwork.Constellation;
        this.hasTokenSupport = false;
        this.supportedAssets = [KeyringAssetType.DAG];
        this.tokens = null; //dagAssetLibrary.getDefaultAssets();
    }
    signTransaction(tx) {
    }
    validateAddress(address) {
        if (!address)
            return false;
        const validLen = address.length === 40;
        const validPrefix = address.substr(0, 3) === 'DAG';
        const par = Number(address.charAt(3));
        const validParity = par >= 0 && par < 10;
        const match = BASE58_ALPHABET.exec(address.substring(4));
        const validBase58 = match && match.length > 0 && match[0].length === 36;
        return validLen && validPrefix && validParity && validBase58;
    }
    getAddress() {
        return this.getAddressFromPublicKey(this.getPublicKey());
    }
    verifyMessage(msg, signature, saysAddress) {
        const publicKey = this.recoverSignedMsgPublicKey(msg, signature);
        const actualAddress = this.getAddressFromPublicKey(publicKey);
        return saysAddress === actualAddress;
    }
    sha256(hash) {
        return jsSha256.sha256(hash);
    }
    getAddressFromPublicKey(publicKeyHex) {
        //PKCS standard requires a prefix '04' for an uncompressed Public Key
        // An uncompressed public key is a 64-byte number; in hex this gives a string length of 128
        // Check to see if prefix is missing
        if (publicKeyHex.length === 128) {
            publicKeyHex = '04' + publicKeyHex;
        }
        publicKeyHex = PKCS_PREFIX + publicKeyHex;
        const sha256Str = this.sha256(Buffer.from(publicKeyHex, 'hex'));
        const bytes = Buffer.from(sha256Str, 'hex');
        const hash = bs58.encode(bytes);
        let end = hash.slice(hash.length - 36, hash.length);
        let sum = end.split('').reduce((val, char) => (isNaN(char) ? val : val + (+char)), 0);
        let par = sum % 9;
        return ('DAG' + par + end);
    }
}
//# sourceMappingURL=dag-account.js.map
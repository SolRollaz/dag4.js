"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LedgerBridge = void 0;
// max length in bytes.
const dag4_1 = require("@stardust-collective/dag4");
const txHashEncodeUtil = __importStar(require("./lib/tx-hash-encode"));
const txTranscodeUtil = __importStar(require("./lib/tx-transcode"));
const MAX_SIGNED_TX_LEN = 512;
const DEVICE_ID = '8004000000';
class LedgerBridge {
    transport;
    constructor(transport) {
        this.transport = transport;
    }
    async buildTx(amount, publicKey, bip44Index, fromAddress, toAddress) {
        const lastRef = await dag4_1.dag4.network.loadBalancerApi.getAddressLastAcceptedTransactionRef(fromAddress);
        const { tx, rle } = dag4_1.dag4.keyStore.prepareTx(amount, toAddress, fromAddress, lastRef, 0);
        const hash = tx.edge.signedObservationEdge.signatureBatch.hash;
        //console.log('rle', rle);
        //console.log('hash', hash);
        const hashReference = txHashEncodeUtil.encodeTxHash(tx, true);
        //tx.edge.observationEdge.data.hashReference = hashReference;
        //console.log('hashReference');
        //console.log(tx.edge.observationEdge.data.hashReference);
        //console.log(hashReference);
        //console.log('amount', tx.edge.data.amount);
        const ledgerEncodedTx = txTranscodeUtil.encodeTx(tx, false, false);
        //console.log(ledgerEncodedTx);
        const signature = await this.signTransaction(publicKey, bip44Index, hash, ledgerEncodedTx);
        const signatureElt = {};
        signatureElt.signature = signature;
        signatureElt.id = {};
        signatureElt.id.hex = publicKey.substring(2); //Remove 04 prefix
        tx.edge.signedObservationEdge.signatureBatch.signatures.push(signatureElt);
        return tx;
    }
    /**
     * Returns a signed transaction ready to be posted to the network.
     */
    async signTransaction(publicKey, bip44Index, hash, ledgerEncodedTx) {
        const results = await this.sign(ledgerEncodedTx, bip44Index);
        //console.log('signTransaction\n' + results.signature);
        //const success = dag4.keyStore.verify(publicKey, hash, results.signature);
        //console.log('verify: ', success);
        return results.signature;
    }
    /**
     * Takes a signed transaction and posts it to the network.
     */
    postTransaction() { }
    async getAccountInfoForPublicKeys(ledgerAccounts) {
        if (ledgerAccounts.length > 0) {
            let responseArray = [];
            for (let i = 0; i < ledgerAccounts.length; i++) {
                const publicKey = ledgerAccounts[i].publicKey;
                dag4_1.dag4.account.loginPublicKey(publicKey);
                const address = dag4_1.dag4.account.address;
                console.log('public', publicKey, address);
                const balance = (await dag4_1.dag4.account.getBalance() || 0);
                const response = {
                    address,
                    publicKey,
                    balance: balance
                };
                responseArray.push(response);
            }
            return responseArray;
        }
        else {
            throw new Error('No accounts found');
        }
    }
    async getPublicKeys(startIndex = 0, numberOfAccounts = 8, progressUpdateCallback) {
        if (!this.transport) {
            throw new Error('Error: A transport must be set via the constructor before calling this method');
        }
        if (isNaN(numberOfAccounts) || numberOfAccounts < 1 || Math.floor(numberOfAccounts) !== numberOfAccounts) {
            throw new Error('Error: Number of accounts must be an integer greater than zero');
        }
        const device = await this.getLedgerInfo();
        const maxIndex = startIndex + numberOfAccounts;
        let results = [];
        // Get the public key for each account
        for (let i = startIndex; i < maxIndex; i++) {
            const bip44Path = this.createBipPathFromAccount(i);
            const result = await this.sendExchangeMessage(bip44Path, device);
            results.push(result);
            if (progressUpdateCallback) {
                progressUpdateCallback((i - startIndex + 1) / numberOfAccounts);
            }
        }
        return results;
    }
    async sign(ledgerEncodedTx, bip44Index) {
        const bip44Path = this.createBipPathFromAccount(bip44Index);
        //console.log('bip44Path', bip44Path);
        const transactionByteLength = Math.ceil(ledgerEncodedTx.length / 2);
        if (transactionByteLength > MAX_SIGNED_TX_LEN) {
            throw new Error(`Transaction length of ${transactionByteLength} bytes exceeds max length of ${MAX_SIGNED_TX_LEN} bytes.`);
        }
        const ledgerMessage = ledgerEncodedTx + bip44Path;
        const messages = this.splitMessageIntoChunks(ledgerMessage);
        const device = await this.getLedgerInfo();
        let lastResponse = undefined;
        // console.log('splitMessageIntoChunks', messages);
        for (let ix = 0; ix < messages.length; ix++) {
            const request = messages[ix];
            const message = Buffer.from(request, 'hex');
            const response = await device.exchange(message);
            const responseStr = response.toString('hex').toUpperCase();
            // console.log('exchange', 'request', request);
            // console.log('exchange', 'response', responseStr);
            lastResponse = responseStr;
        }
        let signature = '';
        let success = false;
        let message = lastResponse;
        if (lastResponse !== undefined) {
            if (lastResponse.endsWith('9000')) {
                signature = this.decodeSignature(lastResponse);
                success = true;
            }
            else {
                if (lastResponse == '6985') {
                    message += ' Tx Denied on Ledger';
                }
                if (lastResponse == '6D08') {
                    message += ' Tx Too Large for Ledger';
                }
                if (lastResponse == '6D06') {
                    message += ' Tx Decoding Buffer Underflow';
                }
            }
        }
        return {
            success,
            message,
            signature,
        };
    }
    createBipPathFromAccount(index) {
        const childIndex = index.toString(16).padStart(8, '0');
        // console.log('createBipPathFromAccount', index, childIndex);
        //`m/44'/1137'/0'/0/${index}`
        const bip44Path = '8000002C' +
            '80000471' +
            '80000000' +
            '00000000' +
            childIndex;
        return bip44Path;
    }
    async getLedgerInfo() {
        const supported = await this.transport.isSupported();
        if (!supported) {
            throw new Error('Your computer does not support the ledger device.');
        }
        const paths = await this.transport.list();
        if (paths.length === 0) {
            throw new Error('No USB device found.');
        }
        else {
            return this.transport.open(paths[0]);
        }
    }
    sendExchangeMessage(bip44Path, device) {
        return new Promise((resolve, reject) => {
            const message = Buffer.from(DEVICE_ID + bip44Path, 'hex');
            device.exchange(message).then((response) => {
                const responseStr = response.toString('hex').toUpperCase();
                let success = false;
                let message = '';
                let publicKey = '';
                if (responseStr.endsWith('9000')) {
                    success = true;
                    message = responseStr;
                    publicKey = responseStr.substring(0, 130);
                }
                else {
                    if (responseStr == '6E01') {
                        message = '6E01 App Not Open On Ledger Device';
                        throw new Error(message);
                    }
                    else {
                        message = responseStr + ' Unknown Error';
                    }
                }
                resolve({
                    success: success,
                    message: message,
                    publicKey: publicKey,
                });
            }).catch((error) => {
                reject({
                    success: false,
                    message: error.message,
                });
            });
        });
    }
    splitMessageIntoChunks(ledgerMessage) {
        const messages = [];
        const bufferSize = 255 * 2;
        let offset = 0;
        while (offset < ledgerMessage.length) {
            let chunk;
            let p1;
            if ((ledgerMessage.length - offset) > bufferSize) {
                chunk = ledgerMessage.substring(offset, offset + bufferSize);
            }
            else {
                chunk = ledgerMessage.substring(offset);
            }
            if ((offset + chunk.length) == ledgerMessage.length) {
                p1 = '80';
            }
            else {
                p1 = '00';
            }
            const chunkLength = chunk.length / 2;
            let chunkLengthHex = chunkLength.toString(16);
            while (chunkLengthHex.length < 2) {
                chunkLengthHex = '0' + chunkLengthHex;
            }
            messages.push('8002' + p1 + '00' + chunkLengthHex + chunk);
            offset += chunk.length;
        }
        return messages;
    }
    decodeSignature(response) {
        const rLenHex = response.substring(6, 8);
        const rLen = parseInt(rLenHex, 16) * 2;
        const rStart = 8;
        const rEnd = rStart + rLen;
        const sLenHex = response.substring(rEnd + 2, rEnd + 4);
        const sLen = parseInt(sLenHex, 16) * 2;
        const sStart = rEnd + 4;
        const sEnd = sStart + sLen;
        return response.substring(0, sEnd);
    }
}
exports.LedgerBridge = LedgerBridge;
//# sourceMappingURL=index.js.map
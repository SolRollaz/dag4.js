"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Encryptor = void 0;
const buffer_1 = require("buffer");
if (typeof window === 'undefined') {
    global['crypto'] = require('crypto').webcrypto;
}
class Encryptor {
    static create() {
        return new Encryptor();
    }
    encrypt(password, data) {
        const salt = this.generateSalt();
        return this.keyFromPassword(password, salt)
            .then((passwordDerivedKey) => {
            return this.encryptWithKey(passwordDerivedKey, data);
        })
            .then((payload) => {
            payload.salt = salt;
            return JSON.stringify(payload);
        });
    }
    decrypt(password, text) {
        const payload = typeof (text) === 'string' ? JSON.parse(text) : text;
        const salt = payload.salt;
        return this.keyFromPassword(password, salt)
            .then((key) => {
            return this.decryptWithKey(key, payload);
        });
    }
    encryptWithKey(key, data) {
        const text = JSON.stringify(data);
        const dataBuffer = buffer_1.Buffer.from(text, 'utf8');
        const vector = crypto.getRandomValues(new Uint8Array(16));
        return crypto.subtle.encrypt({
            name: 'AES-GCM',
            iv: vector,
        }, key, dataBuffer).then(function (buf) {
            const buffer = new Uint8Array(buf);
            const vectorStr = buffer_1.Buffer.from(vector).toString('hex');
            const vaultStr = buffer_1.Buffer.from(buffer).toString('hex');
            return {
                data: vaultStr,
                iv: vectorStr
            };
        });
    }
    decryptWithKey(key, payload) {
        const encryptedData = buffer_1.Buffer.from(payload.data, 'hex');
        const vector = buffer_1.Buffer.from(payload.iv, 'hex');
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: vector }, key, encryptedData)
            .then((result) => {
            const decryptedData = new Uint8Array(result);
            const decryptedStr = buffer_1.Buffer.from(decryptedData).toString('utf8');
            return JSON.parse(decryptedStr);
        })
            .catch((reason) => {
            throw new Error('Incorrect password');
        });
    }
    keyFromPassword(password, salt) {
        const passBuffer = buffer_1.Buffer.from(password, 'utf8');
        const saltBuffer = buffer_1.Buffer.from(salt, 'hex');
        return crypto.subtle.importKey('raw', passBuffer, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']).then((key) => {
            return crypto.subtle.deriveKey({
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: 10000,
                hash: 'SHA-256',
            }, key, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        });
    }
    serializeBufferFromStorage(str) {
        var stripStr = (str.slice(0, 2) === '0x') ? str.slice(2) : str;
        var buf = new Uint8Array(stripStr.length / 2);
        for (let i = 0; i < stripStr.length; i += 2) {
            var seg = stripStr.substr(i, 2);
            buf[i / 2] = parseInt(seg, 16);
        }
        return buf;
    }
    serializeBufferForStorage(buffer) {
        var result = '0x';
        var len = buffer.length || buffer.byteLength;
        for (let i = 0; i < len; i++) {
            result += this.unprefixedHex(buffer[i]);
        }
        return result;
    }
    unprefixedHex(num) {
        let hex = num.toString(16);
        while (hex.length < 2) {
            hex = '0' + hex;
        }
        return hex;
    }
    generateSalt(byteCount = 32) {
        const view = new Uint8Array(byteCount);
        crypto.getRandomValues(view);
        return buffer_1.Buffer.from(view).toString('hex');
    }
}
exports.Encryptor = Encryptor;
//# sourceMappingURL=encryptor.js.map
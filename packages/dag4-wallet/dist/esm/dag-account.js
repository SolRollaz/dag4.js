import { keyStore, KeyTrio } from '@stardust-collective/dag4-keystore';
import { DAG_DECIMALS } from '@stardust-collective/dag4-core';
import { globalDagNetwork, DagNetwork } from '@stardust-collective/dag4-network';
import { BigNumber } from 'bignumber.js';
import { Subject } from 'rxjs';
export class DagAccount {
    constructor() {
        this.sessionChange$ = new Subject();
        this.network = globalDagNetwork;
    }
    connect(networkInfo) {
        this.network = new DagNetwork(networkInfo);
        return this;
    }
    get address() {
        const address = this.m_keyTrio && this.m_keyTrio.address;
        if (!address) {
            throw new Error('Need to login before calling methods on dag4.account');
        }
        return address;
    }
    get keyTrio() {
        return this.m_keyTrio;
    }
    loginSeedPhrase(words) {
        const privateKey = keyStore.getPrivateKeyFromMnemonic(words);
        this.loginPrivateKey(privateKey);
    }
    loginPrivateKey(privateKey) {
        const publicKey = keyStore.getPublicKeyFromPrivate(privateKey);
        const address = keyStore.getDagAddressFromPublicKey(publicKey);
        this.setKeysAndAddress(privateKey, publicKey, address);
    }
    loginPublicKey(publicKey) {
        const address = keyStore.getDagAddressFromPublicKey(publicKey);
        this.setKeysAndAddress('', publicKey, address);
    }
    isActive() {
        return !!this.m_keyTrio;
    }
    logout() {
        this.m_keyTrio = null;
        this.sessionChange$.next(true);
    }
    observeSessionChange() {
        return this.sessionChange$;
    }
    setKeysAndAddress(privateKey, publicKey, address) {
        this.m_keyTrio = new KeyTrio(privateKey, publicKey, address);
        this.sessionChange$.next(true);
    }
    getTransactions(limit, searchAfter) {
        return this.network.blockExplorerApi.getTransactionsByAddress(this.address, limit, searchAfter);
    }
    validateDagAddress(address) {
        return keyStore.validateDagAddress(address);
    }
    async getBalance() {
        return this.getBalanceFor(this.address);
    }
    async getBalanceFor(address) {
        const addressObj = await this.network.getAddressBalance(address);
        if (addressObj && !isNaN(addressObj.balance)) {
            return new BigNumber(addressObj.balance).dividedBy(DAG_DECIMALS).toNumber();
        }
        return undefined;
    }
    async getFeeRecommendation() {
        //Get last tx ref
        const lastRef = (await this.network.getAddressLastAcceptedTransactionRef(this.address));
        const hash = lastRef.prevHash || lastRef.hash; // v1 vs v2 format
        if (!hash) {
            return 0;
        }
        //Check for pending TX
        const lastTx = await this.network.getPendingTransaction(hash);
        if (!lastTx) {
            return 0;
        }
        return 1 / DAG_DECIMALS;
    }
    async generateSignedTransaction(toAddress, amount, fee = 0, lastRef) {
        lastRef = lastRef ? lastRef : await this.network.getAddressLastAcceptedTransactionRef(this.address);
        if (this.network.getNetworkVersion() === '2.0') {
            return keyStore.generateTransactionV2(amount, toAddress, this.keyTrio, lastRef, fee);
        }
        return keyStore.generateTransaction(amount, toAddress, this.keyTrio, lastRef, fee);
    }
    async transferDag(toAddress, amount, fee = 0, autoEstimateFee = false) {
        let normalizedAmount = Math.floor(new BigNumber(amount).multipliedBy(DAG_DECIMALS).toNumber());
        const lastRef = await this.network.getAddressLastAcceptedTransactionRef(this.address);
        if (fee === 0 && autoEstimateFee) {
            const tx = await this.network.getPendingTransaction(lastRef.prevHash || lastRef.hash);
            if (tx) {
                const addressObj = await this.network.getAddressBalance(this.address);
                //Check to see if sending max amount
                if (addressObj.balance === normalizedAmount) {
                    amount -= DAG_DECIMALS;
                    normalizedAmount--;
                }
                fee = DAG_DECIMALS;
            }
        }
        const tx = await this.generateSignedTransaction(toAddress, amount, fee);
        const txHash = await this.network.postTransaction(tx);
        if (txHash) {
            return { timestamp: Date.now(), hash: txHash, amount: normalizedAmount, receiver: toAddress, fee, sender: this.address, ordinal: lastRef.ordinal, pending: true, status: 'POSTED' };
        }
    }
    async waitForCheckPointAccepted(hash) {
        let attempts = 0;
        for (let i = 1;; i++) {
            const result = await this.network.loadBalancerApi.checkTransactionStatus(hash);
            if (result) {
                if (result.accepted) {
                    break;
                }
            }
            else {
                attempts++;
                if (attempts > 20) {
                    throw new Error('Unable to find transaction');
                }
            }
            await this.wait(2.5);
        }
        return true;
    }
    async waitForBalanceChange(initialValue) {
        if (initialValue === undefined) {
            initialValue = await this.getBalance();
            await this.wait(5);
        }
        let changed = false;
        //Run for a max of 2 minutes (5 * 24 times)
        for (let i = 1; i < 24; i++) {
            const result = await this.getBalance();
            if (result !== undefined) {
                if (result !== initialValue) {
                    changed = true;
                    break;
                }
            }
            await this.wait(5);
        }
        return changed;
    }
    wait(time = 5) {
        return new Promise(resolve => setTimeout(resolve, time * 1000));
    }
    transferDagBatch(transfers) {
    }
}
//# sourceMappingURL=dag-account.js.map
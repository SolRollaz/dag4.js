import { RestApi } from '@stardust-collective/dag4-core';
import { DNC } from '../../DNC';
export class L1Api {
    constructor(host) {
        this.service = new RestApi(DNC.L1_URL);
        if (host) {
            this.config().baseUrl(host);
        }
    }
    config() {
        return this.service.configure();
    }
    async getMetrics() {
        // TODO: add parsing for v2 response... returns 404
        return this.service.$get('/metric');
    }
    async getAddressLastAcceptedTransactionRef(address) {
        return this.service.$get(`/transactions/last-reference/${address}`);
    }
    async postTransaction(tx) {
        return this.service.$post('/transactions', tx);
    }
    async getClusterInfo() {
        return this.service.$get('/cluster/info').then(info => this.processClusterInfo(info));
    }
    async getClusterInfoWithRetry() {
        return this.service.$get('/cluster/info', null, { retry: 5 }).then(info => this.retryClusterInfo(info));
    }
    retryClusterInfo(info) {
        if (info && info.map) {
            return this.processClusterInfo(info);
        }
        else {
            return new Promise(resolve => {
                setTimeout(() => {
                    resolve(this.getClusterInfoWithRetry());
                }, 1000);
            });
        }
    }
    processClusterInfo(info) {
        return info && info.map && info.map(d => ({ alias: d.alias, walletId: d.id.hex, ip: d.ip.host, status: d.status, reputation: d.reputation }));
    }
}
export const l1Api = new L1Api();
//# sourceMappingURL=l1-api.js.map
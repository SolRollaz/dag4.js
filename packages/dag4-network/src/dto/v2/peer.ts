export enum PeerNodeState {
  Ready = 'Ready',
  Offline = 'Offline',
  DownloadInProgress = 'DownloadInProgress',
  PendingDownload = 'PendingDownload'
}

export type ClusterPeerInfo = {
  ip: string;
  alias: string;
  status: PeerNodeState;
  walletId: string;
  reputation: number;
}

export type ClusterInfo = {
  "alias": string,
  "id": {
    "hex": string
  },
  "ip": {
    "host": string,
    "port": number //9001
  },
  "status": PeerNodeState,
  "reputation": number
}
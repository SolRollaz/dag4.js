export declare class PeerMetrics {
    walletId: string;
    latency: number;
    pending?: boolean;
    nodeState: PeerNodeState;
    nodeStartTime: number;
    peers: string[];
    externalHost: string;
    TPS_all: number;
    TPS_last_10_seconds: number;
    version: string;
    nextSnapshotHeight: number;
    address: string;
    majorityHeight: number;
    balancesBySnapshot: string;
    snapshotAttempt_failure: number;
    rewardsBalance: number;
    addressBalance: number;
    alias: string;
    static createAsPending(host: string, status: PeerNodeState): PeerMetrics;
    static parse(rawMetrics: PeerMetricsRawData, latency: number): PeerMetrics;
    private static parsePeers;
}
export declare type PeerMetricsRawData = {
    alias: string;
    nodeState: string;
    nodeStartTimeAgo: string;
    nodeStartTime: string;
    peers: string;
    externalHost: string;
    TPS_all: number;
    TPS_last_10_seconds: string;
    version: string;
    nextSnapshotHeight: string;
    address: string;
    snapshotAttempt_failure: number;
    notConnected: boolean;
    cluster_ownJoinedHeight: number;
    totalNumCBsInShapshots: number;
    resolveMajorityCheckpointBlockUniquesCount_2: number;
    checkpointTipsRemoved: number;
    redownload_maxCreatedSnapshotHeight: number;
    peerApiRXFinishedCheckpoint: number;
    consensus_participateInRound: number;
    nodeStartTimeMS: number;
    transactionAccepted: number;
    snapshotAttempt_heightIntervalNotMet: number;
    acceptMajorityCheckpointBlockUniquesCount_1: number;
    resolveMajorityCheckpointBlockProposalCount_3: number;
    peerAddedFromRegistrationFlow: number;
    rewards_snapshotReward: number;
    rewards_snapshotRewardWithoutStardust: number;
    trustDataPollingRound: number;
    blacklistedAddressesSize: number;
    rewards_stardustBalanceAfterReward: number;
    consensus_participateInRound_invalidNodeStateError: number;
    deadPeer: string;
    acceptedCBCacheMatchesAcceptedSize: boolean;
    awaitingForAcceptance: number;
    snapshotHeightIntervalConditionMet: number;
    writeSnapshot_success: number;
    snapshotWriteToDisk_success: number;
    channelCount: number;
    observationService_unknown_size: number;
    addressCount: number;
    snapshotAttempt_success: number;
    id: string;
    transactionService_accepted_size: number;
    checkpointsAcceptedWithDummyTxs: number;
    allowedForAcceptance: number;
    rewards_selfBalanceAfterReward: number;
    snapshotCount: number;
    observationService_inConsensus_size: number;
    addPeerWithRegistrationSymmetric_success: number;
    balancesBySnapshot: string;
    rewards_lastRewardedHeight: number;
    redownload_lastSentHeight: number;
    minTipHeight: number;
    consensus_startOwnRound_consensusError: number;
    checkpointTipsIncremented: number;
    consensus_startOwnRound: number;
    consensus_startOwnRound_noPeersForConsensusError: number;
    checkpointValidationSuccess: number;
    redownload_maxAcceptedSnapshotHeight: number;
    redownload_lastMajorityStateHeight: number;
    consensus_startOwnRound_unknownError: number;
    acceptedCBSinceSnapshot: number;
    checkpointAccepted: number;
    acceptMajorityCheckpointBlockSelectedCount_3: number;
    transactionAcceptedFromRedownload: number;
    badPeerAdditionAttempt: number;
    consensus_startOwnRound_consensusStartError: number;
    rewards_selfSnapshotReward: number;
    metricsRound: number;
    rewards_snapshotCount: number;
    reDownloadFinished_total: number;
    syncBufferSize: number;
    lastSnapshotHeight: number;
    observationService_accepted_size: number;
    observationService_pending_size: number;
    transactionService_pending_size: number;
    rewards_stardustSnapshotReward: number;
    snapshotHeightIntervalConditionNotMet: number;
    checkpointAcceptBlockAlreadyStored: number;
    activeTips: number;
    transactionService_inConsensus_size: number;
};
export declare enum PeerNodeState {
    Ready = "Ready",
    Offline = "Offline",
    DownloadInProgress = "DownloadInProgress",
    PendingDownload = "PendingDownload"
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @title EpochAnchor: append-only registry of AGW epoch roots (Phase 6, ADR-0028).
/// @notice One recorder = one tenant hash chain. recorderId = SHA-256(TAG("AGW/recorder/v1") ||
///         u16(len(tenant)) || tenant || deployment_salt): no tenant names, no payloads, no
///         agent or tool identifiers ever reach the chain. Only the registered submitter of a
///         recorder may anchor, epochs are write-once and strictly contiguous from 0, and the
///         seq ranges they cover must tile (first_seq(t) = last_seq(t-1) + 1).
/// @dev    No proxy, no upgrade, no delete, no selfdestruct. The owner can only register
///         recorders and rotate a recorder's submitter, both visible as events.
///         Anchoring proves a root existed by a block; it does NOT prove that the events behind
///         it were truthful, authorized, complete or semantically correct.
contract EpochAnchor {
    struct Anchor {
        bytes32 root; // R_t (06 §7): commits to tenant, epoch_no, tree_size, seq range, M_t, R_{t-1}
        uint64 treeSize; // number of events in the epoch
        uint64 lastSeq; // last chain seq covered by the epoch
        uint64 timestamp; // block.timestamp at anchoring (informational)
        uint64 blockNumber; // block.number at anchoring (packs into the same slot)
    }

    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable owner; // public getter name is part of the ABI

    mapping(bytes32 recorderId => address submitter) public submitterOf;
    /// Number of anchored epochs = the next epoch number this recorder must anchor.
    mapping(bytes32 recorderId => uint64 nextEpochNo) public nextEpoch;
    mapping(bytes32 recorderId => mapping(uint64 epochNo => Anchor)) private _anchors;

    event RecorderRegistered(bytes32 indexed recorderId, address indexed submitter);
    event SubmitterRotated(bytes32 indexed recorderId, address indexed oldSubmitter, address indexed newSubmitter);
    event Anchored(bytes32 indexed recorderId, uint64 indexed epochNo, bytes32 root, uint64 treeSize, uint64 lastSeq);

    error NotOwner();
    error NotSubmitter();
    error ZeroRecorder();
    error ZeroSubmitter();
    error AlreadyRegistered();
    error UnknownRecorder();
    error EpochOutOfOrder(uint64 expected, uint64 got);
    error ZeroRoot();
    error EmptyEpoch();
    error SeqNotTiled(uint256 expectedFirstSeq, uint256 gotFirstSeq);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function registerRecorder(bytes32 recorderId, address submitter) external onlyOwner {
        if (recorderId == bytes32(0)) revert ZeroRecorder();
        if (submitter == address(0)) revert ZeroSubmitter();
        if (submitterOf[recorderId] != address(0)) revert AlreadyRegistered();
        submitterOf[recorderId] = submitter;
        emit RecorderRegistered(recorderId, submitter);
    }

    function rotateSubmitter(bytes32 recorderId, address newSubmitter) external onlyOwner {
        address old = submitterOf[recorderId];
        if (old == address(0)) revert UnknownRecorder();
        if (newSubmitter == address(0)) revert ZeroSubmitter();
        submitterOf[recorderId] = newSubmitter;
        emit SubmitterRotated(recorderId, old, newSubmitter);
    }

    /// @notice Anchor epoch `epochNo` of `recorderId`. Reverts unless the caller is the
    ///         recorder's submitter, epochNo is exactly the next epoch (no gap, no overwrite,
    ///         no replay), root is non-zero, the epoch is non-empty and its seq range starts
    ///         right after the previous epoch's.
    function anchor(bytes32 recorderId, uint64 epochNo, bytes32 root, uint64 treeSize, uint64 lastSeq) external {
        if (msg.sender != submitterOf[recorderId]) revert NotSubmitter();
        uint64 expected = nextEpoch[recorderId];
        if (epochNo != expected) revert EpochOutOfOrder(expected, epochNo);
        if (root == bytes32(0)) revert ZeroRoot();
        if (treeSize == 0 || treeSize > uint256(lastSeq) + 1) revert EmptyEpoch();
        // uint256 arithmetic: treeSize <= lastSeq + 1 was checked, so no underflow; a
        // previous lastSeq of 2^64-1 makes every next epoch fail the tiling check.
        uint256 firstSeq = uint256(lastSeq) + 1 - treeSize;
        uint256 expectedFirst = epochNo == 0 ? 0 : uint256(_anchors[recorderId][epochNo - 1].lastSeq) + 1;
        if (firstSeq != expectedFirst) revert SeqNotTiled(expectedFirst, firstSeq);
        _anchors[recorderId][epochNo] =
            Anchor(root, treeSize, lastSeq, uint64(block.timestamp), uint64(block.number));
        nextEpoch[recorderId] = expected + 1;
        emit Anchored(recorderId, epochNo, root, treeSize, lastSeq);
    }

    /// @notice The anchor of `epochNo` (all zero if not anchored).
    function getAnchor(bytes32 recorderId, uint64 epochNo)
        external
        view
        returns (bytes32 root, uint64 treeSize, uint64 lastSeq, uint64 timestamp, uint64 blockNumber)
    {
        Anchor storage a = _anchors[recorderId][epochNo];
        return (a.root, a.treeSize, a.lastSeq, a.timestamp, a.blockNumber);
    }

    /// @notice The last anchored epoch (the prompt's `lastEpoch`); exists = false before the
    ///         first anchor, because epochs are numbered from 0.
    function lastEpoch(bytes32 recorderId) external view returns (bool exists, uint64 epochNo) {
        uint64 n = nextEpoch[recorderId];
        return n == 0 ? (false, 0) : (true, n - 1);
    }
}

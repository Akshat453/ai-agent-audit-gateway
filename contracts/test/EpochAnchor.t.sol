// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {EpochAnchor} from "../src/EpochAnchor.sol";
import {TestBase} from "./Vm.sol";

/// Phase 6 contract invariants: write-once, contiguous epochs, seq tiling, only the
/// registered submitter, owner-only registration/rotation, recorder isolation.
contract EpochAnchorTest is TestBase {
    EpochAnchor internal reg;
    address internal constant OWNER = address(0xA11CE);
    address internal constant SUBMITTER = address(0x5B);
    address internal constant MALLORY = address(0xBAD);
    bytes32 internal constant REC = keccak256("recorder-a");
    bytes32 internal constant REC_B = keccak256("recorder-b");

    event RecorderRegistered(bytes32 indexed recorderId, address indexed submitter);
    event SubmitterRotated(bytes32 indexed recorderId, address indexed oldSubmitter, address indexed newSubmitter);
    event Anchored(bytes32 indexed recorderId, uint64 indexed epochNo, bytes32 root, uint64 treeSize, uint64 lastSeq);

    function setUp() public {
        vm.prank(OWNER);
        reg = new EpochAnchor();
        vm.prank(OWNER);
        reg.registerRecorder(REC, SUBMITTER);
    }

    function _anchor(uint64 epochNo, bytes32 root, uint64 treeSize, uint64 lastSeq) internal {
        vm.prank(SUBMITTER);
        reg.anchor(REC, epochNo, root, treeSize, lastSeq);
    }

    // ------------------------------------------------------------------ happy path
    function test_anchor_sequence_and_views() public {
        (bool exists,) = reg.lastEpoch(REC);
        assertTrue(!exists, "no epoch before the first anchor");
        vm.roll(100);
        vm.warp(1_800_000_000);
        vm.expectEmit(true, true, false, true);
        emit Anchored(REC, 0, bytes32(uint256(1)), 1, 0);
        _anchor(0, bytes32(uint256(1)), 1, 0);
        _anchor(1, bytes32(uint256(2)), 5, 5);
        _anchor(2, bytes32(uint256(3)), 8, 13);
        (bytes32 root, uint64 size, uint64 last, uint64 ts, uint64 bn) = reg.getAnchor(REC, 1);
        assertEq(root, bytes32(uint256(2)), "root");
        assertEq(size, 5, "treeSize");
        assertEq(last, 5, "lastSeq");
        assertEq(ts, 1_800_000_000, "timestamp");
        assertEq(bn, 100, "blockNumber");
        uint64 n;
        (exists, n) = reg.lastEpoch(REC);
        assertTrue(exists, "exists");
        assertEq(n, 2, "lastEpoch");
        assertEq(reg.nextEpoch(REC), 3, "nextEpoch");
        (root,,,,) = reg.getAnchor(REC, 3);
        assertEq(root, bytes32(0), "unanchored epoch reads as zero");
    }

    // ------------------------------------------------------------------ required reverts
    function test_overwrite_reverts() public {
        _anchor(0, bytes32(uint256(1)), 1, 0);
        vm.prank(SUBMITTER);
        vm.expectRevert(abi.encodeWithSelector(EpochAnchor.EpochOutOfOrder.selector, uint64(1), uint64(0)));
        reg.anchor(REC, 0, bytes32(uint256(0xEE)), 1, 0);
        (bytes32 root,,,,) = reg.getAnchor(REC, 0);
        assertEq(root, bytes32(uint256(1)), "first root kept");
    }

    function test_replay_same_calldata_reverts() public {
        _anchor(0, bytes32(uint256(1)), 1, 0);
        vm.prank(SUBMITTER);
        vm.expectRevert(abi.encodeWithSelector(EpochAnchor.EpochOutOfOrder.selector, uint64(1), uint64(0)));
        reg.anchor(REC, 0, bytes32(uint256(1)), 1, 0);
        assertEq(reg.nextEpoch(REC), 1, "replay did not advance");
    }

    function test_gap_reverts() public {
        vm.prank(SUBMITTER);
        vm.expectRevert(abi.encodeWithSelector(EpochAnchor.EpochOutOfOrder.selector, uint64(0), uint64(1)));
        reg.anchor(REC, 1, bytes32(uint256(1)), 1, 0);
        _anchor(0, bytes32(uint256(1)), 1, 0);
        vm.prank(SUBMITTER);
        vm.expectRevert(abi.encodeWithSelector(EpochAnchor.EpochOutOfOrder.selector, uint64(1), uint64(2)));
        reg.anchor(REC, 2, bytes32(uint256(2)), 1, 1);
    }

    function test_wrong_submitter_reverts() public {
        vm.prank(MALLORY);
        vm.expectRevert(EpochAnchor.NotSubmitter.selector);
        reg.anchor(REC, 0, bytes32(uint256(1)), 1, 0);
        vm.prank(OWNER); // the owner is not the submitter either
        vm.expectRevert(EpochAnchor.NotSubmitter.selector);
        reg.anchor(REC, 0, bytes32(uint256(1)), 1, 0);
    }

    function test_unregistered_recorder_reverts() public {
        vm.prank(SUBMITTER);
        vm.expectRevert(EpochAnchor.NotSubmitter.selector);
        reg.anchor(REC_B, 0, bytes32(uint256(1)), 1, 0);
    }

    function test_recorders_are_isolated() public {
        vm.prank(OWNER);
        reg.registerRecorder(REC_B, MALLORY);
        vm.prank(MALLORY); // submitter of B cannot write A
        vm.expectRevert(EpochAnchor.NotSubmitter.selector);
        reg.anchor(REC, 0, bytes32(uint256(1)), 1, 0);
        vm.prank(MALLORY);
        reg.anchor(REC_B, 0, bytes32(uint256(9)), 1, 0);
        assertEq(reg.nextEpoch(REC), 0, "A untouched");
    }

    function test_zero_root_reverts() public {
        vm.prank(SUBMITTER);
        vm.expectRevert(EpochAnchor.ZeroRoot.selector);
        reg.anchor(REC, 0, bytes32(0), 1, 0);
    }

    function test_empty_or_oversized_epoch_reverts() public {
        vm.prank(SUBMITTER);
        vm.expectRevert(EpochAnchor.EmptyEpoch.selector);
        reg.anchor(REC, 0, bytes32(uint256(1)), 0, 0);
        vm.prank(SUBMITTER);
        vm.expectRevert(EpochAnchor.EmptyEpoch.selector);
        reg.anchor(REC, 0, bytes32(uint256(1)), 3, 1); // 3 events cannot end at seq 1
    }

    function test_seq_gap_and_overlap_revert() public {
        vm.prank(SUBMITTER);
        vm.expectRevert(abi.encodeWithSelector(EpochAnchor.SeqNotTiled.selector, uint256(0), uint256(1)));
        reg.anchor(REC, 0, bytes32(uint256(1)), 1, 1); // epoch 0 must start at seq 0
        _anchor(0, bytes32(uint256(1)), 4, 3); // seq 0..3
        vm.prank(SUBMITTER);
        vm.expectRevert(abi.encodeWithSelector(EpochAnchor.SeqNotTiled.selector, uint256(4), uint256(5)));
        reg.anchor(REC, 1, bytes32(uint256(2)), 2, 6); // gap: 5..6
        vm.prank(SUBMITTER);
        vm.expectRevert(abi.encodeWithSelector(EpochAnchor.SeqNotTiled.selector, uint256(4), uint256(3)));
        reg.anchor(REC, 1, bytes32(uint256(2)), 2, 4); // overlap: 3..4
    }

    // ------------------------------------------------------------------ owner functions
    function test_register_only_owner_once_nonzero() public {
        vm.prank(MALLORY);
        vm.expectRevert(EpochAnchor.NotOwner.selector);
        reg.registerRecorder(REC_B, MALLORY);
        vm.prank(OWNER);
        vm.expectRevert(EpochAnchor.AlreadyRegistered.selector);
        reg.registerRecorder(REC, MALLORY);
        vm.prank(OWNER);
        vm.expectRevert(EpochAnchor.ZeroSubmitter.selector);
        reg.registerRecorder(REC_B, address(0));
        vm.prank(OWNER);
        vm.expectRevert(EpochAnchor.ZeroRecorder.selector);
        reg.registerRecorder(bytes32(0), SUBMITTER);
        vm.expectEmit(true, true, false, true);
        emit RecorderRegistered(REC_B, SUBMITTER);
        vm.prank(OWNER);
        reg.registerRecorder(REC_B, SUBMITTER);
        assertEq(reg.submitterOf(REC_B), SUBMITTER, "registered");
        assertEq(reg.owner(), OWNER, "owner");
    }

    function test_rotate_submitter() public {
        _anchor(0, bytes32(uint256(1)), 1, 0);
        vm.prank(MALLORY);
        vm.expectRevert(EpochAnchor.NotOwner.selector);
        reg.rotateSubmitter(REC, MALLORY);
        vm.prank(OWNER);
        vm.expectRevert(EpochAnchor.UnknownRecorder.selector);
        reg.rotateSubmitter(REC_B, MALLORY);
        vm.prank(OWNER);
        vm.expectRevert(EpochAnchor.ZeroSubmitter.selector);
        reg.rotateSubmitter(REC, address(0));
        address next = address(0x5C);
        vm.expectEmit(true, true, true, true);
        emit SubmitterRotated(REC, SUBMITTER, next);
        vm.prank(OWNER);
        reg.rotateSubmitter(REC, next);
        vm.prank(SUBMITTER); // old key is dead
        vm.expectRevert(EpochAnchor.NotSubmitter.selector);
        reg.anchor(REC, 1, bytes32(uint256(2)), 1, 1);
        vm.prank(next); // rotation does not reset history: epoch 1 is next
        reg.anchor(REC, 1, bytes32(uint256(2)), 1, 1);
        (bytes32 root,,,,) = reg.getAnchor(REC, 0);
        assertEq(root, bytes32(uint256(1)), "history kept across rotation");
    }

    // ------------------------------------------------------------------ fuzz
    /// Any sender other than the registered submitter is rejected.
    function testFuzz_only_submitter(address sender, bytes32 root) public {
        vm.assume(sender != SUBMITTER && root != bytes32(0));
        vm.prank(sender);
        vm.expectRevert(EpochAnchor.NotSubmitter.selector);
        reg.anchor(REC, 0, root, 1, 0);
    }

    /// Any epoch number other than the next one is rejected (gaps and rewrites alike).
    function testFuzz_only_next_epoch(uint8 anchoredCount, uint64 epochNo) public {
        uint64 n = uint64(anchoredCount % 16);
        for (uint64 i = 0; i < n; i++) {
            _anchor(i, bytes32(uint256(i + 1)), 1, i);
        }
        vm.assume(epochNo != n);
        vm.prank(SUBMITTER);
        vm.expectRevert(abi.encodeWithSelector(EpochAnchor.EpochOutOfOrder.selector, n, epochNo));
        reg.anchor(REC, epochNo, bytes32(uint256(77)), 1, n);
    }

    /// A written anchor never changes, whatever is attempted afterwards.
    function testFuzz_write_once(bytes32 root, bytes32 other, uint64 treeSize) public {
        vm.assume(root != bytes32(0) && other != root);
        treeSize = uint64(bound(treeSize, 1, 1 << 40));
        _anchor(0, root, treeSize, treeSize - 1);
        vm.prank(SUBMITTER);
        try reg.anchor(REC, 0, other, treeSize, treeSize - 1) {
            revert AssertionFailed("overwrite accepted");
        } catch {}
        vm.prank(OWNER);
        try reg.anchor(REC, 0, other, treeSize, treeSize - 1) {
            revert AssertionFailed("owner overwrite accepted");
        } catch {}
        (bytes32 got, uint64 size, uint64 last,,) = reg.getAnchor(REC, 0);
        assertEq(got, root, "root unchanged");
        assertEq(size, treeSize, "size unchanged");
        assertEq(last, treeSize - 1, "lastSeq unchanged");
    }

    /// Tiled sequences of arbitrary epoch sizes are accepted and recorded exactly.
    function testFuzz_tiled_sequence(uint32[8] memory sizes) public {
        uint64 last = type(uint64).max; // "-1": the first epoch starts at seq 0
        for (uint64 i = 0; i < 8; i++) {
            uint64 size = uint64(bound(sizes[i], 1, 1_000_000));
            uint64 end = last == type(uint64).max ? size - 1 : last + size;
            _anchor(i, keccak256(abi.encode(i, size)), size, end);
            last = end;
        }
        (bool exists, uint64 lastNo) = reg.lastEpoch(REC);
        assertTrue(exists && lastNo == 7, "8 epochs anchored");
        (, , uint64 lastSeq,,) = reg.getAnchor(REC, 7);
        assertEq(lastSeq, last, "seq range recorded");
    }

    function bound(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        return lo + (x % (hi - lo + 1));
    }
}

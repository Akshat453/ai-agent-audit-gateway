// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// Minimal subset of Foundry's cheatcodes (instead of the forge-std dependency).
interface Vm {
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function expectRevert(bytes calldata revertData) external;
    function expectRevert(bytes4 revertData) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData) external;
    function assume(bool condition) external pure;
    function roll(uint256 newHeight) external;
    function warp(uint256 newTimestamp) external;
    function envUint(string calldata name) external view returns (uint256);
    function envAddress(string calldata name) external view returns (address);
    function addr(uint256 privateKey) external pure returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

abstract contract TestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error AssertionFailed(string what);

    function assertTrue(bool ok, string memory what) internal pure {
        if (!ok) revert AssertionFailed(what);
    }

    function assertEq(uint256 a, uint256 b, string memory what) internal pure {
        if (a != b) revert AssertionFailed(what);
    }

    function assertEq(bytes32 a, bytes32 b, string memory what) internal pure {
        if (a != b) revert AssertionFailed(what);
    }

    function assertEq(address a, address b, string memory what) internal pure {
        if (a != b) revert AssertionFailed(what);
    }
}

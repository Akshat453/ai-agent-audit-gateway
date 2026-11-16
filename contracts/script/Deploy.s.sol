// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {EpochAnchor} from "../src/EpochAnchor.sol";
import {Vm} from "../test/Vm.sol";

/// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast
/// The deployer (= owner) key comes from DEPLOYER_KEY in the environment; it is never logged.
/// The deployment record (chain id, address, block, deployer, bytecode hashes) is written by
/// `python -m agw_worker.anchoring.admin record-deployment` from the broadcast receipt.
contract Deploy {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (EpochAnchor registry) {
        uint256 key = vm.envUint("DEPLOYER_KEY");
        vm.startBroadcast(key);
        registry = new EpochAnchor();
        vm.stopBroadcast();
    }
}

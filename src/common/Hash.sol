pragma solidity ^0.6.7;

import "./Memory.sol";
import "./Blake2b.sol";

library Hash {

    using Blake2b for Blake2b.Instance;

    function hash(bytes memory src) internal view returns (bytes memory des) {
        return Memory.toBytes(keccak256(src));
        // Blake2b.Instance memory instance = Blake2b.init(hex"", 32);
        // return instance.finalize(src);
    }

    function hash32(bytes memory src) internal view returns (bytes32 des) {
        // return keccak256(src);
        Blake2b.Instance memory instance = Blake2b.init(hex"", 32);
        return abi.decode(instance.finalize(src), (bytes32));
    }
}

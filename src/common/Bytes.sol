pragma solidity ^0.6.7;

import {Memory} from "./Memory.sol";

library Bytes {

    uint internal constant BYTES_HEADER_SIZE = 32;

	// Copies a section of 'self' into a new array, starting at the provided 'startIndex'.
	// Returns the new copy.
	// Requires that 'startIndex <= self.length'
	// The length of the substring is: 'self.length - startIndex'
	function substr(bytes memory self, uint startIndex) internal pure returns (bytes memory) {
		require(startIndex <= self.length);
		uint len = self.length - startIndex;
		uint addr = Memory.dataPtr(self);
		return Memory.toBytes(addr + startIndex, len);
	}

	// Copies 'len' bytes from 'self' into a new array, starting at the provided 'startIndex'.
	// Returns the new copy.
	// Requires that:
	//  - 'startIndex + len <= self.length'
	// The length of the substring is: 'len'
	function substr(bytes memory self, uint startIndex, uint len) internal pure returns (bytes memory) {
		require(startIndex + len <= self.length);
		if (len == 0) {
			return "";
		}
		uint addr = Memory.dataPtr(self);
		return Memory.toBytes(addr + startIndex, len);
	}


	// Combines 'self' and 'other' into a single array.
	// Returns the concatenated arrays:
	//  [self[0], self[1], ... , self[self.length - 1], other[0], other[1], ... , other[other.length - 1]]
	// The length of the new array is 'self.length + other.length'
	function concat(bytes memory self, bytes memory other) internal pure returns (bytes memory) {
		bytes memory ret = new bytes(self.length + other.length);
		uint src;
		uint srcLen;
		(src, srcLen) = Memory.fromBytes(self);
		uint src2;
		uint src2Len;
		(src2, src2Len) = Memory.fromBytes(other);
		uint dest;
		(dest,) = Memory.fromBytes(ret);
		uint dest2 = dest + srcLen;
		Memory.copy(src, dest, srcLen);
		Memory.copy(src2, dest2, src2Len);
		return ret;
	}

}

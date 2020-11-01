pragma solidity >=0.5.0 <0.6.0;

import "./SafeMath.sol";


library Input {

	using SafeMath for uint256;
	
	// Size of a word, in bytes.
	uint internal constant WORD_SIZE = 32;

	struct Data {
		uint256 offset;
		bytes raw;
	}

	function from(bytes memory data) internal pure returns(Data memory) {
		return Data({
			offset: 0,
			raw: data
		});
	}

	modifier shift(Data memory data, uint256 size) {
		require(data.raw.length >= data.offset + size, "Input: Out of range");
		_;
		data.offset += size;
	}

	function finished(Data memory data) internal pure returns(bool) {
		return data.offset == data.raw.length;
	}

	function peekU8(Data memory data) internal pure returns(uint8 v) {
		return uint8(data.raw[data.offset]);
	}

	function peekKeccak256(Data memory data, uint256 length) internal pure returns(bytes32 res) {
		return bytesKeccak256(data.raw, data.offset, length);
	}

	function bytesKeccak256(bytes memory ptr, uint256 offset, uint256 length) internal pure returns(bytes32 res) {
		// solium-disable-next-line security/no-inline-assembly
		assembly {
			res := keccak256(add(add(ptr, 32), offset), length)
		}
	}

	function peekSha256(Data memory data, uint256 length) internal view returns(bytes32) {
		return bytesSha256(data.raw, data.offset, length);
	}

	function bytesSha256(bytes memory ptr, uint256 offset, uint256 length) internal view returns(bytes32) {
		bytes32[1] memory result;
		// solium-disable-next-line security/no-inline-assembly
		assembly {
			pop(staticcall(gas(), 0x02, add(add(ptr, 32), offset), length, result, 32))
		}
		return result[0];
	}

	function decodeU8(Data memory data) internal pure shift(data, 1) returns(uint8 value) {
		value = uint8(data.raw[data.offset]);
	}

	function decodeI8(Data memory data) internal pure shift(data, 1) returns(int8 value) {
		value = int8(data.raw[data.offset]);
	}

	function decodeU16(Data memory data) internal pure returns(uint16 value) {
		value = uint16(decodeU8(data));
		value |= (uint16(decodeU8(data)) << 8);
	}

	function decodeI16(Data memory data) internal pure returns(int16 value) {
		value = int16(decodeI8(data));
		value |= (int16(decodeI8(data)) << 8);
	}

	function decodeU32(Data memory data) internal pure returns(uint32 value) {
		value = uint32(decodeU16(data));
		value |= (uint32(decodeU16(data)) << 16);
	}

	function decodeI32(Data memory data) internal pure returns(int32 value) {
		value = int32(decodeI16(data));
		value |= (int32(decodeI16(data)) << 16);
	}

	function decodeU64(Data memory data) internal pure returns(uint64 value) {
		value = uint64(decodeU32(data));
		value |= (uint64(decodeU32(data)) << 32);
	}

	function decodeI64(Data memory data) internal pure returns(int64 value) {
		value = int64(decodeI32(data));
		value |= (int64(decodeI32(data)) << 32);
	}

	function decodeU128(Data memory data) internal pure returns(uint128 value) {
		value = uint128(decodeU64(data));
		value |= (uint128(decodeU64(data)) << 64);
	}

	function decodeI128(Data memory data) internal pure returns(int128 value) {
		value = int128(decodeI64(data));
		value |= (int128(decodeI64(data)) << 64);
	}

	function decodeU256(Data memory data) internal pure returns(uint256 value) {
		value = uint256(decodeU128(data));
		value |= (uint256(decodeU128(data)) << 128);
	}

	function decodeI256(Data memory data) internal pure returns(int256 value) {
		value = int256(decodeI128(data));
		value |= (int256(decodeI128(data)) << 128);
	}

	function decodeBool(Data memory data) internal pure returns(bool value) {
		value = (decodeU8(data) != 0);
	}

	function decodeBytes(Data memory data) internal pure returns(bytes memory value) {
		value = new bytes(decodeU32(data));
		for (uint i = 0; i < value.length; i++) {
			value[i] = byte(decodeU8(data));
		}
	}

	function decodeBytesN(Data memory data, uint256 N) internal pure shift(data, N) returns(bytes memory value) {
		value = substr(data.raw, data.offset, N);
	}

	function decodeBytes32(Data memory data) internal pure shift(data, 32) returns(bytes32 value) {
		bytes memory raw = data.raw;
		uint256 offset = data.offset;
		// solium-disable-next-line security/no-inline-assembly
		assembly {
			value := mload(add(add(raw, 32), offset))
		}
	}

	function decodeBytes20(Data memory data) internal pure returns(bytes20 value) {
		for (uint i = 0; i < 20; i++) {
			value |= bytes20(byte(decodeU8(data)) & 0xFF) >> (i * 8);
		}
	}

	// Copies a section of 'self' into a new array, starting at the provided 'startIndex'.
	// Returns the new copy.
	// Requires that 'startIndex <= self.length'
	// The length of the substring is: 'self.length - startIndex'
	function substr(bytes memory self, uint startIndex) internal pure returns (bytes memory) {
		require(startIndex <= self.length);
		uint len = self.length - startIndex;
		uint addr = dataPtr(self);
		return toBytes(addr + startIndex, len);
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
		uint addr = dataPtr(self);
		return toBytes(addr + startIndex, len);
	}

	// Returns a memory pointer to the data portion of the provided bytes array.
	function dataPtr(bytes memory bts) internal pure returns (uint addr) {
		assembly {
			addr := add(bts, /*BYTES_HEADER_SIZE*/32)
		}
	}

	// Creates a 'bytes memory' variable from the memory address 'addr', with the
	// length 'len'. The function will allocate new memory for the bytes array, and
	// the 'len bytes starting at 'addr' will be copied into that new memory.
	function toBytes(uint addr, uint len) internal pure returns (bytes memory bts) {
		bts = new bytes(len);
		uint btsptr;
		assembly {
			btsptr := add(bts, /*BYTES_HEADER_SIZE*/32)
		}
		copy(addr, btsptr, len);
	}
	
	// Copies 'self' into a new 'bytes memory'.
	// Returns the newly created 'bytes memory'
	// The returned bytes will be of length '32'.
	function toBytes(bytes32 self) internal pure returns (bytes memory bts) {
		bts = new bytes(32);
		assembly {
			mstore(add(bts, /*BYTES_HEADER_SIZE*/32), self)
		}
	}

	// Copy 'len' bytes from memory address 'src', to address 'dest'.
	// This function does not check the or destination, it only copies
	// the bytes.
	function copy(uint src, uint dest, uint len) internal pure {
		// Copy word-length chunks while possible
		for (; len >= WORD_SIZE; len -= WORD_SIZE) {
			assembly {
				mstore(dest, mload(src))
			}
			dest += WORD_SIZE;
			src += WORD_SIZE;
		}

		// Copy remaining bytes
		uint mask = 256 ** (WORD_SIZE - len) - 1;
		assembly {
			let srcpart := and(mload(src), not(mask))
			let destpart := and(mload(dest), mask)
			mstore(dest, or(destpart, srcpart))
		}
	}

	// Combines 'self' and 'other' into a single array.
	// Returns the concatenated arrays:
	//  [self[0], self[1], ... , self[self.length - 1], other[0], other[1], ... , other[other.length - 1]]
	// The length of the new array is 'self.length + other.length'
	function concat(bytes memory self, bytes memory other) internal pure returns (bytes memory) {
		bytes memory ret = new bytes(self.length + other.length);
		uint src;
		uint srcLen;
		(src, srcLen) = fromBytes(self);
		uint src2;
		uint src2Len;
		(src2, src2Len) = fromBytes(other);
		uint dest;
		(dest,) = fromBytes(ret);
		uint dest2 = dest + srcLen;
		copy(src, dest, srcLen);
		copy(src2, dest2, src2Len);
		return ret;
	}

	// This function does the same as 'dataPtr(bytes memory)', but will also return the
	// length of the provided bytes array.
	function fromBytes(bytes memory bts) internal pure returns (uint addr, uint len) {
		len = bts.length;
		assembly {
			addr := add(bts, /*BYTES_HEADER_SIZE*/32)
		}
	}

}


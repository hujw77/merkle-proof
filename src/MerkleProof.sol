// SPDX-License-Identifier: MIT

// Modified Merkle-Patricia Trie
//
// Note that for the following definitions, `|` denotes concatenation
//
// Branch encoding:
// NodeHeader | Extra partial key length | Partial Key | Value
// `NodeHeader` is a byte such that:
// most significant two bits of `NodeHeader`: 10 if branch w/o value, 11 if branch w/ value
// least significant six bits of `NodeHeader`: if len(key) > 62, 0x3f, otherwise len(key)
// `Extra partial key length` is included if len(key) > 63 and consists of the remaining key length
// `Partial Key` is the branch's key
// `Value` is: Children Bitmap | SCALE Branch node Value | Hash(Enc(Child[i_1])) | Hash(Enc(Child[i_2])) | ... | Hash(Enc(Child[i_n]))
//
// Leaf encoding:
// NodeHeader | Extra partial key length | Partial Key | Value
// `NodeHeader` is a byte such that:
// most significant two bits of `NodeHeader`: 01
// least significant six bits of `NodeHeader`: if len(key) > 62, 0x3f, otherwise len(key)
// `Extra partial key length` is included if len(key) > 63 and consists of the remaining key length
// `Partial Key` is the leaf's key
// `Value` is the leaf's SCALE encoded value

pragma solidity ^0.6.7;
pragma experimental ABIEncoderV2;

import "./common/Input.sol";
import "./common/Blake2b.sol";
import "./common/Bytes.sol";
import "./common/Memory.sol";


/**
 * @dev These functions deal with verification of Merkle trees (hash trees),
 */
 contract MerkleProof {

	using Input for Input.Data;
	using Bytes for bytes;
	using Blake2b for Blake2b.Instance;
	using SafeMath for uint256;
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */

	uint8 internal constant NODEKIND_NOEXT_LEAF  = 1;
	uint8 internal constant NODEKIND_NOEXT_BRANCH_NOVALUE = 2;
	uint8 internal constant NODEKIND_NOEXT_BRANCH_WITHVALUE = 3;

	struct NodeHandle {
		bytes data;
		bool exist;
		bool isInline;
	}

	struct Branch {
		bytes key; //partialkey
		NodeHandle[16] children;
		bytes value;
	}

	struct Leaf {
		bytes key; //partialkey
		bytes value;
	} 

	struct StackEntry {
		bytes prefix;
		uint8 kind;	
		bytes key;
		bytes value;
		NodeHandle[16] children;
		uint8 childIndex;
		bool isInline;
	}

	struct ProofIter {
		bytes[] proof;
		uint256 offset;
	}

	struct ItemsIter {
		Item[] items;
		uint256 offset;
	}

	struct Item {
		bytes key;
		bytes value;
	}

	enum ValueMatch {
		MatchesLeaf,
		MatchesBranch,
		NotOmitted,
		NotFound,
		IsChild
	}

	enum Step {
		Descend,
		UnwindStack
	}

	function Hash(bytes memory src) internal view returns (bytes memory des) {
		return Memory.toBytes(keccak256(src));
		// Blake2b.Instance memory instance = Blake2b.init(hex"", 32);
		// return instance.finalize(src);
	}

	function verify(bytes32 root, bytes[] memory proof, bytes[] memory keys, bytes[] memory values) public view returns (bool) {
		require(proof.length > 0, "no proof");
		require(keys.length > 0, "no keys");
		require(keys.length == values.length, "invalid pair");
		Item[] memory items = new Item[](keys.length);
		for (uint256 i=0; i<keys.length; i++) {
			items[i] = Item({
				key: keys[i],
				value: values[i]
			});
		}
		return verify_proof(root, proof, items);
	}

	//bytes32 root, bytes memory key, bytes memory value 
    function verify_proof(bytes32 root, bytes[] memory proof, Item[] memory items) internal view returns (bool) {
		require(proof.length > 0, "no proof");
		require(items.length >0, "no item");
		//TODO:: OPT
		uint256 maxDepth = proof.length;
		StackEntry[] memory stack = new StackEntry[](maxDepth);
		uint256 stackLen = 0;
		bytes memory rootNode = proof[0];
		StackEntry memory lastEntry = decodeNode(rootNode, hex"", false); 
		ProofIter memory proofIter = ProofIter({
			proof: proof,
			offset: 1
		});
		ItemsIter memory itemsIter = ItemsIter({
			items: items,
			offset: 0
		});
		while (true) {
			Step step;
			bytes memory childPrefix;
			(step, childPrefix) = advanceItem(lastEntry, itemsIter);
			if (step == Step.Descend) {
				StackEntry memory nextEntry = advanceChildIndex(lastEntry, childPrefix, proofIter);
				stack[stackLen] = lastEntry;
				stackLen++;
				lastEntry = nextEntry;
			} else if (step == Step.UnwindStack) {
				bytes memory childRef;
				{
					bool isInline = lastEntry.isInline;
					bytes memory nodeData = encodeNode(lastEntry);
					if (isInline) {
						require(nodeData.length <= 32, "invalid child reference");
						childRef = nodeData;	
					} else {
						childRef = Hash(nodeData);
					}
				}
				{
					if (stackLen > 0) {
						lastEntry = stack[stackLen-1];
						stackLen--;
						lastEntry.children[lastEntry.childIndex].data = childRef;		
					} else {
						require(proofIter.offset == proofIter.proof.length, "exraneous proof");
						require(childRef.length == 32, "root hash length should be 32");
						bytes32 computedRoot = abi.decode(childRef, (bytes32));
						if (computedRoot != root) {
							return false;
						}
						break;
					}
				}
			}
		}
		return true;
	}

	function advanceChildIndex(StackEntry memory entry, bytes memory childPrefix, ProofIter memory proofIter) internal pure returns (StackEntry memory) {
		if (entry.kind == NODEKIND_NOEXT_BRANCH_NOVALUE || entry.kind == NODEKIND_NOEXT_BRANCH_WITHVALUE) {
			require(childPrefix.length > 0, "this is a branch");
			entry.childIndex = uint8(childPrefix[childPrefix.length - 1]);
			NodeHandle memory child = entry.children[entry.childIndex];
			return makeChildEntry(proofIter, child, childPrefix);
		} else {
			revert("cannot have children");
		}
	}

	function makeChildEntry(ProofIter memory proofIter, NodeHandle memory child, bytes memory prefix) internal pure returns (StackEntry memory) {
		if (child.isInline) {
			if (child.data.length == 0) {
				require(proofIter.offset < proofIter.proof.length, "incomplete proof");
				bytes memory nodeData = proofIter.proof[proofIter.offset];
				proofIter.offset++;
				return decodeNode(nodeData, prefix, false); 
			} else {
				return decodeNode(child.data, prefix, true); 
			}	
		} else {
			require(child.data.length == 32, "invalid child reference");
			revert("extraneous hash reference");
		}
	}

	function advanceItem(StackEntry memory entry, ItemsIter memory itemsIter) internal pure returns (Step, bytes memory childPrefix) {
		while (itemsIter.offset < itemsIter.items.length) {
			Item memory item = itemsIter.items[itemsIter.offset];
			bytes memory k = keyToNibbles(item.key);
			bytes memory v = item.value;
			if (startsWith(k, entry.prefix)) {
				ValueMatch vm;
				(vm, childPrefix) = matchKeyToNode(k, entry.prefix.length, entry);
				if (ValueMatch.MatchesLeaf == vm) {
					if (v.length == 0) {
						revert("value mismatch");
					}  
					entry.value = v;
				} else if (ValueMatch.MatchesBranch == vm) {
					entry.value = v;
				} else if (ValueMatch.NotFound == vm) {
					if (v.length > 0) {
						revert("value mismatch");
					} 
				} else if (ValueMatch.NotOmitted == vm) {
					revert("extraneouts value");
				} else if (ValueMatch.IsChild == vm) {
					return (Step.Descend, childPrefix);
				}
				itemsIter.offset++;
				continue;
			} 
			return (Step.UnwindStack, childPrefix);
		}
		return (Step.UnwindStack, childPrefix);
	}

	function matchKeyToNode(bytes memory k, uint256 prefixLen, StackEntry memory entry) internal pure returns (ValueMatch vm, bytes memory childPrefix) {

		uint256 prefixPlufPartialLen = prefixLen + entry.key.length;
		if (entry.kind == NODEKIND_NOEXT_LEAF) {
			if (contains(k, entry.key, prefixLen) &&
			   	k.length == prefixPlufPartialLen) {
			 	if (entry.value.length == 0) {
					return (ValueMatch.MatchesLeaf, childPrefix);
				} else {
					return (ValueMatch.NotOmitted, childPrefix);
				}	
			} else {
				return (ValueMatch.NotFound, childPrefix);
			}
		} else if (entry.kind == NODEKIND_NOEXT_BRANCH_NOVALUE || entry.kind == NODEKIND_NOEXT_BRANCH_WITHVALUE) {
			if (contains(k, entry.key, prefixLen)) {
				if (prefixPlufPartialLen == k.length) {
					if (entry.value.length == 0) {
						return (ValueMatch.MatchesBranch, childPrefix);
					} else {
						return (ValueMatch.NotOmitted, childPrefix);
					}	
				} else {
					uint8 index = uint8(k[prefixPlufPartialLen]);
					if (entry.children[index].exist) {
						childPrefix = k.substr(0, prefixPlufPartialLen + 1);
						return (ValueMatch.IsChild, childPrefix);
					} else {
						return (ValueMatch.NotFound, childPrefix);
					}
				}	
			} else {
				return (ValueMatch.NotFound, childPrefix);
			}
		} else {
			revert("not support node type");
		}
	}

	function contains(bytes memory a, bytes memory b, uint256 offset) internal pure returns (bool) {
		if (a.length < b.length + offset){
			return false;
		}
		for (uint256 i=0; i < b.length; i++) {
			if (a[i+offset] != b[i]) {
				return false;
			} 
		}
		return true;
	}

	// startsWith returns the length of the common prefix between two keys
	function startsWith(bytes memory a, bytes memory b) internal pure returns (bool) {
		if (a.length < b.length) {
			return false;
		} 
		for (uint256 i = 0; i < b.length; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	}

	function encodeNode(StackEntry memory entry) internal view returns (bytes memory) {
		if (entry.kind == NODEKIND_NOEXT_LEAF) {
			Leaf memory l = Leaf({
				key: entry.key,
				value: entry.value
			});
			return encodeLeaf(l);
		} else if (entry.kind == NODEKIND_NOEXT_BRANCH_NOVALUE || entry.kind == NODEKIND_NOEXT_BRANCH_WITHVALUE) {
			Branch memory b = Branch({
				key: entry.key,
				value: entry.value,
				children: entry.children
			});
			return encodeBranch(b);
		} else {
			revert("not support node kind");
		}	
	}

	function decodeNode(bytes memory nodeData, bytes memory prefix, bool isInline) internal pure returns (StackEntry memory entry) {
		Input.Data memory data = Input.from(nodeData);
		uint8 header = data.decodeU8();
		uint8 kind = header >> 6;
		if (kind == NODEKIND_NOEXT_LEAF) {
			//Leaf
			Leaf memory leaf = decodeLeaf(data, header);
			entry.key = leaf.key;
			entry.value = leaf.value;
			entry.kind = kind;
			entry.prefix = prefix;
			entry.isInline = isInline;
		} else if (kind == NODEKIND_NOEXT_BRANCH_NOVALUE || kind == NODEKIND_NOEXT_BRANCH_WITHVALUE) {
			//BRANCH_WITHOUT_MASK_NO_EXT  BRANCH_WITH_MASK_NO_EXT
			Branch memory branch = decodeBranch(data, header);
			entry.key = branch.key;
			entry.value = branch.value;
			entry.kind = kind;
			entry.children = branch.children;
			entry.childIndex = 0;
			entry.prefix = prefix;
			entry.isInline = isInline;
		} else {
			revert("not support node kind");
		}
	}


	function encodeBranch(Branch memory b) internal view returns (bytes memory encoding) {
		encoding = encodeBranchHeader(b);
		encoding = abi.encodePacked(encoding, nibblesToKeyLE(b.key));
		encoding = abi.encodePacked(encoding, u16ToBytes(childrenBitmap(b)));
		if (b.value.length != 0) {
			bytes memory encValue;
			(encValue,) = scaleEncodeByteArray(b.value);
			encoding = abi.encodePacked(encoding, encValue);
		}
		for (uint8 i=0; i < 16; i++) {
			if (b.children[i].exist) {
				//TODO::encode data
				bytes memory childData = b.children[i].data;	
				require(childData.length > 0, "miss child data");
				bytes memory hash;
				if (childData.length <= 32) {
					hash = childData;
				} else {
					hash = Hash(childData);	
				}
				bytes memory encChild;
				(encChild,)= scaleEncodeByteArray(hash);
				encoding = abi.encodePacked(encoding, encChild);
			}
		}
		return encoding;
	}

	// u16ToBytes converts a uint16 into a 2-byte slice
	function u16ToBytes(uint16 src) internal pure returns (bytes memory des) {
		des = new bytes(2);
		des[0] = byte(uint8(src & 0x00FF));
		des[1] = byte(uint8(src >> 8 & 0x00FF));
	}

	function encodeLeaf(Leaf memory l) internal pure returns (bytes memory encoding) {
		encoding = encodeLeafHeader(l);
		encoding = abi.encodePacked(encoding, nibblesToKeyLE(l.key));
		bytes memory encValue;
		(encValue,) = scaleEncodeByteArray(l.value);
		encoding = abi.encodePacked(encoding, encValue);
		return encoding;
	}

	function childrenBitmap(Branch memory b) internal pure returns (uint16 bitmap) {
		for (uint256 i=0; i < 16; i++) {
			if (b.children[i].exist) {
				bitmap = bitmap | uint16(1<<i);
			}
		}
	}

	function encodeBranchHeader(Branch memory b) internal pure returns (bytes memory branchHeader) {
		uint8 header;
		uint256 valueLen = b.value.length;
		require(valueLen < 65536, "partial key too long");
		if (valueLen == 0) {
			header = 2 << 6; // w/o
		} else {
			header = 3 << 6; // w/
		}
		bytes memory encPkLen;
		uint256 pkLen = b.key.length;
		if (pkLen >= 63) {
			header = header | 0x3F;
			encPkLen = encodeExtraPartialKeyLength(uint16(pkLen));
		} else {
			header = header | uint8(pkLen);
		}
		branchHeader = abi.encodePacked(header, encPkLen);
		return branchHeader;
	}

	function encodeLeafHeader(Leaf memory l) internal pure returns (bytes memory leafHeader) {
		uint8 header = 1 << 6;
		uint256 pkLen = l.key.length;
		bytes memory encPkLen;
		if (pkLen >= 63) {
			header = header | 0x3F;
			encPkLen = encodeExtraPartialKeyLength(uint16(pkLen));
		} else {
			header = header | uint8(pkLen);
		} 
		leafHeader = abi.encodePacked(header, encPkLen);
		return leafHeader;
	}

	function encodeExtraPartialKeyLength(uint16 pkLen) internal pure returns (bytes memory encPkLen) {
		pkLen -= 63;
		for(uint8 i=0; i < 65536; i++) {
			if (pkLen < 255) {
				encPkLen = abi.encodePacked(encPkLen, uint8(pkLen));
				break;
			} else {
				encPkLen = abi.encodePacked(encPkLen, uint8(255));
			}
		}
		return encPkLen;
	}

	function decodeBranch(Input.Data memory data, uint8 header) internal pure returns (Branch memory) {
		Branch memory b;
		b.key = decodeNodeKey(data, header);
		uint8[2] memory bitmap;
		bitmap[0] = data.decodeU8();
		bitmap[1] = data.decodeU8();
		uint8 nodeType = header >> 6;
		if (nodeType == NODEKIND_NOEXT_BRANCH_WITHVALUE) {
			//BRANCH_WITH_MASK_NO_EXT
			b.value = scaleDecodeByteArray(data);
		}
		for (uint8 i=0; i < 16; i++){
			if (((bitmap[i/8] >> (i%8)) & 1) == 1) {
				bytes memory childData = scaleDecodeByteArray(data);
				bool isInline = true;
				if (childData.length == 32) {
					isInline = false;
				}
				b.children[i] = NodeHandle({
					data: childData,
					isInline: isInline,
					exist: true
				});
			}
		}
		return b;
	}

	function decodeLeaf(Input.Data memory data, uint8 header) internal pure returns (Leaf memory) {
		Leaf memory l;
		l.key = decodeNodeKey(data, header);
		l.value = scaleDecodeByteArray(data);
		return l;
	}

	function decodeNodeKey(Input.Data memory data, uint8 header) internal pure returns (bytes memory key) {
		uint256 keyLen = header & 0x3F;
		if (keyLen == 0x3f) {
			while (keyLen < 65536) {
				uint8 nextKeyLen = data.decodeU8();
				keyLen += uint256(nextKeyLen);
				if (nextKeyLen < 0xFF) {
					break;
				}
				require(keyLen < 65536, "Size limit reached for a nibble slice");
			}
		}
		if (keyLen != 0) {
			key = data.decodeBytesN(keyLen/2 + keyLen%2);
			key = keyToNibbles(key);
			if (keyLen%2 == 1) {
				key = key.substr(1);
			}
		}
		return key;
	}

	
	// keyToNibbles turns bytes into nibbles
	// does not rearrange the nibbles; assumes they are already ordered in LE
	function keyToNibbles(bytes memory src) internal pure returns (bytes memory des) {
		if (src.length == 0) {
			return des;
		} else if (src.length == 1 && uint8(src[0]) == 0) {
			return hex"0000";
		}
		uint256 l = src.length * 2;
		des = new bytes(l);
        for (uint256 i = 0; i < src.length; i++) {
			des[2*i] = byte(uint8(src[i]) / 16);
			des[2*i+1] = byte(uint8(src[i]) % 16); 
        }
	}

	// nibblesToKeyLE turns a slice of nibbles w/ length k into a little endian byte array
	// assumes nibbles are already LE, does not rearrange nibbles
	// if the length of the input is odd, the result is [ 0000 in[0] | in[1] in[2] | ... | in[k-2] in[k-1] ]
	// otherwise, res = [ in[0] in[1] | ... | in[k-2] in[k-1] ]
	function nibblesToKeyLE(bytes memory src) internal pure returns (bytes memory des) {
		uint256 l = src.length;
		if (l % 2 == 0) {
			des = new bytes(l/2);
			for (uint256 i = 0; i < l; i+=2) {
				uint8 a = uint8(src[i]);
				uint8 b = uint8(src[i+1]);
				des[i/2] = byte((a << 4 & 0xF0) | (b & 0x0F));
			}
		} else {
			des = new bytes(l/2+1);
			des[0] = src[0];
			for (uint256 i = 2; i < l; i+=2) {
				uint8 a = uint8(src[i-1]);
				uint8 b = uint8(src[i]);
				des[i/2] = byte((a << 4 & 0xF0) | (b & 0x0F));
			}
		}	
	}

	// encodeByteArray performs the following:
	// b -> [encodeInteger(len(b)) b]
	// it writes to t.lengthhe buffer a byte array where the first byte is the length of b encoded with SCALE, followed by the
	// byte array b itself
	function scaleEncodeByteArray(bytes memory src) internal pure returns (bytes memory des, uint256 bytesEncoded) {
		uint256 n;
		(des, n) = scaleEncodeU32(uint32(src.length));
		bytesEncoded = n + src.length;
		des = abi.encodePacked(des, src);	
	}

	// encodeInteger performs the following on integer i:
	// i  -> i^0...i^n where n is the length in bits of i
	// note that the bit representation of i is in little endian; ie i^0 is the least significant bit of i,
	// and i^n is the most significant bit
	// if n < 2^6 write [00 i^2...i^8 ] [ 8 bits = 1 byte encoded  ]
	// if 2^6 <= n < 2^14 write [01 i^2...i^16] [ 16 bits = 2 byte encoded  ]
	// if 2^14 <= n < 2^30 write [10 i^2...i^32] [ 32 bits = 4 byte encoded  ]
	// if n >= 2^30 write [lower 2 bits of first byte = 11] [upper 6 bits of first byte = # of bytes following less 4]
	// [append i as a byte array to the first byte]
	function scaleEncodeU32(uint32 i) internal pure returns (bytes memory, uint256) {
		// 1<<6
		if (i < 64) {
			uint8 v = uint8(i) << 2;
			byte b = byte(v);
			bytes memory des = new bytes(1);
			des[0] = b;
			return (des, 1);
		// 1<<14
		} else if (i < 16384) {
			uint16 v = uint16(i<<2)+1;
			bytes memory des = new bytes(2);
			des[0] = byte(uint8(v));
			des[1] = byte(uint8(v>>8));
			return (des, 2);
		// 1<<30
		} else if (i < 1073741824) {
			uint32 v = uint32(i<<2)+2;
			bytes memory des = new bytes(4);
			des[0] = byte(uint8(v));
			des[1] = byte(uint8(v>>8));
			des[2] = byte(uint8(v>>16));
			des[3] = byte(uint8(v>>24));
			return (des, 4);
		} else {
			revert("scale encode not support");
		}
	}
	
	// DecodeByteArray accepts a byte array representing a SCALE encoded byte array and performs SCALE decoding
	// of the byte array
	// if the encoding is valid, it then returns the decoded byte array, the total number of input bytes decoded, and nil
	// otherwise, it returns 0
	function scaleDecodeByteArray(Input.Data memory data) internal pure returns (bytes memory v) {
		uint32 len = scaleDecodeU32(data);
		if (len == 0) {
			return v;
		}
		v = data.decodeBytesN(len);
		return v;
	}

	// DecodeInteger accepts a byte array representing a SCALE encoded integer and performs SCALE decoding of the int
	// if the encoding is valid, it then returns (o, bytesDecoded, err) where o is the decoded integer, bytesDecoded is the
	// number of input bytes decoded, and err is nil
	// otherwise, it returns 0 
	function scaleDecodeU32(Input.Data memory data) internal pure returns (uint32) {
		uint8 b0 = data.decodeU8();
		uint8 mode = b0 & 3;
		require(mode <= 2, "scale decode not support");
		if (mode == 0) {
			return uint32(b0) >> 2;
		} else if (mode == 1) {
			uint8 b1 = data.decodeU8();
			uint16 v = uint16(b0) | uint16(b1)<<8;
			return uint32(v) >> 2;
		} else if (mode == 2) {
			uint8 b1 = data.decodeU8();
			uint8 b2 = data.decodeU8();
			uint8 b3 = data.decodeU8();
			uint32 v = uint32(b0) | uint32(b1)<<8 | uint32(b2)<<18 | uint32(b3)<<24;
			return v >> 2;
		}
	}
   
} 


pragma solidity ^0.6.7;

import "ds-test/test.sol";

import "./MerkleProof.sol";
pragma experimental ABIEncoderV2;

contract MerkleProofTest is MerkleProof, DSTest {

    function setUp() public {
    }

    function testFail_basic_sanity() public {
        assertTrue(false);
    }

    function test_basic_sanity() public {
        assertTrue(true);
    }
	
	function testPairVerifyProof2() public {
		bytes32 root = hex"e24f300814d2ddbb2a6ba465cdc2d31004aee7741d0a4964b879f25053b2ed48";
		bytes[] memory merkleProof = new bytes[](3); 
		merkleProof[0] =  hex"c4646f4000107665726200";
		merkleProof[1] =  hex"c107400014707570707900";
		merkleProof[2] =  hex"410500";

		bytes[] memory keys = new bytes[](1);
		keys[0]= hex"646f6765";
		bytes[] memory values = new bytes[](1);
		values[0] = hex"0000000000000000000000000000000000000000000000000000000000000000";
		bool res = verify(root, merkleProof, keys, values) == true;
		assertTrue(res);
	}

	function testPairsVerifyProof2() public {
		bytes32 root = hex"493825321d9ad0c473bbf85e1a08c742b4a0b75414f890745368b8953b873017";
		bytes[] memory merkleProof; 
		merkleProof[0] =  hex"810616010018487261766f00007c8306f7240030447365207374616c6c696f6e30447365206275696c64696e67";
		merkleProof[1] =  hex"466c6661800000000000000000000000000000000000000000000000000000000000000000";
		merkleProof[2] =  hex"826f400000";
		merkleProof[3] =  hex"8107400000";
		merkleProof[4] =  hex"410500";
		
		bytes[] memory keys;
		keys[0]= hex"646f";
		keys[1]= hex"646f67";
		keys[2]= hex"646f6765";
		keys[3]= hex"627261766f";
		keys[4]= hex"616c6661626574";
		keys[5]= hex"64";
		keys[6]= hex"646f10";
		keys[7]= hex"68616c70";
		bytes[] memory values;
		values[0] = hex"76657262";
		values[1] = hex"7075707079";
		values[2] = hex"0000000000000000000000000000000000000000000000000000000000000000";
		values[3] = hex"627261766f";
		values[4] = hex"";
		values[5] = hex"";
		values[6] = hex"";
		values[7] = hex"";
		bool res = verify(root, merkleProof, keys, values) == true;
		assertTrue(res);
	}
}

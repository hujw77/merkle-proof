pragma solidity ^0.6.7;

import "ds-test/test.sol";

import "./MerkleProof.sol";

contract MerkleProofTest is DSTest {
    MerkleProof proof;

    function setUp() public {
        proof = new MerkleProof();
    }

    function testFail_basic_sanity() public {
        assertTrue(false);
    }

    function test_basic_sanity() public {
        assertTrue(true);
    }
}

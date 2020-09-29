pragma solidity ^0.5.3;

import './BN256ops.sol';

contract AssetUnlocker {

    uint256 constant GX = 0x0000000000000000000000000000000000000000000000000000000000000001;
    uint256 constant GY = 0x0000000000000000000000000000000000000000000000000000000000000002;

    struct participants {
        mapping(address => uint8) addresses;
    }

    mapping( address => participants ) balances;
    mapping( uint256 => address ) PLToOwner;
    mapping( uint256 => uint256 ) PLToS;
    
    function commitAsset( uint256 PLX ) public {
        PLToOwner[PLX] = msg.sender;
    }

    function unlockAsset( uint256 s ) public returns (bool) {
        
        uint256 sGX;
        uint256 sGY;
        (sGX, sGY) = BN256ops.ecmul(GX, GY, s);
        
        if (PLToOwner[sGX] == address(0)) {
            return false;
        }
        balances[msg.sender].addresses[PLToOwner[sGX]] += 1;
        PLToS[sGX] = s;
        return true;
    }
    
    function getKey( uint256 PLX ) public view returns (uint256) {
        return PLToS[PLX];
    }
    
    function checkBalance( address counterpart) public view returns (uint8) {
        return balances[msg.sender].addresses[counterpart];
    }

}